// SPDX-FileCopyrightText: 2026 Infrastacks LLC
// SPDX-License-Identifier: Apache-2.0

//! L7 reverse-proxy router for NeuronEdge Enclave ingress.
//!
//! Resolves HTTP `Host` headers against the [`IngressRegistry`], applies the
//! SSRF guard (targets must be link-local), injects configured headers, and
//! streams the request to the upstream guest service.

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use rustls::ServerConfig as RustlsServerConfig;
use tokio_rustls::TlsAcceptor;

use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::client::conn::http1 as client_http1;
use hyper::server::conn::http1 as server_http1;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;

/// Default ceiling on concurrent in-flight ingress connections.
///
/// The edge is internet-facing and shares a process with the privileged
/// supervisor, so an unbounded per-connection spawn is a remote
/// denial-of-service vector (audit `S7-F2`): a flood would exhaust file
/// descriptors and memory and reap the supervisor. Excess connections wait in
/// the kernel accept backlog until a slot frees.
pub const DEFAULT_MAX_CONNECTIONS: usize = 1024;

/// Default time allowed to receive complete request headers before the
/// connection is dropped (slowloris defense).
pub const DEFAULT_HEADER_READ_TIMEOUT: Duration = Duration::from_secs(15);

/// Default time allowed for the TLS handshake to complete before the connection
/// is dropped (handshake-stall defense).
pub const DEFAULT_TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

use crate::host::{IngressError, parse_ingress_host};
use crate::registry::{IngressRegistry, Target};

/// Why a request was refused (drives the audit `reason` field).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DenyReason {
    /// The `Host` header could not be parsed as `{port}-{wsid}.{domain}`.
    ParseError,
    /// The `Host` header's domain does not match the configured ingress domain.
    DomainMismatch,
    /// The workspace ID is not registered in the ingress registry.
    UnknownWorkspace,
    /// The workspace is registered but the requested port is not exposed.
    UnexposedPort,
    /// The resolved target address is not in the link-local 169.254.0.0/16 pool.
    SsrfGuard,
}

impl DenyReason {
    /// Stable lowercase string for use in audit logs and HTTP error bodies.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ParseError => "parse_error",
            Self::DomainMismatch => "domain_mismatch",
            Self::UnknownWorkspace => "unknown_workspace",
            Self::UnexposedPort => "unexposed_port",
            Self::SsrfGuard => "ssrf_guard",
        }
    }
}

/// Outcome of resolving a `Host` header against the registry.
#[derive(Debug)]
pub enum Decision {
    /// The route was resolved; proxy the request to `target`.
    Allow {
        /// Resolved upstream target.
        target: Target,
        /// Workspace ID extracted from the `Host` header.
        wsid: String,
        /// Port number extracted from the `Host` header.
        port: u16,
    },
    /// The route was denied for the given reason.
    Deny(DenyReason),
}

/// Return `true` iff `ip` is in the link-local 169.254.0.0/16 range.
///
/// Ingress targets must be link-local (the per-slot TAP bridge pool).  This is
/// defence-in-depth: the registry is the only source of upstream addresses, but
/// we double-check here so a hypothetical registry corruption cannot cause the
/// proxy to dial arbitrary hosts (SSRF).
#[must_use]
pub fn is_link_local(ip: &Ipv4Addr) -> bool {
    ip.is_link_local()
}

/// Resolve a `Host` header value to an upstream target or a typed deny reason.
///
/// This is the pure decision function: no I/O, fully testable on macOS.
///
/// A `Host` value with no `.` separator (e.g. a bare label with no domain)
/// is rejected as [`DenyReason::ParseError`] before the domain check, so that
/// junk values produce `ParseError` rather than `DomainMismatch`.
pub async fn route_decision(host: &str, domain: &str, reg: &IngressRegistry) -> Decision {
    // Strip any `:port` authority suffix before the structural check.
    let bare = host.split(':').next().unwrap_or("").trim();
    if !bare.contains('.') {
        return Decision::Deny(DenyReason::ParseError);
    }
    let (port, wsid) = match parse_ingress_host(host, domain) {
        Ok(v) => v,
        Err(IngressError::DomainMismatch) => return Decision::Deny(DenyReason::DomainMismatch),
        Err(IngressError::Parse) => return Decision::Deny(DenyReason::ParseError),
    };
    match reg.resolve(&wsid, port).await {
        Some(target) if is_link_local(&target.guest_ip) => Decision::Allow { target, wsid, port },
        Some(_) => Decision::Deny(DenyReason::SsrfGuard),
        None => {
            if reg.workspace_exists(&wsid).await {
                Decision::Deny(DenyReason::UnexposedPort)
            } else {
                Decision::Deny(DenyReason::UnknownWorkspace)
            }
        }
    }
}

/// Audit hook so the supervisor can sign ingress decisions into its chain
/// without the ingress crate depending on the audit-log type.
///
/// Implementations must be cheap and non-blocking; the supervisor's impl
/// spawns the emit task rather than awaiting it inline.
pub trait AuditSink: Send + Sync + 'static {
    /// Called when a request is successfully routed to a guest service.
    fn route_allowed(&self, host: &str, wsid: &str, port: u16);
    /// Called when a request is denied.
    fn route_denied(&self, host: &str, reason: DenyReason);
}

/// Configuration for the ingress router.
#[derive(Clone)]
pub struct RouterConfig {
    /// The ingress domain (e.g. `apps.example.com`). All `Host` headers must
    /// end with `.<ingress_domain>` or they are rejected with `DomainMismatch`.
    pub ingress_domain: String,
    /// Maximum number of concurrent in-flight connections. Excess connections
    /// wait (kernel accept backlog) until a slot frees. Bounds file-descriptor
    /// and memory use under a connection flood (audit `S7-F2`).
    pub max_connections: usize,
    /// Maximum time to receive complete request headers before the connection
    /// is dropped (slowloris defense).
    pub header_read_timeout: Duration,
    /// Maximum time for the TLS handshake to complete before the connection is
    /// dropped (handshake-stall defense).
    pub tls_handshake_timeout: Duration,
}

impl RouterConfig {
    /// Construct a config for `ingress_domain` with the default connection
    /// ceiling and timeouts.
    #[must_use]
    pub fn new(ingress_domain: String) -> Self {
        Self {
            ingress_domain,
            max_connections: DEFAULT_MAX_CONNECTIONS,
            header_read_timeout: DEFAULT_HEADER_READ_TIMEOUT,
            tls_handshake_timeout: DEFAULT_TLS_HANDSHAKE_TIMEOUT,
        }
    }
}

type ProxyBody = BoxBody<Bytes, hyper::Error>;

/// L7 ingress reverse proxy.
///
/// Holds the shared registry, the configured domain, and an audit sink.
/// Constructed via [`IngressRouter::new`], which returns an `Arc<Self>` for
/// sharing across Tokio tasks.
pub struct IngressRouter {
    registry: Arc<IngressRegistry>,
    cfg: RouterConfig,
    audit: Arc<dyn AuditSink>,
    /// Bounds concurrent in-flight connections; each accepted connection holds
    /// one permit for its lifetime (audit `S7-F2`).
    conn_limit: Arc<Semaphore>,
}

impl IngressRouter {
    /// Create a new router. Returns `Arc<Self>` for task sharing.
    #[must_use]
    pub fn new(
        registry: Arc<IngressRegistry>,
        cfg: RouterConfig,
        audit: Arc<dyn AuditSink>,
    ) -> Arc<Self> {
        let conn_limit = Arc::new(Semaphore::new(cfg.max_connections));
        Arc::new(Self {
            registry,
            cfg,
            audit,
            conn_limit,
        })
    }

    /// Number of connection slots currently free. Exposed for observability and
    /// testing the connection ceiling.
    #[must_use]
    pub fn available_connection_permits(&self) -> usize {
        self.conn_limit.available_permits()
    }

    /// Serve plaintext HTTP/1.1 on an already-bound listener.
    ///
    /// Runs until the listener errors irrecoverably; spawn as a task.
    /// TLS termination is a separate task that wraps the accepted stream
    /// before delegating to [`Self::serve_conn`].
    pub async fn serve_plaintext(self: Arc<Self>, listener: TcpListener) {
        loop {
            let (stream, _peer) = match listener.accept().await {
                Ok(v) => v,
                Err(e) => {
                    tracing::error!(error = %e, "ingress accept failed");
                    continue;
                }
            };
            // Backpressure: wait for a free connection slot before serving. When
            // at capacity the accept loop parks here and the kernel backlog
            // absorbs (then sheds) new connections, bounding fd/memory use.
            // `acquire_owned` only errors when the semaphore is closed → shutdown.
            let Ok(permit) = Arc::clone(&self.conn_limit).acquire_owned().await else {
                return;
            };
            let me = Arc::clone(&self);
            tokio::spawn(async move {
                let _permit = permit; // released when the connection ends
                me.serve_conn(stream).await;
            });
        }
    }

    /// Serve HTTPS on an already-bound listener, terminating TLS with the
    /// provided rustls `ServerConfig`, then delegating each accepted (and
    /// TLS-wrapped) stream to [`Self::serve_conn`]. Runs until the listener
    /// errors irrecoverably; spawn as a task.
    pub async fn serve_tls(self: Arc<Self>, listener: TcpListener, tls: Arc<RustlsServerConfig>) {
        let acceptor = TlsAcceptor::from(tls);
        let handshake_timeout = self.cfg.tls_handshake_timeout;
        loop {
            let (stream, _peer) = match listener.accept().await {
                Ok(v) => v,
                Err(e) => {
                    tracing::error!(error = %e, "ingress TLS accept failed");
                    continue;
                }
            };
            // Backpressure (see `serve_plaintext`): bound concurrent connections.
            let Ok(permit) = Arc::clone(&self.conn_limit).acquire_owned().await else {
                return;
            };
            let acceptor = acceptor.clone();
            let me = Arc::clone(&self);
            tokio::spawn(async move {
                let _permit = permit; // released when the connection ends
                // A stalled handshake must not pin a connection slot forever.
                match tokio::time::timeout(handshake_timeout, acceptor.accept(stream)).await {
                    Ok(Ok(tls_stream)) => me.serve_conn(tls_stream).await,
                    Ok(Err(e)) => tracing::debug!(error = %e, "ingress TLS handshake failed"),
                    Err(_) => tracing::debug!("ingress TLS handshake timed out"),
                }
            });
        }
    }

    /// Serve one accepted connection.
    ///
    /// Public so the TLS task (C4) can call it with a rustls-wrapped stream
    /// (any `AsyncRead + AsyncWrite + Send + Unpin + 'static`).
    pub async fn serve_conn<S>(self: Arc<Self>, stream: S)
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
    {
        let header_read_timeout = self.cfg.header_read_timeout;
        let io = TokioIo::new(stream);
        let svc = hyper::service::service_fn(move |req| {
            let me = Arc::clone(&self);
            async move { me.handle(req).await }
        });
        // Bound the time a connection may spend sending request headers so a
        // slow/idle peer cannot hold a connection slot indefinitely (S7-F2).
        let mut builder = server_http1::Builder::new();
        builder
            .timer(TokioTimer::new())
            .header_read_timeout(header_read_timeout);
        if let Err(e) = builder.serve_connection(io, svc).await {
            tracing::debug!(error = %e, "ingress connection ended");
        }
    }

    async fn handle(
        &self,
        mut req: Request<Incoming>,
    ) -> Result<Response<ProxyBody>, hyper::Error> {
        let host = req
            .headers()
            .get(hyper::header::HOST)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();

        match route_decision(&host, &self.cfg.ingress_domain, &self.registry).await {
            Decision::Deny(reason) => {
                self.audit.route_denied(&host, reason);
                let code = match reason {
                    DenyReason::DomainMismatch => StatusCode::MISDIRECTED_REQUEST,
                    _ => StatusCode::NOT_FOUND,
                };
                Ok(deny_response(code, reason))
            }
            Decision::Allow { target, wsid, port } => {
                self.audit.route_allowed(&host, &wsid, port);
                // Strip hop-by-hop headers, then inject configured headers
                // (injection runs last so it always wins — see fn docs).
                prepare_upstream_headers(req.headers_mut(), &target.inject_headers);
                self.proxy(req, target.guest_ip, target.port).await
            }
        }
    }

    async fn proxy(
        &self,
        req: Request<Incoming>,
        ip: Ipv4Addr,
        port: u16,
    ) -> Result<Response<ProxyBody>, hyper::Error> {
        let upstream = match TcpStream::connect((ip, port)).await {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(error = %e, %ip, port, "ingress upstream connect failed");
                return Ok(deny_response(
                    StatusCode::BAD_GATEWAY,
                    DenyReason::SsrfGuard,
                ));
            }
        };
        let (mut sender, conn) = match client_http1::handshake(TokioIo::new(upstream)).await {
            Ok(pair) => pair,
            Err(e) => {
                tracing::warn!(error = %e, %ip, port, "ingress upstream handshake failed");
                return Ok(deny_response(
                    StatusCode::BAD_GATEWAY,
                    DenyReason::SsrfGuard,
                ));
            }
        };
        tokio::spawn(async move {
            if let Err(e) = conn.await {
                tracing::debug!(error = %e, "ingress upstream connection ended");
            }
        });
        // Upstream request/response framing (Content-Length / Transfer-Encoding)
        // is managed by hyper; inbound framing was already validated by the
        // server-side parser. Never hand-set framing headers here.
        //
        // `send_request` may have partially consumed the request body before
        // failing, so a `?` here legitimately tears down this client connection.
        let resp = sender.send_request(req).await?;
        Ok(resp.map(BodyExt::boxed))
    }
}

/// Prepare the inbound request headers for forwarding: strip RFC 7230 §6.1
/// hop-by-hop headers (and any names the client listed in `Connection`),
/// then apply the configured injected headers (overwrite). Injection runs
/// AFTER stripping so a client cannot strip an injected header by listing
/// its name in `Connection`.
fn prepare_upstream_headers(headers: &mut hyper::HeaderMap, inject: &[(String, String)]) {
    // Names the client marked connection-specific.
    let mut conn_listed: Vec<hyper::header::HeaderName> = Vec::new();
    for v in &headers.get_all(hyper::header::CONNECTION) {
        if let Ok(s) = v.to_str() {
            for tok in s.split(',') {
                if let Ok(name) = hyper::header::HeaderName::from_bytes(tok.trim().as_bytes()) {
                    conn_listed.push(name);
                }
            }
        }
    }
    // Standard hop-by-hop set. Build at runtime ("keep-alive" has no assoc
    // const on HeaderName in this http version).
    let hop = [
        hyper::header::CONNECTION,
        hyper::header::HeaderName::from_static("keep-alive"),
        hyper::header::PROXY_AUTHENTICATE,
        hyper::header::PROXY_AUTHORIZATION,
        hyper::header::TE,
        hyper::header::TRAILER,
        hyper::header::TRANSFER_ENCODING,
        hyper::header::UPGRADE,
    ];
    for name in &hop {
        headers.remove(name);
    }
    for name in &conn_listed {
        headers.remove(name);
    }
    // Inject AFTER stripping — injection wins.
    for (name, value) in inject {
        if let (Ok(n), Ok(v)) = (
            hyper::header::HeaderName::from_bytes(name.as_bytes()),
            hyper::header::HeaderValue::from_str(value),
        ) {
            headers.insert(n, v);
        } else {
            tracing::warn!(header = %name, "skipping invalid inject header");
        }
    }
}

fn deny_response(code: StatusCode, reason: DenyReason) -> Response<ProxyBody> {
    // Full<Bytes> has error type Infallible; map_err converts to hyper::Error
    // via the empty match on the uninhabited type so BoxBody<Bytes, hyper::Error>
    // is satisfied without any actual runtime path.
    let body = Full::new(Bytes::from(format!("ingress: {}\n", reason.as_str())))
        .map_err(|never| match never {})
        .boxed();
    let mut resp = Response::new(body);
    *resp.status_mut() = code;
    resp
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::{IngressRegistry, PortRoute};
    use std::net::Ipv4Addr;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// No-op audit sink for tests that exercise the connection lifecycle.
    struct NoopSink;
    impl AuditSink for NoopSink {
        fn route_allowed(&self, _host: &str, _wsid: &str, _port: u16) {}
        fn route_denied(&self, _host: &str, _reason: DenyReason) {}
    }

    fn test_router(max_connections: usize, header_read_timeout: Duration) -> Arc<IngressRouter> {
        IngressRouter::new(
            IngressRegistry::new(),
            RouterConfig {
                ingress_domain: "apps.example.com".into(),
                max_connections,
                header_read_timeout,
                tls_handshake_timeout: Duration::from_secs(10),
            },
            Arc::new(NoopSink),
        )
    }

    /// Poll `cond` until true or `deadline` elapses; returns whether it became true.
    async fn wait_until(mut cond: impl FnMut() -> bool, deadline: Duration) -> bool {
        let start = std::time::Instant::now();
        while start.elapsed() < deadline {
            if cond() {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        cond()
    }

    #[tokio::test]
    async fn server_drops_slowloris_connection_after_header_timeout() {
        // A connection that sends a partial request and never completes its
        // headers must be dropped by the server within the header-read timeout,
        // not held open indefinitely (slowloris / fd-exhaustion defense).
        let router = test_router(64, Duration::from_millis(150));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(Arc::clone(&router).serve_plaintext(listener));

        let mut conn = TcpStream::connect(addr).await.unwrap();
        // Request line but no terminating CRLF — headers never complete.
        conn.write_all(b"GET / HTTP/1.1\r\n").await.unwrap();

        // The server should close the connection (EOF, read returns 0) well
        // within 2s once the 150ms header timeout fires.
        let mut buf = [0u8; 64];
        let read = tokio::time::timeout(Duration::from_secs(2), conn.read(&mut buf)).await;
        let n = read
            .expect("server must close the idle connection within the header timeout")
            .expect("read after server close");
        assert_eq!(n, 0, "expected EOF (server-side close), got {n} bytes");
    }

    #[tokio::test]
    async fn connection_cap_bounds_concurrent_connections() {
        // With a single permit, an in-flight connection consumes the permit for
        // its lifetime and returns it on close — bounding concurrent connections.
        let router = test_router(1, Duration::from_secs(30));
        assert_eq!(router.available_connection_permits(), 1);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(Arc::clone(&router).serve_plaintext(listener));

        // Open one connection and keep it in header-read (long timeout) so it
        // holds the permit.
        let mut c1 = TcpStream::connect(addr).await.unwrap();
        c1.write_all(b"GET / HTTP/1.1\r\n").await.unwrap();

        assert!(
            wait_until(
                || router.available_connection_permits() == 0,
                Duration::from_secs(2)
            )
            .await,
            "in-flight connection should consume the single permit",
        );

        // Closing it returns the permit.
        drop(c1);
        assert!(
            wait_until(
                || router.available_connection_permits() == 1,
                Duration::from_secs(2)
            )
            .await,
            "permit must be released when the connection closes",
        );
    }

    #[tokio::test]
    async fn decision_allows_known_route_with_wsid_and_port() {
        let reg = IngressRegistry::new();
        reg.upsert_workspace(
            "ws-a",
            "169.254.7.6".parse().unwrap(),
            vec![PortRoute {
                port: 8080,
                inject_headers: vec![("x-a".into(), "1".into())],
            }],
        )
        .await;
        match route_decision("8080-ws-a.apps.example.com", "apps.example.com", &reg).await {
            Decision::Allow { target, wsid, port } => {
                assert_eq!(target.guest_ip, Ipv4Addr::new(169, 254, 7, 6));
                assert_eq!(
                    target.inject_headers,
                    vec![("x-a".to_string(), "1".to_string())]
                );
                assert_eq!(wsid, "ws-a");
                assert_eq!(port, 8080);
            }
            other @ Decision::Deny(_) => panic!("expected Allow, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn decision_denies_unknown_unexposed_parse_and_domain() {
        let reg = IngressRegistry::new();
        reg.upsert_workspace(
            "ws-a",
            "169.254.7.6".parse().unwrap(),
            vec![PortRoute {
                port: 8080,
                inject_headers: vec![],
            }],
        )
        .await;
        assert!(matches!(
            route_decision("8080-ws-z.apps.example.com", "apps.example.com", &reg).await,
            Decision::Deny(DenyReason::UnknownWorkspace)
        ));
        assert!(matches!(
            route_decision("9090-ws-a.apps.example.com", "apps.example.com", &reg).await,
            Decision::Deny(DenyReason::UnexposedPort)
        ));
        assert!(matches!(
            route_decision("8080-ws-a.evil.com", "apps.example.com", &reg).await,
            Decision::Deny(DenyReason::DomainMismatch)
        ));
        assert!(matches!(
            route_decision("garbage", "apps.example.com", &reg).await,
            Decision::Deny(DenyReason::ParseError)
        ));
    }

    #[test]
    fn ssrf_guard_rejects_non_link_local() {
        assert!(is_link_local(&"169.254.7.6".parse().unwrap()));
        assert!(!is_link_local(&"10.0.0.1".parse().unwrap()));
        assert!(!is_link_local(&"127.0.0.1".parse().unwrap()));
        assert!(!is_link_local(&"0.0.0.0".parse().unwrap()));
    }

    #[test]
    fn deny_reason_strings_are_stable() {
        assert_eq!(DenyReason::ParseError.as_str(), "parse_error");
        assert_eq!(DenyReason::DomainMismatch.as_str(), "domain_mismatch");
        assert_eq!(DenyReason::UnknownWorkspace.as_str(), "unknown_workspace");
        assert_eq!(DenyReason::UnexposedPort.as_str(), "unexposed_port");
        assert_eq!(DenyReason::SsrfGuard.as_str(), "ssrf_guard");
    }

    #[test]
    fn prepare_strips_hop_by_hop() {
        let mut h = hyper::HeaderMap::new();
        h.insert(hyper::header::UPGRADE, "websocket".parse().unwrap());
        h.insert(hyper::header::TE, "trailers".parse().unwrap());
        h.insert(hyper::header::TRANSFER_ENCODING, "chunked".parse().unwrap());
        h.insert(hyper::header::CONNECTION, "keep-alive".parse().unwrap());
        prepare_upstream_headers(&mut h, &[]);
        assert!(!h.contains_key(hyper::header::UPGRADE));
        assert!(!h.contains_key(hyper::header::TE));
        assert!(!h.contains_key(hyper::header::TRANSFER_ENCODING));
        assert!(!h.contains_key(hyper::header::CONNECTION));
        // "keep-alive" (listed in Connection) is also gone via the hop set.
        assert!(!h.contains_key(hyper::header::HeaderName::from_static("keep-alive")));
    }

    #[test]
    fn prepare_injection_wins_over_connection_strip() {
        let mut h = hyper::HeaderMap::new();
        // Attacker tries to strip the injected auth header by listing it in
        // Connection, and pre-seeds a forged value.
        h.insert(hyper::header::CONNECTION, "x-enclave-auth".parse().unwrap());
        h.insert(
            hyper::header::HeaderName::from_static("x-enclave-auth"),
            "attacker".parse().unwrap(),
        );
        prepare_upstream_headers(&mut h, &[("x-enclave-auth".into(), "real".into())]);
        let got = h
            .get(hyper::header::HeaderName::from_static("x-enclave-auth"))
            .expect("injected header must survive");
        assert_eq!(got, "real");
        assert!(!h.contains_key(hyper::header::CONNECTION));
    }

    #[test]
    fn prepare_overwrites_client_header() {
        let mut h = hyper::HeaderMap::new();
        h.insert(
            hyper::header::HeaderName::from_static("x-enclave-auth"),
            "attacker".parse().unwrap(),
        );
        prepare_upstream_headers(&mut h, &[("x-enclave-auth".into(), "real".into())]);
        let got = h
            .get(hyper::header::HeaderName::from_static("x-enclave-auth"))
            .expect("injected header present");
        assert_eq!(got, "real");
    }
}
