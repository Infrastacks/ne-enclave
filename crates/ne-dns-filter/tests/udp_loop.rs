// SPDX-FileCopyrightText: 2026 Infrastacks LLC
// SPDX-License-Identifier: Apache-2.0

//! End-to-end UDP loop test for the DNS filter.
//!
//! Stands up a fake upstream resolver on a loopback UDP port, then
//! the filter on another loopback port, then drives both an
//! allowed and a denied query through the filter. Verifies the
//! filter forwards allowed queries to the upstream (and relays the
//! response) and returns NXDOMAIN for denied queries without ever
//! touching the upstream.

#![forbid(unsafe_code)]
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use ne_dns_filter::{Allowlist, run};
use tokio::net::UdpSocket;
use tokio::time::timeout;

fn build_query(qname: &str, qtype: u16, id: u16) -> Vec<u8> {
    let mut v = Vec::with_capacity(64);
    v.extend_from_slice(&id.to_be_bytes());
    v.extend_from_slice(&[0x01, 0x00]); // flags: RD
    v.extend_from_slice(&[0x00, 0x01]); // qdcount = 1
    v.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    for label in qname.split('.') {
        v.push(u8::try_from(label.len()).expect("label fits in u8"));
        v.extend_from_slice(label.as_bytes());
    }
    v.push(0);
    v.extend_from_slice(&qtype.to_be_bytes());
    v.extend_from_slice(&1u16.to_be_bytes()); // IN
    v
}

#[tokio::test]
async fn allowed_query_round_trips_through_upstream() {
    let upstream = UdpSocket::bind("127.0.0.1:0").await.expect("upstream bind");
    let upstream_addr = upstream.local_addr().expect("upstream addr");

    let upstream_hits = Arc::new(AtomicU32::new(0));
    let upstream_hits_clone = Arc::clone(&upstream_hits);

    // Fake upstream: receive a query, ack with a synthetic A-record
    // answer pointing at 192.0.2.42.
    tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        loop {
            let Ok((n, peer)) = upstream.recv_from(&mut buf).await else {
                return;
            };
            upstream_hits_clone.fetch_add(1, Ordering::SeqCst);
            let mut resp = buf[..n].to_vec();
            // Set QR + add one answer pointing at 192.0.2.42.
            resp[2] |= 0x80;
            resp[6] = 0;
            resp[7] = 1;
            // Compression pointer back to the question name + type/class/ttl/rdlen + IP.
            resp.extend_from_slice(&[
                0xC0, 0x0C, // name pointer to offset 12 (start of question)
                0x00, 0x01, // type A
                0x00, 0x01, // class IN
                0x00, 0x00, 0x00, 0x3C, // TTL=60
                0x00, 0x04, // RDLENGTH=4
                192, 0, 2, 42,
            ]);
            let _ = upstream.send_to(&resp, peer).await;
        }
    });

    let filter_addr: SocketAddr = "127.0.0.1:0".parse().expect("addr literal");
    // The filter binds in run(); to learn the chosen port we
    // pre-bind a socket and close it just before run() takes it.
    // Simpler: spawn run() on the wildcard port, then poll until
    // a query gets a response. Instead we pick a free port via a
    // throwaway bind.
    let scout = UdpSocket::bind(filter_addr).await.expect("scout");
    let filter_addr = scout.local_addr().expect("scout addr");
    drop(scout);

    let allow = Allowlist::new(["openai.com"]);
    let upstream_for_run = upstream_addr;
    let run_handle = tokio::spawn(async move {
        let _ = run(filter_addr, upstream_for_run, allow).await;
    });

    // Give the filter a moment to bind. 100ms is generous; CI
    // typically resolves in <10ms on a hot kernel.
    tokio::time::sleep(Duration::from_millis(100)).await;

    let client = UdpSocket::bind("127.0.0.1:0").await.expect("client bind");
    let query = build_query("api.openai.com", 1, 0xBEEF);
    client
        .send_to(&query, filter_addr)
        .await
        .expect("client send");

    let mut buf = vec![0u8; 4096];
    let (n, _) = timeout(Duration::from_secs(2), client.recv_from(&mut buf))
        .await
        .expect("client recv timeout")
        .expect("client recv");
    let resp = &buf[..n];
    assert_eq!(&resp[0..2], &[0xBE, 0xEF], "id echoed");
    assert_eq!(resp[2] & 0x80, 0x80, "QR set");
    assert_eq!(resp[3] & 0x0F, 0, "RCODE=0 (NOERROR)");
    assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 1, "one answer");
    // Trailing 4 bytes of resp are the IP.
    assert_eq!(&resp[resp.len() - 4..], &[192, 0, 2, 42]);
    assert!(
        upstream_hits.load(Ordering::SeqCst) >= 1,
        "upstream must have been hit"
    );

    run_handle.abort();
}

#[tokio::test]
async fn denied_query_gets_nxdomain_without_touching_upstream() {
    // Upstream socket that records hits — we expect zero.
    let upstream = UdpSocket::bind("127.0.0.1:0").await.expect("upstream bind");
    let upstream_addr = upstream.local_addr().expect("upstream addr");
    let upstream_hits = Arc::new(AtomicU32::new(0));
    let upstream_hits_clone = Arc::clone(&upstream_hits);
    tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        loop {
            let r = upstream.recv_from(&mut buf).await;
            if r.is_ok() {
                upstream_hits_clone.fetch_add(1, Ordering::SeqCst);
            } else {
                return;
            }
        }
    });

    let scout = UdpSocket::bind("127.0.0.1:0").await.expect("scout");
    let filter_addr = scout.local_addr().expect("scout addr");
    drop(scout);

    let allow = Allowlist::new(["openai.com"]);
    let upstream_for_run = upstream_addr;
    let run_handle = tokio::spawn(async move {
        let _ = run(filter_addr, upstream_for_run, allow).await;
    });
    tokio::time::sleep(Duration::from_millis(100)).await;

    let client = UdpSocket::bind("127.0.0.1:0").await.expect("client bind");
    let query = build_query("evil.example.com", 1, 0xCAFE);
    client.send_to(&query, filter_addr).await.expect("send");

    let mut buf = vec![0u8; 4096];
    let (n, _) = timeout(Duration::from_secs(2), client.recv_from(&mut buf))
        .await
        .expect("recv timeout")
        .expect("recv");
    let resp = &buf[..n];
    assert_eq!(&resp[0..2], &[0xCA, 0xFE], "id echoed");
    assert_eq!(resp[2] & 0x80, 0x80, "QR set");
    assert_eq!(resp[3] & 0x0F, 3, "RCODE=3 NXDOMAIN");
    assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 0, "zero answers");
    // The denied path must not have touched upstream — that's the
    // whole point of mediation.
    assert_eq!(
        upstream_hits.load(Ordering::SeqCst),
        0,
        "upstream must not be hit"
    );

    run_handle.abort();
}
