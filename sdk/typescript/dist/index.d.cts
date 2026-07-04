import { ChannelOptions, ChannelCredentials, ServiceError } from '@grpc/grpc-js';
import { BinaryWriter, BinaryReader } from '@bufbuild/protobuf/wire';

interface PingRequest {
}
declare const PingRequest: MessageFns<PingRequest>;
interface PingResponse {
    /** Crate version of the ne-api daemon. */
    apiVersion: string;
    /** Milliseconds since the API daemon began serving. */
    apiUptimeMs: number;
    /** Crate version of the ne-supervisor the API relayed to. */
    supervisorVersion: string;
    /** Milliseconds since the supervisor began accepting connections. */
    supervisorUptimeMs: number;
}
declare const PingResponse: MessageFns<PingResponse>;
interface CreateWorkspaceRequest {
    /**
     * Opaque workspace identifier. Caller-supplied; the supervisor
     * does not mint IDs. Must satisfy jailer's grammar
     * ([a-zA-Z0-9-]{1,64}).
     */
    workspaceId: string;
    /** Absolute host path to the guest kernel image (uncompressed vmlinux). */
    kernelImagePath: string;
    /** Absolute host path to the guest rootfs image (ext4 or squashfs). */
    rootfsImagePath: string;
    /** Whether the rootfs should be mounted read-only inside the guest. */
    rootfsReadOnly: boolean;
    /** Guest vCPU count. Protobuf has no u8 — runtime validates 1..=255. */
    vcpuCount: number;
    /** Guest memory in MiB. */
    memSizeMib: number;
    /** Guest vsock CID. 0 disables the vsock device. */
    guestVsockCid: number;
    /**
     * Optional kernel command-line arguments. When unset the supervisor
     * substitutes its configured default.
     */
    kernelBootArgs?: string | undefined;
    /**
     * Optional per-workspace network policy. When unset the workspace
     * gets no eth0 and no NAT. When set, the supervisor provisions a
     * dedicated netns + veth + TAP + (optionally) MASQUERADE. Requires
     * the supervisor to have been started with --enable-networking; if
     * not, the field is logged at warn and otherwise ignored.
     */
    network?: NetworkConfig | undefined;
    /**
     * Optional warm-pool tier tag. When set the supervisor (or pool
     * manager) may satisfy this request from a pre-warmed VM pool keyed
     * by this string. Callers that do not use pools omit the field.
     */
    tier?: string | undefined;
}
declare const CreateWorkspaceRequest: MessageFns<CreateWorkspaceRequest>;
/**
 * Per-workspace network policy.
 *
 * Phase 1 P0 second cut: deny-by-default FORWARD chain populated by
 * `allow_cidrs`. Future iterations add port allowlists, hostname
 * allowlists, and DNS overrides via additional fields — repeated /
 * optional keep the wire shape additive.
 */
interface NetworkConfig {
    /**
     * When true, the supervisor installs a MASQUERADE rule so the
     * workspace egresses through the host's default route. When false,
     * the netns + interfaces still exist but no NAT rule lands — useful
     * for air-gapped / confidential workloads.
     */
    enableEgress: boolean;
    /**
     * Destination CIDRs the workspace is permitted to reach. Empty
     * list combined with `enable_egress = true` keeps the historic
     * open-egress shape (the supervisor inserts an ACCEPT-all rule).
     * Empty list with `enable_egress = false` blocks every outbound
     * destination. Conntrack-tracked return traffic for already-
     * accepted flows is always allowed regardless.
     */
    allowCidrs: string[];
    /**
     * Hostname allowlist enforced by the per-workspace DNS filter.
     * Matches by suffix; `openai.com` allows `api.openai.com`,
     * `chat.openai.com`, etc. Leading `*.` is permitted and
     * equivalent to the bare form. Empty list disables the DNS
     * filter entirely; non-empty switches the workspace into
     * deny-by-default DNS (NXDOMAIN for unlisted names).
     */
    allowHostnames: string[];
    /**
     * When set, the workspace opts into the host-side privacy router
     * (HTTP body PII scanning). The supervisor spawns one
     * ne-privacy-router per workspace inside the netns and
     * installs iptables DNAT to redirect TCP/80 egress to it. The
     * PII policy itself is host-global in Phase 1 P0 (operator-set
     * via supervisor CLI) — the message stays empty for now and will
     * grow per-workspace overrides (e.g. an inline policy) in
     * Phase 2 without breaking existing clients.
     */
    privacyRouter?: PrivacyRouterConfig | undefined;
    /**
     * Ports inside the guest exposed to host-based ingress routing. Only
     * listed ports are reachable via {port}-{workspace_id}.{ingress_domain};
     * everything else is refused. Optional per-port auth-header injection.
     */
    exposedPorts: ExposedPort[];
}
declare const NetworkConfig: MessageFns<NetworkConfig>;
/**
 * Per-workspace privacy-router opt-in marker.
 *
 * Empty in Phase 1 P0: presence is the opt-in signal; the operator-
 * set global policy applies. Kept as a message (rather than a bool)
 * so Phase 2 can add fields (`policy`, `redirect_ports`, etc.)
 * without an SDK migration.
 */
interface PrivacyRouterConfig {
}
declare const PrivacyRouterConfig: MessageFns<PrivacyRouterConfig>;
/**
 * One guest port exposed to host-based ingress, with optional headers the
 * edge injects before forwarding (e.g. an auth/identity header).
 */
interface ExposedPort {
    /** guest TCP port; runtime validates 1..=65535 */
    port: number;
    injectHeaders: HeaderInjection[];
}
declare const ExposedPort: MessageFns<ExposedPort>;
/** A single header injected at the ingress edge. */
interface HeaderInjection {
    name: string;
    value: string;
}
declare const HeaderInjection: MessageFns<HeaderInjection>;
interface CreateWorkspaceResponse {
    workspaceId: string;
    /** PID of the jailer (effectively Firecracker's PID). */
    firecrackerPid: number;
    /**
     * Host-side absolute path to the vsock UDS the guest agent reaches
     * through. See Firecracker's host→guest CONNECT handshake.
     */
    vsockHostSocket: string;
    /** Host-side absolute path to the jailer chroot for this workspace. */
    jailerChroot: string;
    /**
     * Network resources the supervisor provisioned, when the request
     * asked for networking. Absent when the request omitted `network`
     * or the supervisor was not started with --enable-networking.
     */
    network?: WorkspaceNetwork | undefined;
}
declare const CreateWorkspaceResponse: MessageFns<CreateWorkspaceResponse>;
/**
 * Network details for a created workspace. Surfaced back so callers
 * can recognize where the workspace lives on the link-local pool
 * without an extra query.
 */
interface WorkspaceNetwork {
    /**
     * Netns the supervisor placed the workspace into (full path on the
     * host, e.g. `/var/run/netns/ne-<short_id>`).
     */
    netnsPath: string;
    /** TAP device the guest's eth0 is wired to. */
    tapDevice: string;
    /** Host-side veth IP. Workspace uses this as its default gateway. */
    hostIp: string;
    /**
     * Guest-side veth IP — the address the guest's eth0 should be
     * configured with.
     */
    guestIp: string;
    /** Subnet prefix length for both IPs (currently 30 for /30 link-local). */
    prefix: number;
}
declare const WorkspaceNetwork: MessageFns<WorkspaceNetwork>;
interface DestroyWorkspaceRequest {
    workspaceId: string;
    /** Milliseconds to wait between SIGTERM and SIGKILL. */
    gracePeriodMs: number;
}
declare const DestroyWorkspaceRequest: MessageFns<DestroyWorkspaceRequest>;
interface DestroyWorkspaceResponse {
    workspaceId: string;
}
declare const DestroyWorkspaceResponse: MessageFns<DestroyWorkspaceResponse>;
interface ExecuteCommandRequest {
    /**
     * Workspace the command runs in. Must already exist (from a prior
     * CreateWorkspace).
     */
    workspaceId: string;
    /** Path to the command binary, resolved against guest $PATH. */
    command: string;
    /** Arguments passed verbatim — no shell interpretation. */
    args: string[];
    /** Per-call timeout in milliseconds. 0 disables the timeout. */
    timeoutMs: number;
    /**
     * Guest vsock port the agent listens on. Defaults to 52 by
     * convention; surfaced as a field so test harnesses can wire to
     * alternates without recompiling.
     */
    guestPort: number;
}
declare const ExecuteCommandRequest: MessageFns<ExecuteCommandRequest>;
interface ExecuteCommandResponse {
    workspaceId: string;
    /** Captured stdout (lossy UTF-8; full buffer in Phase 1 P0). */
    stdout: string;
    /** Captured stderr (same conversion as stdout). */
    stderr: string;
    /** Process exit code (-1 if terminated by signal in Phase 1 P0). */
    exitCode: number;
    /** Wall-clock duration the command ran for, milliseconds. */
    elapsedMs: number;
    /**
     * True if the guest truncated stdout or stderr at its per-stream cap
     * (audit S3-F2). The captured bytes are still valid; only the tail
     * was dropped.
     */
    truncated: boolean;
}
declare const ExecuteCommandResponse: MessageFns<ExecuteCommandResponse>;
interface ListEventsRequest {
    /** When set, only return events whose workspace_id matches. */
    workspaceId?: string | undefined;
    /**
     * Skip events with chain_index < since_chain_index. 0 returns
     * everything from genesis.
     */
    sinceChainIndex: number;
    /** Soft cap on returned events. 0 is treated as 100. */
    limit: number;
}
declare const ListEventsRequest: MessageFns<ListEventsRequest>;
interface ListEventsResponse {
    events: AuditEvent[];
}
declare const ListEventsResponse: MessageFns<ListEventsResponse>;
/**
 * One signed audit event. Mirrors ne_protocol::audit::AuditEvent;
 * see crates/ne-protocol/src/audit.rs for field semantics. The
 * API daemon forwards the signed bytes unchanged so downstream
 * verifiers reach a stable canonical hash.
 */
interface AuditEvent {
    eventId: string;
    timestampMs: number;
    eventType: string;
    workspaceId?: string | undefined;
    /**
     * Event-specific payload serialized as JSON. Schema is
     * per-event_type; readers branch on event_type.
     */
    payloadJson: string;
    chainIndex: number;
    prevHashHex: string;
    signatureB64: string;
    signerPubkeyB64: string;
}
declare const AuditEvent: MessageFns<AuditEvent>;
interface WriteFileRequest {
    workspaceId: string;
    /**
     * Relative path inside the workspace's /workspace jail root. Absolute
     * paths and ".." segments are rejected by the guest agent.
     */
    path: string;
    /**
     * File contents. Hard cap 10 MiB (10 * 1024 * 1024 bytes); larger
     * requests are rejected at the api daemon with INVALID_ARGUMENT.
     */
    content: Uint8Array;
    /** Guest vsock port; 0 → server defaults to 52. */
    guestPort: number;
}
declare const WriteFileRequest: MessageFns<WriteFileRequest>;
interface WriteFileResponse {
    workspaceId: string;
    bytesWritten: number;
    /**
     * Echoes the canonical absolute path the file landed at, prefixed
     * with the jail root. Useful for audit clarity on the caller side.
     */
    absolutePath: string;
}
declare const WriteFileResponse: MessageFns<WriteFileResponse>;
interface ReadFileRequest {
    workspaceId: string;
    path: string;
    /** Maximum bytes to return. 0 → server default (10 MiB). */
    maxBytes: number;
    guestPort: number;
}
declare const ReadFileRequest: MessageFns<ReadFileRequest>;
interface ReadFileResponse {
    workspaceId: string;
    content: Uint8Array;
    /** Size on disk in bytes. May exceed bytes returned when truncated. */
    sizeBytes: number;
    truncated: boolean;
}
declare const ReadFileResponse: MessageFns<ReadFileResponse>;
interface PauseWorkspaceResponse {
    workspaceId: string;
}
declare const PauseWorkspaceResponse: MessageFns<PauseWorkspaceResponse>;
interface ResumeWorkspaceResponse {
    workspaceId: string;
}
declare const ResumeWorkspaceResponse: MessageFns<ResumeWorkspaceResponse>;
interface SnapshotWorkspaceResponse {
    /** Allocated snapshot id (ULID). */
    snapshotId: string;
    /** Source workspace this snapshot was taken from. */
    createdFromWorkspaceId: string;
    /** SHA-256 (hex) of the memory file. */
    memSha256: string;
    /** SHA-256 (hex) of the vmstate file. */
    vmstateSha256: string;
    /** Combined size of mem + vmstate in bytes. */
    sizeBytes: number;
    /** Source's NEW Firecracker PID after a successful live hot-swap; absent if not live. */
    firecrackerPid?: number | undefined;
}
declare const SnapshotWorkspaceResponse: MessageFns<SnapshotWorkspaceResponse>;
interface RestoreWorkspaceResponse {
    workspaceId: string;
    /** PID of the restored Firecracker process under jailer. */
    firecrackerPid: number;
    /** Host-side absolute path to the vsock UDS. */
    vsockHostSocket: string;
    /** Host-side absolute path to the jailer chroot for this workspace. */
    jailerChroot: string;
}
declare const RestoreWorkspaceResponse: MessageFns<RestoreWorkspaceResponse>;
interface ForkWorkspaceResponse {
    workspaceId: string;
    /** PID of the forked Firecracker process under jailer. */
    firecrackerPid: number;
    /** Host-side absolute path to the vsock UDS. */
    vsockHostSocket: string;
    /** Host-side absolute path to the jailer chroot for this workspace. */
    jailerChroot: string;
    /** Snapshot this fork was created from. */
    sourceSnapshotId: string;
    /** Hostname applied to the fork. */
    hostname: string;
    /** machine-id applied to the fork (32 lowercase hex). */
    machineId: string;
    /** Guest vsock CID (inherited from the snapshot vmstate). */
    guestVsockCid: number;
}
declare const ForkWorkspaceResponse: MessageFns<ForkWorkspaceResponse>;
interface GetPoolStatusResponse {
    /** True when the pool manager is configured with a tier. */
    configured: boolean;
    /** Tier tag this pool manages. Empty when not configured. */
    tier: string;
    /** Target number of pre-warmed VMs the pool aims to maintain. */
    targetSize: number;
    /** Number of VMs currently idle and ready to serve a request. */
    available: number;
    /** Number of VMs currently being prepared (booting / warming). */
    inFlight: number;
}
declare const GetPoolStatusResponse: MessageFns<GetPoolStatusResponse>;
interface ExposePortResponse {
    workspaceId: string;
    port: number;
}
declare const ExposePortResponse: MessageFns<ExposePortResponse>;
interface UnexposePortResponse {
    workspaceId: string;
    port: number;
}
declare const UnexposePortResponse: MessageFns<UnexposePortResponse>;
interface GetAttestationEvidenceResponse {
    evidence?: AttestationEvidence | undefined;
}
declare const GetAttestationEvidenceResponse: MessageFns<GetAttestationEvidenceResponse>;
interface AttestationEvidence {
    /** "software" (sev_snp / tdx reserved) */
    providerType: string;
    workspaceId: string;
    /** 32 bytes */
    measurement: Uint8Array;
    nonce: Uint8Array;
    issuedAt: number;
    reportData: Uint8Array;
    proof?: AttestationProof | undefined;
}
declare const AttestationEvidence: MessageFns<AttestationEvidence>;
interface AttestationProof {
    /** Software proof. Hardware proof fields are reserved for later. */
    signature: Uint8Array;
    /** 32 bytes (software) */
    signerPubkey: Uint8Array;
}
declare const AttestationProof: MessageFns<AttestationProof>;
type Builtin = Date | Function | Uint8Array | string | number | boolean | undefined;
type DeepPartial<T> = T extends Builtin ? T : T extends globalThis.Array<infer U> ? globalThis.Array<DeepPartial<U>> : T extends ReadonlyArray<infer U> ? ReadonlyArray<DeepPartial<U>> : T extends {
    $case: string;
} ? {
    [K in keyof Omit<T, "$case">]?: DeepPartial<T[K]>;
} & {
    $case: T["$case"];
} : T extends {} ? {
    [K in keyof T]?: DeepPartial<T[K]>;
} : Partial<T>;
type KeysOfUnion<T> = T extends T ? keyof T : never;
type Exact<P, I extends P> = P extends Builtin ? P : P & {
    [K in keyof P]: Exact<P[K], I[K]>;
} & {
    [K in Exclude<keyof I, KeysOfUnion<P>>]: never;
};
interface MessageFns<T> {
    encode(message: T, writer?: BinaryWriter): BinaryWriter;
    decode(input: BinaryReader | Uint8Array, length?: number): T;
    fromJSON(object: any): T;
    toJSON(message: T): unknown;
    create<I extends Exact<DeepPartial<T>, I>>(base?: I): T;
    fromPartial<I extends Exact<DeepPartial<T>, I>>(object: I): T;
}

/** Options accepted by `new Client(...)`. */
type ClientOptions = {
    /** gRPC target, e.g. `"127.0.0.1:50051"`. */
    target: string;
    /** Forwarded verbatim to the underlying `@grpc/grpc-js` channel. */
    channelOptions?: ChannelOptions;
    /** Channel credentials; defaults to `createInsecure()`. */
    credentials?: ChannelCredentials;
    /** Default per-call deadline in milliseconds, applied when a method
     *  doesn't pass its own `deadlineMs`. */
    deadlineMs?: number;
};
/** Narrowing guard for `@grpc/grpc-js`'s `ServiceError`. */
declare function isServiceError(err: unknown): err is ServiceError;
/** NeuronEdge Enclave Runtime API client. Wraps `@grpc/grpc-js` and the
 *  ts-proto-generated `RuntimeClient`. */
declare class Client {
    #private;
    constructor(options: ClientOptions);
    /** Closes the underlying channel. Idempotent. */
    close(): void;
    /** Symbol.dispose support — Node 22+ `using` semantics. */
    [Symbol.dispose](): void;
    /** Symbol.asyncDispose support — `await using` semantics. */
    [Symbol.asyncDispose](): Promise<void>;
    ping(options?: {
        deadlineMs?: number;
    }): Promise<PingResponse>;
    createWorkspace(options: {
        workspaceId: string;
        kernelImagePath: string;
        rootfsImagePath: string;
        vcpuCount: number;
        memSizeMib: number;
        guestVsockCid: number;
        rootfsReadOnly?: boolean;
        kernelBootArgs?: string;
        tier?: string;
        enableNetwork?: boolean;
        enableEgress?: boolean;
        allowCidrs?: readonly string[];
        allowHostnames?: readonly string[];
        enablePrivacyRouter?: boolean;
        exposedPorts?: readonly {
            port: number;
            injectHeaders?: readonly {
                name: string;
                value: string;
            }[];
        }[];
        deadlineMs?: number;
    }): Promise<CreateWorkspaceResponse>;
    executeCommand(options: {
        workspaceId: string;
        command: string;
        args?: readonly string[];
        timeoutMs?: number;
        guestPort?: number;
        deadlineMs?: number;
    }): Promise<ExecuteCommandResponse>;
    writeFile(options: {
        workspaceId: string;
        path: string;
        content: Uint8Array;
        guestPort?: number;
        deadlineMs?: number;
    }): Promise<WriteFileResponse>;
    readFile(options: {
        workspaceId: string;
        path: string;
        maxBytes?: number;
        guestPort?: number;
        deadlineMs?: number;
    }): Promise<ReadFileResponse>;
    destroyWorkspace(options: {
        workspaceId: string;
        gracePeriodMs?: number;
        deadlineMs?: number;
    }): Promise<DestroyWorkspaceResponse>;
    listEvents(options?: {
        workspaceId?: string;
        sinceChainIndex?: number;
        limit?: number;
        deadlineMs?: number;
    }): Promise<ListEventsResponse>;
    /** Pause a running workspace (freeze vCPUs in place).
     *
     *  The workspace must already exist and be in the running state.
     *  Use {@link resume} to unfreeze it afterwards.
     *
     *  Deferred: unsupported on current Firecracker; the server returns an Unsupported error. Use snapshot/restore instead. */
    pause(options: {
        workspaceId: string;
        deadlineMs?: number;
    }): Promise<PauseWorkspaceResponse>;
    /** Resume a previously paused workspace.
     *
     *  Deferred: unsupported on current Firecracker; the server returns an Unsupported error. Use snapshot/restore instead. */
    resume(options: {
        workspaceId: string;
        deadlineMs?: number;
    }): Promise<ResumeWorkspaceResponse>;
    /** Snapshot a workspace into a reusable artifact.
     *
     *  Returns a {@link SnapshotWorkspaceResponse} whose `snapshotId`
     *  (ULID) can be passed to {@link restore} to boot a new workspace
     *  from this image.
     *
     *  When `live` is `false` (default) the workspace must be paused first.
     *  When `live` is `true` the source keeps running and stays reachable
     *  during the snapshot (the workspace must be running); the response
     *  `firecrackerPid` field carries the source's new Firecracker PID after
     *  the live hot-swap completes.  For non-live snapshots `firecrackerPid`
     *  is absent. */
    snapshot(options: {
        workspaceId: string;
        live?: boolean;
        deadlineMs?: number;
    }): Promise<SnapshotWorkspaceResponse>;
    /** Restore a fresh workspace from an existing snapshot artifact.
     *
     *  `snapshotId` is the ULID returned by a prior {@link snapshot}
     *  call. `newWorkspaceId` must satisfy the jailer's grammar
     *  `[a-zA-Z0-9-]{1,64}` and must not already exist. */
    restore(options: {
        snapshotId: string;
        newWorkspaceId: string;
        deadlineMs?: number;
    }): Promise<RestoreWorkspaceResponse>;
    /** Fork a fresh workspace from a snapshot, resetting its guest identity.
     *
     *  `snapshotId` is the ULID returned by a prior {@link snapshot} call.
     *  `newWorkspaceId` must satisfy the jailer grammar `[a-zA-Z0-9-]{1,64}`
     *  and must not already exist. The fork's hostname / machine-id / RNG are
     *  reset so it is distinct from the source; `hostname` defaults to
     *  `newWorkspaceId`. To fork N times, call this N times. */
    fork(options: {
        snapshotId: string;
        newWorkspaceId: string;
        hostname?: string;
        deadlineMs?: number;
    }): Promise<ForkWorkspaceResponse>;
    /** Query warm-pool status for the configured tier (if any).
     *
     *  Returns immediately from the pool manager's in-memory state; safe
     *  to call at high frequency for dashboard/health probes. */
    poolStatus(options?: {
        deadlineMs?: number;
    }): Promise<GetPoolStatusResponse>;
    /** Expose a guest port to host-based ingress routing.
     *
     *  After a successful call the port is reachable at
     *  `{port}-{workspaceId}.{ingressDomain}`. The workspace must be
     *  running with networking enabled. */
    exposePort(options: {
        workspaceId: string;
        port: number;
        injectHeaders?: readonly {
            name: string;
            value: string;
        }[];
        deadlineMs?: number;
    }): Promise<ExposePortResponse>;
    /** Stop routing ingress to a previously exposed guest port. */
    unexposePort(options: {
        workspaceId: string;
        port: number;
        deadlineMs?: number;
    }): Promise<UnexposePortResponse>;
    /** Generate attestation evidence for a running workspace.
     *
     *  `nonce` is the caller challenge (16..=64 bytes) bound into the
     *  returned evidence. The software-fallback provider signs with the
     *  runtime's Ed25519 identity key. */
    getAttestationEvidence(options: {
        workspaceId: string;
        nonce: Uint8Array;
        deadlineMs?: number;
    }): Promise<GetAttestationEvidenceResponse>;
}

export { AuditEvent, Client, type ClientOptions, CreateWorkspaceRequest, CreateWorkspaceResponse, DestroyWorkspaceRequest, DestroyWorkspaceResponse, ExecuteCommandRequest, ExecuteCommandResponse, ListEventsRequest, ListEventsResponse, NetworkConfig, PingRequest, PingResponse, PrivacyRouterConfig, ReadFileRequest, ReadFileResponse, WorkspaceNetwork, WriteFileRequest, WriteFileResponse, isServiceError };
