import {
  type CallOptions,
  type ChannelCredentials,
  type ChannelOptions,
  Metadata,
  type ServiceError,
  credentials as grpcCredentials,
  status as grpcStatus,
} from "@grpc/grpc-js";

import {
  type CreateWorkspaceResponse,
  type DestroyWorkspaceResponse,
  type ExecuteCommandResponse,
  type ExposePortResponse,
  type ForkWorkspaceResponse,
  type GetAttestationEvidenceResponse,
  type GetPoolStatusResponse,
  type GetRuntimeCapabilitiesResponse,
  type ListEventsResponse,
  type NetworkConfig,
  type PauseWorkspaceResponse,
  type PingResponse,
  type PrivacyRouterConfig,
  type ReadFileResponse,
  type RestoreWorkspaceResponse,
  type ResumeWorkspaceResponse,
  RuntimeClient,
  type SnapshotWorkspaceResponse,
  type UnexposePortResponse,
  type WriteFileResponse,
} from "./generated/ne/runtime/v1/runtime.js";

/** Options accepted by `new Client(...)`. */
export type ClientOptions = {
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

const CLIENT_CLOSED_MESSAGE = "Client has been closed";

/** Narrowing guard for `@grpc/grpc-js`'s `ServiceError`. */
export function isServiceError(err: unknown): err is ServiceError {
  return (
    err instanceof Error &&
    typeof (err as { code?: unknown }).code === "number" &&
    typeof (err as { details?: unknown }).details === "string"
  );
}

/** NeuronEdge Enclave Runtime API client. Wraps `@grpc/grpc-js` and the
 *  ts-proto-generated `RuntimeClient`. */
export class Client {
  readonly #stub: RuntimeClient;
  readonly #defaultDeadlineMs: number | undefined;
  #closed = false;

  constructor(options: ClientOptions) {
    if (typeof options?.target !== "string" || options.target.length === 0) {
      throw new TypeError("target must be a non-empty string");
    }
    const creds = options.credentials ?? grpcCredentials.createInsecure();
    this.#stub = new RuntimeClient(options.target, creds, options.channelOptions ?? {});
    this.#defaultDeadlineMs = options.deadlineMs;
  }

  /** Closes the underlying channel. Idempotent. */
  close(): void {
    if (this.#closed) return;
    this.#closed = true;
    this.#stub.close();
  }

  /** Symbol.dispose support — Node 22+ `using` semantics. */
  [Symbol.dispose](): void {
    this.close();
  }

  /** Symbol.asyncDispose support — `await using` semantics. */
  async [Symbol.asyncDispose](): Promise<void> {
    this.close();
  }

  // ----- RPC methods ------------------------------------------------

  ping(options: { deadlineMs?: number } = {}): Promise<PingResponse> {
    return this.#unary<PingResponse>(options.deadlineMs, (callOptions, callback) =>
      this.#stub.ping({}, this.#buildMetadata(), callOptions, callback),
    );
  }

  /** Return the runtime's resolved execution and attestation capabilities. */
  getRuntimeCapabilities(
    options: { deadlineMs?: number } = {},
  ): Promise<GetRuntimeCapabilitiesResponse> {
    return this.#unary<GetRuntimeCapabilitiesResponse>(
      options.deadlineMs,
      (callOptions, callback) =>
        this.#stub.getRuntimeCapabilities({}, this.#buildMetadata(), callOptions, callback),
    );
  }

  /** Launch one workspace through the confidential-azure execution profile.
   *
   *  Confidential capacity belongs to the enclosing CVM, so the request uses
   *  empty image digests and zero runtime sizing fields by contract. */
  createConfidentialWorkspace(options: {
    workspaceId: string;
    deadlineMs?: number;
  }): Promise<CreateWorkspaceResponse> {
    return this.createWorkspace({
      workspaceId: options.workspaceId,
      kernelSha256: "",
      rootfsSha256: "",
      rootfsReadOnly: true,
      vcpuCount: 0,
      memSizeMib: 0,
      guestVsockCid: 0,
      ...(options.deadlineMs === undefined ? {} : { deadlineMs: options.deadlineMs }),
    });
  }

  createWorkspace(options: {
    workspaceId: string;
    /** Lowercase SHA-256 for the managed kernel; omit with rootfsSha256 for tier creates. */
    kernelSha256?: string;
    /** Lowercase SHA-256 for the managed rootfs; omit with kernelSha256 for tier creates. */
    rootfsSha256?: string;
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
      injectHeaders?: readonly { name: string; value: string }[];
    }[];
    deadlineMs?: number;
  }): Promise<CreateWorkspaceResponse> {
    const kernelSha256 = options.kernelSha256 ?? "";
    const rootfsSha256 = options.rootfsSha256 ?? "";
    if (Boolean(kernelSha256) !== Boolean(rootfsSha256)) {
      return Promise.reject(
        new TypeError("kernelSha256 and rootfsSha256 must be provided together"),
      );
    }
    const network: NetworkConfig | undefined = options.enableNetwork
      ? {
          enableEgress: options.enableEgress ?? false,
          allowCidrs: options.allowCidrs ? [...options.allowCidrs] : [],
          allowHostnames: options.allowHostnames ? [...options.allowHostnames] : [],
          privacyRouter: options.enablePrivacyRouter
            ? ({} satisfies PrivacyRouterConfig)
            : undefined,
          exposedPorts: options.exposedPorts
            ? options.exposedPorts.map((p) => ({
                port: p.port,
                injectHeaders: p.injectHeaders ? [...p.injectHeaders] : [],
              }))
            : [],
        }
      : undefined;
    const request = {
      workspaceId: options.workspaceId,
      kernelSha256,
      rootfsSha256,
      rootfsReadOnly: options.rootfsReadOnly ?? true,
      vcpuCount: options.vcpuCount,
      memSizeMib: options.memSizeMib,
      guestVsockCid: options.guestVsockCid,
      kernelBootArgs: options.kernelBootArgs,
      tier: options.tier,
      network,
    };
    return this.#unary<CreateWorkspaceResponse>(options.deadlineMs, (callOptions, callback) =>
      this.#stub.createWorkspace(request, this.#buildMetadata(), callOptions, callback),
    );
  }

  executeCommand(options: {
    workspaceId: string;
    command: string;
    args?: readonly string[];
    timeoutMs?: number;
    guestPort?: number;
    deadlineMs?: number;
  }): Promise<ExecuteCommandResponse> {
    const request = {
      workspaceId: options.workspaceId,
      command: options.command,
      args: options.args ? [...options.args] : [],
      timeoutMs: options.timeoutMs ?? 0,
      guestPort: options.guestPort ?? 0,
    };
    return this.#unary<ExecuteCommandResponse>(options.deadlineMs, (callOptions, callback) =>
      this.#stub.executeCommand(request, this.#buildMetadata(), callOptions, callback),
    );
  }

  writeFile(options: {
    workspaceId: string;
    path: string;
    content: Uint8Array;
    guestPort?: number;
    deadlineMs?: number;
  }): Promise<WriteFileResponse> {
    const request = {
      workspaceId: options.workspaceId,
      path: options.path,
      content: options.content,
      guestPort: options.guestPort ?? 0,
    };
    return this.#unary<WriteFileResponse>(options.deadlineMs, (callOptions, callback) =>
      this.#stub.writeFile(request, this.#buildMetadata(), callOptions, callback),
    );
  }

  readFile(options: {
    workspaceId: string;
    path: string;
    maxBytes?: number;
    guestPort?: number;
    deadlineMs?: number;
  }): Promise<ReadFileResponse> {
    const request = {
      workspaceId: options.workspaceId,
      path: options.path,
      maxBytes: options.maxBytes ?? 0,
      guestPort: options.guestPort ?? 0,
    };
    return this.#unary<ReadFileResponse>(options.deadlineMs, (callOptions, callback) =>
      this.#stub.readFile(request, this.#buildMetadata(), callOptions, callback),
    );
  }

  destroyWorkspace(options: {
    workspaceId: string;
    gracePeriodMs?: number;
    deadlineMs?: number;
  }): Promise<DestroyWorkspaceResponse> {
    const request = {
      workspaceId: options.workspaceId,
      gracePeriodMs: options.gracePeriodMs ?? 2_000,
    };
    return this.#unary<DestroyWorkspaceResponse>(options.deadlineMs, (callOptions, callback) =>
      this.#stub.destroyWorkspace(request, this.#buildMetadata(), callOptions, callback),
    );
  }

  listEvents(
    options: {
      workspaceId?: string;
      sinceChainIndex?: number;
      limit?: number;
      deadlineMs?: number;
    } = {},
  ): Promise<ListEventsResponse> {
    const request = {
      workspaceId: options.workspaceId,
      sinceChainIndex: options.sinceChainIndex ?? 0,
      limit: options.limit ?? 0,
    };
    return this.#unary<ListEventsResponse>(options.deadlineMs, (callOptions, callback) =>
      this.#stub.listEvents(request, this.#buildMetadata(), callOptions, callback),
    );
  }

  /** Pause a running workspace (freeze vCPUs in place).
   *
   *  The workspace must already exist and be in the running state.
   *  Use {@link resume} to unfreeze it afterwards.
   *
   *  Deferred: unsupported on current Firecracker; the server returns an Unsupported error. Use snapshot/restore instead. */
  pause(options: { workspaceId: string; deadlineMs?: number }): Promise<PauseWorkspaceResponse> {
    return this.#unary<PauseWorkspaceResponse>(options.deadlineMs, (callOptions, callback) =>
      this.#stub.pauseWorkspace(
        { workspaceId: options.workspaceId },
        this.#buildMetadata(),
        callOptions,
        callback,
      ),
    );
  }

  /** Resume a previously paused workspace.
   *
   *  Deferred: unsupported on current Firecracker; the server returns an Unsupported error. Use snapshot/restore instead. */
  resume(options: { workspaceId: string; deadlineMs?: number }): Promise<ResumeWorkspaceResponse> {
    return this.#unary<ResumeWorkspaceResponse>(options.deadlineMs, (callOptions, callback) =>
      this.#stub.resumeWorkspace(
        { workspaceId: options.workspaceId },
        this.#buildMetadata(),
        callOptions,
        callback,
      ),
    );
  }

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
  }): Promise<SnapshotWorkspaceResponse> {
    return this.#unary<SnapshotWorkspaceResponse>(options.deadlineMs, (callOptions, callback) =>
      this.#stub.snapshotWorkspace(
        { workspaceId: options.workspaceId, live: options.live ?? false },
        this.#buildMetadata(),
        callOptions,
        callback,
      ),
    );
  }

  /** Restore a fresh workspace from an existing snapshot artifact.
   *
   *  `snapshotId` is the ULID returned by a prior {@link snapshot}
   *  call. `newWorkspaceId` must satisfy the jailer's grammar
   *  `[a-zA-Z0-9-]{1,64}` and must not already exist. */
  restore(options: {
    snapshotId: string;
    newWorkspaceId: string;
    deadlineMs?: number;
  }): Promise<RestoreWorkspaceResponse> {
    return this.#unary<RestoreWorkspaceResponse>(options.deadlineMs, (callOptions, callback) =>
      this.#stub.restoreWorkspace(
        { snapshotId: options.snapshotId, newWorkspaceId: options.newWorkspaceId },
        this.#buildMetadata(),
        callOptions,
        callback,
      ),
    );
  }

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
  }): Promise<ForkWorkspaceResponse> {
    return this.#unary<ForkWorkspaceResponse>(options.deadlineMs, (callOptions, callback) =>
      this.#stub.forkWorkspace(
        {
          snapshotId: options.snapshotId,
          newWorkspaceId: options.newWorkspaceId,
          hostname: options.hostname ?? "",
        },
        this.#buildMetadata(),
        callOptions,
        callback,
      ),
    );
  }

  /** Query warm-pool status for the configured tier (if any).
   *
   *  Returns immediately from the pool manager's in-memory state; safe
   *  to call at high frequency for dashboard/health probes. */
  poolStatus(options: { deadlineMs?: number } = {}): Promise<GetPoolStatusResponse> {
    return this.#unary<GetPoolStatusResponse>(options.deadlineMs, (callOptions, callback) =>
      this.#stub.getPoolStatus({}, this.#buildMetadata(), callOptions, callback),
    );
  }

  /** Expose a guest port to host-based ingress routing.
   *
   *  After a successful call the port is reachable at
   *  `{port}-{workspaceId}.{ingressDomain}`. The workspace must be
   *  running with networking enabled. */
  exposePort(options: {
    workspaceId: string;
    port: number;
    injectHeaders?: readonly { name: string; value: string }[];
    deadlineMs?: number;
  }): Promise<ExposePortResponse> {
    const request = {
      workspaceId: options.workspaceId,
      port: {
        port: options.port,
        injectHeaders: options.injectHeaders ? [...options.injectHeaders] : [],
      },
    };
    return this.#unary<ExposePortResponse>(options.deadlineMs, (callOptions, callback) =>
      this.#stub.exposePort(request, this.#buildMetadata(), callOptions, callback),
    );
  }

  /** Stop routing ingress to a previously exposed guest port. */
  unexposePort(options: {
    workspaceId: string;
    port: number;
    deadlineMs?: number;
  }): Promise<UnexposePortResponse> {
    return this.#unary<UnexposePortResponse>(options.deadlineMs, (callOptions, callback) =>
      this.#stub.unexposePort(
        { workspaceId: options.workspaceId, port: options.port },
        this.#buildMetadata(),
        callOptions,
        callback,
      ),
    );
  }

  /** Generate attestation evidence for a running workspace.
   *
   *  `nonce` is the caller challenge (16..=64 bytes) bound into the
   *  returned evidence. The software-fallback provider signs with the
   *  runtime's Ed25519 identity key. */
  getAttestationEvidence(options: {
    workspaceId: string;
    nonce: Uint8Array;
    deadlineMs?: number;
  }): Promise<GetAttestationEvidenceResponse> {
    return this.#unary<GetAttestationEvidenceResponse>(
      options.deadlineMs,
      (callOptions, callback) =>
        this.#stub.getAttestationEvidence(
          { workspaceId: options.workspaceId, nonce: options.nonce },
          this.#buildMetadata(),
          callOptions,
          callback,
        ),
    );
  }

  // ----- internals --------------------------------------------------

  #buildMetadata(): Metadata {
    return new Metadata();
  }

  #buildCallOptions(perCallMs: number | undefined): Partial<CallOptions> {
    const ms = perCallMs ?? this.#defaultDeadlineMs;
    if (ms === undefined) return {};
    return { deadline: new Date(Date.now() + ms) };
  }

  #unary<T>(
    perCallDeadlineMs: number | undefined,
    invoke: (
      callOptions: Partial<CallOptions>,
      callback: (err: ServiceError | null, value?: T) => void,
    ) => unknown,
  ): Promise<T> {
    if (this.#closed) {
      return Promise.reject(new Error(CLIENT_CLOSED_MESSAGE));
    }
    return new Promise<T>((resolve, reject) => {
      const callOptions = this.#buildCallOptions(perCallDeadlineMs);
      invoke(callOptions, (err, value) => {
        if (err !== null) {
          reject(err);
          return;
        }
        if (value === undefined) {
          const synthetic: ServiceError = Object.assign(
            new Error("grpc-js returned neither error nor value"),
            { code: grpcStatus.INTERNAL, details: "empty response", metadata: new Metadata() },
          );
          reject(synthetic);
          return;
        }
        resolve(value);
      });
    });
  }
}
