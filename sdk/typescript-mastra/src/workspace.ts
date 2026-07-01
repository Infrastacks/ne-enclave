import { randomUUID } from "node:crypto";
import type { ChannelOptions } from "@grpc/grpc-js";
import { Client, type ClientOptions } from "@neuronedge/enclave";

import { mapServiceError } from "./errors.js";
import { createEnclaveTools } from "./tools.js";

/** Options for {@link EnclaveWorkspace}. */
export type EnclaveWorkspaceOptions = {
  /** gRPC target, e.g. `"127.0.0.1:50051"`. */
  target: string;
  /** Default: `agent-${crypto.randomUUID().replace(/-/g, "")}`. */
  workspaceId?: string;
  /** Default 2. */
  vcpuCount?: number;
  /** Default 1024. */
  memSizeMib?: number;
  /** Default: `NE_KERNEL_IMAGE_PATH`. */
  kernelImagePath?: string;
  /** Default: `NE_ROOTFS_IMAGE_PATH`. */
  rootfsImagePath?: string;
  /** Default: `NE_VSOCK_CID_BASE` (no silent fallback — must be unique per concurrent workspace on a host). */
  guestVsockCid?: number;
  /** Default false — agents need to write. (The SDK server default is true.) */
  rootfsReadOnly?: boolean;
  kernelBootArgs?: string;
  /** Forwarded verbatim to the underlying base SDK channel. */
  channelOptions?: ChannelOptions;
  /** Default 2000. */
  destroyGracePeriodMs?: number;
  /** @internal Test injection — substitutes the base `Client`. */
  _clientFactory?: () => Client;
};

/** Emit a teardown warning (a destroy failure must not crash a successful
 *  block, and must not mask the caller's exception). Uses `console.warn`
 *  deliberately — STANDARDS' "no console.log" targets debug logging; a genuine
 *  leak/teardown warning is what `console.warn` is for. Mirrors 7.5's
 *  `logging.getLogger("ne_langchain").warning(...)`. */
function warnTeardownFailure(workspaceId: string, err: unknown): void {
  const detail = err instanceof Error ? err.message : String(err);
  console.warn(`[neuronedge-enclave-mastra] destroyWorkspace failed for ${workspaceId}: ${detail}`);
}

/** Owns one Firecracker microVM workspace across `start()` / `stop()`. */
export class EnclaveWorkspace {
  private readonly _opts: EnclaveWorkspaceOptions;
  private readonly _workspaceId: string;
  private _client: Client | null = null;
  private _started = false;
  private _stopped = false;

  constructor(options: EnclaveWorkspaceOptions) {
    this._opts = options;
    this._workspaceId = options.workspaceId ?? `agent-${randomUUID().replace(/-/g, "")}`;
  }

  /** Workspace id (the constructor-generated default is available before start). */
  get workspaceId(): string {
    return this._workspaceId;
  }

  /** The base SDK client (passthrough for power users — snapshot/attest/etc.). */
  get client(): Client {
    if (this._client === null) {
      throw new Error("EnclaveWorkspace not started; call start() (or use withWorkspace).");
    }
    return this._client;
  }

  /** The three tools bound to this workspace. Throws before `start()`. */
  get tools() {
    if (!this._started || this._client === null) {
      throw new Error("EnclaveWorkspace not started; call start() (or use withWorkspace).");
    }
    return createEnclaveTools(this._client, this.workspaceId);
  }

  /** Resolve env defaults, validate, construct a base `Client`, and
   *  `createWorkspace`. Throws before any RPC if required inputs are missing. */
  async start(): Promise<this> {
    if (this._started) return this;

    const workspaceId = this._workspaceId;

    const kernelImagePath = this._opts.kernelImagePath ?? process.env.NE_KERNEL_IMAGE_PATH;
    const rootfsImagePath = this._opts.rootfsImagePath ?? process.env.NE_ROOTFS_IMAGE_PATH;
    const cidEnv = process.env.NE_VSOCK_CID_BASE;
    const guestVsockCid =
      this._opts.guestVsockCid ?? (cidEnv !== undefined ? Number(cidEnv) : undefined);

    const missing: string[] = [];
    if (!kernelImagePath) missing.push("kernelImagePath");
    if (!rootfsImagePath) missing.push("rootfsImagePath");
    if (guestVsockCid === undefined || Number.isNaN(guestVsockCid)) missing.push("guestVsockCid");
    if (missing.length > 0) {
      throw new Error(
        `EnclaveWorkspace missing required inputs (pass as options or set NE_* env): ${missing.join(", ")}`,
      );
    }

    const clientOptions: ClientOptions = {
      target: this._opts.target,
      ...(this._opts.channelOptions !== undefined
        ? { channelOptions: this._opts.channelOptions }
        : {}),
    };
    let client: Client;
    if (this._opts._clientFactory) {
      client = this._opts._clientFactory();
    } else {
      // Production-only path: a real Client needs a live gRPC server. The
      // _clientFactory seam is how unit tests substitute it; this arm is
      // exercised by examples/quickstart.ts + the base SDK's Client tests.
      /* v8 ignore next */
      client = new Client(clientOptions);
    }

    try {
      await client.createWorkspace({
        workspaceId,
        kernelImagePath: kernelImagePath!, // presence validated in `missing` above
        rootfsImagePath: rootfsImagePath!, // presence validated in `missing` above
        vcpuCount: this._opts.vcpuCount ?? 2,
        memSizeMib: this._opts.memSizeMib ?? 1024,
        guestVsockCid: guestVsockCid!, // presence + NaN validated in `missing` above
        ...(this._opts.rootfsReadOnly !== undefined
          ? { rootfsReadOnly: this._opts.rootfsReadOnly }
          : { rootfsReadOnly: false }),
        ...(this._opts.kernelBootArgs !== undefined
          ? { kernelBootArgs: this._opts.kernelBootArgs }
          : {}),
      });
    } catch (err) {
      client.close();
      mapServiceError(err); // always throws — surfaces "enclave RPC <STATUS>: <details>"
    }

    this._client = client;
    this._started = true;
    return this;
  }

  /** Destroy the workspace + close the client. Idempotent. Best-effort: the
   *  swallow/preserve contract belongs to {@link withWorkspace}. */
  async stop(): Promise<void> {
    if (this._stopped || !this._started || this._client === null) return;
    // Set before the RPC + null the client in `finally`: if destroyWorkspace
    // rejects, stop() is unrecoverable — the caller can neither retry stop()
    // nor reach ws.client to destroy manually. Intentional for a dev-pilot:
    // destroy is a terminal best-effort, and operator reaping (the
    // supervisor's `grace_period_ms`) is the recovery path.
    this._stopped = true;
    try {
      await this._client.destroyWorkspace({
        workspaceId: this.workspaceId,
        gracePeriodMs: this._opts.destroyGracePeriodMs ?? 2000,
      });
    } finally {
      this._client.close();
      this._client = null;
    }
  }

  /** `await using` forward-compat (Node 22+). Delegates to `stop()`. */
  async [Symbol.asyncDispose](): Promise<void> {
    await this.stop();
  }
}

/** Primary API: the closest JS analogue of Python's `with`. Boots a workspace,
 *  runs `fn` with its tools, and guarantees teardown on both paths. A destroy
 *  failure on the success path is logged + swallowed; on the exception path the
 *  **original** caller exception always wins (never masked by a destroy error). */
export async function withWorkspace<T>(
  options: EnclaveWorkspaceOptions,
  fn: (ws: EnclaveWorkspace) => Promise<T>,
): Promise<T> {
  const ws = new EnclaveWorkspace(options);
  await ws.start(); // if start rejects, fn is never invoked and the rejection propagates

  let result: T | undefined;
  let callerError: unknown;
  let threw = false;
  try {
    result = await fn(ws);
  } catch (e) {
    callerError = e;
    threw = true;
  }

  try {
    await ws.stop();
  } catch (destroyErr) {
    warnTeardownFailure(ws.workspaceId, destroyErr);
  }

  if (threw) throw callerError;
  return result as T;
}
