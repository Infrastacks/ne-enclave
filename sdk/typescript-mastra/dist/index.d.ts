import * as _mastra_core_tools from '@mastra/core/tools';
import { ChannelOptions } from '@grpc/grpc-js';
import { Client } from '@neuronedge/enclave';

/** Options for {@link EnclaveWorkspace}. */
type EnclaveWorkspaceOptions = {
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
/** Owns one Firecracker microVM workspace across `start()` / `stop()`. */
declare class EnclaveWorkspace {
    private readonly _opts;
    private readonly _workspaceId;
    private _client;
    private _started;
    private _stopped;
    constructor(options: EnclaveWorkspaceOptions);
    /** Workspace id (the constructor-generated default is available before start). */
    get workspaceId(): string;
    /** The base SDK client (passthrough for power users — snapshot/attest/etc.). */
    get client(): Client;
    /** The three tools bound to this workspace. Throws before `start()`. */
    get tools(): {
        enclave_exec: _mastra_core_tools.Tool<{
            command: string;
            args?: string[] | undefined;
            timeoutMs?: number | undefined;
        }, {
            message: string;
        }, unknown, unknown, _mastra_core_tools.ToolExecutionContext<unknown, unknown, unknown>, "enclave_exec", unknown>;
        enclave_write_file: _mastra_core_tools.Tool<{
            path: string;
            content: string;
        }, {
            message: string;
        }, unknown, unknown, _mastra_core_tools.ToolExecutionContext<unknown, unknown, unknown>, "enclave_write_file", unknown>;
        enclave_read_file: _mastra_core_tools.Tool<{
            path: string;
            maxBytes?: number | undefined;
        }, {
            message: string;
        }, unknown, unknown, _mastra_core_tools.ToolExecutionContext<unknown, unknown, unknown>, "enclave_read_file", unknown>;
    };
    /** Resolve env defaults, validate, construct a base `Client`, and
     *  `createWorkspace`. Throws before any RPC if required inputs are missing. */
    start(): Promise<this>;
    /** Destroy the workspace + close the client. Idempotent. Best-effort: the
     *  swallow/preserve contract belongs to {@link withWorkspace}. */
    stop(): Promise<void>;
    /** `await using` forward-compat (Node 22+). Delegates to `stop()`. */
    [Symbol.asyncDispose](): Promise<void>;
}
/** Primary API: the closest JS analogue of Python's `with`. Boots a workspace,
 *  runs `fn` with its tools, and guarantees teardown on both paths. A destroy
 *  failure on the success path is logged + swallowed; on the exception path the
 *  **original** caller exception always wins (never masked by a destroy error). */
declare function withWorkspace<T>(options: EnclaveWorkspaceOptions, fn: (ws: EnclaveWorkspace) => Promise<T>): Promise<T>;

/** Build the three workspace tools bound to `workspaceId` + `client`, keyed by
 *  tool id (`enclave_exec` / `enclave_write_file` / `enclave_read_file`).
 *  Ready to spread into `new Agent({ tools: createEnclaveTools(...) })`. */
declare function createEnclaveTools(client: Client, workspaceId: string): {
    enclave_exec: _mastra_core_tools.Tool<{
        command: string;
        args?: string[] | undefined;
        timeoutMs?: number | undefined;
    }, {
        message: string;
    }, unknown, unknown, _mastra_core_tools.ToolExecutionContext<unknown, unknown, unknown>, "enclave_exec", unknown>;
    enclave_write_file: _mastra_core_tools.Tool<{
        path: string;
        content: string;
    }, {
        message: string;
    }, unknown, unknown, _mastra_core_tools.ToolExecutionContext<unknown, unknown, unknown>, "enclave_write_file", unknown>;
    enclave_read_file: _mastra_core_tools.Tool<{
        path: string;
        maxBytes?: number | undefined;
    }, {
        message: string;
    }, unknown, unknown, _mastra_core_tools.ToolExecutionContext<unknown, unknown, unknown>, "enclave_read_file", unknown>;
};

/** Convert a gRPC `ServiceError` raised by the base SDK into an `Error` that
 *  Mastra surfaces to the agent as a tool-call error. The status name and
 *  details are preserved so the model can react (retry, fix args, give up).
 *  Non-`ServiceError` exceptions are rethrown unmasked. Always throws. */
declare function mapServiceError(err: unknown): never;

/**
 * Mastra adapter for the NeuronEdge Enclave Runtime API.
 *
 * Thin tool set over a managed Firecracker microVM workspace. The base
 * `@neuronedge/enclave` SDK opens an insecure gRPC channel in this phase, so
 * this adapter is local/dev-pilot only until the SDK ships TLS + API-key
 * credentials.
 *
 * Quickstart:
 *
 * ```ts
 * import { withWorkspace } from "@neuronedge/enclave-mastra";
 *
 * await withWorkspace({ target: "127.0.0.1:50051" }, async (ws) => {
 *   const agent = new Agent({ name, model, tools: ws.tools });
 *   // ...
 * });
 * ```
 */

declare const __version__ = "0.1.0";

export { EnclaveWorkspace, type EnclaveWorkspaceOptions, __version__, createEnclaveTools, mapServiceError, withWorkspace };
