import { randomUUID } from 'crypto';
import { isServiceError, Client } from '@neuronedge/enclave';
import { status } from '@grpc/grpc-js';
import { createTool } from '@mastra/core/tools';
import { z } from 'zod';

// src/workspace.ts
var STATUS_NAMES = {
  [status.INVALID_ARGUMENT]: "INVALID_ARGUMENT",
  [status.NOT_FOUND]: "NOT_FOUND",
  [status.UNAVAILABLE]: "UNAVAILABLE",
  [status.DEADLINE_EXCEEDED]: "DEADLINE_EXCEEDED"
};
function mapServiceError(err) {
  if (isServiceError(err)) {
    const serviceErr = err;
    const name = STATUS_NAMES[serviceErr.code] ?? `code ${serviceErr.code}`;
    const details = serviceErr.details;
    throw new Error(`enclave RPC ${name}: ${details}`);
  }
  throw err;
}
var LLM_OUTPUT_LIMIT = 8192;
function truncateForLlm(text, limit = LLM_OUTPUT_LIMIT) {
  if (text.length <= limit) return { text, note: null };
  return {
    text: text.slice(0, limit),
    note: `[tool truncated at ${limit} chars, ${text.length} total]`
  };
}
var messageOutputSchema = z.object({ message: z.string() });
var execInputSchema = z.object({
  command: z.string().describe("Path to the command binary, resolved against guest $PATH."),
  args: z.array(z.string()).default([]).describe("Arguments passed verbatim \u2014 no shell interpretation."),
  timeoutMs: z.number().int().nonnegative().default(0).describe("Per-call guest timeout in milliseconds. 0 disables.")
});
function buildSuffix(guestTruncated, note) {
  let suffix = "";
  if (guestTruncated) suffix += " [guest truncated]";
  if (note) suffix += ` ${note}`;
  return suffix;
}
function execTool(client, workspaceId) {
  return createTool({
    id: "enclave_exec",
    description: "Execute a command inside the confidential enclave workspace. Returns the exit code and captured stdout/stderr. Non-zero exit is reported, not raised.",
    inputSchema: execInputSchema,
    outputSchema: messageOutputSchema,
    execute: async ({ command, args, timeoutMs }) => {
      let resp;
      try {
        resp = await client.executeCommand({
          workspaceId,
          command,
          args: args ?? [],
          timeoutMs: timeoutMs ?? 0
        });
      } catch (err) {
        mapServiceError(err);
      }
      const combined = `${resp.stdout}${resp.stderr}`;
      const { text, note } = truncateForLlm(combined);
      const message = `exit: ${resp.exitCode}
${text}${buildSuffix(resp.truncated, note)}`;
      return { message };
    }
  });
}
function writeFileTool(client, workspaceId) {
  return createTool({
    id: "enclave_write_file",
    description: "Write a file into the confidential enclave workspace. Overwrites if the path exists.",
    inputSchema: z.object({
      path: z.string().describe(
        "Relative path inside the workspace jail. Absolute paths and '..' are rejected server-side."
      ),
      content: z.string().describe("File contents (written as UTF-8). Hard cap 10 MiB server-side.")
    }),
    outputSchema: messageOutputSchema,
    execute: async ({ path, content }) => {
      let resp;
      try {
        resp = await client.writeFile({
          workspaceId,
          path,
          content: new TextEncoder().encode(content)
        });
      } catch (err) {
        mapServiceError(err);
      }
      return { message: `wrote ${path} (${resp.bytesWritten} bytes)` };
    }
  });
}
function readFileTool(client, workspaceId) {
  return createTool({
    id: "enclave_read_file",
    description: "Read a file from the confidential enclave workspace. Output is UTF-8 decoded and size-capped.",
    inputSchema: z.object({
      path: z.string().describe("Relative path inside the workspace jail."),
      maxBytes: z.number().int().nonnegative().default(0).describe("Max bytes to read. 0 uses the server default (10 MiB).")
    }),
    outputSchema: messageOutputSchema,
    execute: async ({ path, maxBytes }) => {
      let resp;
      try {
        resp = await client.readFile({ workspaceId, path, maxBytes: maxBytes ?? 0 });
      } catch (err) {
        mapServiceError(err);
      }
      const decoded = new TextDecoder("utf-8", { fatal: false }).decode(resp.content);
      const { text, note } = truncateForLlm(decoded);
      return { message: `${text}${buildSuffix(resp.truncated, note)}` };
    }
  });
}
function createEnclaveTools(client, workspaceId) {
  return {
    enclave_exec: execTool(client, workspaceId),
    enclave_write_file: writeFileTool(client, workspaceId),
    enclave_read_file: readFileTool(client, workspaceId)
  };
}

// src/workspace.ts
function warnTeardownFailure(workspaceId, err) {
  const detail = err instanceof Error ? err.message : String(err);
  console.warn(`[neuronedge-enclave-mastra] destroyWorkspace failed for ${workspaceId}: ${detail}`);
}
var EnclaveWorkspace = class {
  _opts;
  _workspaceId;
  _client = null;
  _started = false;
  _stopped = false;
  constructor(options) {
    this._opts = options;
    this._workspaceId = options.workspaceId ?? `agent-${randomUUID().replace(/-/g, "")}`;
  }
  /** Workspace id (the constructor-generated default is available before start). */
  get workspaceId() {
    return this._workspaceId;
  }
  /** The base SDK client (passthrough for power users — snapshot/attest/etc.). */
  get client() {
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
  async start() {
    if (this._started) return this;
    const workspaceId = this._workspaceId;
    const kernelImagePath = this._opts.kernelImagePath ?? process.env.NE_KERNEL_IMAGE_PATH;
    const rootfsImagePath = this._opts.rootfsImagePath ?? process.env.NE_ROOTFS_IMAGE_PATH;
    const cidEnv = process.env.NE_VSOCK_CID_BASE;
    const guestVsockCid = this._opts.guestVsockCid ?? (cidEnv !== void 0 ? Number(cidEnv) : void 0);
    const missing = [];
    if (!kernelImagePath) missing.push("kernelImagePath");
    if (!rootfsImagePath) missing.push("rootfsImagePath");
    if (guestVsockCid === void 0 || Number.isNaN(guestVsockCid)) missing.push("guestVsockCid");
    if (missing.length > 0) {
      throw new Error(
        `EnclaveWorkspace missing required inputs (pass as options or set NE_* env): ${missing.join(", ")}`
      );
    }
    const clientOptions = {
      target: this._opts.target,
      ...this._opts.channelOptions !== void 0 ? { channelOptions: this._opts.channelOptions } : {}
    };
    let client;
    if (this._opts._clientFactory) {
      client = this._opts._clientFactory();
    } else {
      client = new Client(clientOptions);
    }
    try {
      await client.createWorkspace({
        workspaceId,
        kernelImagePath,
        // presence validated in `missing` above
        rootfsImagePath,
        // presence validated in `missing` above
        vcpuCount: this._opts.vcpuCount ?? 2,
        memSizeMib: this._opts.memSizeMib ?? 1024,
        guestVsockCid,
        // presence + NaN validated in `missing` above
        ...this._opts.rootfsReadOnly !== void 0 ? { rootfsReadOnly: this._opts.rootfsReadOnly } : { rootfsReadOnly: false },
        ...this._opts.kernelBootArgs !== void 0 ? { kernelBootArgs: this._opts.kernelBootArgs } : {}
      });
    } catch (err) {
      client.close();
      mapServiceError(err);
    }
    this._client = client;
    this._started = true;
    return this;
  }
  /** Destroy the workspace + close the client. Idempotent. Best-effort: the
   *  swallow/preserve contract belongs to {@link withWorkspace}. */
  async stop() {
    if (this._stopped || !this._started || this._client === null) return;
    this._stopped = true;
    try {
      await this._client.destroyWorkspace({
        workspaceId: this.workspaceId,
        gracePeriodMs: this._opts.destroyGracePeriodMs ?? 2e3
      });
    } finally {
      this._client.close();
      this._client = null;
    }
  }
  /** `await using` forward-compat (Node 22+). Delegates to `stop()`. */
  async [Symbol.asyncDispose]() {
    await this.stop();
  }
};
async function withWorkspace(options, fn) {
  const ws = new EnclaveWorkspace(options);
  await ws.start();
  let result;
  let callerError;
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
  return result;
}

// src/index.ts
var __version__ = "0.1.0";

export { EnclaveWorkspace, __version__, createEnclaveTools, mapServiceError, withWorkspace };
//# sourceMappingURL=index.mjs.map
//# sourceMappingURL=index.mjs.map