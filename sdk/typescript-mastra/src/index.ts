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

export { withWorkspace, EnclaveWorkspace, type EnclaveWorkspaceOptions } from "./workspace.js";
export { createEnclaveTools } from "./tools.js";
export { mapServiceError } from "./errors.js";

export const __version__ = "0.1.0";
