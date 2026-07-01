import { type ServiceError, status as grpcStatus } from "@grpc/grpc-js";

import { isServiceError } from "@neuronedge/enclave";

/** gRPC status codes we surface by name. Unknown codes fall back to `code <N>`. */
const STATUS_NAMES: Record<number, string> = {
  [grpcStatus.INVALID_ARGUMENT]: "INVALID_ARGUMENT",
  [grpcStatus.NOT_FOUND]: "NOT_FOUND",
  [grpcStatus.UNAVAILABLE]: "UNAVAILABLE",
  [grpcStatus.DEADLINE_EXCEEDED]: "DEADLINE_EXCEEDED",
};

/** Convert a gRPC `ServiceError` raised by the base SDK into an `Error` that
 *  Mastra surfaces to the agent as a tool-call error. The status name and
 *  details are preserved so the model can react (retry, fix args, give up).
 *  Non-`ServiceError` exceptions are rethrown unmasked. Always throws. */
export function mapServiceError(err: unknown): never {
  if (isServiceError(err)) {
    const serviceErr: ServiceError = err;
    const name = STATUS_NAMES[serviceErr.code] ?? `code ${serviceErr.code}`;
    const details = serviceErr.details;
    throw new Error(`enclave RPC ${name}: ${details}`);
  }
  throw err;
}
