import { status as grpcStatus } from "@grpc/grpc-js";
import { describe, expect, it } from "vitest";

import { mapServiceError } from "../src/errors.js";

/** Build a ServiceError-shaped Error (numeric code + details string) — exactly
 *  what the base SDK's isServiceError guard narrows on. */
function fakeServiceError(code: number, details: string): Error {
  return Object.assign(new Error(details), { code, details });
}

describe("mapServiceError", () => {
  it("throws for INVALID_ARGUMENT with status name + details", () => {
    const err = fakeServiceError(grpcStatus.INVALID_ARGUMENT, "path traversal");
    expect(() => mapServiceError(err)).toThrow(/INVALID_ARGUMENT: path traversal/);
  });

  it("throws for NOT_FOUND", () => {
    const err = fakeServiceError(grpcStatus.NOT_FOUND, "no such workspace");
    expect(() => mapServiceError(err)).toThrow(/NOT_FOUND/);
  });

  it("throws for UNAVAILABLE", () => {
    const err = fakeServiceError(grpcStatus.UNAVAILABLE, "transport down");
    expect(() => mapServiceError(err)).toThrow(/UNAVAILABLE/);
  });

  it("throws for DEADLINE_EXCEEDED", () => {
    const err = fakeServiceError(grpcStatus.DEADLINE_EXCEEDED, "timed out");
    expect(() => mapServiceError(err)).toThrow(/DEADLINE_EXCEEDED/);
  });

  it("falls back to the numeric code for unmapped statuses", () => {
    const err = fakeServiceError(2, "UNKNOWN-ish"); // 2 == UNKNOWN, not in our name map
    expect(() => mapServiceError(err)).toThrow(/enclave RPC code 2/);
  });

  it("rethrows a non-ServiceError error unmasked", () => {
    const original = new Error("totally unrelated");
    expect(() => mapServiceError(original)).toThrow(original);
  });
});
