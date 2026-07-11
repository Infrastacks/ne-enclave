import { status as grpcStatus } from "@grpc/grpc-js";
import type { ChannelOptions } from "@grpc/grpc-js";
import { afterEach, describe, expect, it } from "vitest";

import { EnclaveWorkspace, type EnclaveWorkspaceOptions, withWorkspace } from "../src/workspace.js";

import { FakeClient, toClient } from "./helpers/fake-client.js";

function fakeServiceError(code: number, details: string): Error {
  return Object.assign(new Error(details), { code, details });
}

/** Build options with env defaults set + a FakeClient injected via _clientFactory. */
function options(
  fake: FakeClient,
  overrides: Partial<EnclaveWorkspaceOptions> = {},
): EnclaveWorkspaceOptions {
  return {
    target: "127.0.0.1:50051",
    kernelSha256: "11".repeat(32),
    rootfsSha256: "22".repeat(32),
    guestVsockCid: 42,
    _clientFactory: () => toClient(fake),
    ...overrides,
  };
}

const ENV_KEYS = [
  "NE_KERNEL_SHA256",
  "NE_ROOTFS_SHA256",
  "NE_KERNEL_IMAGE_PATH",
  "NE_ROOTFS_IMAGE_PATH",
  "NE_VSOCK_CID_BASE",
] as const;

afterEach(() => {
  for (const key of ENV_KEYS) delete process.env[key];
});

function setEnv(): void {
  process.env.NE_KERNEL_SHA256 = "11".repeat(32);
  process.env.NE_ROOTFS_SHA256 = "22".repeat(32);
  process.env.NE_VSOCK_CID_BASE = "42";
}

describe("EnclaveWorkspace.start", () => {
  it("calls createWorkspace with options + rootfsReadOnly=false (agents write)", async () => {
    const fake = new FakeClient();
    const ws = new EnclaveWorkspace(options(fake));
    await ws.start();
    const call = fake.createCalls[0];
    expect(call?.workspaceId).toBe(ws.workspaceId);
    expect(ws.workspaceId).toMatch(/^agent-[0-9a-f]+$/);
    expect(call?.kernelSha256).toBe("11".repeat(32));
    expect(call?.rootfsSha256).toBe("22".repeat(32));
    expect(call?.guestVsockCid).toBe(42);
    expect(call?.vcpuCount).toBe(2);
    expect(call?.memSizeMib).toBe(1024);
    expect(call?.rootfsReadOnly).toBe(false);
    await ws.stop();
  });

  it("explicit options override env defaults", async () => {
    setEnv();
    const fake = new FakeClient();
    const ws = new EnclaveWorkspace(
      options(fake, {
        workspaceId: "my-ws",
        kernelSha256: "33".repeat(32),
        rootfsSha256: "44".repeat(32),
        guestVsockCid: 99,
        vcpuCount: 4,
        memSizeMib: 2048,
      }),
    );
    await ws.start();
    const call = fake.createCalls[0];
    expect(call?.workspaceId).toBe("my-ws");
    expect(call?.kernelSha256).toBe("33".repeat(32));
    expect(call?.rootfsSha256).toBe("44".repeat(32));
    expect(call?.guestVsockCid).toBe(99);
    expect(call?.vcpuCount).toBe(4);
    await ws.stop();
  });

  it("throws before any RPC when kernelSha256 is missing (no option, no env)", async () => {
    // biome-ignore lint/performance/noDelete: process.env stringifies assigned values; delete is the only correct unset.
    delete process.env.NE_KERNEL_SHA256;
    const fake = new FakeClient();
    const ws = new EnclaveWorkspace({
      target: "127.0.0.1:50051",
      rootfsSha256: "22".repeat(32),
      guestVsockCid: 42,
      _clientFactory: () => toClient(fake),
    });
    await expect(ws.start()).rejects.toThrow(/kernelSha256/);
    expect(fake.createCalls.length).toBe(0);
  });

  it("throws before any RPC when rootfsSha256 is missing (no option, no env)", async () => {
    // biome-ignore lint/performance/noDelete: process.env stringifies assigned values; delete is the only correct unset.
    delete process.env.NE_ROOTFS_SHA256;
    const fake = new FakeClient();
    const ws = new EnclaveWorkspace({
      target: "127.0.0.1:50051",
      kernelSha256: "11".repeat(32),
      guestVsockCid: 42,
      _clientFactory: () => toClient(fake),
    });
    await expect(ws.start()).rejects.toThrow(/rootfsSha256/);
    expect(fake.createCalls.length).toBe(0);
  });

  it("throws before any RPC when guestVsockCid is missing (no option, no env)", async () => {
    // biome-ignore lint/performance/noDelete: process.env stringifies assigned values; delete is the only correct unset.
    delete process.env.NE_VSOCK_CID_BASE;
    const fake = new FakeClient();
    const ws = new EnclaveWorkspace({
      target: "127.0.0.1:50051",
      kernelSha256: "11".repeat(32),
      rootfsSha256: "22".repeat(32),
      _clientFactory: () => toClient(fake),
    });
    await expect(ws.start()).rejects.toThrow(/guestVsockCid/);
    expect(fake.createCalls.length).toBe(0);
  });

  it("ignores legacy image path environment variables", async () => {
    process.env.NE_KERNEL_IMAGE_PATH = "/legacy/kernel";
    process.env.NE_ROOTFS_IMAGE_PATH = "/legacy/rootfs";
    const fake = new FakeClient();
    const ws = new EnclaveWorkspace({
      target: "127.0.0.1:50051",
      guestVsockCid: 42,
      _clientFactory: () => toClient(fake),
    });
    await expect(ws.start()).rejects.toThrow(/kernelSha256, rootfsSha256/);
    expect(fake.createCalls.length).toBe(0);
  });

  it("on createWorkspace rejection, closes the client and rethrows", async () => {
    const fake = new FakeClient();
    fake.create_error = fakeServiceError(grpcStatus.UNAVAILABLE, "down");
    const ws = new EnclaveWorkspace(options(fake));
    await expect(ws.start()).rejects.toThrow(/UNAVAILABLE/);
    expect(fake.closed).toBe(true);
  });

  it("forwards rootfsReadOnly and kernelBootArgs to createWorkspace, accepts channelOptions", async () => {
    const fake = new FakeClient();
    // channelOptions flows to the real Client constructor (the _clientFactory
    // seam takes no args), so it is asserted only for acceptance here; setting
    // it exercises the clientOptions conditional-spread branch in start().
    const channelOptions: ChannelOptions = { "grpc.keepalive_time_ms": 30000 };
    const ws = new EnclaveWorkspace(
      options(fake, {
        workspaceId: "ws-opt",
        channelOptions,
        rootfsReadOnly: true,
        kernelBootArgs: "console=ttyS0",
      }),
    );
    await ws.start();
    const call = fake.createCalls[0];
    expect(call?.rootfsReadOnly).toBe(true);
    expect(call?.kernelBootArgs).toBe("console=ttyS0");
    await ws.stop();
  });
});

describe("EnclaveWorkspace.client", () => {
  it("returns the injected client after start; throws before start", async () => {
    const fake = new FakeClient();
    const ws = new EnclaveWorkspace(options(fake, { workspaceId: "ws-g" }));
    expect(() => ws.client).toThrow(/not started/);
    await ws.start();
    expect(ws.client).toBeDefined();
    await ws.stop();
    expect(() => ws.client).toThrow(/not started/);
  });
});

describe("EnclaveWorkspace.stop", () => {
  it("destroys the workspace + closes the client", async () => {
    const fake = new FakeClient();
    const ws = new EnclaveWorkspace(options(fake, { workspaceId: "ws-a" }));
    await ws.start();
    await ws.stop();
    const call = fake.destroyCalls[0];
    expect(call?.workspaceId).toBe("ws-a");
    expect(fake.closed).toBe(true);
  });

  it("is idempotent", async () => {
    const fake = new FakeClient();
    const ws = new EnclaveWorkspace(options(fake));
    await ws.start();
    await ws.stop();
    await ws.stop(); // no-op, no throw
    expect(fake.destroyCalls.length).toBe(1);
  });

  it("tools getter throws before start", () => {
    const fake = new FakeClient();
    const ws = new EnclaveWorkspace(options(fake));
    expect(() => ws.tools).toThrow(/not started/);
  });
});

describe("EnclaveWorkspace[Symbol.asyncDispose]", () => {
  it("[Symbol.asyncDispose] delegates to stop() (destroy + close, idempotent)", async () => {
    const fake = new FakeClient();
    const ws = new EnclaveWorkspace(options(fake, { workspaceId: "ws-e" }));
    await ws.start();
    await ws[Symbol.asyncDispose](); // direct invocation — NOT `await using` (Node 20 floor)
    expect(fake.destroyCalls[0]?.workspaceId).toBe("ws-e");
    expect(fake.closed).toBe(true);
    // idempotent: a second dispose is a no-op (stop() already ran)
    await ws[Symbol.asyncDispose]();
    expect(fake.destroyCalls.length).toBe(1);
  });
});

describe("withWorkspace", () => {
  it("boots, yields tools bound to the workspace, and destroys on normal exit", async () => {
    const fake = new FakeClient();
    let seenWorkspaceId: string | undefined;
    const result = await withWorkspace(options(fake, { workspaceId: "ws-b" }), async (ws) => {
      seenWorkspaceId = ws.workspaceId;
      expect(Object.keys(ws.tools).sort()).toEqual([
        "enclave_exec",
        "enclave_read_file",
        "enclave_write_file",
      ]);
      return 42;
    });
    expect(result).toBe(42);
    expect(seenWorkspaceId).toBe("ws-b");
    expect(fake.destroyCalls[0]?.workspaceId).toBe("ws-b");
    expect(fake.closed).toBe(true);
  });

  it("destroys on exception and re-raises the original caller error", async () => {
    const fake = new FakeClient();
    await expect(
      withWorkspace(options(fake, { workspaceId: "ws-c" }), async () => {
        throw new Error("boom");
      }),
    ).rejects.toThrow("boom");
    expect(fake.destroyCalls[0]?.workspaceId).toBe("ws-c");
  });

  it("swallows a stop() failure on the success path", async () => {
    const fake = new FakeClient();
    fake.destroy_error = fakeServiceError(grpcStatus.UNAVAILABLE, "teardown flaked");
    const result = await withWorkspace(options(fake, { workspaceId: "ws-d" }), async () => "ok");
    expect(result).toBe("ok"); // destroy threw, but the success path must not throw
    expect(fake.destroyCalls.length).toBe(1);
  });

  it("preserves the original caller exception when stop() also fails on the exception path", async () => {
    const fake = new FakeClient();
    fake.destroy_error = fakeServiceError(grpcStatus.UNAVAILABLE, "teardown flaked");
    await expect(
      withWorkspace(options(fake), async () => {
        throw new Error("original");
      }),
    ).rejects.toThrow("original"); // NOT "UNAVAILABLE" — original wins, never masked
    expect(fake.destroyCalls.length).toBe(1);
  });

  it("if start() rejects, fn is never invoked and the rejection propagates", async () => {
    const fake = new FakeClient();
    fake.create_error = fakeServiceError(grpcStatus.UNAVAILABLE, "down");
    let invoked = false;
    await expect(
      withWorkspace(options(fake), async () => {
        invoked = true;
        return "x";
      }),
    ).rejects.toThrow(/UNAVAILABLE/);
    expect(invoked).toBe(false);
  });
});
