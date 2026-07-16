import { readFileSync } from "node:fs";
import { status as grpcStatus } from "@grpc/grpc-js";
import { afterEach, describe, expect, test } from "vitest";

import type {
  CreateWorkspaceRequest,
  DestroyWorkspaceRequest,
  ExecuteCommandRequest,
  ExposePortRequest,
  GetAttestationEvidenceRequest,
  ListEventsRequest,
  ReadFileRequest,
  UnexposePortRequest,
  WriteFileRequest,
} from "../src/generated/ne/runtime/v1/runtime.js";
import {
  AttestationBackend,
  AttestationProvider,
  Client,
  ExecutionBackend,
  ExecutionProfile,
  WorkspaceOperation,
  isServiceError,
} from "../src/index.js";
import { type FakeServerHandle, startFakeServer, statusError } from "./helpers/fake-server.js";

describe("Client", () => {
  let server: FakeServerHandle | undefined;

  afterEach(async () => {
    if (server) {
      await server.stop();
      server = undefined;
    }
  });

  test("close is idempotent and rejects subsequent calls", async () => {
    server = await startFakeServer({
      ping: () => ({
        apiVersion: "0.0.0-fake-api",
        apiUptimeMs: 1,
        supervisorVersion: "0.0.0-fake-sup",
        supervisorUptimeMs: 2,
      }),
    });
    const client = new Client({ target: server.target });
    client.close();
    client.close();
    await expect(client.ping()).rejects.toThrow("Client has been closed");
  });

  test("ping round-trips api_version + supervisor_version", async () => {
    server = await startFakeServer({
      ping: () => ({
        apiVersion: "1.2.3-api",
        apiUptimeMs: 11,
        supervisorVersion: "4.5.6-sup",
        supervisorUptimeMs: 22,
      }),
    });
    const client = new Client({ target: server.target });
    try {
      const pong = await client.ping();
      expect(pong.apiVersion).toBe("1.2.3-api");
      expect(pong.supervisorVersion).toBe("4.5.6-sup");
      expect(pong.supervisorUptimeMs).toBe(22);
    } finally {
      client.close();
    }
  });

  test("ping rejects after close", async () => {
    server = await startFakeServer({
      ping: () => ({
        apiVersion: "v",
        apiUptimeMs: 0,
        supervisorVersion: "v",
        supervisorUptimeMs: 0,
      }),
    });
    const client = new Client({ target: server.target });
    client.close();
    await expect(client.ping()).rejects.toThrow("Client has been closed");
  });

  test("createWorkspace round-trips required fields", async () => {
    let seen: CreateWorkspaceRequest | undefined;
    server = await startFakeServer({
      createWorkspace: (req) => {
        seen = req;
        return {
          workspaceId: req.workspaceId,
          firecrackerPid: 99,
          vsockHostSocket: "/x",
          jailerChroot: "/y",
          network: undefined,
        };
      },
    });
    const client = new Client({ target: server.target });
    try {
      const resp = await client.createWorkspace({
        workspaceId: "wks-ts-1",
        kernelSha256: "11".repeat(32),
        rootfsSha256: "22".repeat(32),
        vcpuCount: 2,
        memSizeMib: 512,
        guestVsockCid: 3,
        kernelBootArgs: "console=ttyS0",
      });
      expect(seen?.workspaceId).toBe("wks-ts-1");
      expect(seen?.kernelSha256).toBe("11".repeat(32));
      expect(seen?.rootfsSha256).toBe("22".repeat(32));
      expect(seen?.vcpuCount).toBe(2);
      expect(seen?.memSizeMib).toBe(512);
      expect(seen?.guestVsockCid).toBe(3);
      expect(seen?.kernelBootArgs).toBe("console=ttyS0");
      expect(seen?.rootfsReadOnly).toBe(true);
      expect(seen?.network).toBeUndefined();
      expect(resp.workspaceId).toBe("wks-ts-1");
      expect(resp.firecrackerPid).toBe(99);
    } finally {
      client.close();
    }
  });

  test("createConfidentialWorkspace sends profile-neutral zero fields", async () => {
    let seen: CreateWorkspaceRequest | undefined;
    server = await startFakeServer({
      createWorkspace: (req) => {
        seen = req;
        return {
          workspaceId: req.workspaceId,
          firecrackerPid: 0,
          vsockHostSocket: "",
          jailerChroot: "",
          network: undefined,
        };
      },
    });
    const client = new Client({ target: server.target });
    try {
      await client.createConfidentialWorkspace({ workspaceId: "secret-1" });
      expect(seen).toMatchObject({
        workspaceId: "secret-1",
        kernelSha256: "",
        rootfsSha256: "",
        rootfsReadOnly: true,
        vcpuCount: 0,
        memSizeMib: 0,
        guestVsockCid: 0,
      });
    } finally {
      client.close();
    }
  });

  test("getRuntimeCapabilities returns the resolved execution profile", async () => {
    server = await startFakeServer({
      getRuntimeCapabilities: () => ({
        runtimeVersion: "0.2.0",
        executionProfile: ExecutionProfile.EXECUTION_PROFILE_CONFIDENTIAL_AZURE,
        executionBackend: ExecutionBackend.EXECUTION_BACKEND_OPEN_SHELL,
        attestationBackend: AttestationBackend.ATTESTATION_BACKEND_SEV_SNP_AZURE,
        supportedOperations: [
          WorkspaceOperation.WORKSPACE_OPERATION_CREATE,
          WorkspaceOperation.WORKSPACE_OPERATION_ATTEST,
        ],
        hardWorkspaceCapacity: 1,
        confidentialSnapshotSupported: false,
        evidenceSchemaVersion: 1,
      }),
    });
    const client = new Client({ target: server.target });
    try {
      const capabilities = await client.getRuntimeCapabilities();
      expect(capabilities.executionProfile).toBe(
        ExecutionProfile.EXECUTION_PROFILE_CONFIDENTIAL_AZURE,
      );
      expect(capabilities.hardWorkspaceCapacity).toBe(1);
      expect(capabilities.evidenceSchemaVersion).toBe(1);
    } finally {
      client.close();
    }
  });

  test("createWorkspace source exposes only digest image options", () => {
    const source = readFileSync(new URL("../src/client.ts", import.meta.url), "utf8");
    expect(source).toContain("kernelSha256");
    expect(source).toContain("rootfsSha256");
    expect(source).not.toContain(["kernel", "Image", "Path"].join(""));
    expect(source).not.toContain(["rootfs", "Image", "Path"].join(""));
  });

  test("createWorkspace tier omits managed image digests", async () => {
    let seen: CreateWorkspaceRequest | undefined;
    server = await startFakeServer({
      createWorkspace: (req) => {
        seen = req;
        return {
          workspaceId: req.workspaceId,
          firecrackerPid: 99,
          vsockHostSocket: "/x",
          jailerChroot: "/y",
          network: undefined,
        };
      },
    });
    const client = new Client({ target: server.target });
    try {
      await client.createWorkspace({
        workspaceId: "wks-ts-tier",
        vcpuCount: 1,
        memSizeMib: 256,
        guestVsockCid: 3,
        tier: "warm-small",
      });
      expect(seen?.kernelSha256).toBe("");
      expect(seen?.rootfsSha256).toBe("");
      expect(seen?.tier).toBe("warm-small");
    } finally {
      client.close();
    }
  });

  test.each([{ kernelSha256: "11".repeat(32) }, { rootfsSha256: "22".repeat(32) }])(
    "createWorkspace rejects a half digest pair",
    async (digestOptions) => {
      server = await startFakeServer({
        createWorkspace: (req) => ({
          workspaceId: req.workspaceId,
          firecrackerPid: 99,
          vsockHostSocket: "/x",
          jailerChroot: "/y",
          network: undefined,
        }),
      });
      const client = new Client({ target: server.target });
      try {
        await expect(
          client.createWorkspace({
            workspaceId: "wks-ts-half",
            vcpuCount: 1,
            memSizeMib: 256,
            guestVsockCid: 3,
            tier: "warm-small",
            ...digestOptions,
          }),
        ).rejects.toThrow("provided together");
      } finally {
        client.close();
      }
    },
  );

  test("createWorkspace with network populates allowCidrs and allowHostnames", async () => {
    let seen: CreateWorkspaceRequest | undefined;
    server = await startFakeServer({
      createWorkspace: (req) => {
        seen = req;
        return {
          workspaceId: req.workspaceId,
          firecrackerPid: 9001,
          vsockHostSocket: "/x",
          jailerChroot: "/y",
          network: {
            netnsPath: "/var/run/netns/ne-feedfa",
            tapDevice: "tap-feedfa",
            hostIp: "169.254.42.1",
            guestIp: "169.254.42.2",
            prefix: 30,
          },
        };
      },
    });
    const client = new Client({ target: server.target });
    try {
      const resp = await client.createWorkspace({
        workspaceId: "wks-ts-net",
        kernelSha256: "11".repeat(32),
        rootfsSha256: "22".repeat(32),
        vcpuCount: 1,
        memSizeMib: 256,
        guestVsockCid: 3,
        enableNetwork: true,
        enableEgress: true,
        allowCidrs: ["10.0.0.0/8", "203.0.113.0/24"],
        allowHostnames: ["openai.com", "*.github.com"],
      });
      expect(seen?.network).toBeDefined();
      expect(seen?.network?.enableEgress).toBe(true);
      expect(seen?.network?.allowCidrs).toEqual(["10.0.0.0/8", "203.0.113.0/24"]);
      expect(seen?.network?.allowHostnames).toEqual(["openai.com", "*.github.com"]);
      expect(resp.network?.tapDevice).toBe("tap-feedfa");
      expect(resp.network?.guestIp).toBe("169.254.42.2");
    } finally {
      client.close();
    }
  });

  test("createWorkspace with enablePrivacyRouter populates privacy_router marker", async () => {
    let seen: CreateWorkspaceRequest | undefined;
    server = await startFakeServer({
      createWorkspace: (req) => {
        seen = req;
        return {
          workspaceId: req.workspaceId,
          firecrackerPid: 1,
          vsockHostSocket: "/x",
          jailerChroot: "/y",
          network: undefined,
        };
      },
    });
    const client = new Client({ target: server.target });
    try {
      await client.createWorkspace({
        workspaceId: "wks-ts-privacy",
        kernelSha256: "11".repeat(32),
        rootfsSha256: "22".repeat(32),
        vcpuCount: 1,
        memSizeMib: 256,
        guestVsockCid: 3,
        enableNetwork: true,
        enableEgress: true,
        enablePrivacyRouter: true,
      });
      expect(seen?.network?.privacyRouter).toBeDefined();
    } finally {
      client.close();
    }
  });

  test("createWorkspace propagates INVALID_ARGUMENT", async () => {
    server = await startFakeServer({
      createWorkspace: () => statusError(grpcStatus.INVALID_ARGUMENT, "vcpu_count out of range"),
    });
    const client = new Client({ target: server.target });
    try {
      await expect(
        client.createWorkspace({
          workspaceId: "bad",
          kernelSha256: "11".repeat(32),
          rootfsSha256: "22".repeat(32),
          vcpuCount: 999,
          memSizeMib: 256,
          guestVsockCid: 3,
        }),
      ).rejects.toMatchObject({ code: grpcStatus.INVALID_ARGUMENT });
    } finally {
      client.close();
    }
  });

  test.each([
    [grpcStatus.NOT_FOUND, "kernel image not found"],
    [grpcStatus.FAILED_PRECONDITION, "rootfs image digest mismatch"],
    [grpcStatus.INTERNAL, "rootfs image staging failed"],
  ])("createWorkspace preserves image error status %s and details", async (code, details) => {
    server = await startFakeServer({
      createWorkspace: () => statusError(code, details),
    });
    const client = new Client({ target: server.target });
    try {
      const error = await client
        .createWorkspace({
          workspaceId: "wks-image-error",
          kernelSha256: "11".repeat(32),
          rootfsSha256: "22".repeat(32),
          vcpuCount: 1,
          memSizeMib: 256,
          guestVsockCid: 3,
        })
        .catch((caught: unknown) => caught);
      expect(error).toMatchObject({ code, details });
    } finally {
      client.close();
    }
  });

  test("destroyWorkspace round-trips grace_period_ms", async () => {
    let seen: DestroyWorkspaceRequest | undefined;
    server = await startFakeServer({
      destroyWorkspace: (req) => {
        seen = req;
        return { workspaceId: req.workspaceId };
      },
    });
    const client = new Client({ target: server.target });
    try {
      const resp = await client.destroyWorkspace({ workspaceId: "wks-d", gracePeriodMs: 1_000 });
      expect(seen?.workspaceId).toBe("wks-d");
      expect(seen?.gracePeriodMs).toBe(1_000);
      expect(resp.workspaceId).toBe("wks-d");
    } finally {
      client.close();
    }
  });

  test("destroyWorkspace propagates NOT_FOUND", async () => {
    server = await startFakeServer({
      destroyWorkspace: () => statusError(grpcStatus.NOT_FOUND, "no such workspace"),
    });
    const client = new Client({ target: server.target });
    try {
      const err = await client.destroyWorkspace({ workspaceId: "ghost" }).catch((e) => e);
      expect(isServiceError(err)).toBe(true);
      expect((err as { code: number }).code).toBe(grpcStatus.NOT_FOUND);
    } finally {
      client.close();
    }
  });

  test("executeCommand round-trips command + args + timeout_ms", async () => {
    let seen: ExecuteCommandRequest | undefined;
    server = await startFakeServer({
      executeCommand: (req) => {
        seen = req;
        return {
          workspaceId: req.workspaceId,
          stdout: `ran: ${req.command} ${req.args.join(" ")}\n`,
          stderr: "",
          exitCode: 0,
          elapsedMs: 5,
        };
      },
    });
    const client = new Client({ target: server.target });
    try {
      const resp = await client.executeCommand({
        workspaceId: "wks-ts-2",
        command: "/bin/echo",
        args: ["hello", "enclave"],
        timeoutMs: 5_000,
      });
      expect(seen?.command).toBe("/bin/echo");
      expect(seen?.args).toEqual(["hello", "enclave"]);
      expect(seen?.timeoutMs).toBe(5_000);
      expect(resp.exitCode).toBe(0);
      expect(resp.stdout).toContain("hello enclave");
    } finally {
      client.close();
    }
  });

  test("executeCommand propagates DEADLINE_EXCEEDED", async () => {
    server = await startFakeServer({
      executeCommand: () => statusError(grpcStatus.DEADLINE_EXCEEDED, "vsock RPC exceeded 100ms"),
    });
    const client = new Client({ target: server.target });
    try {
      await expect(
        client.executeCommand({ workspaceId: "w", command: "/bin/sleep", args: ["10"] }),
      ).rejects.toMatchObject({ code: grpcStatus.DEADLINE_EXCEEDED });
    } finally {
      client.close();
    }
  });

  test("executeCommand propagates UNAVAILABLE", async () => {
    server = await startFakeServer({
      executeCommand: () => statusError(grpcStatus.UNAVAILABLE, "guest agent unreachable"),
    });
    const client = new Client({ target: server.target });
    try {
      await expect(
        client.executeCommand({ workspaceId: "w", command: "/bin/true" }),
      ).rejects.toMatchObject({ code: grpcStatus.UNAVAILABLE });
    } finally {
      client.close();
    }
  });

  test("writeFile round-trips Uint8Array content", async () => {
    let seen: WriteFileRequest | undefined;
    server = await startFakeServer({
      writeFile: (req) => {
        seen = req;
        return {
          workspaceId: req.workspaceId,
          bytesWritten: req.content.length,
          absolutePath: `/workspace/${req.path}`,
        };
      },
    });
    const client = new Client({ target: server.target });
    try {
      const content = new TextEncoder().encode("fn main() {}");
      const resp = await client.writeFile({
        workspaceId: "wks-w-1",
        path: "src/main.rs",
        content,
      });
      expect(seen?.path).toBe("src/main.rs");
      expect(Array.from(seen?.content ?? [])).toEqual(Array.from(content));
      expect(seen?.guestPort).toBe(0);
      expect(resp.bytesWritten).toBe(12);
      expect(resp.absolutePath).toBe("/workspace/src/main.rs");
    } finally {
      client.close();
    }
  });

  test("writeFile propagates INVALID_ARGUMENT on oversized body", async () => {
    server = await startFakeServer({
      writeFile: () => statusError(grpcStatus.INVALID_ARGUMENT, "content exceeds 10 MiB cap"),
    });
    const client = new Client({ target: server.target });
    try {
      await expect(
        client.writeFile({ workspaceId: "w", path: "big.bin", content: new Uint8Array(1) }),
      ).rejects.toMatchObject({ code: grpcStatus.INVALID_ARGUMENT });
    } finally {
      client.close();
    }
  });

  test("writeFile propagates INVALID_ARGUMENT on path rejection", async () => {
    server = await startFakeServer({
      writeFile: () => statusError(grpcStatus.INVALID_ARGUMENT, "path contains '..' segment"),
    });
    const client = new Client({ target: server.target });
    try {
      const err = await client
        .writeFile({ workspaceId: "w", path: "../etc/passwd", content: new Uint8Array([1]) })
        .catch((e) => e);
      expect(isServiceError(err)).toBe(true);
      expect((err as { code: number }).code).toBe(grpcStatus.INVALID_ARGUMENT);
    } finally {
      client.close();
    }
  });

  test("readFile round-trips content + size_bytes + truncated", async () => {
    let seen: ReadFileRequest | undefined;
    server = await startFakeServer({
      readFile: (req) => {
        seen = req;
        return {
          workspaceId: req.workspaceId,
          content: new Uint8Array([104, 105]),
          sizeBytes: 4096,
          truncated: true,
        };
      },
    });
    const client = new Client({ target: server.target });
    try {
      const resp = await client.readFile({
        workspaceId: "wks-r-1",
        path: "big.bin",
        maxBytes: 2,
      });
      expect(seen?.path).toBe("big.bin");
      expect(seen?.maxBytes).toBe(2);
      expect(Array.from(resp.content)).toEqual([104, 105]);
      expect(resp.sizeBytes).toBe(4096);
      expect(resp.truncated).toBe(true);
    } finally {
      client.close();
    }
  });

  test("readFile propagates NOT_FOUND", async () => {
    server = await startFakeServer({
      readFile: () => statusError(grpcStatus.NOT_FOUND, "no such file"),
    });
    const client = new Client({ target: server.target });
    try {
      await expect(client.readFile({ workspaceId: "w", path: "nope.txt" })).rejects.toMatchObject({
        code: grpcStatus.NOT_FOUND,
      });
    } finally {
      client.close();
    }
  });

  test("pause/resume/snapshot/restore", async () => {
    server = await startFakeServer({
      pauseWorkspace: (req) => ({ workspaceId: req.workspaceId }),
      resumeWorkspace: (req) => ({ workspaceId: req.workspaceId }),
      snapshotWorkspace: (req) => ({
        snapshotId: `snap-${req.workspaceId}`,
        createdFromWorkspaceId: req.workspaceId,
        memSha256: "a".repeat(64),
        vmstateSha256: "b".repeat(64),
        sizeBytes: 1024,
      }),
      restoreWorkspace: (req) => ({
        workspaceId: req.newWorkspaceId,
        firecrackerPid: 4343,
        vsockHostSocket: "/tmp/fake/restored.sock",
        jailerChroot: "/tmp/fake/restored-chroot",
      }),
    });
    const client = new Client({ target: server.target });
    try {
      await expect(client.pause({ workspaceId: "ws-a" })).resolves.toMatchObject({
        workspaceId: "ws-a",
      });
      await expect(client.resume({ workspaceId: "ws-a" })).resolves.toMatchObject({
        workspaceId: "ws-a",
      });
      const snap = await client.snapshot({ workspaceId: "ws-a" });
      expect(snap.snapshotId).toBeTruthy();
      await expect(
        client.restore({ snapshotId: snap.snapshotId, newWorkspaceId: "ws-b" }),
      ).resolves.toMatchObject({ workspaceId: "ws-b" });
    } finally {
      client.close();
    }
  });

  test("fork relays request and returns identity", async () => {
    server = await startFakeServer({
      forkWorkspace: (req) => ({
        workspaceId: req.newWorkspaceId,
        firecrackerPid: 99,
        vsockHostSocket: "/x/vsock.sock",
        jailerChroot: "/x",
        sourceSnapshotId: req.snapshotId,
        hostname: req.hostname || "default",
        machineId: "0123456789abcdef0123456789abcdef",
        guestVsockCid: 3,
      }),
    });
    const client = new Client({ target: server.target });
    try {
      const resp = await client.fork({
        snapshotId: "01J0SNAP",
        newWorkspaceId: "fork-a",
        hostname: "fork-a",
      });
      expect(resp.workspaceId).toBe("fork-a");
      expect(resp.hostname).toBe("fork-a");
      expect(resp.guestVsockCid).toBe(3);
    } finally {
      client.close();
    }
  });

  test("createWorkspace with exposedPorts populates network.exposedPorts", async () => {
    let seen: CreateWorkspaceRequest | undefined;
    server = await startFakeServer({
      createWorkspace: (req) => {
        seen = req;
        return {
          workspaceId: req.workspaceId,
          firecrackerPid: 1,
          vsockHostSocket: "/x",
          jailerChroot: "/y",
          network: undefined,
        };
      },
    });
    const client = new Client({ target: server.target });
    try {
      await client.createWorkspace({
        workspaceId: "wks-ep",
        kernelSha256: "11".repeat(32),
        rootfsSha256: "22".repeat(32),
        vcpuCount: 1,
        memSizeMib: 256,
        guestVsockCid: 3,
        enableNetwork: true,
        enableEgress: true,
        exposedPorts: [
          { port: 8080, injectHeaders: [{ name: "X-Enclave-Id", value: "wks-ep" }] },
          { port: 3000 },
        ],
      });
      expect(seen?.network?.exposedPorts).toHaveLength(2);
      expect(seen?.network?.exposedPorts?.[0]?.port).toBe(8080);
      expect(seen?.network?.exposedPorts?.[0]?.injectHeaders).toEqual([
        { name: "X-Enclave-Id", value: "wks-ep" },
      ]);
      expect(seen?.network?.exposedPorts?.[1]?.port).toBe(3000);
      expect(seen?.network?.exposedPorts?.[1]?.injectHeaders).toEqual([]);
    } finally {
      client.close();
    }
  });

  test("exposePort round-trips workspaceId + port + injectHeaders", async () => {
    let seen: ExposePortRequest | undefined;
    server = await startFakeServer({
      exposePort: (req) => {
        seen = req;
        return { workspaceId: req.workspaceId, port: req.port?.port ?? 0 };
      },
    });
    const client = new Client({ target: server.target });
    try {
      const resp = await client.exposePort({
        workspaceId: "wks-exp",
        port: 8080,
        injectHeaders: [{ name: "X-Auth", value: "token-abc" }],
      });
      expect(seen?.workspaceId).toBe("wks-exp");
      expect(seen?.port?.port).toBe(8080);
      expect(seen?.port?.injectHeaders).toEqual([{ name: "X-Auth", value: "token-abc" }]);
      expect(resp.workspaceId).toBe("wks-exp");
      expect(resp.port).toBe(8080);
    } finally {
      client.close();
    }
  });

  test("exposePort without injectHeaders sends empty array", async () => {
    let seen: ExposePortRequest | undefined;
    server = await startFakeServer({
      exposePort: (req) => {
        seen = req;
        return { workspaceId: req.workspaceId, port: req.port?.port ?? 0 };
      },
    });
    const client = new Client({ target: server.target });
    try {
      await client.exposePort({ workspaceId: "wks-noheaders", port: 3000 });
      expect(seen?.port?.injectHeaders).toEqual([]);
    } finally {
      client.close();
    }
  });

  test("unexposePort round-trips workspaceId + port", async () => {
    let seen: UnexposePortRequest | undefined;
    server = await startFakeServer({
      unexposePort: (req) => {
        seen = req;
        return { workspaceId: req.workspaceId, port: req.port };
      },
    });
    const client = new Client({ target: server.target });
    try {
      const resp = await client.unexposePort({ workspaceId: "wks-unexp", port: 8080 });
      expect(seen?.workspaceId).toBe("wks-unexp");
      expect(seen?.port).toBe(8080);
      expect(resp.workspaceId).toBe("wks-unexp");
      expect(resp.port).toBe(8080);
    } finally {
      client.close();
    }
  });

  test("exposePort propagates NOT_FOUND", async () => {
    server = await startFakeServer({
      exposePort: () => statusError(grpcStatus.NOT_FOUND, "no such workspace"),
    });
    const client = new Client({ target: server.target });
    try {
      await expect(client.exposePort({ workspaceId: "ghost", port: 8080 })).rejects.toMatchObject({
        code: grpcStatus.NOT_FOUND,
      });
    } finally {
      client.close();
    }
  });

  test("unexposePort propagates NOT_FOUND", async () => {
    server = await startFakeServer({
      unexposePort: () => statusError(grpcStatus.NOT_FOUND, "port not exposed"),
    });
    const client = new Client({ target: server.target });
    try {
      await expect(client.unexposePort({ workspaceId: "wks-x", port: 9999 })).rejects.toMatchObject(
        { code: grpcStatus.NOT_FOUND },
      );
    } finally {
      client.close();
    }
  });

  test("getAttestationEvidence round-trips workspaceId + nonce", async () => {
    let seen: GetAttestationEvidenceRequest | undefined;
    server = await startFakeServer({
      getAttestationEvidence: (req) => {
        seen = req;
        return {
          evidence: {
            providerType: "software",
            workspaceId: req.workspaceId,
            measurement: new Uint8Array(32),
            nonce: req.nonce,
            issuedAt: 1,
            reportData: new Uint8Array([1, 2]),
            proof: {
              signature: new Uint8Array(64),
              signerPubkey: new Uint8Array(32),
              sevSnpReport: new Uint8Array(),
              sevSnpVcekChain: new Uint8Array(),
            },
          },
        };
      },
    });
    const client = new Client({ target: server.target });
    try {
      const resp = await client.getAttestationEvidence({
        workspaceId: "ws-att",
        nonce: new Uint8Array(16).fill(9),
      });
      expect(seen?.workspaceId).toBe("ws-att");
      expect(resp.evidence?.providerType).toBe("software");
      expect(resp.evidence?.workspaceId).toBe("ws-att");
    } finally {
      client.close();
    }
  });

  test("getAttestationEvidence preserves all Azure typed proof fields", async () => {
    server = await startFakeServer({
      getAttestationEvidence: (req) => ({
        evidence: undefined,
        publicEvidence: {
          schemaVersion: 1,
          provider: AttestationProvider.ATTESTATION_PROVIDER_SEV_SNP_AZURE,
          workspaceId: req.workspaceId,
          workspaceMeasurement: new Uint8Array(32).fill(1),
          nonce: req.nonce,
          issuedAt: 1,
          reportData: new Uint8Array([2]),
          proof: {
            $case: "sevSnpAzure",
            sevSnpAzure: {
              report: new Uint8Array([3]),
              vcekCertChain: new Uint8Array([4]),
              varData: new Uint8Array([5]),
              akPubTpm2b: new Uint8Array([6]),
              quoteMsg: new Uint8Array([7]),
              quoteSig: new Uint8Array([8]),
            },
          },
        },
      }),
    });
    const client = new Client({ target: server.target });
    try {
      const resp = await client.getAttestationEvidence({
        workspaceId: "ws-azure",
        nonce: new Uint8Array(16).fill(9),
      });
      expect(resp.publicEvidence?.provider).toBe(
        AttestationProvider.ATTESTATION_PROVIDER_SEV_SNP_AZURE,
      );
      expect(resp.publicEvidence?.proof?.$case).toBe("sevSnpAzure");
      if (resp.publicEvidence?.proof?.$case !== "sevSnpAzure") {
        throw new Error("expected Azure proof");
      }
      expect(Array.from(resp.publicEvidence.proof.sevSnpAzure.report)).toEqual([3]);
      expect(Array.from(resp.publicEvidence.proof.sevSnpAzure.vcekCertChain)).toEqual([4]);
      expect(Array.from(resp.publicEvidence.proof.sevSnpAzure.varData)).toEqual([5]);
      expect(Array.from(resp.publicEvidence.proof.sevSnpAzure.akPubTpm2b)).toEqual([6]);
      expect(Array.from(resp.publicEvidence.proof.sevSnpAzure.quoteMsg)).toEqual([7]);
      expect(Array.from(resp.publicEvidence.proof.sevSnpAzure.quoteSig)).toEqual([8]);
    } finally {
      client.close();
    }
  });

  test("listEvents with optional workspace_id filter", async () => {
    let seen: ListEventsRequest | undefined;
    server = await startFakeServer({
      listEvents: (req) => {
        seen = req;
        return {
          events: [
            {
              eventId: "01HBQ",
              timestampMs: 1,
              eventType: "workspace_created",
              workspaceId: req.workspaceId,
              payloadJson: "{}",
              chainIndex: 0,
              prevHashHex: "0".repeat(64),
              signatureB64: "sig",
              signerPubkeyB64: "key",
            },
          ],
        };
      },
    });
    const client = new Client({ target: server.target });
    try {
      const resp = await client.listEvents({ workspaceId: "wks-ts-3", limit: 10 });
      expect(seen?.workspaceId).toBe("wks-ts-3");
      expect(seen?.limit).toBe(10);
      expect(resp.events).toHaveLength(1);
      expect(resp.events[0]?.eventType).toBe("workspace_created");
      expect(resp.events[0]?.signatureB64).toBe("sig");
      expect(resp.events[0]?.prevHashHex).toBe("0".repeat(64));
    } finally {
      client.close();
    }
  });
});
