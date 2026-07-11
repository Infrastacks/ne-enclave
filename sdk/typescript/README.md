# @neuronedge/enclave — TypeScript SDK

Thin client wrapper over the NeuronEdge Enclave Runtime API (gRPC). Mirrors the Python SDK
at `sdk/python/`.

## Install

This SDK is not yet npm-published. Use it in-repo or via `npm link`.

## Usage

```ts
import { Client } from "@neuronedge/enclave";

// Node 20+ baseline — explicit close.
const client = new Client({ target: "127.0.0.1:50051" });
try {
  const pong = await client.ping();
  console.log(pong.apiVersion, pong.supervisorVersion);

  const created = await client.createWorkspace({
    workspaceId: "wks-demo-1",
    kernelSha256: "11".repeat(32),
    rootfsSha256: "22".repeat(32),
    vcpuCount: 1,
    memSizeMib: 256,
    guestVsockCid: 3,
  });
  console.log(created.workspaceId);
} finally {
  client.close();
}

// Node 22+ — explicit resource management.
{
  using client = new Client({ target: "127.0.0.1:50051" });
  const pong = await client.ping();
}
```

The two SHA-256 values identify artifacts already installed in the
supervisor-managed image store. They must be 64-character lowercase hex
digests for a cold Firecracker create; callers cannot provide host paths.

## Development

```sh
npm install
npm run codegen   # regenerate src/generated/ from proto/ne/
npm run lint
npm run typecheck
npm run test
npm run build
```

`codegen.sh` regenerates `src/generated/` from the canonical proto in
`proto/ne/runtime/v1/runtime.proto`. The output is checked into the repo
(mirrors the Python SDK's `runtime_pb2.py` pattern).
