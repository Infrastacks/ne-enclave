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
} finally {
  client.close();
}

// Node 22+ — explicit resource management.
{
  using client = new Client({ target: "127.0.0.1:50051" });
  const pong = await client.ping();
}
```

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
