#!/bin/sh
# Regenerate the NeuronEdge Enclave TypeScript SDK's protobuf + gRPC stubs from
# the canonical .proto definitions at the repo root. Expects the SDK's
# devDeps to be installed (`npm install`) so `grpc-tools` provides
# protoc and `ts-proto` provides the plugin.

set -eu

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
PROTO_ROOT="$REPO_ROOT/proto"
OUT_DIR="$HERE/src/generated"

PROTOC="$HERE/node_modules/.bin/grpc_tools_node_protoc"
TS_PROTO_PLUGIN="$HERE/node_modules/.bin/protoc-gen-ts_proto"

if [ ! -x "$PROTOC" ]; then
    echo "error: $PROTOC not found; run 'npm install' first" >&2
    exit 1
fi
if [ ! -x "$TS_PROTO_PLUGIN" ]; then
    echo "error: $TS_PROTO_PLUGIN not found; run 'npm install' first" >&2
    exit 1
fi

rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR"

"$PROTOC" \
    --plugin="protoc-gen-ts_proto=$TS_PROTO_PLUGIN" \
    --ts_proto_out="$OUT_DIR" \
    --ts_proto_opt=outputServices=grpc-js \
    --ts_proto_opt=esModuleInterop=true \
    --ts_proto_opt=useOptionals=messages \
    --ts_proto_opt=oneof=unions \
    -I"$PROTO_ROOT" \
    "$PROTO_ROOT/ne/runtime/v1/runtime.proto"

echo "Regenerated stubs under $OUT_DIR/"
