#!/bin/sh
# Regenerate the NeuronEdge Enclave Python SDK's protobuf + gRPC stubs from
# the canonical .proto definitions at the repo root. Expects the
# SDK's dev venv to be active (`pip install -e .[dev]`) so the
# `python -m grpc_tools.protoc` invocation finds grpcio-tools.

set -eu

HERE="$(cd "$(dirname "$0")/.." && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
PROTO_ROOT="$REPO_ROOT/proto"
OUT_DIR="$HERE/src"

mkdir -p "$OUT_DIR/ne/runtime/v1"

python -m grpc_tools.protoc \
    -I"$PROTO_ROOT" \
    --python_out="$OUT_DIR" \
    --grpc_python_out="$OUT_DIR" \
    "$PROTO_ROOT/ne/runtime/v1/runtime.proto"

# Ensure every package level has an __init__.py so import works
# without relying on namespace packages.
for dir in "$OUT_DIR/ne" "$OUT_DIR/ne/runtime" "$OUT_DIR/ne/runtime/v1"; do
    init="$dir/__init__.py"
    if [ ! -f "$init" ]; then
        touch "$init"
    fi
done

echo "Regenerated stubs under $OUT_DIR/ne/runtime/v1/"
