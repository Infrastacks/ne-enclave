#!/usr/bin/env sh
# NeuronEdge Enclave self-host installer (thin). Downloads + verifies the `nee`
# binary, then hands off to `nee install` for all provisioning.
set -eu

REPO="${NE_REPO:-Infrastacks/neuronedge.ai}"
VERSION="${NE_VERSION:-latest}"
BIN_DIR="/opt/ne-enclave/bin"
BIN_PATH="${BIN_DIR}/nee"

arch="$(uname -m)"
if [ "$arch" != "x86_64" ]; then
  echo "error: NeuronEdge Enclave self-host currently supports x86_64 only (got: $arch)" >&2
  exit 1
fi
os="$(uname -s)"
if [ "$os" != "Linux" ]; then
  echo "error: NeuronEdge Enclave runs on Linux only (got: $os)" >&2
  exit 1
fi

base="https://github.com/${REPO}/releases/${VERSION}/download"
if [ "$VERSION" = "latest" ]; then
  base="https://github.com/${REPO}/releases/latest/download"
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

echo "Downloading nee + checksums from ${base} ..."
curl -fsSL -o "$tmp/nee" "${base}/nee-x86_64-unknown-linux-musl"
curl -fsSL -o "$tmp/SHA256SUMS" "${base}/SHA256SUMS"

echo "Verifying checksum ..."
expected="$(grep 'nee-x86_64-unknown-linux-musl' "$tmp/SHA256SUMS" | awk '{print $1}')"
actual="$(sha256sum "$tmp/nee" | awk '{print $1}')"
if [ "$expected" != "$actual" ]; then
  echo "error: checksum mismatch (expected $expected, got $actual)" >&2
  exit 1
fi

# cosign verification is a documented later step:
#   cosign verify-blob --signature nee.sig --certificate nee.pem "$tmp/nee"

echo "Installing binary to ${BIN_PATH} ..."
sudo mkdir -p "$BIN_DIR"
sudo install -m 0755 "$tmp/nee" "$BIN_PATH"

echo "Provisioning host ..."
exec sudo "$BIN_PATH" install "$@"
