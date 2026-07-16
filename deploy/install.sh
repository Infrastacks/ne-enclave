#!/usr/bin/env sh
# NeuronEdge Enclave self-host installer (thin). Downloads and verifies the
# selected profile's release components, then hands off to `nee install`.
set -eu

REPO="${NE_REPO:-Infrastacks/ne-enclave}"
VERSION="${NE_VERSION:-latest}"
PROFILE="${NE_EXECUTION_PROFILE:-standard}"
NEE_ASSET="nee-x86_64-unknown-linux-musl"
OPENSHELL_ASSET="openshell-sandbox-x86_64-unknown-linux-musl"
POLICY_RULES_ASSET="openshell-policy.rego"
POLICY_DATA_ASSET="openshell-policy.yaml"
CHECKSUMS_ASSET="SHA256SUMS"
BIN_DIR="/opt/ne-enclave/bin"
BIN_PATH="${BIN_DIR}/nee"

case "$PROFILE" in
  standard | confidential-azure) ;;
  *)
    echo "error: unsupported NE_EXECUTION_PROFILE '$PROFILE' (expected standard or confidential-azure)" >&2
    exit 1
    ;;
esac

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

if [ -n "${NE_RELEASE_BASE_URL:-}" ]; then
  base="${NE_RELEASE_BASE_URL%/}"
elif [ "$VERSION" = "latest" ]; then
  base="https://github.com/${REPO}/releases/latest/download"
else
  base="https://github.com/${REPO}/releases/download/${VERSION}"
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

download() {
  asset="$1"
  destination="$2"
  curl -fsSL -o "$destination" "${base}/${asset}"
}

verify_checksum() {
  asset="$1"
  path="$2"
  expected="$(
    awk -v asset="$asset" '
      $2 == asset || $2 == "*" asset { print $1; found = 1; exit }
      END { if (!found) exit 1 }
    ' "$tmp/$CHECKSUMS_ASSET"
  )" || {
    echo "error: $asset is missing from $CHECKSUMS_ASSET" >&2
    exit 1
  }
  actual="$(sha256sum "$path" | awk '{print $1}')"
  if [ "$expected" != "$actual" ]; then
    echo "error: checksum mismatch for $asset (expected $expected, got $actual)" >&2
    exit 1
  fi
}

echo "Downloading release components from ${base} ..."
download "$CHECKSUMS_ASSET" "$tmp/$CHECKSUMS_ASSET"
download "$NEE_ASSET" "$tmp/nee"
verify_checksum "$NEE_ASSET" "$tmp/nee"

if [ "$PROFILE" = "confidential-azure" ]; then
  download "$OPENSHELL_ASSET" "$tmp/openshell-sandbox"
  download "$POLICY_RULES_ASSET" "$tmp/openshell-policy.rego"
  download "$POLICY_DATA_ASSET" "$tmp/openshell-policy.yaml"
  verify_checksum "$OPENSHELL_ASSET" "$tmp/openshell-sandbox"
  verify_checksum "$POLICY_RULES_ASSET" "$tmp/openshell-policy.rego"
  verify_checksum "$POLICY_DATA_ASSET" "$tmp/openshell-policy.yaml"
fi

# cosign verification is a documented later step:
#   cosign verify-blob --signature nee.sig --certificate nee.pem "$tmp/nee"

echo "Installing binary to ${BIN_PATH} ..."
sudo mkdir -p "$BIN_DIR"
sudo install -m 0755 "$tmp/nee" "$BIN_PATH"

echo "Provisioning host ..."
set -- install --execution-profile "$PROFILE" "$@"
if [ "$PROFILE" = "confidential-azure" ]; then
  set -- "$@" \
    --openshell-sandbox-source "$tmp/openshell-sandbox" \
    --openshell-policy-rules-source "$tmp/openshell-policy.rego" \
    --openshell-policy-data-source "$tmp/openshell-policy.yaml"
fi
sudo "$BIN_PATH" "$@"
