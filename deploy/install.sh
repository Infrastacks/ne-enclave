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
MANIFEST_ASSET="release-components.json"
SIGSTORE_SUFFIX=".sigstore.json"
COSIGN_ISSUER="https://token.actions.githubusercontent.com"
BIN_DIR="/opt/ne-enclave/bin"
BIN_PATH="${BIN_DIR}/nee"

case "$REPO" in
  *[!A-Za-z0-9._/-]* | /* | */ | *//* | */*/*)
    echo "error: invalid NE_REPO '$REPO' (expected owner/repository)" >&2
    exit 1
    ;;
esac
repo_identity="$(printf '%s' "$REPO" | sed 's/\./\\./g')"
if [ "$VERSION" = "latest" ]; then
  tag_identity='v[0-9].*'
else
  case "$VERSION" in
    v*) release_tag="$VERSION" ;;
    *) release_tag="v$VERSION" ;;
  esac
  version_number="${release_tag#v}"
  if ! printf '%s\n' "$version_number" |
    awk -F. '
      NF != 3 { exit 1 }
      {
        for (i = 1; i <= 3; i++) {
          if ($i !~ /^[0-9]+$/) exit 1
        }
      }
    '; then
    echo "error: invalid NE_VERSION '$VERSION' (expected vMAJOR.MINOR.PATCH)" >&2
    exit 1
  fi
  tag_identity="$(printf '%s' "$release_tag" | sed 's/\./\\./g')"
fi
COSIGN_IDENTITY_REGEXP="^https://github\\.com/${repo_identity}/\\.github/workflows/release\\.yml@refs/tags/${tag_identity}$"

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
if ! command -v cosign >/dev/null 2>&1; then
  echo "error: cosign is required to verify release signatures" >&2
  exit 1
fi
for tool in curl jq sha256sum; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "error: $tool is required to install NeuronEdge Enclave" >&2
    exit 1
  fi
done

if [ -n "${NE_RELEASE_BASE_URL:-}" ]; then
  base="${NE_RELEASE_BASE_URL%/}"
elif [ "$VERSION" = "latest" ]; then
  base="https://github.com/${REPO}/releases/latest/download"
else
  base="https://github.com/${REPO}/releases/download/${release_tag}"
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

download() {
  asset="$1"
  destination="$2"
  curl -fsSL -o "$destination" "${base}/${asset}"
}

verify_signature() {
  asset="$1"
  path="$2"
  bundle="$tmp/${asset}${SIGSTORE_SUFFIX}"
  if [ ! -f "$bundle" ]; then
    echo "error: signature bundle is missing for $asset" >&2
    exit 1
  fi
  cosign verify-blob "$path" \
    --bundle "$bundle" \
    --certificate-identity-regexp "$COSIGN_IDENTITY_REGEXP" \
    --certificate-oidc-issuer "$COSIGN_ISSUER" \
    >/dev/null
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

verify_manifest_digest() {
  asset="$1"
  path="$2"
  key="$(
    jq -er --arg asset "$asset" '
      .assets
      | to_entries[]
      | select(.value == $asset)
      | .key
    ' "$tmp/$MANIFEST_ASSET"
  )"
  expected="$(
    jq -er --arg key "$key" '
      .resolved_sha256[$key]
      | select(type == "string" and test("^[0-9a-f]{64}$"))
    ' "$tmp/$MANIFEST_ASSET"
  )"
  actual="$(sha256sum "$path" | awk '{print $1}')"
  if [ "$expected" != "$actual" ]; then
    echo "error: resolved manifest digest mismatch for $asset" >&2
    exit 1
  fi
}

verify_manifest_contract() {
  jq -e \
    --arg nee "$NEE_ASSET" \
    --arg openshell "$OPENSHELL_ASSET" \
    --arg policy_rules "$POLICY_RULES_ASSET" \
    --arg policy_data "$POLICY_DATA_ASSET" \
    --arg checksums "$CHECKSUMS_ASSET" \
    '
      .schema_version == 1
      and (.release_version | type == "string" and length > 0)
      and .assets.nee == $nee
      and .assets.openshell_sandbox == $openshell
      and .assets.policy_rules == $policy_rules
      and .assets.policy_data == $policy_data
      and .assets.checksums == $checksums
    ' "$tmp/$MANIFEST_ASSET" >/dev/null || {
    echo "error: signed release component manifest is incompatible" >&2
    exit 1
  }
  if [ "$VERSION" != "latest" ]; then
    requested_version="${VERSION#v}"
    manifest_version="$(jq -er '.release_version' "$tmp/$MANIFEST_ASSET")"
    if [ "$manifest_version" != "$requested_version" ]; then
      echo "error: signed manifest version $manifest_version does not match requested $requested_version" >&2
      exit 1
    fi
  fi
}

verify_component() {
  asset="$1"
  path="$2"
  download "$asset" "$path"
  download "${asset}${SIGSTORE_SUFFIX}" "$tmp/${asset}${SIGSTORE_SUFFIX}"
  verify_signature "$asset" "$path"
  verify_checksum "$asset" "$path"
  verify_manifest_digest "$asset" "$path"
}

echo "Downloading release components from ${base} ..."
download "$MANIFEST_ASSET" "$tmp/$MANIFEST_ASSET"
download "${MANIFEST_ASSET}${SIGSTORE_SUFFIX}" \
  "$tmp/${MANIFEST_ASSET}${SIGSTORE_SUFFIX}"
verify_signature "$MANIFEST_ASSET" "$tmp/$MANIFEST_ASSET"
download "$CHECKSUMS_ASSET" "$tmp/$CHECKSUMS_ASSET"
download "${CHECKSUMS_ASSET}${SIGSTORE_SUFFIX}" \
  "$tmp/${CHECKSUMS_ASSET}${SIGSTORE_SUFFIX}"
verify_signature "$CHECKSUMS_ASSET" "$tmp/$CHECKSUMS_ASSET"
verify_checksum "$MANIFEST_ASSET" "$tmp/$MANIFEST_ASSET"
verify_manifest_contract
verify_component "$NEE_ASSET" "$tmp/nee"

if [ "$PROFILE" = "confidential-azure" ]; then
  verify_component "$OPENSHELL_ASSET" "$tmp/openshell-sandbox"
  verify_component "$POLICY_RULES_ASSET" "$tmp/openshell-policy.rego"
  verify_component "$POLICY_DATA_ASSET" "$tmp/openshell-policy.yaml"
fi

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
