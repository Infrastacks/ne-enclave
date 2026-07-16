#!/usr/bin/env sh
set -eu

repo_root="$(CDPATH='' cd -- "$(dirname "$0")/.." && pwd)"
manifest="$repo_root/deploy/release-components.json"
install="$repo_root/deploy/install.sh"
ci="$repo_root/.github/workflows/ci.yml"
release="$repo_root/.github/workflows/release.yml"

schema_version="$(jq -er .schema_version "$manifest")"
release_version="$(jq -er .release_version "$manifest")"
nee_asset="$(jq -r .assets.nee "$manifest")"
openshell_asset="$(jq -r .assets.openshell_sandbox "$manifest")"
policy_rules_asset="$(jq -r .assets.policy_rules "$manifest")"
policy_data_asset="$(jq -r .assets.policy_data "$manifest")"
typescript_sdk_asset="$(jq -r .assets.typescript_sdk "$manifest")"
python_wheel_asset="$(jq -r .assets.python_wheel "$manifest")"
python_sdist_asset="$(jq -r .assets.python_sdist "$manifest")"
sbom_asset="$(jq -r .assets.sbom "$manifest")"
provenance_asset="$(jq -r .assets.provenance "$manifest")"
checksums_asset="$(jq -r .assets.checksums "$manifest")"
openshell_repo="$(jq -r .openshell.repository "$manifest")"
openshell_rev="$(jq -r .openshell.commit "$manifest")"

if [ "$schema_version" != "1" ] ||
  [ -z "$release_version" ] ||
  ! jq -e '.resolved_sha256 == {}' "$manifest" >/dev/null; then
  echo "invalid release component schema/version" >&2
  exit 1
fi
case "$openshell_rev" in
  *[!0-9a-f]* | "")
    echo "OpenShell commit must be a lowercase hexadecimal SHA" >&2
    exit 1
    ;;
esac
if [ "${#openshell_rev}" -ne 40 ]; then
  echo "OpenShell commit must be a full 40-character SHA" >&2
  exit 1
fi

require_code_count() {
  expected="$1"
  file="$2"
  wanted="$3"
  count="$(
    awk -v expected="$expected" '
      {
        line = $0
        sub(/^[[:space:]]+/, "", line)
        if (line == expected) count++
      }
      END { print count + 0 }
    ' "$file"
  )"
  if [ "$count" -ne "$wanted" ]; then
    echo "expected $wanted exact occurrence(s) of '$expected' in $file, found $count" >&2
    exit 1
  fi
}

require_code_count "NEE_ASSET=\"$nee_asset\"" "$install" 1
require_code_count "OPENSHELL_ASSET=\"$openshell_asset\"" "$install" 1
require_code_count "POLICY_RULES_ASSET=\"$policy_rules_asset\"" "$install" 1
require_code_count "POLICY_DATA_ASSET=\"$policy_data_asset\"" "$install" 1
require_code_count "CHECKSUMS_ASSET=\"$checksums_asset\"" "$install" 1
require_code_count 'MANIFEST_ASSET="release-components.json"' "$install" 1
require_code_count 'if ! command -v cosign >/dev/null 2>&1; then' "$install" 1
require_code_count "verify_signature \"\$MANIFEST_ASSET\" \"\$tmp/\$MANIFEST_ASSET\"" "$install" 1
require_code_count "verify_signature \"\$CHECKSUMS_ASSET\" \"\$tmp/\$CHECKSUMS_ASSET\"" "$install" 1
require_code_count "verify_manifest_digest \"\$asset\" \"\$path\"" "$install" 1

require_code_count "cp nee $nee_asset" "$ci" 1
require_code_count "sha256sum $nee_asset > $checksums_asset" "$ci" 1
require_code_count "target/x86_64-unknown-linux-musl/release/$nee_asset" "$ci" 1
require_code_count "run: sh deploy/test-release-contract.sh" "$ci" 1
require_code_count '*"statically linked"* | *"static-pie linked"*) ;;' "$ci" 1
require_code_count "run: sh scripts/check-advisory-exceptions.sh deny.toml" "$ci" 1

require_code_count "git clone $openshell_repo \"\$RUNNER_TEMP/OpenShell\"" "$release" 1
require_code_count "git -C \"\$RUNNER_TEMP/OpenShell\" checkout --detach $openshell_rev" "$release" 1
require_code_count "cp crates/ne/templates/openshell-policy.rego staging/$policy_rules_asset" "$release" 1
require_code_count "cp crates/ne/templates/openshell-policy.yaml staging/$policy_data_asset" "$release" 1
require_code_count "test -f staging/$typescript_sdk_asset" "$release" 1
require_code_count "test -f staging/$python_wheel_asset" "$release" 1
require_code_count "test -f staging/$python_sdist_asset" "$release" 1
require_code_count "output-file: staging/$sbom_asset" "$release" 1
require_code_count "staging/$provenance_asset" "$release" 1
require_code_count "subject-checksums: staging/$checksums_asset" "$release" 1
require_code_count "uses: actions/attest@v4" "$release" 1
require_code_count "artifact-metadata: write" "$release" 1
require_code_count "uses: sigstore/cosign-installer@v4.1.2" "$release" 1
require_code_count "cosign sign-blob --yes --bundle \"\${file}.sigstore.json\" \"\$file\"" "$release" 1
require_code_count "cosign verify-blob \"\$file\" \\" "$release" 1
require_code_count "gh attestation verify \"staging/\$file\" \\" "$release" 1
require_code_count "--bundle staging/$provenance_asset \\" "$release" 1
require_code_count "--signer-workflow Infrastacks/ne-enclave/.github/workflows/release.yml \\" "$release" 1
require_code_count "--source-ref \"\$GITHUB_REF\"" "$release" 1
require_code_count "path: staging/" "$release" 1
require_code_count "files: staging/*" "$release" 1
require_code_count "npm publish staging/$typescript_sdk_asset --access public" "$release" 1
require_code_count "twine upload staging/$python_wheel_asset staging/$python_sdist_asset" "$release" 1
require_code_count "run: sh deploy/test-release-contract.sh" "$release" 1
require_code_count "run: sh scripts/check-advisory-exceptions.sh deny.toml" "$release" 1
require_code_count '*"statically linked"* | *"static-pie linked"*) ;;' "$release" 1
require_code_count "contract_v=\$(jq -r .release_version deploy/release-components.json)" "$release" 1

if grep -F "ne-x86_64-unknown-linux-musl" "$install" "$ci" "$release" >/dev/null; then
  echo "legacy mistyped ne-x86_64-unknown-linux-musl asset remains" >&2
  exit 1
fi

echo "release contract OK"
