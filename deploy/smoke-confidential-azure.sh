#!/usr/bin/env bash
# Exercise the installed confidential-azure profile on an Azure DCasv5 CVM
# using only the exact signed release candidate copied onto the host.
set -euo pipefail

BUNDLE_DIR="${1:?signed candidate bundle directory required}"
READY=/tmp/ne-release-gate-ready
CLIENTS_DONE=/tmp/ne-release-gate-clients-complete
api=http://127.0.0.1:8080/v1
nee=/opt/ne-enclave/bin/nee
workspace=azure-release-gate

test -d "$BUNDLE_DIR"
test -f "${BUNDLE_DIR}/install.sh"
test -c /dev/tpmrm0
test ! -e /dev/kvm
tpm2 nvread -C o 0x01400001 >/dev/null
tpm2 readpublic -c 0x81000003 -f tss -o /tmp/ne-ak.tpm2b >/dev/null
rm -f "$READY" "$CLIENTS_DONE"

NE_RELEASE_BASE_URL="file://${BUNDLE_DIR}" \
NE_EXECUTION_PROFILE=confidential-azure \
sh "${BUNDLE_DIR}/install.sh" --no-start

"$nee" doctor --execution-profile confidential-azure
systemctl daemon-reload
systemctl restart ne-supervisor.service ne-api.service

for _attempt in $(seq 1 60); do
  curl -fsS "${api}/host/health" >/dev/null && break
  sleep 2
done
curl -fsS "${api}/host/health" >/dev/null

curl -fsS "${api}/runtime/capabilities" |
  tee /tmp/ne-azure-capabilities.json |
  jq -e '
    .execution_profile == "confidential-azure"
    and .execution_backend == "open_shell"
    and .attestation_backend == "sev_snp_azure"
    and .hard_workspace_capacity == 1
  '

curl -fsS "${api}/workspaces" \
  -H 'content-type: application/json' \
  -d '{
    "workspace_id":"azure-release-gate",
    "kernel_sha256":"",
    "rootfs_sha256":"",
    "rootfs_read_only":true,
    "vcpu_count":0,
    "mem_size_mib":0,
    "guest_vsock_cid":0
  }'

exec_ok=
for _attempt in $(seq 1 60); do
  if output="$(curl -fsS "${api}/workspaces/${workspace}/exec" \
    -H 'content-type: application/json' \
    -d '{"command":"/bin/echo","args":["azure-confidential-ok"]}' \
    2>/dev/null)"; then
    printf '%s\n' "$output" | grep -F azure-confidential-ok
    exec_ok=1
    break
  fi
  sleep 2
done
test -n "$exec_ok"

payload="$(printf azure-release-proof | base64 | tr -d '\n')"
curl -fsS -X PUT "${api}/workspaces/${workspace}/files" \
  -H 'content-type: application/json' \
  -d "{\"path\":\"release-proof.txt\",\"content\":\"${payload}\"}"
curl -fsS "${api}/workspaces/${workspace}/files?path=release-proof.txt" |
  grep -F "$payload"

touch "$READY"
for _attempt in $(seq 1 300); do
  test -f "$CLIENTS_DONE" && break
  sleep 2
done
test -f "$CLIENTS_DONE"

curl -fsS -X DELETE "${api}/workspaces/${workspace}"
export_dir="$("$nee" audit export --out /tmp)"
"$nee" audit verify "$export_dir"
