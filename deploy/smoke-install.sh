#!/usr/bin/env bash
# NeuronEdge Enclave install smoke: install from a locally-built nee binary, start
# the systemd units, and drive one workspace create->exec->write->read->
# destroy through the INSTALLED REST api. Idempotent; safe to re-run.
#
# Firecracker + jailer are staged into /opt/ne-enclave/bin/ (where the installed
# supervisor expects them) from NE_E2E_FIRECRACKER/NE_E2E_JAILER, then
# /usr/local/bin, then PATH — erroring with guidance if neither is found. A real
# operator-provided binary already under /opt/ne-enclave/bin/ is left as-is.
#
# Usage: sudo deploy/smoke-install.sh /path/to/nee /path/to/vmlinux /path/to/rootfs.img
set -euo pipefail

NE_BIN="${1:?path to built nee binary required}"
KERNEL="${2:?path to vmlinux required}"
ROOTFS="${3:?path to rootfs image required}"

# Stage a runtime binary (firecracker/jailer) into the install bin dir so the
# installed supervisor — which reads NE_FIRECRACKER_BIN/NE_JAILER_BIN defaulting
# to /opt/ne-enclave/bin/ — can spawn it. If a smoke host already has these
# under /usr/local/bin/, we symlink from there; a real operator install puts
# them under /opt/ne-enclave/bin/ directly. We symlink, never clobbering an
# existing operator-provided binary.
#   $1 = binary name (firecracker | jailer)
#   $2 = env var that may override the source (NE_E2E_FIRECRACKER | NE_E2E_JAILER)
stage_runtime_bin () {
  local name="$1"
  local env_var="$2"
  local dest="/opt/ne-enclave/bin/${name}"

  # Already operator-provided (real file or working symlink)? Leave it.
  if [ -x "$dest" ]; then
    echo "    ${name}: already present at ${dest}"
    return 0
  fi

  local src="" found env_src="${!env_var:-}"
  if [ -n "$env_src" ] && [ -x "$env_src" ]; then
    src="$env_src"
  elif [ -x "/usr/local/bin/${name}" ]; then
    src="/usr/local/bin/${name}"
  else
    found="$(command -v "${name}" 2>/dev/null || true)"
    if [ -n "$found" ] && [ -x "$found" ]; then src="$found"; fi
  fi

  if [ -z "$src" ]; then
    echo "error: ${name} not found anywhere on this host." >&2
    echo "       The installed runtime expects it at ${dest}." >&2
    echo "       Install Firecracker from" >&2
    echo "         https://github.com/firecracker-microvm/firecracker/releases" >&2
    echo "       into /opt/ne-enclave/bin/, or export ${env_var}=/path/to/${name}." >&2
    exit 1
  fi
  ln -sf "$src" "$dest"
  echo "    ${name}: ${dest} -> ${src}"
}

echo "== Installing nee from ${NE_BIN} =="
install -d -m 0755 /opt/ne-enclave/bin
install -m 0755 "$NE_BIN" /opt/ne-enclave/bin/nee

echo "== Staging firecracker + jailer into /opt/ne-enclave/bin/ =="
stage_runtime_bin firecracker NE_E2E_FIRECRACKER
stage_runtime_bin jailer      NE_E2E_JAILER

# Provision host (no image fetch; we import the locally-built image next).
/opt/ne-enclave/bin/nee install --no-start --no-image

echo "== Importing guest image =="
ksum="$(sha256sum "$KERNEL" | awk '{print $1}')"
rsum="$(sha256sum "$ROOTFS" | awk '{print $1}')"
/opt/ne-enclave/bin/nee image import \
  --kernel "$KERNEL" --kernel-sha256 "$ksum" \
  --rootfs "$ROOTFS" --rootfs-sha256 "$rsum"
echo "kernel sha256 -> $ksum"
echo "rootfs sha256 -> $rsum"

echo "== Starting units =="
systemctl daemon-reload
systemctl restart ne-supervisor.service
systemctl restart ne-api.service
sleep 2
systemctl --no-pager --full status ne-supervisor.service ne-api.service | head -n 25 || true

echo "== Driving a workspace through the installed REST api =="
api="http://127.0.0.1:8080/v1"
curl -fsS "${api}/host/health"; echo

wsid="smoke-$(date +%s)"
echo "create $wsid"
curl -fsS -X POST "${api}/workspaces" -H 'content-type: application/json' -d @- <<JSON
{
  "workspace_id": "${wsid}",
  "kernel_sha256": "${ksum}",
  "rootfs_sha256": "${rsum}",
  "rootfs_read_only": true,
  "vcpu_count": 1,
  "mem_size_mib": 256,
  "guest_vsock_cid": 3
}
JSON
echo

echo "exec in $wsid (poll until the guest agent is ready)"
# `create` returns at VM launch; the guest agent needs a few seconds to
# boot and listen on vsock. The supervisor's vsock connect is single-shot,
# so poll the exec (as a real SDK client would poll for workspace
# readiness) until it succeeds, up to ~30s.
exec_ok=""
for _attempt in $(seq 1 30); do
  if out=$(curl -fsS -X POST "${api}/workspaces/${wsid}/exec" -H 'content-type: application/json' \
            -d '{"command":"/bin/echo","args":["hello-from-installed-nee"]}' 2>/dev/null); then
    echo "$out"
    exec_ok=1
    break
  fi
  sleep 1
done
if [ -z "$exec_ok" ]; then
  echo "error: exec never succeeded (guest agent not ready after 30s)" >&2
  exit 1
fi
echo

# Paths are relative to the workspace jail root (/workspace); the guest
# agent rejects absolute paths. "proof.txt" lands at /workspace/proof.txt.
echo "write+read proof.txt (-> /workspace/proof.txt)"
payload="$(printf 'installed-roundtrip' | base64 | tr -d '\n')"
curl -fsS -X PUT "${api}/workspaces/${wsid}/files" -H 'content-type: application/json' \
  -d "{\"path\":\"proof.txt\",\"content\":\"${payload}\"}"
echo
curl -fsS "${api}/workspaces/${wsid}/files?path=proof.txt"
echo

echo "destroy $wsid"
curl -fsS -X DELETE "${api}/workspaces/${wsid}"
echo

echo "== Recent audit events =="
curl -fsS "${api}/events?limit=10" || true
echo

echo "SMOKE OK"
