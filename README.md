# NeuronEdge Enclave

**The open-source, hardware-attested execution boundary for AI agents.**

Autonomous agents run code, install packages, call APIs, and touch sensitive data. NeuronEdge Enclave gives each agent a **governed sandbox** — a Firecracker microVM (own kernel) on the standard tier, or an OpenShell sandbox inside a hardware-attested SEV-SNP CVM on the confidential tier.

Apache-2.0. Self-hosted. Rust top-to-bottom.

```sh
# Install on any Linux + KVM host (Ubuntu 22.04+/24.04, x86_64):
curl -fsSL https://github.com/Infrastacks/ne-enclave/releases/latest/download/install.sh | sh
```

---

## Why

Agent frameworks (LangChain, Mastra, CrewAI, custom) need somewhere safe to execute the code they generate. Today's options each have a catch:

- **Containers (Docker/gVisor)** — share a kernel with the host. Container escapes are a long, real history; agent-generated code (from prompt injection, supply-chain compromise, adversarial inputs) is exactly the threat model where a shared-kernel boundary isn't enough.
- **Managed sandbox clouds (E2B, Modal)** — solve isolation but move your data to someone else's infrastructure. Regulated enterprises (finance, healthcare, government) can't approve them: data residency, DPAs, attestation gaps.
- **No boundary** — agents run on the developer's laptop or a shared CI runner. The blast radius of a compromised agent is the whole machine.

NeuronEdge Enclave is the **fourth option**: a self-hosted runtime where every workspace gets its own kernel (standard tier, Firecracker microVM) — or, in confidential mode, runs directly inside a hardware-attested SEV-SNP CVM with OpenShell shared-kernel isolation, so even the cloud operator can't read its memory.

**The wedge:** *a hardware-attested execution boundary, deployable on customer-owned infrastructure, Apache-2.0.*

---

## What it is

A Rust runtime that creates, controls, snapshots, and destroys Firecracker-backed microVM sandboxes for agent workloads — with audit-grade governance (PII redaction, supply-chain enforcement, egress policy) inherited from [OpenShell](https://github.com/Infrastacks/OpenShell).

| Capability | Status |
|---|---|
| Firecracker microVM isolation (separate kernel per workspace) | ✅ Shipping |
| gRPC + REST API + Python/TypeScript SDKs | ✅ Shipping |
| Host networking (per-workspace netns + TAP + deny-by-default egress) | ✅ Shipping |
| DNS mediation + L7 privacy router (PII redaction, credential rewriting) | ✅ Shipping |
| Signed audit event stream (independently verifiable) | ✅ Shipping |
| Snapshot / restore / fork / live-state snapshot | ✅ Shipping |
| Warm pool (pre-forked microVMs, ~2ms pool-hit create) | ✅ Shipping |
| Host-based ingress routing (`{port}-{wsid}.{domain}`) | ✅ Shipping |
| Single-binary self-host install + hardened systemd units | ✅ Shipping |
| **Confidential mode** (AMD SEV-SNP, single-CVM-direct, attestation-gated key release) | ✅ **Verified on Azure DCasv5 silicon** |
| Intel TDX confidential mode | ⏳ Planned |
| Per-microVM hardware attestation (bare-metal SNP) | ⏳ Future (v2) |

### The two tiers

Enclave ships a **two-tier** runtime, selected by a single env var:

- **Standard tier** (default) — each workspace is a Firecracker microVM with its own kernel. Real isolation for multi-tenant or untrusted-code workloads. This is the Daytona/E2B-competing baseline.
- **Confidential tier** (`NE_CONFIDENTIAL_MODE=1`) — the workspace runs directly inside an AMD SEV-SNP confidential VM. Memory is encrypted; the cloud operator is excluded; key release is gated on hardware-rooted attestation evidence. **One CVM per sensitive workspace.** Verified end-to-end on Azure DCasv5 (2026-06-30).

Both tiers share the same API, SDKs, and audit surface. See [deploy/README.md](deploy/README.md#two-execution-tiers-standard--confidential) for the confidential-tier activation path.

---

## Quickstart

**Prerequisites:** a Linux x86_64 host with `/dev/kvm` (bare metal, a VM with nested virtualization, or a cloud VM like Azure Dv4+/Ev4+). For the standard tier, install [Firecracker](https://github.com/firecracker-microvm/firecracker/releases) + jailer to `/opt/ne-enclave/bin/`.

```sh
# 1. Install the runtime (renders config + hardened systemd units + starts them)
curl -fsSL https://github.com/Infrastacks/ne-enclave/releases/latest/download/install.sh | sh

# 2. Verify
/opt/ne-enclave/bin/nee doctor      # preflight: KVM, Firecracker, jailer
systemctl status ne-supervisor ne-api

# 3. Import into the privileged managed store and retain its verified digests
KERNEL_SHA256=$(sha256sum /path/to/vmlinux | cut -d' ' -f1)
ROOTFS_SHA256=$(sha256sum /path/to/rootfs.img | cut -d' ' -f1)
sudo /opt/ne-enclave/bin/nee image import \
  --kernel /path/to/vmlinux --kernel-sha256 "$KERNEL_SHA256" \
  --rootfs /path/to/rootfs.img --rootfs-sha256 "$ROOTFS_SHA256"

# 4. Create a workspace + run a command (REST)
curl -s http://127.0.0.1:8080/v1/workspaces \
  -H 'Content-Type: application/json' \
  -d "{\"workspace_id\":\"hello\",\"kernel_sha256\":\"$KERNEL_SHA256\",\"rootfs_sha256\":\"$ROOTFS_SHA256\",\"rootfs_read_only\":true,\"vcpu_count\":1,\"mem_size_mib\":512,\"guest_vsock_cid\":3}"

curl -s http://127.0.0.1:8080/v1/workspaces/hello/exec \
  -H 'Content-Type: application/json' \
  -d '{"command":"echo","args":["hello from a microVM"]}'
```

**Python SDK:**
```python
from ne import Client
c = Client("127.0.0.1:50051")
ws = c.create_workspace(
    workspace_id="hello",
    kernel_sha256="<kernel digest supplied during import>",
    rootfs_sha256="<rootfs digest supplied during import>",
    vcpu_count=1,
    mem_size_mib=512,
    guest_vsock_cid=3,
)
c.execute_command(workspace_id=ws.workspace_id, command="echo", args=["hello from Python"])
```

**TypeScript SDK:**
```typescript
import { Client } from "@neuronedge/enclave";
const c = new Client({ target: "127.0.0.1:50051" });
const ws = await c.createWorkspace({
  workspaceId: "hello",
  kernelSha256: "<kernel digest supplied during import>",
  rootfsSha256: "<rootfs digest supplied during import>",
  vcpuCount: 1,
  memSizeMib: 512,
  guestVsockCid: 3,
});
await c.executeCommand({ workspaceId: ws.workspaceId, command: "echo", args: ["hello from TS"] });
```

For air-gapped installs, custom images, and the full CLI surface, see [deploy/README.md](deploy/README.md).

---

## How it works

```
┌─── Host (Linux + KVM) ─────────────────────────────────────────────┐
│                                                                     │
│  Your agent framework (LangChain, Mastra, custom)                   │
│        │  gRPC / REST                                               │
│        ▼                                                            │
│  ┌─ ne-api (unprivileged, the front door) ──┐                       │
│  └───────────────┬──────────────────────────┘                       │
│                  │ Unix socket (peer-cred auth)                      │
│  ┌───────────────▼──────────────────────────┐                       │
│  │ ne-supervisor (privileged)               │                       │
│  │   ├─ Firecracker microVM (per workspace) │ ← standard tier       │
│  │   │   └─ guest agent over vsock          │                       │
│  │   ├─ L7 privacy router (PII, egress)     │                       │
│  │   └─ signed audit chain                  │                       │
│  └──────────────────────────────────────────┘                       │
│                                                                     │
│  Confidential tier: the whole host is a SEV-SNP CVM; the workspace  │
│  runs directly in it, memory-encrypted + attested.                  │
└─────────────────────────────────────────────────────────────────────┘
```

Every workspace gets: a separate kernel, a network namespace with deny-by-default egress, an L7 proxy that enforces PII redaction + supply-chain policy + OPA/Rego rules, and a signed audit event for every action. Snapshots, forks, and warm-pool pre-forking are first-class.

---

## Foundation

Built on two production-credible Apache-2.0 Rust projects, both under Infrastacks ownership with substantial additions:

- **[NVIDIA OpenShell](https://github.com/Infrastacks/OpenShell)** — the agent-sandbox governance layer (Landlock/seccomp/netns isolation, L7 OPA policy engine, PII redaction, supply-chain enforcement). Our fork adds the entire PII detection stack + supply-chain engine.
- **[AWS Firecracker](https://github.com/firecracker-microvm/firecracker)** — the microVM substrate (upstream prebuilt binary for the standard tier).

---

## Security posture

- **Standard tier:** per-workspace kernel isolation via Firecracker + jailer (chroot, cgroups, seccomp, namespaces). The host operator is trusted (no memory encryption).
- **Confidential tier:** the workspace runs inside an AMD SEV-SNP CVM — operator-excluded, hardware-attested. Key release is gated on a two-layer binding (the boot-fixed AMD report + a TPM-Quote nonce), verified to the genuine AMD Milan ARK.
- **Honest ceiling:** the confidential tier attests the *host CVM launch*, not the agent's guest code (guest-code measurement is a tracked follow-on). The isolation within the CVM is OpenShell's shared-kernel sandbox (Landlock/seccomp/netns), not a separate per-workspace hardware boundary (that's a future bare-metal tier). Per-workspace hardware isolation via nested microVMs is architecturally impossible on managed cloud (AMD SEV-SNP strips the virtualization extensions from the leaf guest).

The full, as-built threat model — trust boundaries, attack trees, and an explicit residual-risk register — is in [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md). It is written for a hostile reader and names every limitation honestly.

---

## Status

**The OSS runtime is feature-complete for a v0.1 release** (the standard tier + the confidential tier, verified on Azure DCasv5 silicon). What's tracked for v0.2+:

- Intel TDX confidential mode (needs DCesv5 silicon)
- Per-workspace hardware attestation (bare-metal SEV-SNP, the v2 premium tier)
- Snapshot/restore for the confidential tier (the OpenShell arm returns `Unsupported` in v0.1)
- mTLS for the runtime↔control-plane transport
- Live AWS KMS backing (the attestation gate currently uses a software KEK)

---

## Documentation

- [**Self-host install guide**](deploy/README.md) — the operator-facing deep dive: install layout, hardened systemd units, networking model, air-gapped installs, and the confidential-tier activation path.
- [Threat model](docs/THREAT-MODEL.md) — the as-built security posture: trust boundaries, attack trees, and an explicit residual-risk register.
- [Benchmark harness](bench/README.md) — the measurement harness (cold start, boot storm, density, exec latency, snapshot/restore).

---

## Community

- **Issues:** [github.com/Infrastacks/ne-enclave/issues](https://github.com/Infrastacks/ne-enclave/issues)
- **Discussions:** [github.com/Infrastacks/ne-enclave/discussions](https://github.com/Infrastacks/ne-enclave/discussions)

We are looking for **design partners** — regulated enterprises (finance, healthcare, government) evaluating confidential agent execution. If your CISO has blocked an agent deployment on isolation or attestation grounds, we'd like to talk: `eng@infrastacks.com`.

---

## License

Apache-2.0. The runtime, SDKs, guest agent, image builder, and deployment artifacts are all Apache-2.0, forever.
