# Breaking changes

## Next release

Workspace creation now identifies managed images by content digest. The request fields
`kernel_image_path` and `rootfs_image_path` (and the TypeScript spellings
`kernelImagePath` and `rootfsImagePath`) have been removed. Use `kernel_sha256` and
`rootfs_sha256` in protobuf, REST, and Python, or `kernelSha256` and `rootfsSha256` in
TypeScript. LangChain and Mastra environment configuration now uses
`NE_KERNEL_SHA256` and `NE_ROOTFS_SHA256`; legacy path variables are ignored.

Import images with `sudo /opt/ne-enclave/bin/nee image import` and pass the same lowercase
64-character SHA-256 values when creating a cold Firecracker workspace. The supervisor
resolves and verifies those artifacts beneath `NE_IMAGE_STORE` (default
`/var/lib/ne-enclave/images`) and stages independent copies for each workspace.

Snapshot manifests are now schema version 5 and sign the managed kernel/rootfs digest
pair. Restore and fork reject manifests older than version 5; there is no migration path.
Snapshots also require a read-only rootfs, so create a snapshot source with
`rootfs_read_only=true`.

The implicit confidential-mode switch `NE_CONFIDENTIAL_MODE` has been removed.
Select an explicit execution profile with `NE_EXECUTION_PROFILE=standard` or
`NE_EXECUTION_PROFILE=confidential-azure`. Installations should use
`nee install --execution-profile <profile>` and discover the active contract
through `GetRuntimeCapabilities`, `GET /v1/runtime/capabilities`, or
`nee runtime capabilities`.

Complete attestation evidence is now a versioned typed envelope. The public
provider is an enum (`software`, `sev_snp_direct`, or `sev_snp_azure`) and the
proof is a provider-specific oneof instead of an untyped proof-property bag.
Consumers that parsed legacy `provider_type` strings or arbitrary proof
properties must migrate to the typed fields. Legacy summary evidence remains
available for software and direct SEV-SNP compatibility. Azure callers must use
the complete typed envelope because the two-layer proof cannot be represented
safely in the legacy summary.

Confidential workspace creation now has profile-specific semantics: provide the
workspace ID and leave Firecracker image digests, VM sizing, networking, and
snapshot fields unset. Python callers can use
`create_confidential_workspace`; TypeScript callers can use
`createConfidentialWorkspace`.

Release asset names now use the `nee-` prefix. The Linux runtime artifact is
`nee-x86_64-unknown-linux-musl`, and the v0.2.0 installer requires Cosign to
verify the signed manifest, checksums, resolved component digests, and
profile-specific components before installation.
