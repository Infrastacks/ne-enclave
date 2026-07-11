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
