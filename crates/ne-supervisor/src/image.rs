// SPDX-FileCopyrightText: 2026 Mindpool, Inc.
// SPDX-FileCopyrightText: 2026 Infrastacks LLC
// SPDX-License-Identifier: Apache-2.0

//! Verified resolution and independent staging of managed VM images.

use std::fmt;
use std::io;
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

use sha2::Digest as _;
use tokio::io::{AsyncReadExt as _, AsyncSeekExt as _, AsyncWriteExt as _};

/// A canonical lowercase SHA-256 image digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageDigest(String);

impl ImageDigest {
    /// Parses a canonical 64-character lowercase hexadecimal SHA-256 digest.
    pub fn parse(kind: ImageKind, raw: &str) -> Result<Self, ImageError> {
        if raw.len() == 64
            && raw
                .as_bytes()
                .iter()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
        {
            Ok(Self(raw.to_owned()))
        } else {
            Err(ImageError::InvalidDigest {
                kind,
                digest: raw.to_owned(),
            })
        }
    }

    /// Returns the digest as canonical lowercase hexadecimal.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The managed image artifact type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageKind {
    /// A Firecracker kernel image.
    Kernel,
    /// A Firecracker root filesystem image.
    Rootfs,
}

impl fmt::Display for ImageKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Kernel => "kernel",
            Self::Rootfs => "rootfs",
        })
    }
}

/// Failure to validate, resolve, or stage a managed image.
#[derive(Debug, thiserror::Error)]
pub enum ImageError {
    /// The caller supplied a non-canonical SHA-256 digest.
    #[error("invalid {kind} image digest {digest:?}")]
    InvalidDigest {
        /// Image artifact type.
        kind: ImageKind,
        /// Rejected caller input.
        digest: String,
    },
    /// The requested image artifact does not exist.
    #[error("{kind} image {digest} not found")]
    NotFound {
        /// Image artifact type.
        kind: ImageKind,
        /// Requested digest.
        digest: String,
    },
    /// The managed image path or file type failed validation.
    #[error("{kind} image {digest} rejected: {reason}")]
    Rejected {
        /// Image artifact type.
        kind: ImageKind,
        /// Requested digest.
        digest: String,
        /// Path-independent rejection reason.
        reason: String,
    },
    /// The retained image file does not hash to its requested digest.
    #[error("{kind} image {digest} content digest mismatch (actual {actual})")]
    DigestMismatch {
        /// Image artifact type.
        kind: ImageKind,
        /// Requested digest.
        digest: String,
        /// Actual SHA-256 digest.
        actual: String,
    },
    /// Copying or configuring an independently staged image failed.
    #[error("staging {kind} image {digest}: {source}")]
    Stage {
        /// Image artifact type.
        kind: ImageKind,
        /// Verified image digest.
        digest: String,
        /// Underlying staging failure.
        #[source]
        source: io::Error,
    },
}

impl ImageError {
    pub(crate) fn with_cleanup_failure(self, operation: &str, cleanup: io::Error) -> Self {
        let (kind, digest) = match &self {
            Self::InvalidDigest { kind, digest }
            | Self::NotFound { kind, digest }
            | Self::Rejected { kind, digest, .. }
            | Self::DigestMismatch { kind, digest, .. }
            | Self::Stage { kind, digest, .. } => (*kind, digest.clone()),
        };
        Self::Stage {
            kind,
            digest,
            source: io::Error::other(format!(
                "primary staging failure: {self}; {operation}: {cleanup}"
            )),
        }
    }
}

/// Root of the digest-addressed managed image store.
#[derive(Debug, Clone)]
pub struct ImageStore {
    root: PathBuf,
}

/// A verified image represented by the exact retained file handle that was hashed.
pub struct VerifiedImageFile {
    kind: ImageKind,
    digest: ImageDigest,
    file: tokio::fs::File,
}

/// A verified kernel and root filesystem pair.
pub struct VerifiedImagePair {
    /// Verified kernel image.
    kernel: VerifiedImageFile,
    /// Verified root filesystem image.
    rootfs: VerifiedImageFile,
}

impl ImageStore {
    /// Creates a managed image store rooted at `root`.
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    /// Resolves, opens, and hashes one managed image through a retained handle.
    pub async fn resolve(
        &self,
        kind: ImageKind,
        raw_digest: &str,
    ) -> Result<VerifiedImageFile, ImageError> {
        let digest = ImageDigest::parse(kind, raw_digest)?;
        let requested = digest.as_str().to_owned();
        let root = canonicalize(&self.root, kind, &requested).await?;
        let artifact = managed_path(&root, kind, digest.as_str());

        let symlink_metadata = tokio::fs::symlink_metadata(&artifact)
            .await
            .map_err(|source| map_resolve_io(kind, &requested, source))?;
        if symlink_metadata.file_type().is_symlink() {
            return Err(rejected(kind, &requested, "symlink endpoint"));
        }
        if !symlink_metadata.is_file() {
            return Err(rejected(kind, &requested, "not a regular file"));
        }

        let canonical_artifact = canonicalize(&artifact, kind, &requested).await?;
        if !canonical_artifact.starts_with(&root) {
            return Err(rejected(kind, &requested, "path escapes image store"));
        }

        let std_file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_NOFOLLOW)
            .open(&artifact)
            .map_err(|source| map_resolve_io(kind, &requested, source))?;
        if !std_file
            .metadata()
            .map_err(|source| map_resolve_io(kind, &requested, source))?
            .is_file()
        {
            return Err(rejected(kind, &requested, "not a regular file"));
        }

        let mut file = tokio::fs::File::from_std(std_file);
        let mut hasher = sha2::Sha256::new();
        let mut buffer = vec![0_u8; 64 * 1024];
        loop {
            let count = file
                .read(&mut buffer)
                .await
                .map_err(|source| operational_error(kind, &requested, source))?;
            if count == 0 {
                break;
            }
            hasher.update(&buffer[..count]);
        }
        let actual = hex::encode(hasher.finalize());
        if actual != requested {
            return Err(ImageError::DigestMismatch {
                kind,
                digest: requested,
                actual,
            });
        }
        file.rewind()
            .await
            .map_err(|source| operational_error(kind, digest.as_str(), source))?;

        Ok(VerifiedImageFile { kind, digest, file })
    }

    /// Resolves a verified kernel and root filesystem pair.
    pub async fn resolve_pair(
        &self,
        kernel: &str,
        rootfs: &str,
    ) -> Result<VerifiedImagePair, ImageError> {
        Ok(VerifiedImagePair {
            kernel: self.resolve(ImageKind::Kernel, kernel).await?,
            rootfs: self.resolve(ImageKind::Rootfs, rootfs).await?,
        })
    }
}

impl VerifiedImageFile {
    /// Returns the verified content digest.
    pub fn digest(&self) -> &ImageDigest {
        &self.digest
    }

    /// Copies this verified image into a newly created independent destination.
    pub async fn stage(
        &mut self,
        destination: &Path,
        mode: u32,
        uid: u32,
        gid: u32,
    ) -> Result<(), ImageError> {
        self.stage_with_cleanup(destination, mode, uid, gid, |path| {
            std::fs::remove_file(path)
        })
        .await
    }

    async fn stage_with_cleanup<F>(
        &mut self,
        destination: &Path,
        mode: u32,
        uid: u32,
        gid: u32,
        cleanup: F,
    ) -> Result<(), ImageError>
    where
        F: FnOnce(&Path) -> io::Result<()>,
    {
        let mode_is_valid = match self.kind {
            ImageKind::Kernel => mode == 0o400,
            ImageKind::Rootfs => matches!(mode, 0o400 | 0o600),
        };
        if !mode_is_valid {
            return Err(self.stage_error(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid mode {mode:#o} for {} image", self.kind),
            )));
        }

        self.file
            .rewind()
            .await
            .map_err(|source| self.stage_error(source))?;

        let mut staged = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(destination)
            .await
            .map_err(|source| self.stage_error(source))?;

        let result = async {
            tokio::io::copy(&mut self.file, &mut staged).await?;
            staged.flush().await?;
            std::os::unix::fs::chown(destination, Some(uid), Some(gid))?;
            tokio::fs::set_permissions(destination, std::fs::Permissions::from_mode(mode)).await
        }
        .await;

        drop(staged);
        if let Err(source) = result {
            let primary = self.stage_error(source);
            return match cleanup(destination) {
                Ok(()) => Err(primary),
                Err(cleanup_error) => Err(primary
                    .with_cleanup_failure("removing partially staged destination", cleanup_error)),
            };
        }
        Ok(())
    }

    fn stage_error(&self, source: io::Error) -> ImageError {
        ImageError::Stage {
            kind: self.kind,
            digest: self.digest.as_str().to_owned(),
            source,
        }
    }
}

impl VerifiedImagePair {
    /// Returns the content identities verified through the retained handles.
    pub fn digests(&self) -> (&str, &str) {
        (self.kernel.digest().as_str(), self.rootfs.digest().as_str())
    }
}

/// Stages a verified pair with a read-only kernel and caller-selected rootfs access.
pub async fn stage_verified_pair(
    pair: &mut VerifiedImagePair,
    kernel_destination: &Path,
    rootfs_destination: &Path,
    rootfs_read_only: bool,
    uid: u32,
    gid: u32,
) -> Result<(), ImageError> {
    stage_verified_pair_with_cleanup(
        pair,
        kernel_destination,
        rootfs_destination,
        rootfs_read_only,
        uid,
        gid,
        |path| std::fs::remove_file(path),
    )
    .await
}

async fn stage_verified_pair_with_cleanup<F>(
    pair: &mut VerifiedImagePair,
    kernel_destination: &Path,
    rootfs_destination: &Path,
    rootfs_read_only: bool,
    uid: u32,
    gid: u32,
    cleanup: F,
) -> Result<(), ImageError>
where
    F: FnOnce(&Path) -> io::Result<()>,
{
    pair.kernel
        .stage(kernel_destination, 0o400, uid, gid)
        .await?;
    let rootfs_mode = if rootfs_read_only { 0o400 } else { 0o600 };
    if let Err(error) = pair
        .rootfs
        .stage(rootfs_destination, rootfs_mode, uid, gid)
        .await
    {
        return match cleanup(kernel_destination) {
            Ok(()) => Err(error),
            Err(cleanup_error) => Err(error.with_cleanup_failure(
                "rolling back staged kernel after rootfs failure",
                cleanup_error,
            )),
        };
    }
    Ok(())
}

fn managed_path(root: &Path, kind: ImageKind, digest: &str) -> PathBuf {
    match kind {
        ImageKind::Kernel => root.join("kernels").join(digest).join("vmlinux"),
        ImageKind::Rootfs => root.join("rootfs").join(digest).join("rootfs.img"),
    }
}

async fn canonicalize(path: &Path, kind: ImageKind, digest: &str) -> Result<PathBuf, ImageError> {
    tokio::fs::canonicalize(path)
        .await
        .map_err(|source| map_resolve_io(kind, digest, source))
}

fn map_resolve_io(kind: ImageKind, digest: &str, source: io::Error) -> ImageError {
    if source.kind() == io::ErrorKind::NotFound {
        ImageError::NotFound {
            kind,
            digest: digest.to_owned(),
        }
    } else {
        operational_error(kind, digest, source)
    }
}

fn operational_error(kind: ImageKind, digest: &str, source: io::Error) -> ImageError {
    ImageError::Stage {
        kind,
        digest: digest.to_owned(),
        source,
    }
}

fn rejected(kind: ImageKind, digest: &str, reason: impl Into<String>) -> ImageError {
    ImageError::Rejected {
        kind,
        digest: digest.to_owned(),
        reason: reason.into(),
    }
}

/// Exclusive ownership token for one newly-created jailer workspace tree.
///
/// Construction atomically creates `<chroot_base>/firecracker/<workspace_id>`.
/// A caller that receives an error never owns that path and must not clean it.
#[cfg(any(target_os = "linux", test))]
#[derive(Debug)]
pub(crate) struct WorkspaceClaim {
    workspace_root: PathBuf,
    jailer_chroot: PathBuf,
}

#[cfg(any(target_os = "linux", test))]
impl WorkspaceClaim {
    /// Atomically claims a workspace id after ensuring only the shared parent exists.
    pub(crate) async fn claim(chroot_base: &Path, workspace_id: &str) -> io::Result<Self> {
        let shared_root = chroot_base.join("firecracker");
        tokio::fs::create_dir_all(&shared_root).await?;
        let workspace_root = shared_root.join(workspace_id);
        tokio::fs::create_dir(&workspace_root).await?;
        let jailer_chroot = workspace_root.join("root");
        if let Err(primary) = tokio::fs::create_dir(&jailer_chroot).await {
            return match tokio::fs::remove_dir(&workspace_root).await {
                Ok(()) => Err(primary),
                Err(cleanup) => Err(io::Error::other(format!(
                    "creating claimed workspace chroot failed: {primary}; removing owned claim: \
                     {cleanup}"
                ))),
            };
        }
        Ok(Self {
            workspace_root,
            jailer_chroot,
        })
    }

    pub(crate) fn workspace_root(&self) -> &Path {
        &self.workspace_root
    }

    pub(crate) fn jailer_chroot(&self) -> &Path {
        &self.jailer_chroot
    }

    /// Removes this invocation's owned tree after an image failure.
    pub(crate) async fn cleanup_image_failure(self, primary: ImageError) -> ImageError {
        match tokio::fs::remove_dir_all(&self.workspace_root).await {
            Ok(()) => primary,
            Err(cleanup) => primary.with_cleanup_failure("removing failed workspace tree", cleanup),
        }
    }

    /// Removes this invocation's owned tree for a non-image staging failure.
    pub(crate) async fn cleanup(self) -> io::Result<()> {
        tokio::fs::remove_dir_all(&self.workspace_root).await
    }

    #[cfg(test)]
    fn cleanup_image_failure_with<F>(self, primary: ImageError, cleanup: F) -> ImageError
    where
        F: FnOnce(&Path) -> io::Result<()>,
    {
        match cleanup(&self.workspace_root) {
            Ok(()) => primary,
            Err(cleanup_error) => {
                primary.with_cleanup_failure("removing failed workspace tree", cleanup_error)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_requires_canonical_lower_hex() {
        let good = "ab".repeat(32);
        assert_eq!(
            ImageDigest::parse(ImageKind::Kernel, &good)
                .unwrap()
                .as_str(),
            good
        );
        for bad in [
            String::new(),
            "A".repeat(64),
            "g".repeat(64),
            "a".repeat(63),
        ] {
            assert!(matches!(
                ImageDigest::parse(ImageKind::Kernel, &bad),
                Err(ImageError::InvalidDigest { .. })
            ));
        }
    }

    #[test]
    fn operational_resolver_io_is_stage_failed_while_absence_is_not_found() {
        let digest = "ab".repeat(32);
        assert!(matches!(
            map_resolve_io(
                ImageKind::Kernel,
                &digest,
                io::Error::new(io::ErrorKind::PermissionDenied, "denied"),
            ),
            ImageError::Stage { .. }
        ));
        assert!(matches!(
            map_resolve_io(
                ImageKind::Kernel,
                &digest,
                io::Error::new(io::ErrorKind::NotFound, "gone"),
            ),
            ImageError::NotFound { .. }
        ));
    }

    #[tokio::test]
    async fn resolver_uses_only_fixed_managed_paths() {
        use sha2::Digest as _;

        let temp = tempfile::tempdir().unwrap();
        let bytes = b"kernel";
        let digest = hex::encode(sha2::Sha256::digest(bytes));
        let path = temp.path().join("kernels").join(&digest).join("vmlinux");
        tokio::fs::create_dir_all(path.parent().unwrap())
            .await
            .unwrap();
        tokio::fs::write(&path, bytes).await.unwrap();
        let store = ImageStore::new(temp.path().to_path_buf());
        let verified = store.resolve(ImageKind::Kernel, &digest).await.unwrap();
        assert_eq!(verified.digest().as_str(), digest);
    }

    #[tokio::test]
    async fn verified_pair_reports_the_digests_bound_to_its_handles() {
        use sha2::Digest as _;

        let dir = tempfile::tempdir().unwrap();
        let kernel_digest = hex::encode(sha2::Sha256::digest(b"kernel"));
        let rootfs_digest = hex::encode(sha2::Sha256::digest(b"rootfs"));
        let kernel = dir
            .path()
            .join("kernels")
            .join(&kernel_digest)
            .join("vmlinux");
        let rootfs = dir
            .path()
            .join("rootfs")
            .join(&rootfs_digest)
            .join("rootfs.img");
        tokio::fs::create_dir_all(kernel.parent().unwrap())
            .await
            .unwrap();
        tokio::fs::create_dir_all(rootfs.parent().unwrap())
            .await
            .unwrap();
        tokio::fs::write(kernel, b"kernel").await.unwrap();
        tokio::fs::write(rootfs, b"rootfs").await.unwrap();
        let store = ImageStore::new(dir.path().to_path_buf());
        let pair = store
            .resolve_pair(&kernel_digest, &rootfs_digest)
            .await
            .unwrap();
        assert_eq!(pair.digests(), (&*kernel_digest, &*rootfs_digest));
    }

    #[tokio::test]
    async fn symlink_endpoint_is_rejected() {
        use sha2::Digest as _;
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let bytes = b"kernel";
        let digest = hex::encode(sha2::Sha256::digest(bytes));
        let target = temp.path().join("target");
        tokio::fs::write(&target, bytes).await.unwrap();
        let artifact = temp.path().join("kernels").join(&digest).join("vmlinux");
        tokio::fs::create_dir_all(artifact.parent().unwrap())
            .await
            .unwrap();
        symlink(&target, &artifact).unwrap();

        let error = ImageStore::new(temp.path().to_path_buf())
            .resolve(ImageKind::Kernel, &digest)
            .await
            .err()
            .unwrap();
        assert!(matches!(error, ImageError::Rejected { .. }));
    }

    #[tokio::test]
    async fn canonical_escape_is_rejected() {
        use sha2::Digest as _;
        use std::os::unix::fs::symlink;

        let store_root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let bytes = b"rootfs";
        let digest = hex::encode(sha2::Sha256::digest(bytes));
        let outside_digest = outside.path().join(&digest);
        tokio::fs::create_dir_all(&outside_digest).await.unwrap();
        tokio::fs::write(outside_digest.join("rootfs.img"), bytes)
            .await
            .unwrap();
        let kind_root = store_root.path().join("rootfs");
        tokio::fs::create_dir_all(&kind_root).await.unwrap();
        symlink(&outside_digest, kind_root.join(&digest)).unwrap();

        let error = ImageStore::new(store_root.path().to_path_buf())
            .resolve(ImageKind::Rootfs, &digest)
            .await
            .err()
            .unwrap();
        assert!(matches!(error, ImageError::Rejected { .. }));
    }

    #[tokio::test]
    async fn non_regular_artifact_is_rejected() {
        use sha2::Digest as _;

        let temp = tempfile::tempdir().unwrap();
        let digest = hex::encode(sha2::Sha256::digest(b"rootfs"));
        let artifact = temp.path().join("rootfs").join(&digest).join("rootfs.img");
        tokio::fs::create_dir_all(&artifact).await.unwrap();

        let error = ImageStore::new(temp.path().to_path_buf())
            .resolve(ImageKind::Rootfs, &digest)
            .await
            .err()
            .unwrap();
        assert!(matches!(error, ImageError::Rejected { .. }));
    }

    #[tokio::test]
    async fn mismatched_content_is_rejected() {
        use sha2::Digest as _;

        let temp = tempfile::tempdir().unwrap();
        let digest = hex::encode(sha2::Sha256::digest(b"expected"));
        let artifact = temp.path().join("kernels").join(&digest).join("vmlinux");
        tokio::fs::create_dir_all(artifact.parent().unwrap())
            .await
            .unwrap();
        tokio::fs::write(&artifact, b"tampered").await.unwrap();

        let error = ImageStore::new(temp.path().to_path_buf())
            .resolve(ImageKind::Kernel, &digest)
            .await
            .err()
            .unwrap();
        assert!(matches!(error, ImageError::DigestMismatch { .. }));
    }

    #[tokio::test]
    async fn missing_artifact_maps_to_not_found() {
        let temp = tempfile::tempdir().unwrap();
        let digest = "ab".repeat(32);
        let error = ImageStore::new(temp.path().to_path_buf())
            .resolve(ImageKind::Kernel, &digest)
            .await
            .err()
            .unwrap();
        assert!(matches!(error, ImageError::NotFound { .. }));
    }

    #[tokio::test]
    async fn writable_stages_are_independent_and_leave_source_unchanged() {
        use sha2::Digest as _;
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let temp = tempfile::tempdir().unwrap();
        let source_bytes = b"rootfs";
        let digest = hex::encode(sha2::Sha256::digest(source_bytes));
        let source = temp.path().join("rootfs").join(&digest).join("rootfs.img");
        tokio::fs::create_dir_all(source.parent().unwrap())
            .await
            .unwrap();
        tokio::fs::write(&source, source_bytes).await.unwrap();
        tokio::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o640))
            .await
            .unwrap();
        let before = std::fs::metadata(&source).unwrap();
        let store = ImageStore::new(temp.path().to_path_buf());
        let mut first = store.resolve(ImageKind::Rootfs, &digest).await.unwrap();
        let mut second = store.resolve(ImageKind::Rootfs, &digest).await.unwrap();
        let d1 = temp.path().join("w1/rootfs.img");
        let d2 = temp.path().join("w2/rootfs.img");
        tokio::fs::create_dir_all(d1.parent().unwrap())
            .await
            .unwrap();
        tokio::fs::create_dir_all(d2.parent().unwrap())
            .await
            .unwrap();
        first
            .stage(&d1, 0o600, before.uid(), before.gid())
            .await
            .unwrap();
        second
            .stage(&d2, 0o600, before.uid(), before.gid())
            .await
            .unwrap();
        tokio::fs::write(&d1, b"changed").await.unwrap();
        assert_eq!(tokio::fs::read(&source).await.unwrap(), b"rootfs");
        assert_eq!(tokio::fs::read(&d2).await.unwrap(), b"rootfs");
        let after = std::fs::metadata(&source).unwrap();
        assert_eq!(before.uid(), after.uid());
        assert_eq!(before.gid(), after.gid());
        assert_eq!(before.mode(), after.mode());
        assert_ne!(before.ino(), std::fs::metadata(&d1).unwrap().ino());
        assert_ne!(
            std::fs::metadata(&d1).unwrap().ino(),
            std::fs::metadata(&d2).unwrap().ino()
        );
    }

    #[tokio::test]
    async fn staging_refuses_an_existing_destination() {
        use sha2::Digest as _;
        use std::os::unix::fs::MetadataExt;

        let temp = tempfile::tempdir().unwrap();
        let bytes = b"kernel";
        let digest = hex::encode(sha2::Sha256::digest(bytes));
        let source = temp.path().join("kernels").join(&digest).join("vmlinux");
        tokio::fs::create_dir_all(source.parent().unwrap())
            .await
            .unwrap();
        tokio::fs::write(&source, bytes).await.unwrap();
        let metadata = std::fs::metadata(&source).unwrap();
        let mut verified = ImageStore::new(temp.path().to_path_buf())
            .resolve(ImageKind::Kernel, &digest)
            .await
            .unwrap();
        let destination = temp.path().join("existing");
        tokio::fs::write(&destination, b"keep").await.unwrap();

        let error = verified
            .stage(&destination, 0o400, metadata.uid(), metadata.gid())
            .await
            .unwrap_err();
        assert!(matches!(error, ImageError::Stage { .. }));
        assert_eq!(tokio::fs::read(&destination).await.unwrap(), b"keep");
    }

    #[tokio::test]
    async fn staging_applies_exact_valid_modes() {
        use sha2::Digest as _;
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let temp = tempfile::tempdir().unwrap();
        let kernel_digest = hex::encode(sha2::Sha256::digest(b"kernel"));
        let rootfs_digest = hex::encode(sha2::Sha256::digest(b"rootfs"));
        let kernel_source = temp
            .path()
            .join("kernels")
            .join(&kernel_digest)
            .join("vmlinux");
        let rootfs_source = temp
            .path()
            .join("rootfs")
            .join(&rootfs_digest)
            .join("rootfs.img");
        tokio::fs::create_dir_all(kernel_source.parent().unwrap())
            .await
            .unwrap();
        tokio::fs::create_dir_all(rootfs_source.parent().unwrap())
            .await
            .unwrap();
        tokio::fs::write(&kernel_source, b"kernel").await.unwrap();
        tokio::fs::write(&rootfs_source, b"rootfs").await.unwrap();
        let metadata = std::fs::metadata(&kernel_source).unwrap();
        let store = ImageStore::new(temp.path().to_path_buf());

        for (index, (kind, digest, mode)) in [
            (ImageKind::Kernel, &kernel_digest, 0o400),
            (ImageKind::Rootfs, &rootfs_digest, 0o400),
            (ImageKind::Rootfs, &rootfs_digest, 0o600),
        ]
        .into_iter()
        .enumerate()
        {
            let mut verified = store.resolve(kind, digest).await.unwrap();
            let destination = temp.path().join(format!("stage-{index}"));
            verified
                .stage(&destination, mode, metadata.uid(), metadata.gid())
                .await
                .unwrap();
            assert_eq!(
                std::fs::metadata(destination).unwrap().permissions().mode() & 0o777,
                mode
            );
        }
    }

    #[tokio::test]
    async fn staging_rejects_invalid_kind_mode_before_destination_creation() {
        use sha2::Digest as _;
        use std::os::unix::fs::MetadataExt;

        let temp = tempfile::tempdir().unwrap();
        let kernel_digest = hex::encode(sha2::Sha256::digest(b"kernel"));
        let rootfs_digest = hex::encode(sha2::Sha256::digest(b"rootfs"));
        let kernel_source = temp
            .path()
            .join("kernels")
            .join(&kernel_digest)
            .join("vmlinux");
        let rootfs_source = temp
            .path()
            .join("rootfs")
            .join(&rootfs_digest)
            .join("rootfs.img");
        tokio::fs::create_dir_all(kernel_source.parent().unwrap())
            .await
            .unwrap();
        tokio::fs::create_dir_all(rootfs_source.parent().unwrap())
            .await
            .unwrap();
        tokio::fs::write(&kernel_source, b"kernel").await.unwrap();
        tokio::fs::write(&rootfs_source, b"rootfs").await.unwrap();
        let metadata = std::fs::metadata(&kernel_source).unwrap();
        let store = ImageStore::new(temp.path().to_path_buf());

        for (index, (kind, digest, mode)) in [
            (ImageKind::Kernel, &kernel_digest, 0o600),
            (ImageKind::Rootfs, &rootfs_digest, 0o700),
        ]
        .into_iter()
        .enumerate()
        {
            let mut verified = store.resolve(kind, digest).await.unwrap();
            let destination = temp.path().join(format!("invalid-{index}"));
            let error = verified
                .stage(&destination, mode, metadata.uid(), metadata.gid())
                .await
                .unwrap_err();
            assert!(matches!(
                error,
                ImageError::Stage { source, .. }
                    if source.kind() == io::ErrorKind::InvalidInput
            ));
            assert!(!destination.exists());
        }
    }

    #[tokio::test]
    async fn pair_staging_applies_read_only_and_writable_rootfs_modes() {
        use sha2::Digest as _;
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let temp = tempfile::tempdir().unwrap();
        let kernel_digest = hex::encode(sha2::Sha256::digest(b"kernel"));
        let rootfs_digest = hex::encode(sha2::Sha256::digest(b"rootfs"));
        let kernel_source = temp
            .path()
            .join("kernels")
            .join(&kernel_digest)
            .join("vmlinux");
        let rootfs_source = temp
            .path()
            .join("rootfs")
            .join(&rootfs_digest)
            .join("rootfs.img");
        tokio::fs::create_dir_all(kernel_source.parent().unwrap())
            .await
            .unwrap();
        tokio::fs::create_dir_all(rootfs_source.parent().unwrap())
            .await
            .unwrap();
        tokio::fs::write(&kernel_source, b"kernel").await.unwrap();
        tokio::fs::write(&rootfs_source, b"rootfs").await.unwrap();
        let metadata = std::fs::metadata(&kernel_source).unwrap();
        let store = ImageStore::new(temp.path().to_path_buf());

        for (index, (rootfs_read_only, expected_rootfs_mode)) in
            [(true, 0o400), (false, 0o600)].into_iter().enumerate()
        {
            let mut pair = store
                .resolve_pair(&kernel_digest, &rootfs_digest)
                .await
                .unwrap();
            let stage_dir = temp.path().join(format!("stage-{index}"));
            let kernel_destination = stage_dir.join("vmlinux");
            let rootfs_destination = stage_dir.join("rootfs.img");
            tokio::fs::create_dir_all(&stage_dir).await.unwrap();

            stage_verified_pair(
                &mut pair,
                &kernel_destination,
                &rootfs_destination,
                rootfs_read_only,
                metadata.uid(),
                metadata.gid(),
            )
            .await
            .unwrap();

            assert_eq!(
                tokio::fs::read(&kernel_destination).await.unwrap(),
                b"kernel"
            );
            assert_eq!(
                tokio::fs::read(&rootfs_destination).await.unwrap(),
                b"rootfs"
            );
            assert_eq!(
                std::fs::metadata(kernel_destination)
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o400
            );
            assert_eq!(
                std::fs::metadata(rootfs_destination)
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                expected_rootfs_mode
            );
        }
    }

    #[tokio::test]
    async fn pair_staging_removes_created_kernel_when_rootfs_staging_fails() {
        use sha2::Digest as _;
        use std::os::unix::fs::MetadataExt;

        let temp = tempfile::tempdir().unwrap();
        let kernel_digest = hex::encode(sha2::Sha256::digest(b"kernel"));
        let rootfs_digest = hex::encode(sha2::Sha256::digest(b"rootfs"));
        let kernel_source = temp
            .path()
            .join("kernels")
            .join(&kernel_digest)
            .join("vmlinux");
        let rootfs_source = temp
            .path()
            .join("rootfs")
            .join(&rootfs_digest)
            .join("rootfs.img");
        tokio::fs::create_dir_all(kernel_source.parent().unwrap())
            .await
            .unwrap();
        tokio::fs::create_dir_all(rootfs_source.parent().unwrap())
            .await
            .unwrap();
        tokio::fs::write(&kernel_source, b"kernel").await.unwrap();
        tokio::fs::write(&rootfs_source, b"rootfs").await.unwrap();
        let metadata = std::fs::metadata(&kernel_source).unwrap();
        let mut pair = ImageStore::new(temp.path().to_path_buf())
            .resolve_pair(&kernel_digest, &rootfs_digest)
            .await
            .unwrap();
        let stage_dir = temp.path().join("stage-failure");
        let kernel_destination = stage_dir.join("vmlinux");
        let rootfs_destination = stage_dir.join("rootfs.img");
        tokio::fs::create_dir_all(&stage_dir).await.unwrap();
        tokio::fs::write(&rootfs_destination, b"pre-existing")
            .await
            .unwrap();

        let error = stage_verified_pair(
            &mut pair,
            &kernel_destination,
            &rootfs_destination,
            false,
            metadata.uid(),
            metadata.gid(),
        )
        .await
        .unwrap_err();

        assert!(matches!(error, ImageError::Stage { .. }));
        assert!(!kernel_destination.exists());
        assert_eq!(
            tokio::fs::read(&rootfs_destination).await.unwrap(),
            b"pre-existing"
        );
    }

    #[tokio::test]
    async fn staging_removes_destination_after_copy_failure() {
        use std::os::unix::fs::MetadataExt;

        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("write-only");
        tokio::fs::write(&source, b"rootfs").await.unwrap();
        let metadata = std::fs::metadata(&source).unwrap();
        let file = std::fs::OpenOptions::new()
            .write(true)
            .open(&source)
            .unwrap();
        let mut verified = VerifiedImageFile {
            kind: ImageKind::Rootfs,
            digest: ImageDigest::parse(ImageKind::Rootfs, &"ab".repeat(32)).unwrap(),
            file: tokio::fs::File::from_std(file),
        };
        let destination = temp.path().join("partial");

        assert!(
            verified
                .stage(&destination, 0o600, metadata.uid(), metadata.gid())
                .await
                .is_err()
        );
        assert!(!destination.exists());
    }

    #[tokio::test]
    async fn staging_surfaces_primary_and_cleanup_failures() {
        use std::os::unix::fs::MetadataExt;

        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("write-only-cleanup");
        tokio::fs::write(&source, b"rootfs").await.unwrap();
        let metadata = std::fs::metadata(&source).unwrap();
        let file = std::fs::OpenOptions::new()
            .write(true)
            .open(&source)
            .unwrap();
        let mut verified = VerifiedImageFile {
            kind: ImageKind::Rootfs,
            digest: ImageDigest::parse(ImageKind::Rootfs, &"ab".repeat(32)).unwrap(),
            file: tokio::fs::File::from_std(file),
        };
        let destination = temp.path().join("partial-cleanup");

        let error = verified
            .stage_with_cleanup(&destination, 0o600, metadata.uid(), metadata.gid(), |_| {
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "cleanup denied",
                ))
            })
            .await
            .unwrap_err();
        let message = error.to_string();
        assert!(message.contains("cleanup denied"), "{message}");
        assert!(message.contains("primary staging failure"), "{message}");
    }

    #[tokio::test]
    async fn pair_rollback_failure_preserves_primary_and_cleanup_context() {
        use sha2::Digest as _;
        use std::os::unix::fs::MetadataExt;

        let temp = tempfile::tempdir().unwrap();
        let kernel_digest = hex::encode(sha2::Sha256::digest(b"kernel"));
        let rootfs_digest = hex::encode(sha2::Sha256::digest(b"rootfs"));
        let kernel_source = temp
            .path()
            .join("kernels")
            .join(&kernel_digest)
            .join("vmlinux");
        let rootfs_source = temp
            .path()
            .join("rootfs")
            .join(&rootfs_digest)
            .join("rootfs.img");
        tokio::fs::create_dir_all(kernel_source.parent().unwrap())
            .await
            .unwrap();
        tokio::fs::create_dir_all(rootfs_source.parent().unwrap())
            .await
            .unwrap();
        tokio::fs::write(&kernel_source, b"kernel").await.unwrap();
        tokio::fs::write(&rootfs_source, b"rootfs").await.unwrap();
        let metadata = std::fs::metadata(&kernel_source).unwrap();
        let mut pair = ImageStore::new(temp.path().to_path_buf())
            .resolve_pair(&kernel_digest, &rootfs_digest)
            .await
            .unwrap();
        let stage_dir = temp.path().join("pair-rollback-failure");
        tokio::fs::create_dir_all(&stage_dir).await.unwrap();
        let kernel_destination = stage_dir.join("vmlinux");
        let rootfs_destination = stage_dir.join("rootfs.img");
        tokio::fs::write(&rootfs_destination, b"pre-existing")
            .await
            .unwrap();

        let error = stage_verified_pair_with_cleanup(
            &mut pair,
            &kernel_destination,
            &rootfs_destination,
            false,
            metadata.uid(),
            metadata.gid(),
            |_| {
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "rollback denied",
                ))
            },
        )
        .await
        .unwrap_err();
        let message = error.to_string();
        assert!(message.contains("rollback denied"), "{message}");
        assert!(message.contains("primary staging failure"), "{message}");
    }

    #[tokio::test]
    async fn workspace_claim_collision_preserves_preexisting_tree() {
        let temp = tempfile::tempdir().unwrap();
        let existing = temp.path().join("firecracker/ws-existing");
        tokio::fs::create_dir_all(existing.join("root"))
            .await
            .unwrap();
        tokio::fs::write(existing.join("sentinel"), b"owned elsewhere")
            .await
            .unwrap();

        let error = WorkspaceClaim::claim(temp.path(), "ws-existing")
            .await
            .unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(
            tokio::fs::read(existing.join("sentinel")).await.unwrap(),
            b"owned elsewhere"
        );
    }

    #[tokio::test]
    async fn concurrent_same_id_has_one_cleanup_owner() {
        let temp = tempfile::tempdir().unwrap();
        let (first, second) = tokio::join!(
            WorkspaceClaim::claim(temp.path(), "ws-race"),
            WorkspaceClaim::claim(temp.path(), "ws-race")
        );
        let (claim, loser_error) = match (first, second) {
            (Ok(claim), Err(error)) | (Err(error), Ok(claim)) => (claim, error),
            other => panic!("expected exactly one claimant, got {other:?}"),
        };
        assert_eq!(loser_error.kind(), io::ErrorKind::AlreadyExists);
        tokio::fs::write(claim.workspace_root().join("sentinel"), b"winner")
            .await
            .unwrap();
        assert_eq!(
            tokio::fs::read(claim.workspace_root().join("sentinel"))
                .await
                .unwrap(),
            b"winner"
        );
        claim.cleanup().await.unwrap();
        assert!(!temp.path().join("firecracker/ws-race").exists());
    }

    #[tokio::test]
    async fn failed_workspace_cleanup_removes_only_target_and_preserves_sibling() {
        use sha2::Digest as _;
        use std::os::unix::fs::MetadataExt;

        let temp = tempfile::tempdir().unwrap();
        let firecracker = temp.path().join("firecracker");
        let claim = WorkspaceClaim::claim(temp.path(), "ws-failing")
            .await
            .unwrap();
        let failing_chroot = claim.jailer_chroot().to_path_buf();
        let sibling = firecracker.join("ws-sibling");
        std::fs::create_dir_all(&sibling).unwrap();
        std::fs::write(sibling.join("sentinel"), b"keep").unwrap();
        let kernel_digest = hex::encode(sha2::Sha256::digest(b"kernel"));
        let rootfs_digest = hex::encode(sha2::Sha256::digest(b"rootfs"));
        let kernel_source = temp
            .path()
            .join("images/kernels")
            .join(&kernel_digest)
            .join("vmlinux");
        let rootfs_source = temp
            .path()
            .join("images/rootfs")
            .join(&rootfs_digest)
            .join("rootfs.img");
        tokio::fs::create_dir_all(kernel_source.parent().unwrap())
            .await
            .unwrap();
        tokio::fs::create_dir_all(rootfs_source.parent().unwrap())
            .await
            .unwrap();
        tokio::fs::write(&kernel_source, b"kernel").await.unwrap();
        tokio::fs::write(&rootfs_source, b"rootfs").await.unwrap();
        let metadata = std::fs::metadata(&kernel_source).unwrap();
        let mut pair = ImageStore::new(temp.path().join("images"))
            .resolve_pair(&kernel_digest, &rootfs_digest)
            .await
            .unwrap();
        tokio::fs::write(
            failing_chroot.join("rootfs.img"),
            b"force create_new failure",
        )
        .await
        .unwrap();
        let primary = stage_verified_pair(
            &mut pair,
            &failing_chroot.join("vmlinux"),
            &failing_chroot.join("rootfs.img"),
            false,
            metadata.uid(),
            metadata.gid(),
        )
        .await
        .unwrap_err();

        let error = claim.cleanup_image_failure(primary).await;

        assert!(matches!(error, ImageError::Stage { .. }));
        assert!(!firecracker.join("ws-failing").exists());
        assert_eq!(std::fs::read(sibling.join("sentinel")).unwrap(), b"keep");
    }

    #[tokio::test]
    async fn failed_workspace_cleanup_surfaces_cleanup_failure() {
        let temp = tempfile::tempdir().unwrap();
        let claim = WorkspaceClaim::claim(temp.path(), "ws").await.unwrap();
        let primary = ImageError::Stage {
            kind: ImageKind::Rootfs,
            digest: "cd".repeat(32),
            source: io::Error::other("forced staging failure"),
        };

        let error = claim.cleanup_image_failure_with(primary, |_| {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "workspace cleanup denied",
            ))
        });
        let message = error.to_string();
        assert!(message.contains("forced staging failure"), "{message}");
        assert!(message.contains("workspace cleanup denied"), "{message}");
    }
}
