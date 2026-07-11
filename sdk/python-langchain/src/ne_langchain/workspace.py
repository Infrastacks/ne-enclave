"""Managed-workspace lifecycle for the LangChain adapter."""

from __future__ import annotations

import logging
import os
import uuid
from collections.abc import Iterable
from types import TracebackType

import ne

from ne_langchain.tools import EnclaveToolkit

_log = logging.getLogger("ne_langchain")


class EnclaveWorkspace:
    """Owns one Firecracker microVM workspace for the lifetime of a ``with`` block.

    On enter: resolves kernel/rootfs digests and vsock-cid from kwargs or ``NE_*`` env
    vars (raising ``ValueError`` if any are missing), opens a base-SDK
    ``ne.Client`` (insecure channel in this phase), and calls
    ``create_workspace``. On exit: always calls ``destroy_workspace``;
    teardown failures on the success path are logged and swallowed, on the
    exception path the original exception wins.

    Example::

        with EnclaveWorkspace(target="127.0.0.1:50051") as ws:
            tools = ws.tools.get_tools()
    """

    def __init__(
        self,
        target: str,
        *,
        workspace_id: str | None = None,
        vcpu_count: int = 2,
        mem_size_mib: int = 1024,
        kernel_sha256: str | None = None,
        rootfs_sha256: str | None = None,
        guest_vsock_cid: int | None = None,
        rootfs_read_only: bool = False,
        kernel_boot_args: str | None = None,
        channel_options: Iterable[tuple[str, object]] | None = None,
        destroy_grace_period_ms: int = 2_000,
    ) -> None:
        self._target = target
        self._workspace_id = workspace_id or f"agent-{uuid.uuid4().hex}"
        self._vcpu_count = vcpu_count
        self._mem_size_mib = mem_size_mib
        self._kernel_sha256 = kernel_sha256
        self._rootfs_sha256 = rootfs_sha256
        self._guest_vsock_cid = guest_vsock_cid
        self._rootfs_read_only = rootfs_read_only
        self._kernel_boot_args = kernel_boot_args
        self._channel_options = channel_options
        self._destroy_grace_period_ms = destroy_grace_period_ms
        self._client: ne.Client | None = None

    @property
    def workspace_id(self) -> str:
        return self._workspace_id

    @property
    def client(self) -> ne.Client:
        if self._client is None:
            raise RuntimeError(
                "EnclaveWorkspace not entered; use 'with EnclaveWorkspace(...) as ws:'"
            )
        return self._client

    @property
    def tools(self) -> EnclaveToolkit:
        return EnclaveToolkit(client=self.client, workspace_id=self._workspace_id)

    def __enter__(self) -> EnclaveWorkspace:
        kernel = self._kernel_sha256 or os.environ.get("NE_KERNEL_SHA256")
        rootfs = self._rootfs_sha256 or os.environ.get("NE_ROOTFS_SHA256")
        cid_env = os.environ.get("NE_VSOCK_CID_BASE")
        cid = (
            self._guest_vsock_cid
            if self._guest_vsock_cid is not None
            else (int(cid_env) if cid_env else None)
        )

        missing = [
            name
            for name, value in (
                ("kernel_sha256", kernel),
                ("rootfs_sha256", rootfs),
                ("guest_vsock_cid", cid),
            )
            if not value
        ]
        if missing:
            raise ValueError(
                "EnclaveWorkspace missing required inputs (pass as kwargs or set NE_* env): "
                + ", ".join(missing)
            )

        client = ne.Client(self._target, channel_options=list(self._channel_options or ()))
        try:
            client.create_workspace(
                workspace_id=self._workspace_id,
                kernel_sha256=kernel,
                rootfs_sha256=rootfs,
                vcpu_count=self._vcpu_count,
                mem_size_mib=self._mem_size_mib,
                guest_vsock_cid=int(cid),  # type: ignore[arg-type]
                rootfs_read_only=self._rootfs_read_only,
                kernel_boot_args=self._kernel_boot_args,
            )
        except BaseException:
            client.close()
            raise
        self._client = client
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        client = self._client
        if client is None:
            return None
        try:
            client.destroy_workspace(
                workspace_id=self._workspace_id,
                grace_period_ms=self._destroy_grace_period_ms,
            )
        except BaseException as destroy_err:
            # Never re-raise: on the success path we swallow after logging;
            # on the exception path swallowing lets the caller's original
            # exception propagate unmasked (a re-raise here would replace it).
            _log.warning("destroy_workspace failed for %s: %s", self._workspace_id, destroy_err)
        finally:
            client.close()
            self._client = None
        return None
