import grpc
import pytest

from ne_langchain.workspace import EnclaveWorkspace

from conftest import FakeClient, FakeRpcError


def _factory(monkeypatch):
    """Patch the base SDK ``ne.Client`` used by workspace.py with a factory
    that returns a per-test FakeClient the test can inspect."""
    fake = FakeClient()
    monkeypatch.setattr(
        "ne_langchain.workspace.ne.Client",
        lambda *a, **kw: fake,
    )
    return fake


def _env(monkeypatch, **kw):
    monkeypatch.setenv("NE_KERNEL_IMAGE_PATH", "/k/kernel")
    monkeypatch.setenv("NE_ROOTFS_IMAGE_PATH", "/r/rootfs")
    monkeypatch.setenv("NE_VSOCK_CID_BASE", "42")
    for k, v in kw.items():
        if v is None:
            monkeypatch.delenv(k, raising=False)
        else:
            monkeypatch.setenv(k, v)


def test_enter_creates_workspace_with_env_defaults(monkeypatch):
    fake = _factory(monkeypatch)
    _env(monkeypatch)
    with EnclaveWorkspace(target="127.0.0.1:50051") as ws:
        assert ws.workspace_id.startswith("agent-")
        call = fake.create_calls[-1]
        assert call["kernel_image_path"] == "/k/kernel"
        assert call["rootfs_image_path"] == "/r/rootfs"
        assert call["guest_vsock_cid"] == 42
        assert call["vcpu_count"] == 2
        assert call["mem_size_mib"] == 1024
        assert call["rootfs_read_only"] is False


def test_explicit_kwargs_override_env(monkeypatch):
    fake = _factory(monkeypatch)
    _env(monkeypatch)
    with EnclaveWorkspace(
        target="127.0.0.1:50051",
        workspace_id="my-ws",
        kernel_image_path="/x/k",
        rootfs_image_path="/x/r",
        guest_vsock_cid=99,
        vcpu_count=4,
        mem_size_mib=2048,
    ) as ws:
        assert ws.workspace_id == "my-ws"
        call = fake.create_calls[-1]
        assert call["kernel_image_path"] == "/x/k"
        assert call["guest_vsock_cid"] == 99
        assert call["vcpu_count"] == 4


@pytest.mark.parametrize(
    ("missing_env", "field"),
    [
        ("NE_KERNEL_IMAGE_PATH", "kernel_image_path"),
        ("NE_ROOTFS_IMAGE_PATH", "rootfs_image_path"),
        ("NE_VSOCK_CID_BASE", "guest_vsock_cid"),
    ],
)
def test_missing_required_input_raises_before_rpc(monkeypatch, missing_env, field):
    _factory(monkeypatch)
    _env(monkeypatch, **{missing_env: None})
    with pytest.raises(ValueError, match=field), EnclaveWorkspace(target="127.0.0.1:50051"):
        pass


def test_exit_destroys_on_normal_exit(monkeypatch):
    fake = _factory(monkeypatch)
    _env(monkeypatch)
    with EnclaveWorkspace(target="127.0.0.1:50051", workspace_id="ws-a") as ws:
        assert ws.workspace_id == "ws-a"
    assert fake.destroy_calls and fake.destroy_calls[-1]["workspace_id"] == "ws-a"
    assert fake.closed is True


def test_exit_destroys_on_exception_and_reraises(monkeypatch):
    fake = _factory(monkeypatch)
    _env(monkeypatch)
    with pytest.raises(RuntimeError, match="boom"), EnclaveWorkspace(
        target="127.0.0.1:50051", workspace_id="ws-b"
    ):
        raise RuntimeError("boom")
    assert fake.destroy_calls and fake.destroy_calls[-1]["workspace_id"] == "ws-b"


def test_exit_swallows_destroy_failure_on_success_path(monkeypatch):
    fake = _factory(monkeypatch)
    _env(monkeypatch)
    fake.destroy_raises = FakeRpcError(grpc.StatusCode.UNAVAILABLE, "teardown flaked")
    # Must NOT raise even though destroy_workspace raises.
    with EnclaveWorkspace(target="127.0.0.1:50051", workspace_id="ws-c"):
        pass
    assert fake.destroy_calls


def test_exit_preserves_original_exception_when_destroy_also_fails(monkeypatch):
    fake = _factory(monkeypatch)
    _env(monkeypatch)
    fake.destroy_raises = FakeRpcError(grpc.StatusCode.UNAVAILABLE, "teardown flaked")
    with pytest.raises(RuntimeError, match="original"), EnclaveWorkspace(target="127.0.0.1:50051"):
        raise RuntimeError("original")


def test_tools_property_returns_toolkit_bound_to_workspace(monkeypatch):
    fake = _factory(monkeypatch)
    _env(monkeypatch)
    with EnclaveWorkspace(target="127.0.0.1:50051", workspace_id="ws-d") as ws:
        tk = ws.tools
        names = [t.name for t in tk.get_tools()]
        assert names == ["enclave_exec", "enclave_write_file", "enclave_read_file"]
        for t in tk.get_tools():
            assert t.workspace_id == "ws-d"
            assert t.client is fake
