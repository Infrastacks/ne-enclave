import grpc
import pytest
from langchain_core.tools import BaseTool, ToolException

from ne_langchain.errors import map_rpc_error  # noqa: F401  (sanity import)
from ne_langchain.tools import (
    EnclaveExecTool,
    EnclaveReadFileTool,
    EnclaveToolkit,
    EnclaveWriteFileTool,
    _truncate_for_llm,
)

from conftest import FakeClient, FakeRpcError

# ---- _truncate_for_llm --------------------------------------------------


def test_truncate_under_limit_returns_unchanged():
    text, note = _truncate_for_llm("hello", 8192)
    assert text == "hello"
    assert note is None


def test_truncate_over_limit_cuts_and_notes():
    big = "x" * 9000
    text, note = _truncate_for_llm(big, 8192)
    assert len(text) == 8192
    assert note is not None
    assert "9000" in note


# ---- enclave_exec -------------------------------------------------------


def _make_exec(client=None):
    return EnclaveExecTool(client=client or FakeClient(), workspace_id="ws-1")


def test_exec_is_a_basetool():
    tool = _make_exec()
    assert isinstance(tool, BaseTool)
    assert tool.name == "enclave_exec"


def test_exec_returns_exit_code_and_output():
    client = FakeClient()
    client.exec_response = type("R", (), {"exit_code": 0, "stdout": "hello\n", "stderr": "", "truncated": False})()
    tool = _make_exec(client)
    out = tool._run(command="echo", args=["hello"])
    assert out.startswith("exit: 0\n")
    assert "hello" in out
    assert client.exec_calls[-1]["workspace_id"] == "ws-1"
    assert client.exec_calls[-1]["command"] == "echo"


def test_exec_nonzero_exit_is_not_raised():
    client = FakeClient()
    client.exec_response = type("R", (), {"exit_code": 2, "stdout": "", "stderr": "not found", "truncated": False})()
    out = _make_exec(client)._run(command="ls", args=["/nope"])
    assert "exit: 2" in out
    assert "not found" in out


def test_exec_truncates_large_output():
    client = FakeClient()
    client.exec_response = type(
        "R", (), {"exit_code": 0, "stdout": "y" * 20_000, "stderr": "", "truncated": False}
    )()
    out = _make_exec(client)._run(command="cat", args=["big"])
    assert len(out) < 20_000
    assert "tool truncated" in out


def test_exec_marks_guest_truncated():
    client = FakeClient()
    client.exec_response = type("R", (), {"exit_code": 0, "stdout": "x", "stderr": "", "truncated": True})()
    out = _make_exec(client)._run(command="x")
    assert "guest truncated" in out


def test_exec_raises_tool_exception_on_rpc_error():
    client = FakeClient()
    client.exec_response = FakeRpcError(grpc.StatusCode.DEADLINE_EXCEEDED, "timed out")
    with pytest.raises(ToolException) as ei:
        _make_exec(client)._run(command="sleep", args=["99"])
    assert "DEADLINE_EXCEEDED" in str(ei.value)


@pytest.mark.asyncio
async def test_exec_arun_delegates_to_run():
    client = FakeClient()
    client.exec_response = type("R", (), {"exit_code": 0, "stdout": "ok", "stderr": "", "truncated": False})()
    out = await _make_exec(client)._arun(command="true")
    assert out.startswith("exit: 0")


# ---- enclave_write_file -------------------------------------------------


def _make_write(client=None):
    return EnclaveWriteFileTool(client=client or FakeClient(), workspace_id="ws-1")


def test_write_returns_path_and_bytes():
    client = FakeClient()
    out = _make_write(client)._run(path="in/data.txt", content="hello")
    assert client.write_calls[-1]["path"] == "in/data.txt"
    assert client.write_calls[-1]["content"] == b"hello"
    assert client.write_calls[-1]["workspace_id"] == "ws-1"
    assert "wrote in/data.txt" in out
    assert "5 bytes" in out  # len(b"hello")


def test_write_raises_tool_exception_on_invalid_argument():
    client = FakeClient()
    client.write_response = FakeRpcError(grpc.StatusCode.INVALID_ARGUMENT, "path traversal")
    with pytest.raises(ToolException):
        _make_write(client)._run(path="../escape", content="x")


# ---- enclave_read_file --------------------------------------------------


def _make_read(client=None):
    return EnclaveReadFileTool(client=client or FakeClient(), workspace_id="ws-1")


def test_read_returns_decoded_content():
    client = FakeClient()
    client.read_response = type("R", (), {"content": b"file body", "size_bytes": 8, "truncated": False})()
    out = _make_read(client)._run(path="out/result.txt")
    assert client.read_calls[-1]["path"] == "out/result.txt"
    assert out.startswith("file body")
    assert "out/result.txt" not in out  # we return content, not an echo


def test_read_truncates_large_file():
    client = FakeClient()
    client.read_response = type("R", (), {"content": b"z" * 20_000, "size_bytes": 20_000, "truncated": False})()
    out = _make_read(client)._run(path="big.bin")
    assert len(out) < 20_000
    assert "tool truncated" in out


def test_read_marks_guest_truncated():
    client = FakeClient()
    client.read_response = type("R", (), {"content": b"partial", "size_bytes": 9_999_999, "truncated": True})()
    out = _make_read(client)._run(path="huge.log")
    assert "guest truncated" in out


def test_read_raises_tool_exception_on_rpc_error():
    client = FakeClient()
    client.read_response = FakeRpcError(grpc.StatusCode.NOT_FOUND, "no such file")
    with pytest.raises(ToolException) as ei:
        _make_read(client)._run(path="missing")
    assert "NOT_FOUND" in str(ei.value)


# ---- EnclaveToolkit -----------------------------------------------------


def test_toolkit_enumerates_three_tools():
    client = FakeClient()
    tk = EnclaveToolkit(client=client, workspace_id="ws-1")
    tools = tk.get_tools()
    names = [t.name for t in tools]
    assert names == ["enclave_exec", "enclave_write_file", "enclave_read_file"]
    for t in tools:
        assert t.workspace_id == "ws-1"
        assert t.client is client


def test_toolkit_get_tools_returns_fresh_instances():
    tk = EnclaveToolkit(client=FakeClient(), workspace_id="ws-1")
    a = tk.get_tools()
    b = tk.get_tools()
    assert a is not b
    assert [t.name for t in a] == [t.name for t in b]
