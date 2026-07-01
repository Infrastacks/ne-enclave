from __future__ import annotations

from types import SimpleNamespace

import grpc


class FakeRpcError(grpc.RpcError):
    """Test double for a gRPC RpcError carrying a status code."""

    def __init__(self, code: grpc.StatusCode, details: str = "") -> None:
        super().__init__(details)
        self._code = code
        self._details = details

    def code(self) -> grpc.StatusCode:
        return self._code

    def details(self) -> str:
        return self._details


def _resp(**kwargs):
    """Build a SimpleNamespace response double."""
    return SimpleNamespace(**kwargs)


class FakeClient:
    """Duck-typed stand-in for ``ne.Client``. Tests configure the
    ``*_response`` attributes to drive tool behavior."""

    def __init__(self, *args: object, **kwargs: object) -> None:
        self.create_calls: list[dict] = []
        self.destroy_calls: list[dict] = []
        self.exec_calls: list[dict] = []
        self.write_calls: list[dict] = []
        self.read_calls: list[dict] = []
        self.exec_response: object = None
        self.write_response: object = None
        self.read_response: object = None
        self.destroy_raises: BaseException | None = None
        self.closed = False

    def create_workspace(self, **kw):
        self.create_calls.append(kw)
        return _resp(workspace_id=kw.get("workspace_id", ""))

    def destroy_workspace(self, **kw):
        self.destroy_calls.append(kw)
        if self.destroy_raises is not None:
            raise self.destroy_raises
        return _resp()

    def execute_command(self, **kw):
        self.exec_calls.append(kw)
        if isinstance(self.exec_response, BaseException):
            raise self.exec_response
        return self.exec_response or _resp(exit_code=0, stdout="", stderr="", truncated=False)

    def write_file(self, **kw):
        self.write_calls.append(kw)
        if isinstance(self.write_response, BaseException):
            raise self.write_response
        if self.write_response is not None:
            return self.write_response
        return _resp(bytes_written=len(kw.get("content", b"")), absolute_path=kw.get("path", ""))

    def read_file(self, **kw):
        self.read_calls.append(kw)
        if isinstance(self.read_response, BaseException):
            raise self.read_response
        return self.read_response or _resp(content=b"", size_bytes=0, truncated=False)

    def close(self):
        self.closed = True
