"""LangChain tools + toolkit for a NeuronEdge Enclave workspace."""

from __future__ import annotations

import asyncio
from typing import Any, Protocol, runtime_checkable

import grpc
from langchain_core.tools import BaseTool, BaseToolkit
from pydantic import BaseModel, ConfigDict, Field

from ne_langchain.errors import map_rpc_error

#: Hard cap on any string handed to the LLM (context-window hygiene).
_LLM_OUTPUT_LIMIT = 8192


def _truncate_for_llm(text: str, limit: int = _LLM_OUTPUT_LIMIT) -> tuple[str, str | None]:
    """Return ``(text, note)``. If ``text`` exceeds ``limit`` chars, cut it
    and return a human-readable note explaining the truncation."""
    if len(text) <= limit:
        return text, None
    return text[:limit], f"[tool truncated at {limit} chars, {len(text)} total]"


@runtime_checkable
class EnclaveClient(Protocol):
    """Structural type matching the slice of ``ne.Client`` the tools use."""

    def execute_command(self, **kw: Any) -> Any: ...
    def write_file(self, **kw: Any) -> Any: ...
    def read_file(self, **kw: Any) -> Any: ...
    def create_workspace(self, **kw: Any) -> Any: ...
    def destroy_workspace(self, **kw: Any) -> Any: ...
    def close(self) -> None: ...


class ExecInput(BaseModel):
    command: str = Field(..., description="Path to the command binary, resolved against guest $PATH.")
    args: list[str] = Field(default_factory=list, description="Arguments passed verbatim — no shell interpretation.")
    timeout_ms: int = Field(0, description="Per-call guest timeout in milliseconds. 0 disables.")


class EnclaveExecTool(BaseTool):
    """Run a command inside the workspace jail and return its exit code + output."""

    name: str = "enclave_exec"
    description: str = (
        "Execute a command inside the confidential enclave workspace. "
        "Returns the exit code and captured stdout/stderr. Non-zero exit "
        "is reported, not raised."
    )
    args_schema: type[BaseModel] = ExecInput

    client: EnclaveClient
    workspace_id: str

    def _run(self, command: str, args: list[str] | None = None, timeout_ms: int = 0) -> str:
        try:
            resp = self.client.execute_command(
                workspace_id=self.workspace_id,
                command=command,
                args=list(args or []),
                timeout_ms=timeout_ms,
            )
        except grpc.RpcError as exc:
            raise map_rpc_error(exc) from exc
        combined = (resp.stdout or "") + (resp.stderr or "")
        combined, note = _truncate_for_llm(combined)
        suffix = ""
        if getattr(resp, "truncated", False):
            suffix += " [guest truncated]"
        if note:
            suffix += f" {note}"
        return f"exit: {resp.exit_code}\n{combined}{suffix}"

    async def _arun(self, **kwargs: Any) -> str:
        return await asyncio.to_thread(self._run, **kwargs)


class WriteFileInput(BaseModel):
    path: str = Field(..., description="Relative path inside the workspace jail. Absolute paths and '..' are rejected.")
    content: str = Field(..., description="File contents (written as UTF-8). Hard cap 10 MiB server-side.")


class EnclaveWriteFileTool(BaseTool):
    """Write a UTF-8 file into the workspace jail."""

    name: str = "enclave_write_file"
    description: str = "Write a file into the confidential enclave workspace. Overwrites if the path exists."
    args_schema: type[BaseModel] = WriteFileInput

    client: EnclaveClient
    workspace_id: str

    def _run(self, path: str, content: str) -> str:
        try:
            resp = self.client.write_file(
                workspace_id=self.workspace_id,
                path=path,
                content=content.encode("utf-8"),
            )
        except grpc.RpcError as exc:
            raise map_rpc_error(exc) from exc
        return f"wrote {path} ({resp.bytes_written} bytes)"

    async def _arun(self, **kwargs: Any) -> str:
        return await asyncio.to_thread(self._run, **kwargs)


class ReadFileInput(BaseModel):
    path: str = Field(..., description="Relative path inside the workspace jail.")
    max_bytes: int = Field(0, description="Max bytes to read. 0 uses the server default (10 MiB).")


class EnclaveReadFileTool(BaseTool):
    """Read a file from the workspace jail. Output is capped for the LLM context window."""

    name: str = "enclave_read_file"
    description: str = "Read a file from the confidential enclave workspace. Output is UTF-8 decoded and size-capped."
    args_schema: type[BaseModel] = ReadFileInput

    client: EnclaveClient
    workspace_id: str

    def _run(self, path: str, max_bytes: int = 0) -> str:
        try:
            resp = self.client.read_file(
                workspace_id=self.workspace_id,
                path=path,
                max_bytes=max_bytes,
            )
        except grpc.RpcError as exc:
            raise map_rpc_error(exc) from exc
        text = resp.content.decode("utf-8", errors="replace")
        text, note = _truncate_for_llm(text)
        suffix = ""
        if getattr(resp, "truncated", False):
            suffix += " [guest truncated]"
        if note:
            suffix += f" {note}"
        return f"{text}{suffix}"

    async def _arun(self, **kwargs: Any) -> str:
        return await asyncio.to_thread(self._run, **kwargs)


class EnclaveToolkit(BaseToolkit):
    """Bundles the three workspace tools an agent needs: run a command,
    ingest an input file, read an output file."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    name: str = "enclave"
    description: str = (
        "Run shell commands and move files in/out of a confidential Firecracker microVM workspace."
    )

    client: EnclaveClient
    workspace_id: str

    def get_tools(self) -> list[BaseTool]:
        return [
            EnclaveExecTool(client=self.client, workspace_id=self.workspace_id),
            EnclaveWriteFileTool(client=self.client, workspace_id=self.workspace_id),
            EnclaveReadFileTool(client=self.client, workspace_id=self.workspace_id),
        ]
