"""Translate gRPC errors raised by the base SDK into LangChain ToolExceptions."""

from __future__ import annotations

import grpc
from langchain_core.tools import ToolException


def map_rpc_error(exc: grpc.RpcError) -> ToolException:
    """Convert a ``grpc.RpcError`` into a ``ToolException`` the LangChain
    agent executor surfaces to the LLM. The status name + details are
    preserved so the model can react (retry, fix args, give up)."""
    code = exc.code() if hasattr(exc, "code") else grpc.StatusCode.UNKNOWN
    details = exc.details() if hasattr(exc, "details") else ""
    return ToolException(f"enclave RPC {code.name}: {details}")
