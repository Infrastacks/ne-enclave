"""LangChain adapter for the NeuronEdge Enclave Runtime API.

Thin Toolkit over a managed Firecracker microVM workspace. The base
``neuronedge-enclave`` SDK Client opens an insecure gRPC channel in this
phase, so this adapter is local/dev-pilot only until the SDK ships TLS +
API-key credentials.

Quickstart::

    from ne_langchain import EnclaveWorkspace

    with EnclaveWorkspace(target="127.0.0.1:50051") as ws:
        tools = ws.tools.get_tools()
"""

from ne_langchain.tools import (
    EnclaveExecTool,
    EnclaveReadFileTool,
    EnclaveToolkit,
    EnclaveWriteFileTool,
)
from ne_langchain.workspace import EnclaveWorkspace

__all__ = [  # noqa: RUF022  (intentional public-surface order, not alphabetical)
    "EnclaveWorkspace",
    "EnclaveToolkit",
    "EnclaveExecTool",
    "EnclaveWriteFileTool",
    "EnclaveReadFileTool",
]
__version__ = "0.1.0"
