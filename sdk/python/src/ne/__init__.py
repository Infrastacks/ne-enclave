"""NeuronEdge Enclave Python SDK.

Thin client wrapper over the NeuronEdge Enclave Runtime API (gRPC). Phase 1 P0
surface: Ping, CreateWorkspace, ExecuteCommand, DestroyWorkspace.
"""

from ne.client import Client

__all__ = ["Client"]
__version__ = "0.1.1"
