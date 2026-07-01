import grpc
import pytest
from langchain_core.tools import ToolException

from ne_langchain.errors import map_rpc_error

from conftest import FakeRpcError


@pytest.mark.parametrize(
    "code",
    [
        grpc.StatusCode.INVALID_ARGUMENT,
        grpc.StatusCode.NOT_FOUND,
        grpc.StatusCode.UNAVAILABLE,
        grpc.StatusCode.DEADLINE_EXCEEDED,
    ],
)
def test_map_rpc_error_translates_known_codes(code):
    exc = FakeRpcError(code, "boom details")
    out = map_rpc_error(exc)
    assert isinstance(out, ToolException)
    assert code.name in str(out)
    assert "boom details" in str(out)


def test_map_rpc_error_includes_details_when_empty():
    exc = FakeRpcError(grpc.StatusCode.UNAVAILABLE, "")
    out = map_rpc_error(exc)
    assert grpc.StatusCode.UNAVAILABLE.name in str(out)
