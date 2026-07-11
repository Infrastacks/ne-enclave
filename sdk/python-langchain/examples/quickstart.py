"""Manual end-to-end smoke (not run in CI).

Requires a running `nee` daemon and the env vars NE_KERNEL_SHA256 /
NE_ROOTFS_SHA256 / NE_VSOCK_CID_BASE. Use the digests supplied to
`nee image import`, then run with the project venv active.
"""

from ne_langchain import EnclaveWorkspace


def main() -> None:
    with EnclaveWorkspace(target="127.0.0.1:50051") as ws:
        tools = ws.tools.get_tools()
        exec_tool = next(t for t in tools if t.name == "enclave_exec")
        write_tool = next(t for t in tools if t.name == "enclave_write_file")
        read_tool = next(t for t in tools if t.name == "enclave_read_file")

        print(write_tool._run(path="greeting.txt", content="hi from enclave\n"))
        print(exec_tool._run(command="cat", args=["greeting.txt"]))
        print(read_tool._run(path="greeting.txt"))


if __name__ == "__main__":
    main()
