/**
 * Manual end-to-end smoke (not run in CI).
 *
 * Requires a running `nee` daemon and the env vars NE_KERNEL_SHA256 /
 * NE_ROOTFS_SHA256 / NE_VSOCK_CID_BASE. Use the digests supplied to
 * `nee image import`, then run with:
 *   npx tsx sdk/typescript-mastra/examples/quickstart.ts
 */
import { withWorkspace } from "../src/index.js";

async function main(): Promise<void> {
  await withWorkspace({ target: "127.0.0.1:50051" }, async (ws) => {
    const write = ws.tools.enclave_write_file;
    const exec = ws.tools.enclave_exec;
    const read = ws.tools.enclave_read_file;
    if (!write || !exec || !read) throw new Error("missing tool");

    console.log(
      (
        await write.execute(
          { path: "greeting.txt", content: "hi from enclave\n" } as never,
          {} as never,
        )
      ).message,
    );
    console.log(
      (await exec.execute({ command: "cat", args: ["greeting.txt"] } as never, {} as never))
        .message,
    );
    console.log((await read.execute({ path: "greeting.txt" } as never, {} as never)).message);
  });
}

void main();
