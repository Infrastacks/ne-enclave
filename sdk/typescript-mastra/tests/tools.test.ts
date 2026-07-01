import { status as grpcStatus } from "@grpc/grpc-js";
import { describe, expect, it } from "vitest";

import {
  LLM_OUTPUT_LIMIT,
  createEnclaveTools,
  execInputSchema,
  execTool,
  readFileTool,
  truncateForLlm,
  writeFileTool,
} from "../src/tools.js";

import { FakeClient, toClient } from "./helpers/fake-client.js";

const encoder = new TextEncoder();

function fakeServiceError(code: number, details: string): Error {
  return Object.assign(new Error(details), { code, details });
}

async function runExec(client: FakeClient, input: Record<string, unknown>): Promise<string> {
  const tool = execTool(toClient(client), "ws-1");
  const out = await tool.execute(input as never, {} as never);
  return (out as { message: string }).message;
}

// ---- truncateForLlm --------------------------------------------------------

describe("truncateForLlm", () => {
  it("returns text unchanged when under the limit", () => {
    const { text, note } = truncateForLlm("hello", 8192);
    expect(text).toBe("hello");
    expect(note).toBeNull();
  });

  it("cuts and notes when over the limit", () => {
    const big = "x".repeat(9000);
    const { text, note } = truncateForLlm(big, 8192);
    expect(text.length).toBe(8192);
    expect(note).toContain("9000");
  });

  it("defaults the limit to LLM_OUTPUT_LIMIT", () => {
    expect(LLM_OUTPUT_LIMIT).toBe(8192);
    const big = "y".repeat(9000);
    const { text } = truncateForLlm(big);
    expect(text.length).toBe(8192);
  });
});

// ---- enclave_exec ----------------------------------------------------------

describe("enclave_exec", () => {
  it("returns exit code + combined stdout/stderr", async () => {
    const client = new FakeClient();
    client.execResponse = {
      exitCode: 0,
      stdout: "hello\n",
      stderr: "",
      elapsedMs: 4,
      truncated: false,
    };
    const message = await runExec(client, { command: "echo", args: ["hello"] });
    expect(message.startsWith("exit: 0\n")).toBe(true);
    expect(message).toContain("hello");
    const call = client.execCalls[0];
    expect(call?.workspaceId).toBe("ws-1");
    expect(call?.command).toBe("echo");
    expect(call?.args).toEqual(["hello"]);
  });

  it("reports non-zero exit in the string, never throws", async () => {
    const client = new FakeClient();
    client.execResponse = {
      exitCode: 2,
      stdout: "",
      stderr: "not found",
      elapsedMs: 1,
      truncated: false,
    };
    const message = await runExec(client, { command: "ls", args: ["/nope"] });
    expect(message).toContain("exit: 2");
    expect(message).toContain("not found");
  });

  it("applies the 8 KiB tool truncation to large output", async () => {
    const client = new FakeClient();
    client.execResponse = {
      exitCode: 0,
      stdout: "y".repeat(20_000),
      stderr: "",
      elapsedMs: 1,
      truncated: false,
    };
    const message = await runExec(client, { command: "cat", args: ["big"] });
    expect(message.length).toBeLessThan(20_000);
    expect(message).toContain("tool truncated");
  });

  it("marks guest-side truncation", async () => {
    const client = new FakeClient();
    client.execResponse = { exitCode: 0, stdout: "x", stderr: "", elapsedMs: 1, truncated: true };
    const message = await runExec(client, { command: "x" });
    expect(message).toContain("guest truncated");
  });

  it("inputSchema defaults args to [] and timeoutMs to 0", () => {
    expect(execInputSchema.parse({ command: "true" })).toEqual({
      command: "true",
      args: [],
      timeoutMs: 0,
    });
  });

  it("throws (so Mastra surfaces a tool error) on a mapped ServiceError", async () => {
    const client = new FakeClient();
    client.exec_error = fakeServiceError(grpcStatus.DEADLINE_EXCEEDED, "timed out");
    await expect(runExec(client, { command: "sleep", args: ["99"] })).rejects.toThrow(
      /DEADLINE_EXCEEDED/,
    );
  });
});

// ---- enclave_write_file ----------------------------------------------------

describe("enclave_write_file", () => {
  async function runWrite(client: FakeClient, input: Record<string, unknown>): Promise<string> {
    const tool = writeFileTool(toClient(client), "ws-1");
    const out = await tool.execute(input as never, {} as never);
    return (out as { message: string }).message;
  }

  it("encodes content UTF-8 and reports bytes written", async () => {
    const client = new FakeClient();
    client.writeResponse = { bytesWritten: 5, absolutePath: "/workspace/in/data.txt" };
    const message = await runWrite(client, { path: "in/data.txt", content: "hello" });
    const call = client.writeCalls[0];
    expect(call?.path).toBe("in/data.txt");
    expect(call?.workspaceId).toBe("ws-1");
    expect(call?.content).toEqual(encoder.encode("hello"));
    expect(message).toContain("wrote in/data.txt");
    expect(message).toContain("5 bytes");
  });

  it("throws on INVALID_ARGUMENT (path traversal)", async () => {
    const client = new FakeClient();
    client.write_error = fakeServiceError(3, "path traversal"); // 3 == INVALID_ARGUMENT
    await expect(runWrite(client, { path: "../escape", content: "x" })).rejects.toThrow(
      /INVALID_ARGUMENT/,
    );
  });
});

// ---- enclave_read_file -----------------------------------------------------

describe("enclave_read_file", () => {
  async function runRead(client: FakeClient, input: Record<string, unknown>): Promise<string> {
    const tool = readFileTool(toClient(client), "ws-1");
    const out = await tool.execute(input as never, {} as never);
    return (out as { message: string }).message;
  }

  it("decodes content as UTF-8 and returns it", async () => {
    const client = new FakeClient();
    client.readResponse = { content: encoder.encode("file body"), sizeBytes: 8, truncated: false };
    const message = await runRead(client, { path: "out/result.txt" });
    const call = client.readCalls[0];
    expect(call?.path).toBe("out/result.txt");
    expect(message.startsWith("file body")).toBe(true);
  });

  it("applies the 8 KiB tool truncation to large files", async () => {
    const client = new FakeClient();
    client.readResponse = {
      content: encoder.encode("z".repeat(20_000)),
      sizeBytes: 20_000,
      truncated: false,
    };
    const message = await runRead(client, { path: "big.bin" });
    expect(message.length).toBeLessThan(20_000);
    expect(message).toContain("tool truncated");
  });

  it("marks guest-side truncation", async () => {
    const client = new FakeClient();
    client.readResponse = {
      content: encoder.encode("partial"),
      sizeBytes: 9_999_999,
      truncated: true,
    };
    const message = await runRead(client, { path: "huge.log" });
    expect(message).toContain("guest truncated");
  });

  it("throws on NOT_FOUND", async () => {
    const client = new FakeClient();
    client.read_error = fakeServiceError(5, "no such file"); // 5 == NOT_FOUND
    await expect(runRead(client, { path: "missing" })).rejects.toThrow(/NOT_FOUND/);
  });
});

// ---- createEnclaveTools ----------------------------------------------------

describe("createEnclaveTools", () => {
  it("returns the three tools keyed by id, all bound to the same workspace", () => {
    const client = new FakeClient();
    const tools = createEnclaveTools(toClient(client), "ws-9");
    expect(Object.keys(tools).sort()).toEqual([
      "enclave_exec",
      "enclave_read_file",
      "enclave_write_file",
    ]);
    expect(tools.enclave_exec?.id).toBe("enclave_exec");
    expect(tools.enclave_write_file?.id).toBe("enclave_write_file");
    expect(tools.enclave_read_file?.id).toBe("enclave_read_file");
  });

  it("every tool targets the bound workspaceId", async () => {
    const client = new FakeClient();
    client.execResponse = { exitCode: 0, stdout: "ok", stderr: "", elapsedMs: 0, truncated: false };
    client.writeResponse = { bytesWritten: 2, absolutePath: "/workspace/x" };
    const tools = createEnclaveTools(toClient(client), "ws-9");
    await tools.enclave_exec!.execute({ command: "true" } as never, {} as never);
    await tools.enclave_write_file!.execute({ path: "x", content: "hi" } as never, {} as never);
    expect(client.execCalls[0]?.workspaceId).toBe("ws-9");
    expect(client.writeCalls[0]?.workspaceId).toBe("ws-9");
  });
});
