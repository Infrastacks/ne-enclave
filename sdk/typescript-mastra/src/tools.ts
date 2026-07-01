import { createTool } from "@mastra/core/tools";
import type {
  Client,
  ExecuteCommandResponse,
  ReadFileResponse,
  WriteFileResponse,
} from "@neuronedge/enclave";
import { z } from "zod";

import { mapServiceError } from "./errors.js";

/** Hard cap on any string handed to the LLM (context-window hygiene). */
export const LLM_OUTPUT_LIMIT = 8192;

/** Truncate `text` to `limit` chars, returning a note when cutting occurred. */
export function truncateForLlm(
  text: string,
  limit: number = LLM_OUTPUT_LIMIT,
): { text: string; note: string | null } {
  if (text.length <= limit) return { text, note: null };
  return {
    text: text.slice(0, limit),
    note: `[tool truncated at ${limit} chars, ${text.length} total]`,
  };
}

const messageOutputSchema = z.object({ message: z.string() });

/** `enclave_exec` input schema. Exported so tests can assert defaults via
 *  `.parse()` independent of Mastra's direct-execute invocation semantics. */
export const execInputSchema = z.object({
  command: z.string().describe("Path to the command binary, resolved against guest $PATH."),
  args: z
    .array(z.string())
    .default([])
    .describe("Arguments passed verbatim — no shell interpretation."),
  timeoutMs: z
    .number()
    .int()
    .nonnegative()
    .default(0)
    .describe("Per-call guest timeout in milliseconds. 0 disables."),
});

/** Append `[guest truncated]` and/or the tool-truncation note. */
function buildSuffix(guestTruncated: boolean, note: string | null): string {
  let suffix = "";
  if (guestTruncated) suffix += " [guest truncated]";
  if (note) suffix += ` ${note}`;
  return suffix;
}

/** `enclave_exec` — run a command inside the workspace jail and return its
 *  exit code + output. Non-zero exit is reported in the string, never thrown. */
export function execTool(client: Client, workspaceId: string) {
  return createTool({
    id: "enclave_exec",
    description:
      "Execute a command inside the confidential enclave workspace. Returns the exit code and captured stdout/stderr. Non-zero exit is reported, not raised.",
    inputSchema: execInputSchema,
    outputSchema: messageOutputSchema,
    execute: async ({ command, args, timeoutMs }) => {
      let resp: ExecuteCommandResponse;
      try {
        resp = await client.executeCommand({
          workspaceId,
          command,
          args: args ?? [],
          timeoutMs: timeoutMs ?? 0,
        });
      } catch (err) {
        mapServiceError(err); // always throws
      }
      const combined = `${resp.stdout}${resp.stderr}`;
      const { text, note } = truncateForLlm(combined);
      const message = `exit: ${resp.exitCode}\n${text}${buildSuffix(resp.truncated, note)}`;
      return { message };
    },
  });
}

/** `enclave_write_file` — write a UTF-8 file into the workspace jail. */
export function writeFileTool(client: Client, workspaceId: string) {
  return createTool({
    id: "enclave_write_file",
    description:
      "Write a file into the confidential enclave workspace. Overwrites if the path exists.",
    inputSchema: z.object({
      path: z
        .string()
        .describe(
          "Relative path inside the workspace jail. Absolute paths and '..' are rejected server-side.",
        ),
      content: z
        .string()
        .describe("File contents (written as UTF-8). Hard cap 10 MiB server-side."),
    }),
    outputSchema: messageOutputSchema,
    execute: async ({ path, content }) => {
      let resp: WriteFileResponse;
      try {
        resp = await client.writeFile({
          workspaceId,
          path,
          content: new TextEncoder().encode(content),
        });
      } catch (err) {
        mapServiceError(err);
      }
      return { message: `wrote ${path} (${resp.bytesWritten} bytes)` };
    },
  });
}

/** `enclave_read_file` — read a file from the workspace jail. Output is
 *  unconditionally size-capped for the LLM context window. */
export function readFileTool(client: Client, workspaceId: string) {
  return createTool({
    id: "enclave_read_file",
    description:
      "Read a file from the confidential enclave workspace. Output is UTF-8 decoded and size-capped.",
    inputSchema: z.object({
      path: z.string().describe("Relative path inside the workspace jail."),
      maxBytes: z
        .number()
        .int()
        .nonnegative()
        .default(0)
        .describe("Max bytes to read. 0 uses the server default (10 MiB)."),
    }),
    outputSchema: messageOutputSchema,
    execute: async ({ path, maxBytes }) => {
      let resp: ReadFileResponse;
      try {
        resp = await client.readFile({ workspaceId, path, maxBytes: maxBytes ?? 0 });
      } catch (err) {
        mapServiceError(err);
      }
      const decoded = new TextDecoder("utf-8", { fatal: false }).decode(resp.content);
      const { text, note } = truncateForLlm(decoded);
      return { message: `${text}${buildSuffix(resp.truncated, note)}` };
    },
  });
}

/** Build the three workspace tools bound to `workspaceId` + `client`, keyed by
 *  tool id (`enclave_exec` / `enclave_write_file` / `enclave_read_file`).
 *  Ready to spread into `new Agent({ tools: createEnclaveTools(...) })`. */
export function createEnclaveTools(client: Client, workspaceId: string) {
  return {
    enclave_exec: execTool(client, workspaceId),
    enclave_write_file: writeFileTool(client, workspaceId),
    enclave_read_file: readFileTool(client, workspaceId),
  };
}
