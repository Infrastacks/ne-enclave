import type {
  Client,
  CreateWorkspaceResponse,
  DestroyWorkspaceResponse,
  ExecuteCommandResponse,
  ReadFileResponse,
  WriteFileResponse,
} from "@neuronedge/enclave";

/** Duck-typed stand-in for the base SDK `Client`. Records every call and
 *  returns canned responses. Set the `*_error` field on a method to make its
 *  next call reject with that value (use a ServiceError-shaped Error for the
 *  mapped codes — see `fakeServiceError` in `tests/helpers/errors.ts`). */
export class FakeClient {
  readonly createCalls: Array<Record<string, unknown>> = [];
  readonly destroyCalls: Array<Record<string, unknown>> = [];
  readonly execCalls: Array<Record<string, unknown>> = [];
  readonly writeCalls: Array<Record<string, unknown>> = [];
  readonly readCalls: Array<Record<string, unknown>> = [];
  closed = false;

  execResponse: Partial<ExecuteCommandResponse> = {
    exitCode: 0,
    stdout: "",
    stderr: "",
    elapsedMs: 0,
    truncated: false,
  };
  writeResponse: Partial<WriteFileResponse> = {};
  readResponse: Partial<ReadFileResponse> = {
    content: new Uint8Array(),
    sizeBytes: 0,
    truncated: false,
  };
  createResponse: Partial<CreateWorkspaceResponse> = {};
  destroyResponse: Partial<DestroyWorkspaceResponse> = {};

  exec_error: unknown = null;
  write_error: unknown = null;
  read_error: unknown = null;
  create_error: unknown = null;
  destroy_error: unknown = null;

  async createWorkspace(options: Record<string, unknown>): Promise<CreateWorkspaceResponse> {
    this.createCalls.push(options);
    if (this.create_error) throw this.create_error;
    return {
      workspaceId: String(options.workspaceId ?? ""),
      firecrackerPid: 123,
      vsockHostSocket: "",
      jailerChroot: "",
      ...this.createResponse,
    };
  }

  async executeCommand(options: Record<string, unknown>): Promise<ExecuteCommandResponse> {
    this.execCalls.push(options);
    if (this.exec_error) throw this.exec_error;
    return {
      workspaceId: String(options.workspaceId ?? ""),
      stdout: "",
      stderr: "",
      exitCode: 0,
      elapsedMs: 0,
      truncated: false,
      ...this.execResponse,
    };
  }

  async writeFile(options: Record<string, unknown>): Promise<WriteFileResponse> {
    this.writeCalls.push(options);
    if (this.write_error) throw this.write_error;
    return {
      workspaceId: String(options.workspaceId ?? ""),
      bytesWritten: 0,
      absolutePath: "",
      ...this.writeResponse,
    };
  }

  async readFile(options: Record<string, unknown>): Promise<ReadFileResponse> {
    this.readCalls.push(options);
    if (this.read_error) throw this.read_error;
    return {
      workspaceId: String(options.workspaceId ?? ""),
      content: new Uint8Array(),
      sizeBytes: 0,
      truncated: false,
      ...this.readResponse,
    };
  }

  async destroyWorkspace(options: Record<string, unknown>): Promise<DestroyWorkspaceResponse> {
    this.destroyCalls.push(options);
    if (this.destroy_error) throw this.destroy_error;
    return { workspaceId: String(options.workspaceId ?? ""), ...this.destroyResponse };
  }

  close(): void {
    this.closed = true;
  }

  /** Reset recorders + canned responses between tests. */
  reset(): void {
    this.createCalls.length = 0;
    this.destroyCalls.length = 0;
    this.execCalls.length = 0;
    this.writeCalls.length = 0;
    this.readCalls.length = 0;
    this.closed = false;
    this.exec_error = null;
    this.write_error = null;
    this.read_error = null;
    this.create_error = null;
    this.destroy_error = null;
  }
}

/** Cast the duck-typed fake to the real Client type for injection into
 *  tool/workspace code under test. Single, localized cast site. */
export const toClient = (fake: FakeClient): Client => fake as unknown as Client;
