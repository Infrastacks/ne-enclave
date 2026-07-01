import {
  Server,
  ServerCredentials,
  type ServerUnaryCall,
  status as grpcStatus,
  type sendUnaryData,
} from "@grpc/grpc-js";

import {
  type CreateWorkspaceRequest,
  type CreateWorkspaceResponse,
  type DestroyWorkspaceRequest,
  type DestroyWorkspaceResponse,
  type ExecuteCommandRequest,
  type ExecuteCommandResponse,
  type ExposePortRequest,
  type ExposePortResponse,
  type ForkWorkspaceRequest,
  type ForkWorkspaceResponse,
  type GetAttestationEvidenceRequest,
  type GetAttestationEvidenceResponse,
  type GetPoolStatusRequest,
  type GetPoolStatusResponse,
  type ListEventsRequest,
  type ListEventsResponse,
  type PauseWorkspaceRequest,
  type PauseWorkspaceResponse,
  type PingRequest,
  type PingResponse,
  type ReadFileRequest,
  type ReadFileResponse,
  type RestoreWorkspaceRequest,
  type RestoreWorkspaceResponse,
  type ResumeWorkspaceRequest,
  type ResumeWorkspaceResponse,
  RuntimeService,
  type SnapshotWorkspaceRequest,
  type SnapshotWorkspaceResponse,
  type UnexposePortRequest,
  type UnexposePortResponse,
  type WriteFileRequest,
  type WriteFileResponse,
} from "../../src/generated/ne/runtime/v1/runtime.js";

type HandlerResult<Resp> = Resp | Error | Promise<Resp | Error>;

export type RuntimeHandlers = Partial<{
  ping: (req: PingRequest) => HandlerResult<PingResponse>;
  createWorkspace: (req: CreateWorkspaceRequest) => HandlerResult<CreateWorkspaceResponse>;
  destroyWorkspace: (req: DestroyWorkspaceRequest) => HandlerResult<DestroyWorkspaceResponse>;
  executeCommand: (req: ExecuteCommandRequest) => HandlerResult<ExecuteCommandResponse>;
  writeFile: (req: WriteFileRequest) => HandlerResult<WriteFileResponse>;
  readFile: (req: ReadFileRequest) => HandlerResult<ReadFileResponse>;
  listEvents: (req: ListEventsRequest) => HandlerResult<ListEventsResponse>;
  pauseWorkspace: (req: PauseWorkspaceRequest) => HandlerResult<PauseWorkspaceResponse>;
  resumeWorkspace: (req: ResumeWorkspaceRequest) => HandlerResult<ResumeWorkspaceResponse>;
  snapshotWorkspace: (req: SnapshotWorkspaceRequest) => HandlerResult<SnapshotWorkspaceResponse>;
  restoreWorkspace: (req: RestoreWorkspaceRequest) => HandlerResult<RestoreWorkspaceResponse>;
  forkWorkspace: (req: ForkWorkspaceRequest) => HandlerResult<ForkWorkspaceResponse>;
  getPoolStatus: (req: GetPoolStatusRequest) => HandlerResult<GetPoolStatusResponse>;
  exposePort: (req: ExposePortRequest) => HandlerResult<ExposePortResponse>;
  unexposePort: (req: UnexposePortRequest) => HandlerResult<UnexposePortResponse>;
  getAttestationEvidence: (
    req: GetAttestationEvidenceRequest,
  ) => HandlerResult<GetAttestationEvidenceResponse>;
}>;

export type FakeServerHandle = {
  target: string;
  stop: () => Promise<void>;
};

function wrapUnary<Req, Resp>(
  name: string,
  handler: ((req: Req) => HandlerResult<Resp>) | undefined,
): (call: ServerUnaryCall<Req, Resp>, callback: sendUnaryData<Resp>) => void {
  return (call, callback) => {
    if (handler === undefined) {
      callback({
        code: grpcStatus.UNIMPLEMENTED,
        details: `no handler for ${name}`,
        name: "Error",
        message: `no handler for ${name}`,
        metadata: call.metadata,
      });
      return;
    }
    Promise.resolve()
      .then(() => handler(call.request))
      .then((value) => {
        if (value instanceof Error) {
          const err = value as Error & { code?: number; details?: string };
          callback({
            code: typeof err.code === "number" ? err.code : grpcStatus.UNKNOWN,
            details: typeof err.details === "string" ? err.details : err.message,
            name: err.name,
            message: err.message,
            metadata: call.metadata,
          });
          return;
        }
        callback(null, value);
      })
      .catch((err: unknown) => {
        const e = err as { code?: number; details?: string; message?: string };
        callback({
          code: typeof e.code === "number" ? e.code : grpcStatus.INTERNAL,
          details: typeof e.details === "string" ? e.details : (e.message ?? "handler threw"),
          name: "Error",
          message: e.message ?? "handler threw",
          metadata: call.metadata,
        });
      });
  };
}

export async function startFakeServer(handlers: RuntimeHandlers): Promise<FakeServerHandle> {
  const server = new Server();
  server.addService(RuntimeService, {
    ping: wrapUnary("Ping", handlers.ping),
    createWorkspace: wrapUnary("CreateWorkspace", handlers.createWorkspace),
    destroyWorkspace: wrapUnary("DestroyWorkspace", handlers.destroyWorkspace),
    executeCommand: wrapUnary("ExecuteCommand", handlers.executeCommand),
    writeFile: wrapUnary("WriteFile", handlers.writeFile),
    readFile: wrapUnary("ReadFile", handlers.readFile),
    listEvents: wrapUnary("ListEvents", handlers.listEvents),
    pauseWorkspace: wrapUnary("PauseWorkspace", handlers.pauseWorkspace),
    resumeWorkspace: wrapUnary("ResumeWorkspace", handlers.resumeWorkspace),
    snapshotWorkspace: wrapUnary("SnapshotWorkspace", handlers.snapshotWorkspace),
    restoreWorkspace: wrapUnary("RestoreWorkspace", handlers.restoreWorkspace),
    forkWorkspace: wrapUnary("ForkWorkspace", handlers.forkWorkspace),
    getPoolStatus: wrapUnary("GetPoolStatus", handlers.getPoolStatus),
    exposePort: wrapUnary("ExposePort", handlers.exposePort),
    unexposePort: wrapUnary("UnexposePort", handlers.unexposePort),
    getAttestationEvidence: wrapUnary("GetAttestationEvidence", handlers.getAttestationEvidence),
  });

  const port: number = await new Promise((resolve, reject) => {
    server.bindAsync("127.0.0.1:0", ServerCredentials.createInsecure(), (err, boundPort) => {
      if (err) {
        reject(err);
        return;
      }
      resolve(boundPort);
    });
  });

  const target = `127.0.0.1:${port}`;

  const stop = async (): Promise<void> => {
    await new Promise<void>((resolve) => {
      server.tryShutdown((err) => {
        if (err) {
          server.forceShutdown();
        }
        resolve();
      });
    });
  };

  return { target, stop };
}

/** Build a `ServiceError`-compatible Error with a gRPC status code. Tests
 *  use this to make a handler reject with a typed status. */
export function statusError(code: number, message: string): Error {
  return Object.assign(new Error(message), { code, details: message });
}
