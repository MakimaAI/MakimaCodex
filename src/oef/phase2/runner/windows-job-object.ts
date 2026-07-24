export interface WindowsJobController {
  terminate(exitCode?: number): void;
  close(): void;
}

const JOB_OBJECT_EXTENDED_LIMIT_INFORMATION = 9;
const JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000;
const PROCESS_TERMINATE = 0x0001;
const PROCESS_SET_QUOTA = 0x0100;
const PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;

export async function attachWindowsKillOnCloseJob(pid: number): Promise<WindowsJobController | null> {
  if (process.platform !== "win32") return null;
  if (!Number.isInteger(pid) || pid <= 0) throw new Error("WINDOWS_JOB_INVALID_PID");
  const { dlopen, FFIType, ptr } = await import("bun:ffi");
  const library = dlopen("kernel32.dll", {
    CreateJobObjectW: { args: [FFIType.ptr, FFIType.ptr], returns: FFIType.ptr },
    SetInformationJobObject: { args: [FFIType.ptr, FFIType.u32, FFIType.ptr, FFIType.u32], returns: FFIType.u32 },
    OpenProcess: { args: [FFIType.u32, FFIType.u32, FFIType.u32], returns: FFIType.ptr },
    AssignProcessToJobObject: { args: [FFIType.ptr, FFIType.ptr], returns: FFIType.u32 },
    TerminateJobObject: { args: [FFIType.ptr, FFIType.u32], returns: FFIType.u32 },
    CloseHandle: { args: [FFIType.ptr], returns: FFIType.u32 },
  });
  const { symbols } = library;
  const job = symbols.CreateJobObjectW(null, null) as Pointer | null;
  if (!job) { library.close(); throw new Error("WINDOWS_JOB_CREATE_FAILED"); }
  let processHandle: Pointer | null = null;
  try {
    const information = Buffer.alloc(process.arch === "ia32" ? 112 : 144);
    information.writeUInt32LE(JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, 16);
    if (!symbols.SetInformationJobObject(job, JOB_OBJECT_EXTENDED_LIMIT_INFORMATION, ptr(information), information.length)) {
      throw new Error("WINDOWS_JOB_LIMIT_CONFIGURATION_FAILED");
    }
    processHandle = symbols.OpenProcess(PROCESS_TERMINATE | PROCESS_SET_QUOTA | PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) as Pointer | null;
    if (!processHandle) throw new Error("WINDOWS_JOB_OPEN_PROCESS_FAILED");
    if (!symbols.AssignProcessToJobObject(job, processHandle)) throw new Error("WINDOWS_JOB_ASSIGN_FAILED");
  } catch (error) {
    if (processHandle) symbols.CloseHandle(processHandle);
    symbols.CloseHandle(job);
    library.close();
    throw error;
  }
  symbols.CloseHandle(processHandle);
  let closed = false;
  return {
    terminate(exitCode = 1) {
      if (!closed && !symbols.TerminateJobObject(job, exitCode)) throw new Error("WINDOWS_JOB_TERMINATE_FAILED");
    },
    close() {
      if (closed) return;
      closed = true;
      symbols.CloseHandle(job);
      library.close();
    },
  };
}
import type { Pointer } from "bun:ffi";
