// Copyright 2018-2026 the Deno authors. MIT license.
// Copyright Joyent, Inc. and Node.js contributors. All rights reserved. MIT license.

import { core, internals, primordials } from "ext:core/mod.js";
// Installs `internals.__inspectorNetwork` so ext/fetch (and other
// extensions) can emit Network.* CDP events without requiring user code
// to import `node:inspector`. Side-effect import; no exports.
core.loadExtScript("ext:deno_node/inspector_network_bridge.js");
const { initializeDebugEnv } = core.loadExtScript(
  "ext:deno_node/internal/util/debuglog.ts",
);
const { format } = core.loadExtScript(
  "ext:deno_node/internal/util/inspect.mjs",
);
import {
  op_current_thread_cpu_usage,
  op_fs_umask,
  op_getegid,
  op_geteuid,
  op_getgroups,
  op_inspector_close,
  op_inspector_enabled,
  op_inspector_port,
  op_node_load_env_file,
  op_node_process_constrained_memory,
  op_node_process_kill,
  op_node_process_resource_usage,
  op_node_process_set_title,
  op_node_process_setegid,
  op_node_process_seteuid,
  op_node_process_setgid,
  op_node_process_setuid,
  op_oden_guard_deny_only_surface,
  op_process_abort,
  op_stream_base_register_state,
} from "ext:core/ops";

const { EventEmitter } = core.loadExtScript("ext:deno_node/_events.mjs");
// Lazy: a static `import ... from "node:module"` makes node:process eagerly
// pull node:module's entire eager closure (~95 loadExtScript) at process
// bootstrap. When node:process is itself cold-bootstrapping (node-defer path),
// those closure modules eval while node:process is mid-eval and capture its
// not-yet-ready exports -> circular-require TDZs. `Module`/`getBuiltinModule`
// are only used at call time, so load node:module lazily on first use.
const lazyNodeModule = core.createLazyLoader("node:module");
const { report } = core.loadExtScript(
  "ext:deno_node/internal/process/report.ts",
);
const { onWarning } = core.loadExtScript(
  "ext:deno_node/internal/process/warning.ts",
);
const {
  parseFileMode,
  validateBoolean,
  validateFunction,
  validateNumber,
  validateObject,
  validateString,
  validateUint32,
} = core.loadExtScript("ext:deno_node/internal/validators.mjs");
const {
  denoErrorToNodeError,
  ERR_INVALID_ARG_TYPE,
  ERR_INVALID_ARG_VALUE_RANGE,
  ERR_OUT_OF_RANGE,
  ERR_UNCAUGHT_EXCEPTION_CAPTURE_ALREADY_SET,
  ERR_UNKNOWN_SIGNAL,
  ERR_WORKER_UNSUPPORTED_OPERATION,
  errnoException,
  NodeTypeError,
} = core.loadExtScript("ext:deno_node/internal/errors.ts");
const { getOptionValue } = core.loadExtScript(
  "ext:deno_node/internal/options.ts",
);
const { default: assert } = core.loadExtScript("ext:deno_node/assert.ts");
import { join } from "node:path";
const { pathFromURL } = core.loadExtScript("ext:deno_web/00_infra.js");
const {
  arch: arch_,
  chdir,
  cwd,
  env,
  nextTick: _nextTick,
  version,
  versions,
} = core.loadExtScript("ext:deno_node/_process/process.ts");
const { _exiting } = core.loadExtScript("ext:deno_node/_process/exiting.ts");
export { _nextTick as nextTick, chdir, cwd, env, version, versions };
// Lazily load the stream/tty machinery. Static imports here would pin
// `node:stream`, `node:net` and `node:tty` (TTYWriteStream extends net.Socket)
// into the snapshot heap for EVERY program. Instead, `process.stdout` /
// `stderr` / `stdin` are built on first access (see the getters installed in
// `__bootstrapNodeProcess`), so a program that never touches stdio never pulls
// the stream/net/tty closure into the heap - the single biggest chunk of node
// snapshot-deserialization time.
const lazyStreamsMod = core.createLazyLoader(
  "ext:deno_node/_process/streams.mjs",
);
const lazyTtyMod = core.createLazyLoader("ext:deno_node/internal/tty.js");
const { enableNextTick } = core.loadExtScript("ext:deno_node/_next_tick.ts");
const { isAndroid, isWindows } = core.loadExtScript(
  "ext:deno_node/_util/os.ts",
);
const io = core.loadExtScript("ext:deno_io/12_io.js");
const denoOs = core.loadExtScript("ext:deno_os/30_os.js");

export let argv0 = "";

export let arch = "";

export let platform = isWindows ? "win32" : ""; // initialized during bootstrap

export let pid = 0;
export let ppid = 0;

let stdin, stdout, stderr;

export { stderr, stdin, stdout };

import { getBinding } from "ext:deno_node/internal_binding/mod.ts";
const constants = core.loadExtScript(
  "ext:deno_node/internal_binding/constants.ts",
);
const uv = core.loadExtScript("ext:deno_node/internal_binding/uv.ts");
import type { BindingName } from "ext:deno_node/internal_binding/mod.ts";
const { buildAllowedFlags } = core.loadExtScript(
  "ext:deno_node/internal/process/per_thread.mjs",
);
const {
  getActiveHandles,
  getActiveRequests,
  getActiveResourceNames,
} = core.loadExtScript("ext:deno_node/internal/process/active_resources.ts");
const {
  getActiveResourcesInfo: getTimerActiveResourcesInfo,
} = core.loadExtScript("ext:deno_node/internal/timers.mjs");
import type fsUtils from "ext:deno_node/internal/fs/utils.mjs";
import type * as utilModule from "ext:deno_node/util.ts";

let fsUtilsModule: typeof fsUtils;
const lazyLoadFsUtils = core.createLazyLoader<typeof fsUtils>(
  "ext:deno_node/internal/fs/utils.mjs",
);
// Lazy-loaded to avoid a static circular import:
//   process.ts -> util.ts -> internal/util/parse_args/parse_args.js
//     -> "node:process" -> process.ts
const lazyLoadUtil = core.createLazyLoader<typeof utilModule>(
  "node:util",
);

const {
  ArrayIsArray,
  ArrayPrototypeConcat,
  ArrayPrototypeFind,
  ArrayPrototypePush,
  BigInt,
  Error,
  ErrorCaptureStackTrace,
  ErrorPrototype,
  Float64Array,
  FunctionPrototypeBind,
  FunctionPrototypeCall,
  MathFloor,
  Number,
  NumberIsFinite,
  NumberIsInteger,
  NumberMAX_SAFE_INTEGER,
  NumberPrototypeToFixed,
  ObjectCreate,
  ObjectDefineProperty,
  ObjectEntries,
  ObjectFreeze,
  ObjectKeys,
  ObjectPrototypeIsPrototypeOf,
  Proxy,
  RangeError,
  ReflectApply,
  ReflectConstruct,
  ReflectDeleteProperty,
  ReflectDefineProperty,
  ReflectGet,
  ReflectGetOwnPropertyDescriptor,
  ReflectGetPrototypeOf,
  ReflectHas,
  ReflectOwnKeys,
  ReflectSet,
  ReflectSetPrototypeOf,
  SafeArrayIterator,
  SafeMap,
  SafeWeakMap,
  SafeWeakSet,
  String,
  StringPrototypeStartsWith,
  Symbol,
  SymbolToStringTag,
  TypeError,
} = primordials;

export const argv: string[] = ["", ""];

// In Node, `process.exitCode` is initially `undefined` until set.
// And retains any value as long as it's nullish or number-ish.
let ProcessExitCode: undefined | null | string | number;

export const execArgv: string[] = [];

/** https://nodejs.org/api/process.html#process_process_exit_code */
export const exit = (code?: number | string) => {
  if (code !== undefined) {
    process.exitCode = code;
  }

  ProcessExitCode = denoOs.getExitCode();
  if (!process._exiting) {
    process._exiting = true;
    // FIXME(bartlomieju): this is wrong, we won't be using syscall to exit
    // and thus the `unload` event will not be emitted to properly trigger "emit"
    // event on `process`.
    process.emit("exit", ProcessExitCode);
  }

  // Any valid thing `process.exitCode` set is already held in Deno.exitCode.
  // At this point, we don't have to pass around Node's raw/string exit value.
  process.reallyExit(ProcessExitCode);

  // In a worker, reallyExit() returns because Deno.exit() calls workerClose()
  // instead of std::process::exit(). workerClose() already called V8's
  // terminate_execution(). Unlike Node.js where reallyExit is a C++ binding
  // and a single nop() call suffices to trigger the stack guard check, in Deno
  // reallyExit goes through JS frames (Deno.exit -> exitHandler -> workerClose
  // -> op), so we need a loop back-edge for V8 to reliably detect the pending
  // termination and throw an uncatchable TerminationException.
  // On the main thread reallyExit() normally never returns, but users can
  // override it (test-process-really-exit.js), so only spin in workers.
  // ref: https://github.com/nodejs/node/blob/9cc7fcc26d/lib/internal/process/per_thread.js#L243-L251
  if (internals.__isWorkerThread) {
    // deno-lint-ignore no-empty
    for (;;) {}
  }
};

/** https://nodejs.org/api/process.html#processumaskmask */
export function umask(mask?: number | string): number {
  if (mask !== undefined) {
    if (internals.__isWorkerThread) {
      throw new ERR_WORKER_UNSUPPORTED_OPERATION("Setting process.umask()");
    }
    mask = parseFileMode(mask, "mask");
    return op_fs_umask(mask & 0o777);
  }
  // Note: reading the umask without setting has an inherent race condition
  // (two syscalls: set to 0 then restore). Node.js has the same issue and
  // has deprecated process.umask() with no arguments.
  return op_fs_umask(null);
}

export const abort = () => {
  op_process_abort();
};

function addReadOnlyProcessAlias(
  name: string,
  option: string,
  enumerable = true,
) {
  const value = getOptionValue(option);

  if (value) {
    ObjectDefineProperty(process, name, {
      __proto__: null,
      writable: false,
      configurable: true,
      enumerable,
      value,
    });
  }
}

interface CpuUsage {
  user: number;
  system: number;
}

// Ensure that a previously passed in value is valid. Currently, the native
// implementation always returns numbers <= Number.MAX_SAFE_INTEGER.
function previousCpuUsageValueIsValid(num) {
  return typeof num === "number" && num >= 0 && num <= NumberMAX_SAFE_INTEGER;
}

export function cpuUsage(previousValue?: CpuUsage): CpuUsage {
  const cpuValues = Deno.cpuUsage(previousValue);

  if (previousValue) {
    if (!previousCpuUsageValueIsValid(previousValue.user)) {
      validateObject(previousValue, "prevValue");

      validateNumber(previousValue.user, "prevValue.user");
      throw new ERR_INVALID_ARG_VALUE_RANGE(
        "prevValue.user",
        previousValue.user,
      );
    }

    if (!previousCpuUsageValueIsValid(previousValue.system)) {
      validateNumber(previousValue.system, "prevValue.system");
      throw new ERR_INVALID_ARG_VALUE_RANGE(
        "prevValue.system",
        previousValue.system,
      );
    }

    return {
      user: cpuValues.user - previousValue.user,
      system: cpuValues.system - previousValue.system,
    };
  }

  return cpuValues;
}

const threadCpuValues = new Float64Array(2);

export function threadCpuUsage(
  previousValue?: CpuUsage,
): CpuUsage {
  if (previousValue) {
    if (!previousCpuUsageValueIsValid(previousValue.user)) {
      validateObject(previousValue, "prevValue");

      validateNumber(previousValue.user, "prevValue.user");
      throw new ERR_INVALID_ARG_VALUE_RANGE(
        "prevValue.user",
        previousValue.user,
      );
    }

    if (!previousCpuUsageValueIsValid(previousValue.system)) {
      validateNumber(previousValue.system, "prevValue.system");
      throw new ERR_INVALID_ARG_VALUE_RANGE(
        "prevValue.system",
        previousValue.system,
      );
    }
  }

  op_current_thread_cpu_usage(threadCpuValues);

  if (previousValue) {
    return {
      user: threadCpuValues[0] - previousValue.user,
      system: threadCpuValues[1] - previousValue.system,
    };
  }

  return {
    user: threadCpuValues[0],
    system: threadCpuValues[1],
  };
}

function createWarningObject(
  warning: string,
  type: string,
  code?: string,
  // deno-lint-ignore ban-types
  ctor?: Function,
  detail?: string,
): Error {
  assert(typeof warning === "string");

  // deno-lint-ignore no-explicit-any
  const warningErr: any = new Error(warning);
  warningErr.name = String(type || "Warning");

  if (code !== undefined) {
    warningErr.code = code;
  }
  if (detail !== undefined) {
    warningErr.detail = detail;
  }

  ErrorCaptureStackTrace(warningErr, ctor || process.emitWarning);

  return warningErr;
}

function doEmitWarning(warning: Error) {
  process.emit("warning", warning);
}

/** https://nodejs.org/api/process.html#process_process_emitwarning_warning_options */
export function emitWarning(
  warning: string | Error,
  type:
    // deno-lint-ignore ban-types
    | { type: string; detail: string; code: string; ctor: Function }
    | string
    | null,
  code?: string,
  // deno-lint-ignore ban-types
  ctor?: Function,
) {
  let detail;

  if (type !== null && typeof type === "object" && !ArrayIsArray(type)) {
    ctor = type.ctor;
    code = type.code;

    if (typeof type.detail === "string") {
      detail = type.detail;
    }

    type = type.type || "Warning";
  } else if (typeof type === "function") {
    ctor = type;
    code = undefined;
    type = "Warning";
  }

  if (type !== undefined) {
    validateString(type, "type");
  }

  if (typeof code === "function") {
    ctor = code;
    code = undefined;
  } else if (code !== undefined) {
    validateString(code, "code");
  }

  if (typeof warning === "string") {
    warning = createWarningObject(warning, type as string, code, ctor, detail);
  } else if (!ObjectPrototypeIsPrototypeOf(ErrorPrototype, warning)) {
    throw new ERR_INVALID_ARG_TYPE("warning", ["Error", "string"], warning);
  }

  if (warning.name === "DeprecationWarning") {
    // deno-lint-ignore no-explicit-any
    if ((process as any).noDeprecation) {
      return;
    }

    // deno-lint-ignore no-explicit-any
    if ((process as any).throwDeprecation) {
      // Delay throwing the error to guarantee that all former warnings were
      // properly logged.
      return process.nextTick(() => {
        throw warning;
      });
    }
  }

  process.nextTick(doEmitWarning, warning);
}

export function hrtime(time?: [number, number]): [number, number] {
  const milli = performance.now();
  const sec = MathFloor(milli / 1000);
  const nano = MathFloor(milli * 1_000_000 - sec * 1_000_000_000);
  if (!time) {
    return [sec, nano];
  }
  if (!ArrayIsArray(time)) {
    throw new ERR_INVALID_ARG_TYPE("time", "Array", time);
  }
  if (time.length !== 2) {
    throw new ERR_OUT_OF_RANGE("time", 2, time.length);
  }
  const prevSec = time[0];
  const prevNano = time[1];
  let diffSec = sec - prevSec;
  let diffNano = nano - prevNano;
  if (diffNano < 0) {
    diffSec -= 1;
    diffNano += 1_000_000_000;
  }
  return [diffSec, diffNano];
}

hrtime.bigint = function (): bigint {
  const t = hrtime();
  const sec = t[0];
  const nano = t[1];
  return BigInt(sec) * 1_000_000_000n + BigInt(nano);
};

export function memoryUsage(): {
  rss: number;
  heapTotal: number;
  heapUsed: number;
  external: number;
  arrayBuffers: number;
} {
  return {
    ...Deno.memoryUsage(),
    arrayBuffers: 0,
  };
}

memoryUsage.rss = function (): number {
  return memoryUsage().rss;
};

// stdin/stdout/stderr are reported as "TTYWrap" when connected to a terminal,
// matching Node, where the TTY handles keep the event loop alive. When they're
// redirected to a pipe or file Node uses synchronous I/O without a libuv
// handle, so nothing is reported.
function getStdioActiveResources(): string[] {
  const result: string[] = [];
  const streams = [io.stdin, io.stdout, io.stderr];
  for (const stream of new SafeArrayIterator(streams)) {
    try {
      if (stream && stream.isTerminal()) {
        ArrayPrototypePush(result, "TTYWrap");
      }
    } catch {
      // Stream may be closed or unavailable (e.g. in a worker); ignore.
    }
  }
  return result;
}

export function getActiveResourcesInfo(): string[] {
  const result: string[] = [];
  for (const name of new SafeArrayIterator(getStdioActiveResources())) {
    ArrayPrototypePush(result, name);
  }
  for (const name of new SafeArrayIterator(getActiveResourceNames())) {
    ArrayPrototypePush(result, name);
  }
  for (const name of new SafeArrayIterator(getTimerActiveResourcesInfo())) {
    ArrayPrototypePush(result, name);
  }
  return result;
}

export function availableMemory(): number {
  return Deno.systemMemoryInfo().available;
}

export function constrainedMemory(): number {
  return op_node_process_constrained_memory();
}

interface ResourceUsage {
  userCPUTime: number;
  systemCPUTime: number;
  maxRSS: number;
  sharedMemorySize: number;
  unsharedDataSize: number;
  unsharedStackSize: number;
  minorPageFault: number;
  majorPageFault: number;
  swappedOut: number;
  fsRead: number;
  fsWrite: number;
  ipcSent: number;
  ipcReceived: number;
  signalsCount: number;
  voluntaryContextSwitches: number;
  involuntaryContextSwitches: number;
}

const resourceUsageValues = new Float64Array(16);

export function resourceUsage(): ResourceUsage {
  op_node_process_resource_usage(resourceUsageValues);
  return {
    userCPUTime: resourceUsageValues[0],
    systemCPUTime: resourceUsageValues[1],
    maxRSS: resourceUsageValues[2],
    sharedMemorySize: resourceUsageValues[3],
    unsharedDataSize: resourceUsageValues[4],
    unsharedStackSize: resourceUsageValues[5],
    minorPageFault: resourceUsageValues[6],
    majorPageFault: resourceUsageValues[7],
    swappedOut: resourceUsageValues[8],
    fsRead: resourceUsageValues[9],
    fsWrite: resourceUsageValues[10],
    ipcSent: resourceUsageValues[11],
    ipcReceived: resourceUsageValues[12],
    signalsCount: resourceUsageValues[13],
    voluntaryContextSwitches: resourceUsageValues[14],
    involuntaryContextSwitches: resourceUsageValues[15],
  };
}

// Returns a negative error code than can be recognized by errnoException
function _kill(pid: number, sig: number): number {
  const maybeMapErrno = (res: number) =>
    // the windows implementation is ported from libuv, so the error numbers already match libuv and don't need mapping
    res === 0 ? res : isWindows ? res : uv.mapSysErrnoToUvErrno(res);
  // signal 0 does not exist in constants.os.signals, thats why it have to be handled explicitly
  if (sig === 0) {
    return maybeMapErrno(op_node_process_kill(pid, 0));
  }
  const maybeSignal = ArrayPrototypeFind(
    ObjectEntries(constants.os.signals),
    (entry) => entry[1] === sig,
  );

  if (!maybeSignal) {
    return uv.codeMap.get("EINVAL");
  }
  return maybeMapErrno(op_node_process_kill(pid, sig));
}

export function dlopen(module, filename, _flags) {
  // NOTE(bartlomieju): _flags is currently ignored, but we don't warn for it
  // as it makes DX bad, even though it might not be needed:
  // https://github.com/denoland/deno/issues/20075
  lazyNodeModule().default._extensions[".node"](module, filename);
  return module;
}

export function kill(pid: number, sig: string | number = "SIGTERM") {
  if (pid != (pid | 0)) {
    throw new ERR_INVALID_ARG_TYPE("pid", "number", pid);
  }

  let err;
  if (typeof sig === "number") {
    err = process._kill(pid, sig);
  } else {
    if (ReflectHas(constants.os.signals, sig)) {
      // @ts-ignore Index previously checked
      err = process._kill(pid, constants.os.signals[sig]);
    } else {
      throw new ERR_UNKNOWN_SIGNAL(sig);
    }
  }

  if (err) {
    throw errnoException(err, "kill");
  }

  return true;
}

let getgid, getuid, getegid, geteuid, setegid, seteuid, setgid, setuid;

function wrapIdSetter(
  syscall: string,
  fn: (id: number | string) => void,
): (id: number | string) => void {
  return function (id: number | string) {
    if (typeof id === "number") {
      validateUint32(id, "id");
      id >>>= 0;
    } else if (typeof id !== "string") {
      throw new ERR_INVALID_ARG_TYPE("id", ["number", "string"], id);
    }

    try {
      fn(id);
    } catch (err) {
      throw denoErrorToNodeError(err as Error, { syscall });
    }
  };
}

if (!isWindows) {
  getgid = () => Deno.gid();
  getuid = () => Deno.uid();
  getegid = () => op_getegid();
  geteuid = () => op_geteuid();

  if (!isAndroid) {
    setegid = wrapIdSetter("setegid", op_node_process_setegid);
    seteuid = wrapIdSetter("seteuid", op_node_process_seteuid);
    setgid = wrapIdSetter("setgid", op_node_process_setgid);
    setuid = wrapIdSetter("setuid", op_node_process_setuid);
  }
}

export {
  getegid,
  geteuid,
  getgid,
  getuid,
  report,
  setegid,
  seteuid,
  setgid,
  setuid,
};

const ALLOWED_FLAGS = buildAllowedFlags();

// Tracks error values for which the synchronous Module._load entry-module
// path in 01_require.js has already invoked process._fatalException. When
// the same error is later re-thrown and surfaces as a module-evaluation
// rejection (via the ESM wrapper that loads the main CJS module), the
// unhandled-rejection fallback below uses this set to skip emitting
// 'uncaughtExceptionMonitor' / 'uncaughtException' a second time.
// deno-lint-ignore no-explicit-any
const _dispatchedFatalErrors = new SafeWeakSet<any>();
internals._dispatchedFatalErrors = _dispatchedFatalErrors;

// deno-lint-ignore no-explicit-any
function uncaughtExceptionHandler(err: any, origin: string): boolean {
  // The origin parameter can be 'unhandledRejection' or 'uncaughtException'
  // depending on how the uncaught exception was created. In Node.js,
  // exceptions thrown from the top level of a CommonJS module are reported as
  // 'uncaughtException', while exceptions thrown from the top level of an ESM
  // module are reported as 'unhandledRejection'. Deno does not have a true
  // CommonJS implementation; sync throws in the entry CJS module are
  // dispatched up-front via Module._load (see ext/node/polyfills/01_require.js)
  // so this path only fires for real unhandled promise rejections.
  return fatalExceptionHandler(err, origin === "unhandledRejection");
}

export let execPath: string = "";

// The process class needs to be an ES5 class because it can be instantiated
// in Node without the `new` keyword. It's not a true class in Node. Popular
// test runners like Jest rely on this.
//
// Use a named function expression so the syntactic name ("process") is
// captured at parse time. V8 uses that name for runtime class strings
// in error messages like "Cannot delete property 'exitCode' of
// #<process>", which `Object.defineProperty(F, "name", ...)` does not
// affect. Match Node's FunctionTemplate-based binding (see
// CreateProcessObject in src/node_process_object.cc).
// deno-lint-ignore no-explicit-any
const Process = function process(this: any) {
  if (!ObjectPrototypeIsPrototypeOf(Process.prototype, this)) {
    // deno-lint-ignore no-explicit-any
    return new (Process as any)();
  }

  FunctionPrototypeCall(EventEmitter, this);
};
Process.prototype = ObjectCreate(EventEmitter.prototype);
// Point the prototype's `constructor` at the real class with the same
// descriptor Node uses (writable, non-enumerable, configurable) so
// `process instanceof process.constructor` is true.
ObjectDefineProperty(Process.prototype, "constructor", {
  __proto__: null,
  value: Process,
  writable: true,
  enumerable: false,
  configurable: true,
});

// Maps original user listeners to wrapped versions that pass the signal name.
// Node.js calls signal listeners with the signal name as the first argument,
// but Deno.addSignalListener calls them with no arguments.
type SignalListener = (...args: string[]) => void;
const _signalListenerWrappers = new SafeWeakMap<
  SignalListener,
  Map<string, SignalListener>
>();

function _wrapSignalListener(
  event: string,
  listener: SignalListener,
): SignalListener {
  let wrappersByEvent = _signalListenerWrappers.get(listener);
  if (!wrappersByEvent) {
    wrappersByEvent = new SafeMap();
    _signalListenerWrappers.set(listener, wrappersByEvent);
  }
  let wrapper = wrappersByEvent.get(event);
  if (!wrapper) {
    wrapper = () => listener(event);
    wrappersByEvent.set(event, wrapper);
  }
  return wrapper;
}

function _unwrapSignalListener(
  event: string,
  listener: SignalListener,
): SignalListener {
  const wrappersByEvent = _signalListenerWrappers.get(listener);
  if (!wrappersByEvent) return listener;
  const wrapper = wrappersByEvent.get(event);
  if (wrapper) {
    wrappersByEvent.delete(event);
  }
  return wrapper ?? listener;
}

// Look up the actual registered listener for a signal event. When `once()` is
// used, EventEmitter wraps the listener in a function with a `.listener`
// property. We need the wrapper to pass to `Deno.removeSignalListener`.
function _findSignalListener(
  // deno-lint-ignore no-explicit-any
  target: any,
  event: string,
  // deno-lint-ignore no-explicit-any
  listener: (...args: any[]) => void,
  // deno-lint-ignore no-explicit-any
): ((...args: any[]) => void) | undefined {
  const events = target._events;
  if (events === undefined) return undefined;
  const list = events[event];
  if (list === undefined) return undefined;
  if (typeof list === "function") {
    if (list !== listener && list.listener === listener) return list;
    return undefined;
  }
  for (let i = list.length - 1; i >= 0; i--) {
    if (list[i] !== listener && list[i].listener === listener) return list[i];
  }
  return undefined;
}

function isProtectedProcessExceptionEvent(event: unknown): boolean {
  return event === "uncaughtException" ||
    event === "uncaughtExceptionMonitor" ||
    event === "unhandledRejection" ||
    event === "rejectionHandled" ||
    event === "multipleResolves";
}

function isProtectedProcessMetaEvent(event: unknown): boolean {
  return event === "newListener" || event === "removeListener";
}

function guardProcessExceptionEvent(event: unknown, api: string) {
  if (isProtectedProcessExceptionEvent(event)) {
    // @ref LLP 0019#runtime-and-memory-inspection [implements]
    op_oden_guard_deny_only_surface(
      "runtime",
      "inspect",
      String(event),
      api,
    );
  }
}

function guardProcessMetaEvent(event: unknown, api: string) {
  if (isProtectedProcessMetaEvent(event)) {
    op_oden_guard_deny_only_surface(
      "runtime",
      "inspect",
      String(event),
      api,
    );
  }
}

function guardProcessSignalEvent(
  event: unknown,
  action: string,
  api: string,
) {
  if (typeof event === "string" && StringPrototypeStartsWith(event, "SIG")) {
    op_oden_guard_deny_only_surface(
      "process",
      "signal",
      `${action}:${event}`,
      api,
    );
  }
}

function guardProcessEventObservation(event: unknown, api: string) {
  guardProcessExceptionEvent(event, api);
  guardProcessMetaEvent(event, api);
  guardProcessSignalEvent(event, "inspect", api);
}

let trustedProcessEventAccess: unknown;
let trustedProcessMetaTableAccess: unknown;
let trustedProcessMetaEmission;

function withTrustedProcessEventAccess(
  event: unknown,
  // deno-lint-ignore no-explicit-any
  operation: () => any,
) {
  const previous = trustedProcessEventAccess;
  trustedProcessEventAccess = event;
  try {
    return operation();
  } finally {
    trustedProcessEventAccess = previous;
  }
}

function withTrustedProcessMetaEmission(
  metaEvent: "newListener" | "removeListener",
  targetEvent: unknown,
  listener: unknown,
  // deno-lint-ignore no-explicit-any
  operation: () => any,
) {
  const previousTableAccess = trustedProcessMetaTableAccess;
  const previousEmission = trustedProcessMetaEmission;
  trustedProcessMetaTableAccess = {
    __proto__: null,
    metaEvent,
    targetEvent,
  };
  trustedProcessMetaEmission = {
    __proto__: null,
    metaEvent,
    targetEvent,
    listener,
  };
  try {
    return operation();
  } finally {
    trustedProcessMetaTableAccess = previousTableAccess;
    trustedProcessMetaEmission = previousEmission;
  }
}

function addProcessListenerInternal(target, event, listener, prepend) {
  validateFunction(listener, "listener");
  return withTrustedProcessMetaEmission(
    "newListener",
    event,
    listener.listener ?? listener,
    () =>
      FunctionPrototypeCall(
        prepend
          ? EventEmitter.prototype.prependListener
          : EventEmitter.prototype.on,
        target,
        event,
        listener,
      ),
  );
}

function removeProcessListenerInternal(target, event, listener) {
  validateFunction(listener, "listener");
  return withTrustedProcessMetaEmission(
    "removeListener",
    event,
    listener.listener ?? listener,
    () =>
      FunctionPrototypeCall(
        EventEmitter.prototype.removeListener,
        target,
        event,
        listener,
      ),
  );
}

/** https://nodejs.org/api/process.html#process_process_events */
Process.prototype.on = function (
  // deno-lint-ignore no-explicit-any
  this: any,
  event: string,
  // deno-lint-ignore no-explicit-any
  listener: (...args: any[]) => void,
) {
  guardProcessExceptionEvent(event, "process.on");
  guardProcessMetaEvent(event, "process.on");
  if (typeof event === "string" && StringPrototypeStartsWith(event, "SIG")) {
    if (event === "SIGBREAK" && Deno.build.os !== "windows") {
      // Ignores SIGBREAK if the platform is not windows.
    } else if (event === "SIGTERM" && Deno.build.os === "windows") {
      // Ignores SIGTERM on windows.
    } else if (
      event !== "SIGBREAK" && event !== "SIGINT" &&
      event !== "SIGWINCH" && Deno.build.os === "windows"
    ) {
      // TODO(#26331): Ignores all signals except SIGBREAK, SIGINT, and SIGWINCH on windows.
    } else {
      guardProcessSignalEvent(event, "listen", "process.on");
      addProcessListenerInternal(this, event, listener, false);
      Deno.addSignalListener(
        event as Deno.Signal,
        _wrapSignalListener(event, listener),
      );
    }
  } else {
    addProcessListenerInternal(this, event, listener, false);
  }

  return this;
};

Process.prototype.off = function (
  // deno-lint-ignore no-explicit-any
  this: any,
  event: string,
  // deno-lint-ignore no-explicit-any
  listener: (...args: any[]) => void,
) {
  guardProcessExceptionEvent(event, "process.off");
  guardProcessMetaEvent(event, "process.off");
  if (typeof event === "string" && StringPrototypeStartsWith(event, "SIG")) {
    if (event === "SIGBREAK" && Deno.build.os !== "windows") {
      // Ignores SIGBREAK if the platform is not windows.
    } else if (
      event !== "SIGBREAK" && event !== "SIGINT" &&
      event !== "SIGWINCH" && Deno.build.os === "windows"
    ) {
      // Ignores all signals except SIGBREAK, SIGINT, and SIGWINCH on windows.
    } else {
      guardProcessSignalEvent(event, "unlisten", "process.off");
      // Find the actual registered listener before EventEmitter removes it.
      // When using `once()`, EventEmitter wraps the original listener in a
      // wrapper with a `.listener` property pointing to the original. We need
      // to pass the wrapper (not the original) to Deno.removeSignalListener.
      const registered = _findSignalListener(this, event, listener);
      removeProcessListenerInternal(this, event, listener);
      const unwrapped = _unwrapSignalListener(event, registered ?? listener);
      Deno.removeSignalListener(
        event as Deno.Signal,
        unwrapped,
      );
    }
  } else {
    removeProcessListenerInternal(this, event, listener);
  }

  return this;
};

Process.prototype.emit = function (
  // deno-lint-ignore no-explicit-any
  this: any,
  event: string,
  // deno-lint-ignore no-explicit-any
  ...args: any[]
): boolean {
  guardProcessSignalEvent(event, "emit", "process.emit");
  let trustedMetaEmission = false;
  let trustedMetaExpected;
  if (isProtectedProcessMetaEvent(event)) {
    const expected = trustedProcessMetaEmission;
    if (
      expected?.metaEvent === event &&
      expected.targetEvent === args[0] &&
      (event === "removeListener" || expected.listener === args[1])
    ) {
      trustedProcessMetaEmission = undefined;
      trustedMetaEmission = true;
      trustedMetaExpected = expected;
      trustedProcessMetaTableAccess = undefined;
    } else {
      guardProcessMetaEvent(event, `process.emit(${event})`);
    }
  }
  guardProcessExceptionEvent(event, "process.emit");
  const emit = () =>
    ReflectApply(
      EventEmitter.prototype.emit,
      this,
      ArrayPrototypeConcat([event], args),
    );
  if (!trustedMetaEmission) return emit();
  const result = withTrustedProcessEventAccess(event, emit);
  if (isProtectedProcessMetaEvent(trustedMetaExpected.targetEvent)) {
    trustedProcessMetaTableAccess = trustedMetaExpected.targetEvent;
  }
  return result;
};

Process.prototype.prependListener = function (
  // deno-lint-ignore no-explicit-any
  this: any,
  event: string,
  // deno-lint-ignore no-explicit-any
  listener: (...args: any[]) => void,
) {
  guardProcessExceptionEvent(event, "process.prependListener");
  guardProcessMetaEvent(event, "process.prependListener");
  if (typeof event === "string" && StringPrototypeStartsWith(event, "SIG")) {
    if (event === "SIGBREAK" && Deno.build.os !== "windows") {
      // Ignores SIGBREAK if the platform is not windows.
    } else {
      guardProcessSignalEvent(event, "listen", "process.prependListener");
      addProcessListenerInternal(this, event, listener, true);
      Deno.addSignalListener(
        event as Deno.Signal,
        _wrapSignalListener(event, listener),
      );
    }
  } else {
    addProcessListenerInternal(this, event, listener, true);
  }

  return this;
};

function addProcessOnceListener(
  // deno-lint-ignore no-explicit-any
  target: any,
  event: string,
  // deno-lint-ignore no-explicit-any
  listener: (...args: any[]) => void,
  prepend: boolean,
) {
  validateFunction(listener, "listener");
  let fired = false;
  // deno-lint-ignore no-explicit-any
  const wrapped: any = function (this: any, ...args: any[]) {
    if (fired) return;
    fired = true;
    withTrustedProcessEventAccess(
      event,
      () => removeProcessListenerInternal(target, event, wrapped),
    );
    return ReflectApply(listener, this, args);
  };
  wrapped.listener = listener;
  addProcessListenerInternal(target, event, wrapped, prepend);
  return target;
}

Process.prototype.once = function (
  // deno-lint-ignore no-explicit-any
  this: any,
  event: string,
  // deno-lint-ignore no-explicit-any
  listener: (...args: any[]) => void,
) {
  guardProcessExceptionEvent(event, "process.once");
  guardProcessMetaEvent(event, "process.once");
  return isProtectedProcessExceptionEvent(event)
    ? addProcessOnceListener(this, event, listener, false)
    : FunctionPrototypeCall(EventEmitter.prototype.once, this, event, listener);
};

Process.prototype.prependOnceListener = function (
  // deno-lint-ignore no-explicit-any
  this: any,
  event: string,
  // deno-lint-ignore no-explicit-any
  listener: (...args: any[]) => void,
) {
  guardProcessExceptionEvent(event, "process.prependOnceListener");
  guardProcessMetaEvent(event, "process.prependOnceListener");
  return isProtectedProcessExceptionEvent(event)
    ? addProcessOnceListener(this, event, listener, true)
    : FunctionPrototypeCall(
      EventEmitter.prototype.prependOnceListener,
      this,
      event,
      listener,
    );
};

Process.prototype.addListener = function (
  // deno-lint-ignore no-explicit-any
  this: any,
  event: string,
  // deno-lint-ignore no-explicit-any
  listener: (...args: any[]) => void,
) {
  return this.on(event, listener);
};

Process.prototype.removeListener = function (
  // deno-lint-ignore no-explicit-any
  this: any,
  event: string, // deno-lint-ignore no-explicit-any
  listener: (...args: any[]) => void,
) {
  return this.off(event, listener);
};

Process.prototype.removeAllListeners = function (
  // deno-lint-ignore no-explicit-any
  event?: string | any,
) {
  if (arguments.length === 0) {
    op_oden_guard_deny_only_surface(
      "runtime",
      "inspect",
      "process-exception-listeners",
      "process.removeAllListeners",
    );
  } else {
    guardProcessExceptionEvent(event, "process.removeAllListeners");
    guardProcessMetaEvent(event, "process.removeAllListeners");
  }
  if (arguments.length === 0) {
    // Remove all listeners for all events - find all signal events and
    // unregister their Deno signal listeners before clearing.
    const events = this._events;
    if (events !== undefined) {
      const keys = ObjectKeys(events);
      for (let i = 0; i < keys.length; i++) {
        const key = keys[i];
        if (typeof key === "string" && StringPrototypeStartsWith(key, "SIG")) {
          _removeAllSignalListeners(this, key);
        }
      }
    }
    return FunctionPrototypeCall(
      EventEmitter.prototype.removeAllListeners,
      this,
    );
  }
  if (typeof event === "string" && StringPrototypeStartsWith(event, "SIG")) {
    guardProcessSignalEvent(event, "unlisten", "process.removeAllListeners");
    _removeAllSignalListeners(this, event);
  }
  return FunctionPrototypeCall(
    EventEmitter.prototype.removeAllListeners,
    this,
    event,
  );
};

Process.prototype.listeners = function (event: string) {
  guardProcessEventObservation(event, "process.listeners");
  return FunctionPrototypeCall(EventEmitter.prototype.listeners, this, event);
};

Process.prototype.rawListeners = function (event: string) {
  guardProcessEventObservation(event, "process.rawListeners");
  return FunctionPrototypeCall(
    EventEmitter.prototype.rawListeners,
    this,
    event,
  );
};

Process.prototype.listenerCount = function (
  event: string,
  // deno-lint-ignore no-explicit-any
  listener?: (...args: any[]) => void,
) {
  guardProcessEventObservation(event, "process.listenerCount");
  return FunctionPrototypeCall(
    EventEmitter.prototype.listenerCount,
    this,
    event,
    listener,
  );
};

function _removeAllSignalListeners(
  // deno-lint-ignore no-explicit-any
  target: any,
  event: string,
) {
  const events = target._events;
  if (events === undefined) return;
  const list = events[event];
  if (list === undefined) return;
  if (typeof list === "function") {
    const actual = list.listener ?? list;
    Deno.removeSignalListener(event as Deno.Signal, actual);
  } else {
    for (let i = 0; i < list.length; i++) {
      const actual = list[i].listener ?? list[i];
      Deno.removeSignalListener(event as Deno.Signal, actual);
    }
  }
}

/** https://nodejs.org/api/process.html#process_process */
// @ts-ignore TS doesn't work well with ES5 classes
const process = new Process();

const nodeProcessTrustedToken = Symbol("node-process-trusted-runtime");

function requireNodeProcessTrustedToken(token: unknown) {
  if (token !== nodeProcessTrustedToken) {
    throw new TypeError("Node process internal requires trusted runtime token");
  }
}

function defineNodeProcessTrustedInternalValue(name: string, value: unknown) {
  ObjectDefineProperty(internals, name, {
    __proto__: null,
    value,
    writable: false,
    enumerable: false,
    configurable: false,
  });
}

// The real extension `internals` stays closure-private while capsec is armed;
// its user-facing facade omits these names. The token keeps an accidentally
// leaked helper inert on its own.
// @ref LLP 0010#revision-11-patch-profile [implements] -- Trusted process-event bookkeeping uses an unforgeable extension-closure channel.
defineNodeProcessTrustedInternalValue(
  "nodeProcessTrustedToken",
  nodeProcessTrustedToken,
);
defineNodeProcessTrustedInternalValue(
  "nodeProcessAddListenerInternal",
  function (
    token: unknown,
    event: string,
    // deno-lint-ignore no-explicit-any
    listener: (...args: any[]) => void,
    prepend = false,
  ) {
    requireNodeProcessTrustedToken(token);
    return addProcessListenerInternal(process, event, listener, prepend);
  },
);
defineNodeProcessTrustedInternalValue(
  "nodeProcessRemoveListenerInternal",
  function (
    token: unknown,
    event: string,
    // deno-lint-ignore no-explicit-any
    listener: (...args: any[]) => void,
  ) {
    requireNodeProcessTrustedToken(token);
    return removeProcessListenerInternal(process, event, listener);
  },
);

// Borrowing EventEmitter.prototype must not bypass the process-specific
// guards. Protect the sensitive keys in the backing event table as the final
// check; ordinary process events retain normal EventEmitter behavior.
// deno-lint-ignore no-explicit-any
let processEventsStore: any = process._events;
// deno-lint-ignore no-explicit-any
let guardedProcessEvents: any;

// deno-lint-ignore no-explicit-any
function wrapProcessEvents(store: any) {
  function hasTrustedMetaTableAccess(property) {
    const access = trustedProcessMetaTableAccess;
    return access === property ||
      access?.metaEvent === property ||
      access?.targetEvent === property;
  }
  return new Proxy(store, {
    get(target, property) {
      if (trustedProcessEventAccess === property) {
        trustedProcessEventAccess = undefined;
        return ReflectGet(target, property, target);
      }
      if (hasTrustedMetaTableAccess(property)) {
        return ReflectGet(target, property, target);
      }
      guardProcessExceptionEvent(property, "process._events.get");
      guardProcessMetaEvent(property, "process._events.get");
      guardProcessSignalEvent(property, "inspect", "process._events.get");
      return ReflectGet(target, property, target);
    },
    set(target, property, value) {
      if (hasTrustedMetaTableAccess(property)) {
        return ReflectSet(target, property, value, target);
      }
      guardProcessExceptionEvent(property, "process._events.set");
      guardProcessMetaEvent(property, "process._events.set");
      guardProcessSignalEvent(property, "control", "process._events.set");
      return ReflectSet(target, property, value, target);
    },
    defineProperty(target, property, descriptor) {
      if (hasTrustedMetaTableAccess(property)) {
        return ReflectDefineProperty(target, property, descriptor);
      }
      guardProcessExceptionEvent(property, "process._events.defineProperty");
      guardProcessMetaEvent(property, "process._events.defineProperty");
      guardProcessSignalEvent(
        property,
        "control",
        "process._events.defineProperty",
      );
      return ReflectDefineProperty(target, property, descriptor);
    },
    deleteProperty(target, property) {
      if (hasTrustedMetaTableAccess(property)) {
        return ReflectDeleteProperty(target, property);
      }
      guardProcessExceptionEvent(property, "process._events.deleteProperty");
      guardProcessMetaEvent(property, "process._events.deleteProperty");
      guardProcessSignalEvent(
        property,
        "control",
        "process._events.deleteProperty",
      );
      return ReflectDeleteProperty(target, property);
    },
    has(target, property) {
      if (hasTrustedMetaTableAccess(property)) {
        return ReflectHas(target, property);
      }
      guardProcessExceptionEvent(property, "process._events.has");
      guardProcessMetaEvent(property, "process._events.has");
      guardProcessSignalEvent(property, "inspect", "process._events.has");
      return ReflectHas(target, property);
    },
    ownKeys(target) {
      let protectedEvent;
      if (ReflectHas(target, "uncaughtException")) {
        protectedEvent = "uncaughtException";
      } else if (ReflectHas(target, "uncaughtExceptionMonitor")) {
        protectedEvent = "uncaughtExceptionMonitor";
      } else if (ReflectHas(target, "unhandledRejection")) {
        protectedEvent = "unhandledRejection";
      } else if (ReflectHas(target, "rejectionHandled")) {
        protectedEvent = "rejectionHandled";
      } else if (ReflectHas(target, "multipleResolves")) {
        protectedEvent = "multipleResolves";
      }
      if (protectedEvent !== undefined) {
        guardProcessExceptionEvent(
          protectedEvent,
          "process._events.ownKeys",
        );
      }
      if (
        ReflectHas(target, "newListener") ||
        ReflectHas(target, "removeListener")
      ) {
        guardProcessMetaEvent("newListener", "process._events.ownKeys");
      }
      const keys = ReflectOwnKeys(target);
      for (const key of new SafeArrayIterator(keys)) {
        if (typeof key === "string" && StringPrototypeStartsWith(key, "SIG")) {
          guardProcessSignalEvent(key, "inspect", "process._events.ownKeys");
          break;
        }
      }
      return keys;
    },
    getOwnPropertyDescriptor(target, property) {
      guardProcessExceptionEvent(
        property,
        "process._events.getOwnPropertyDescriptor",
      );
      guardProcessMetaEvent(
        property,
        "process._events.getOwnPropertyDescriptor",
      );
      guardProcessSignalEvent(
        property,
        "inspect",
        "process._events.getOwnPropertyDescriptor",
      );
      return ReflectGetOwnPropertyDescriptor(target, property);
    },
  });
}

guardedProcessEvents = wrapProcessEvents(processEventsStore);
ObjectDefineProperty(process, "_events", {
  __proto__: null,
  configurable: false,
  enumerable: true,
  get() {
    return guardedProcessEvents;
  },
  set(value) {
    op_oden_guard_deny_only_surface(
      "runtime",
      "inspect",
      "process-events",
      "process._events=set",
    );
    processEventsStore = value;
    guardedProcessEvents = wrapProcessEvents(value);
  },
});

// `node:process` exposes `stdin`/`stdout`/`stderr` as ESM named exports. The
// underlying streams are constructed lazily via accessor properties installed
// on `process` in `__bootstrapNodeProcess`, so initialize the export bindings
// with delegating proxies. Code like `import { stdin } from "node:process"`
// can use the binding before anything has touched `process.stdin`; the proxy
// forwards the operation to `process.stdin`, triggering lazy construction. The
// accessor then writes the materialized stream back into the binding, so later
// reads see the real stream directly.
const streamDelegates = new SafeWeakSet<object>();

function makeStreamDelegate(name: "stdin" | "stdout" | "stderr"): unknown {
  const delegate = new Proxy(ObjectCreate(null), {
    get(_target, prop) {
      const real = process[name];
      if (real == null) return undefined;
      const value = ReflectGet(real, prop, real);
      return typeof value === "function"
        ? FunctionPrototypeBind(value, real)
        : value;
    },
    set(_target, prop, value) {
      const real = process[name];
      if (real == null) return true;
      real[prop] = value;
      return true;
    },
    has(_target, prop) {
      const real = process[name];
      return real != null && ReflectHas(real, prop);
    },
    deleteProperty(_target, prop) {
      const real = process[name];
      if (real == null) return true;
      delete real[prop];
      return true;
    },
    ownKeys(_target) {
      const real = process[name];
      return real != null ? ReflectOwnKeys(real) : [];
    },
    getOwnPropertyDescriptor(_target, prop) {
      const real = process[name];
      return real != null
        ? ReflectGetOwnPropertyDescriptor(real, prop)
        : undefined;
    },
    getPrototypeOf(_target) {
      const real = process[name];
      return real != null ? ReflectGetPrototypeOf(real) : null;
    },
  });
  streamDelegates.add(delegate);
  return delegate;
}
stdin = makeStreamDelegate("stdin");
stdout = makeStreamDelegate("stdout");
stderr = makeStreamDelegate("stderr");

/** https://nodejs.org/api/process.html#processrelease */
ObjectDefineProperty(process, "release", {
  __proto__: null,
  get() {
    return {
      name: "node",
      sourceUrl:
        `https://nodejs.org/download/release/${version}/node-${version}.tar.gz`,
      headersUrl:
        `https://nodejs.org/download/release/${version}/node-${version}-headers.tar.gz`,
    };
  },
});

/** https://nodejs.org/api/process.html#process_process_arch */
ObjectDefineProperty(process, "arch", {
  __proto__: null,
  get() {
    return arch;
  },
  configurable: true,
});

ObjectDefineProperty(process, "report", {
  __proto__: null,
  get() {
    return report;
  },
});

let processTitle: string | undefined;
ObjectDefineProperty(process, "title", {
  __proto__: null,
  get() {
    if (processTitle == null) {
      return String(execPath);
    }
    return processTitle;
  },
  set(value) {
    const nextTitle = `${value}`;
    op_node_process_set_title(nextTitle);
    processTitle = nextTitle;
  },
});

/**
 * https://nodejs.org/api/process.html#process_process_argv
 * Read permissions are required in order to get the executable route
 */
process.argv = argv;

ObjectDefineProperty(process, "argv0", {
  __proto__: null,
  get() {
    return argv0;
  },
  set(_val) {},
});

/**
 * https://nodejs.org/api/process.html#processdebugport
 *
 * Node coerces the value via v8's ToInt32 (so numeric strings convert to
 * numbers, objects/arrays/NaN/Infinity become 0, booleans become 0 or 1,
 * and Symbols throw TypeError). Out-of-range values throw RangeError.
 */
// Node's default inspector port (kDefaultInspectorPort in src/node_options.h).
let _debugPort = 9229;
let _debugPortWasSet = false;
ObjectDefineProperty(process, "debugPort", {
  __proto__: null,
  get() {
    // When the inspector is running, report the actual bound port so
    // `--inspect=...:0` reflects the ephemeral port chosen at bind
    // time. An explicit assignment via the setter wins over this
    // (matching Node's mutable `process.debugPort`).
    if (!_debugPortWasSet) {
      const port = op_inspector_port();
      if (port !== 0) return port;
    }
    return _debugPort;
  },
  set(val) {
    // `| 0` performs ToInt32, matching Int32Value() in node_process_object.cc.
    const port = val | 0;
    if ((port !== 0 && port < 1024) || port > 65535) {
      throw new RangeError(
        "process.debugPort must be 0 or in range 1024 to 65535",
      );
    }
    _debugPort = port;
    _debugPortWasSet = true;
  },
  enumerable: true,
  configurable: true,
});

/**
 * Undocumented but public Node API: stops the inspector / debugger session
 * if one is running. No-op if no inspector is attached. See
 * `lib/internal/inspector.js` in the Node source.
 */
process._debugEnd = function _debugEnd() {
  if (op_inspector_enabled()) {
    op_inspector_close();
  }
};

/**
 * Undocumented but public Node API: starts the inspector in another process by
 * sending `SIGUSR1` to it. The native signal preflight treats a self-directed
 * SIGUSR1 as the conjunctive process:signal + inspector:activate effect and
 * routes an authorized self activation through the internal inspector channel.
 */
process._debugProcess = function _debugProcess(pid) {
  if (typeof pid !== "number") {
    throw new ERR_INVALID_ARG_TYPE("pid", "number", pid);
  }
  process.kill(pid, "SIGUSR1");
};

/** https://nodejs.org/api/process.html#process_process_chdir_directory */
process.chdir = chdir;

/** https://nodejs.org/api/process.html#processconfig */
let _configCache: Record<string, unknown> | undefined;
ObjectDefineProperty(process, "config", {
  __proto__: null,
  get() {
    if (_configCache === undefined) {
      // Internal escape hatch for the node_compat test runner: allows a
      // single test to opt into the "externally-linked OpenSSL" branch of
      // upstream Node test fixtures, where Deno's aws-lc-rs/BoringSSL
      // backend matches that branch's expectations. Not for user code; the
      // env var is reserved (DENO_INTERNAL_*) and undocumented.
      let forceSharedOpenssl = false;
      try {
        forceSharedOpenssl =
          Deno.env.get("DENO_INTERNAL_NODE_TEST_FORCE_SHARED_OPENSSL") === "1";
      } catch {
        // Permission denied or no env access; leave forceSharedOpenssl false.
      }
      _configCache = ObjectFreeze({
        target_defaults: ObjectFreeze({
          default_configuration: "Release",
        }),
        variables: ObjectFreeze({
          // Match Node's lib/internal/process/per_thread.js process.config:
          // `node_module_version` is an integer ABI version exposed for native
          // addons. Mirror process.versions.modules so a single source of truth
          // wins.
          "node_module_version": Number(versions.modules),
          "llvm_version": "0.0",
          "enable_lto": "false",
          // Node 26's bundled common.gypi gates LTO settings on these two
          // variables. node-gyp materializes process.config into config.gypi,
          // so they must be defined or `gyp` fails to evaluate the conditions
          // (e.g. "name 'enable_thin_lto' is not defined") when building native
          // addons against Node >= 26 headers.
          "enable_thin_lto": "false",
          "lto_jobs": "",
          "host_arch": arch,
          ...(forceSharedOpenssl ? { "node_shared_openssl": 1 } : {}),
        }),
      });
    }
    return _configCache;
  },
  configurable: true,
});

process.cpuUsage = cpuUsage;
process.threadCpuUsage = threadCpuUsage;

/** https://nodejs.org/api/process.html#process_process_cwd */
process.cwd = cwd;

/**
 * https://nodejs.org/api/process.html#process_process_env
 * Requires env permissions
 */
process.env = env;

/** https://nodejs.org/api/process.html#process_process_execargv */
process.execArgv = execArgv;

/** https://nodejs.org/api/process.html#process_process_exit_code */
process.exit = exit;

/** https://nodejs.org/api/process.html#processabort */
process.abort = abort;

/** https://nodejs.org/api/process.html#processopenStdin */
process.openStdin = () => {
  process.stdin.resume();
  return process.stdin;
};

// NB(bartlomieju): this is a private API in Node.js, but there are packages like
// `aws-iot-device-sdk-v2` that depend on it
// https://github.com/denoland/deno/issues/30115
process._rawDebug = (...args: unknown[]) => {
  core.print(`${format(...new SafeArrayIterator(args))}\n`, true);
};

process.getActiveResourcesInfo = getActiveResourcesInfo;
process._getActiveRequests = getActiveRequests;
process._getActiveHandles = getActiveHandles;

// Undocumented Node API that is used by `signal-exit` which in turn
// is used by `node-tap`. It was marked for removal a couple of years
// ago. See https://github.com/nodejs/node/blob/6a6b3c54022104cc110ab09044a2a0cecb8988e7/lib/internal/bootstrap/node.js#L172
process.reallyExit = (code: number) => {
  return Deno.exit(code || 0);
};

process._exiting = _exiting;

// Exception capture callback (used by node:domain)
// deno-lint-ignore no-explicit-any
let _uncaughtExceptionCaptureFn: ((err: any) => void) | null = null;

// deno-lint-ignore no-explicit-any
function setUncaughtExceptionCaptureCallbackImpl(fn: any) {
  if (fn === null) {
    _uncaughtExceptionCaptureFn = null;
    synchronizeListeners();
    return;
  }
  if (typeof fn !== "function") {
    throw new ERR_INVALID_ARG_TYPE("fn", ["function", "null"], fn);
  }
  if (_uncaughtExceptionCaptureFn !== null) {
    throw new ERR_UNCAUGHT_EXCEPTION_CAPTURE_ALREADY_SET();
  }
  _uncaughtExceptionCaptureFn = fn;
  synchronizeListeners();
}

// Domain and the REPL are trusted compatibility-runtime consumers. Their
// registration must not be reattributed to a package whose code caused the
// runtime to enter those helpers.
defineNodeProcessTrustedInternalValue(
  "nodeProcessSetUncaughtExceptionCaptureCallback",
  // deno-lint-ignore no-explicit-any
  function (token: unknown, fn: any) {
    requireNodeProcessTrustedToken(token);
    return setUncaughtExceptionCaptureCallbackImpl(fn);
  },
);

// deno-lint-ignore no-explicit-any
process.setUncaughtExceptionCaptureCallback = function (fn: any) {
  op_oden_guard_deny_only_surface(
    "runtime",
    "inspect",
    "uncaught-exception-capture",
    "process.setUncaughtExceptionCaptureCallback",
  );
  return setUncaughtExceptionCaptureCallbackImpl(fn);
};

process.hasUncaughtExceptionCaptureCallback = function () {
  op_oden_guard_deny_only_surface(
    "runtime",
    "inspect",
    "uncaught-exception-capture",
    "process.hasUncaughtExceptionCaptureCallback",
  );
  return _uncaughtExceptionCaptureFn !== null;
};

// Exception dispatch is a runtime responsibility. It must reach listeners
// installed by root even when the exception originated in package code, while
// the public process.emit/listenerCount routes still re-check the caller.
function emitProcessExceptionInternal(event: string, ...args: unknown[]) {
  return withTrustedProcessEventAccess(
    event,
    () =>
      ReflectApply(
        EventEmitter.prototype.emit,
        process,
        ArrayPrototypeConcat([event], args),
      ),
  );
}

function processExceptionListenerCountInternal(event: string) {
  return withTrustedProcessEventAccess(
    event,
    () =>
      FunctionPrototypeCall(
        EventEmitter.prototype.listenerCount,
        process,
        event,
      ),
  );
}

// deno-lint-ignore no-explicit-any
function fatalExceptionImpl(err: any, fromPromise?: boolean) {
  const origin = fromPromise ? "unhandledRejection" : "uncaughtException";
  emitProcessExceptionInternal("uncaughtExceptionMonitor", err, origin);
  if (_uncaughtExceptionCaptureFn !== null) {
    _uncaughtExceptionCaptureFn(err);
    return true;
  }
  if (processExceptionListenerCountInternal("uncaughtException") > 0) {
    emitProcessExceptionInternal("uncaughtException", err, origin);
    return true;
  }
  return false;
}

// Root may replace Node's private hook for compatibility, but packages cannot
// mutate or invoke the process-global handler. Internal exception dispatch
// uses the separately retained trusted value.
// deno-lint-ignore no-explicit-any
let fatalExceptionHandler: any = fatalExceptionImpl;
// deno-lint-ignore no-explicit-any
const guardedFatalException = function (err: any, fromPromise?: boolean) {
  op_oden_guard_deny_only_surface(
    "runtime",
    "inspect",
    "fatal-exception-dispatch",
    "process._fatalException",
  );
  return fatalExceptionHandler(err, fromPromise);
};
defineNodeProcessTrustedInternalValue(
  "nodeProcessFatalException",
  function (token: unknown, err: unknown, fromPromise?: boolean) {
    requireNodeProcessTrustedToken(token);
    return typeof fatalExceptionHandler === "function"
      ? fatalExceptionHandler(err, fromPromise)
      : false;
  },
);
ObjectDefineProperty(process, "_fatalException", {
  __proto__: null,
  configurable: true,
  enumerable: true,
  get() {
    op_oden_guard_deny_only_surface(
      "runtime",
      "inspect",
      "fatal-exception-handler",
      "process._fatalException=get",
    );
    return typeof fatalExceptionHandler === "function"
      ? guardedFatalException
      : fatalExceptionHandler;
  },
  // deno-lint-ignore no-explicit-any
  set(value: any) {
    op_oden_guard_deny_only_surface(
      "runtime",
      "inspect",
      "fatal-exception-handler",
      "process._fatalException=set",
    );
    fatalExceptionHandler = value;
  },
});

/** https://nodejs.org/api/process.html#processexitcode_1 */
ObjectDefineProperty(process, "exitCode", {
  __proto__: null,
  get() {
    return ProcessExitCode;
  },
  set(code: number | string | null | undefined) {
    let parsedCode: number;
    if (code == null) {
      parsedCode = 0;
    } else if (typeof code === "number") {
      if (!NumberIsInteger(code)) {
        throw new ERR_OUT_OF_RANGE("code", "an integer", code);
      }
      parsedCode = code;
    } else if (typeof code === "string") {
      if (
        code === "" || !NumberIsFinite(Number(code)) ||
        !NumberIsInteger(Number(code))
      ) {
        throw new ERR_INVALID_ARG_TYPE("code", "integer", code);
      }
      parsedCode = Number(code);
    } else {
      throw new ERR_INVALID_ARG_TYPE("code", "integer", code);
    }

    denoOs.setExitCode(parsedCode);
    ProcessExitCode = code;
  },
});

// Typed as any to avoid importing "module" module for types
process.mainModule = undefined;

/** https://nodejs.org/api/process.html#process_process_nexttick_callback_args */
process.nextTick = _nextTick;

process.dlopen = dlopen;

/** https://nodejs.org/api/process.html#process_process_pid */
ObjectDefineProperty(process, "pid", {
  __proto__: null,
  get() {
    return pid;
  },
});

/** https://nodejs.org/api/process.html#processppid */
ObjectDefineProperty(process, "ppid", {
  __proto__: null,
  get() {
    return Deno.ppid;
  },
});

/** https://nodejs.org/api/process.html#process_process_platform */
ObjectDefineProperty(process, "platform", {
  __proto__: null,
  get() {
    return platform;
  },
  set(value) {
    platform = value;
  },
  configurable: true,
});

// https://nodejs.org/api/process.html#processsetsourcemapsenabledval
process.setSourceMapsEnabled = (val: boolean) => {
  validateBoolean(val, "val");
  // This is a no-op in Deno. Source maps are always enabled.
  // TODO(@satyarohith): support disabling source maps if needed.
};

// Source maps are always enabled in Deno.
ObjectDefineProperty(process, "sourceMapsEnabled", {
  __proto__: null,
  get() {
    return true; // Source maps are always enabled in Deno.
  },
  enumerable: true,
  configurable: true,
});

/**
 * Returns the current high-resolution real time in a [seconds, nanoseconds]
 * tuple.
 *
 * Note: You need to give --allow-hrtime permission to Deno to actually get
 * nanoseconds precision values. If you don't give 'hrtime' permission, the returned
 * values only have milliseconds precision.
 *
 * `time` is an optional parameter that must be the result of a previous process.hrtime() call to diff with the current time.
 *
 * These times are relative to an arbitrary time in the past, and not related to the time of day and therefore not subject to clock drift. The primary use is for measuring performance between intervals.
 * https://nodejs.org/api/process.html#process_process_hrtime_time
 */
process.hrtime = hrtime;

/**
 * @private
 *
 * NodeJS internal, use process.kill instead
 */
process._kill = _kill;

/** https://nodejs.org/api/process.html#processkillpid-signal */
process.kill = kill;

process.memoryUsage = memoryUsage;
process.availableMemory = availableMemory;
process.constrainedMemory = constrainedMemory;

/** https://nodejs.org/api/process.html#processresourceusage */
process.resourceUsage = resourceUsage;

/** https://nodejs.org/api/process.html#process_process_stderr */
process.stderr = stderr;

/** https://nodejs.org/api/process.html#process_process_stdin */
process.stdin = stdin;

/** https://nodejs.org/api/process.html#process_process_stdout */
process.stdout = stdout;

/** https://nodejs.org/api/process.html#process_process_version */
process.version = version;

/** https://nodejs.org/api/process.html#process_process_versions */
process.versions = versions;

/** https://nodejs.org/api/process.html#process_process_emitwarning_warning_options */
process.emitWarning = emitWarning;

const guardedBindingValues = new SafeWeakMap<object, object>();
const guardedBindingTargets = new SafeWeakMap<object, object>();

function guardBindingUse(path: string, api: string) {
  op_oden_guard_deny_only_surface(
    "runtime",
    "inspect",
    path,
    api,
  );
}

// A binding object obtained by root must not become ambient authority merely
// because it is later passed into package code. Recursively guard every use,
// including typed-array element access and extracted binding functions.
// deno-lint-ignore no-explicit-any
function guardBindingValue(value: any, path: string): any {
  if (
    value === null ||
    (typeof value !== "object" && typeof value !== "function")
  ) {
    return value;
  }
  const cached = guardedBindingValues.get(value);
  if (cached !== undefined) return cached;

  const proxy = new Proxy(value, {
    get(target, property) {
      const targetPath = `${path}.${String(property)}`;
      guardBindingUse(targetPath, "process.binding.get");
      return guardBindingValue(
        ReflectGet(target, property, target),
        targetPath,
      );
    },
    set(target, property, nextValue) {
      const targetPath = `${path}.${String(property)}`;
      guardBindingUse(targetPath, "process.binding.set");
      return ReflectSet(
        target,
        property,
        guardedBindingTargets.get(nextValue) ?? nextValue,
        target,
      );
    },
    apply(target, thisArg, args) {
      guardBindingUse(path, "process.binding.call");
      const rawThis = guardedBindingTargets.get(thisArg) ?? thisArg;
      const rawArgs = [];
      for (let i = 0; i < args.length; i++) {
        ArrayPrototypePush(
          rawArgs,
          guardedBindingTargets.get(args[i]) ?? args[i],
        );
      }
      return guardBindingValue(ReflectApply(target, rawThis, rawArgs), path);
    },
    construct(target, args, newTarget) {
      guardBindingUse(path, "process.binding.construct");
      const rawArgs = [];
      for (let i = 0; i < args.length; i++) {
        ArrayPrototypePush(
          rawArgs,
          guardedBindingTargets.get(args[i]) ?? args[i],
        );
      }
      return guardBindingValue(
        ReflectConstruct(
          target,
          rawArgs,
          guardedBindingTargets.get(newTarget) ?? newTarget,
        ),
        path,
      );
    },
    defineProperty(target, property, descriptor) {
      guardBindingUse(
        `${path}.${String(property)}`,
        "process.binding.defineProperty",
      );
      return ReflectDefineProperty(target, property, descriptor);
    },
    deleteProperty(target, property) {
      guardBindingUse(
        `${path}.${String(property)}`,
        "process.binding.deleteProperty",
      );
      return ReflectDeleteProperty(target, property);
    },
    has(target, property) {
      guardBindingUse(`${path}.${String(property)}`, "process.binding.has");
      return ReflectHas(target, property);
    },
    ownKeys(target) {
      guardBindingUse(path, "process.binding.ownKeys");
      return ReflectOwnKeys(target);
    },
    getOwnPropertyDescriptor(target, property) {
      const targetPath = `${path}.${String(property)}`;
      guardBindingUse(targetPath, "process.binding.getOwnPropertyDescriptor");
      const descriptor = ReflectGetOwnPropertyDescriptor(target, property);
      if (descriptor === undefined) return undefined;
      // deno-lint-ignore no-explicit-any
      const wrappedDescriptor: any = {
        __proto__: null,
        configurable: descriptor.configurable,
        enumerable: descriptor.enumerable,
      };
      if (ReflectHas(descriptor, "value")) {
        if (
          descriptor.configurable === false &&
          descriptor.writable === false &&
          descriptor.value !== null &&
          (typeof descriptor.value === "object" ||
            typeof descriptor.value === "function")
        ) {
          throw new TypeError(
            `Cannot safely expose non-configurable binding property ${targetPath}`,
          );
        }
        wrappedDescriptor.value = guardBindingValue(
          descriptor.value,
          targetPath,
        );
        wrappedDescriptor.writable = descriptor.writable;
      } else {
        wrappedDescriptor.get = guardBindingValue(
          descriptor.get,
          `${targetPath}.get`,
        );
        wrappedDescriptor.set = guardBindingValue(
          descriptor.set,
          `${targetPath}.set`,
        );
      }
      return wrappedDescriptor;
    },
    getPrototypeOf(target) {
      guardBindingUse(path, "process.binding.getPrototypeOf");
      return guardBindingValue(
        ReflectGetPrototypeOf(target),
        `${path}.[[Prototype]]`,
      );
    },
    setPrototypeOf(target, prototype) {
      guardBindingUse(path, "process.binding.setPrototypeOf");
      return ReflectSetPrototypeOf(
        target,
        guardedBindingTargets.get(prototype) ?? prototype,
      );
    },
  });
  guardedBindingValues.set(value, proxy);
  guardedBindingTargets.set(proxy, value);
  return proxy;
}

process.binding = (name: BindingName) => {
  op_oden_guard_deny_only_surface(
    "runtime",
    "inspect",
    String(name),
    "process.binding",
  );
  return guardBindingValue(getBinding(name), `binding:${String(name)}`);
};

/** https://nodejs.org/api/process.html#processumaskmask */
process.umask = umask;

/** This method is removed on Windows */
process.getgid = getgid;

/** This method is removed on Windows */
process.getuid = getuid;

/** This method is removed on Windows */
process.getgroups = () => op_getgroups();

/** This method is removed on Windows */
process.getegid = getegid;

/** This method is removed on Windows */
process.geteuid = geteuid;

/** This method is removed on Windows */
process.setegid = setegid;

/** This method is removed on Windows */
process.seteuid = seteuid;

/** This method is removed on Windows */
process.setgid = setgid;

/** This method is removed on Windows */
process.setuid = setuid;

// `getBuiltinModule` is also a named export of node:process (Node 22+).
// Resolve node:module lazily so node:process stays out of the eager snapshot.
export function getBuiltinModule(id) {
  return lazyNodeModule().getBuiltinModule(id);
}

// Lazy getter: a direct assignment here would call `lazyNodeModule()` at
// node:process eval time, eagerly pulling node:module's closure (and the
// cold-bootstrap TDZ cascade). Resolve node:module only when
// `process.getBuiltinModule` is first accessed.
ObjectDefineProperty(process, "getBuiltinModule", {
  __proto__: null,
  get() {
    return lazyNodeModule().getBuiltinModule;
  },
  set(v) {
    ObjectDefineProperty(process, "getBuiltinModule", {
      __proto__: null,
      value: v,
      writable: true,
      enumerable: true,
      configurable: true,
    });
  },
  enumerable: true,
  configurable: true,
});

// TODO(kt3k): Implement this when we added -e option to node compat mode
process._eval = undefined;

export function loadEnvFile(path = ".env") {
  if (typeof path !== "string") {
    fsUtilsModule ??= lazyLoadFsUtils();
    path = fsUtilsModule.getValidatedPathToString(path);
  }

  try {
    return op_node_load_env_file(path);
  } catch (err) {
    if (ObjectPrototypeIsPrototypeOf(Deno.errors.InvalidData.prototype, err)) {
      throw new NodeTypeError(
        "ERR_INVALID_ARG_TYPE",
        `Contents of '${path}' should be a valid string.`,
      );
    }
    throw denoErrorToNodeError(err as Error, { syscall: "open", path });
  }
}

process.loadEnvFile = loadEnvFile;

/** https://nodejs.org/api/process.html#processexecpath */

ObjectDefineProperty(process, "execPath", {
  __proto__: null,
  get() {
    return String(execPath);
  },
  set(path: string) {
    execPath = path;
  },
});

/** https://nodejs.org/api/process.html#processuptime */
process.uptime = () => {
  return Number(NumberPrototypeToFixed(performance.now() / 1000, 9));
};

/** https://nodejs.org/api/process.html#processallowednodeenvironmentflags */
ObjectDefineProperty(process, "allowedNodeEnvironmentFlags", {
  __proto__: null,
  get() {
    return ALLOWED_FLAGS;
  },
});

export const allowedNodeEnvironmentFlags = ALLOWED_FLAGS;

const features = {
  inspector: true,
  // TODO(bartlomieju): not sure if it's worth getting actual value during build process
  debug: false,
  uv: true,
  ipv6: true,
  // deno-lint-ignore camelcase
  tls_alpn: true,
  // deno-lint-ignore camelcase
  tls_sni: true,
  // deno-lint-ignore camelcase
  tls_ocsp: true,
  tls: true,
  // Deno uses aws-lc, which is BoringSSL-based.
  // deno-lint-ignore camelcase
  openssl_is_boringssl: true,
  quic: false,
  // deno-lint-ignore camelcase
  cached_builtins: true,
  // deno-lint-ignore camelcase
  require_module: true,
  get typescript() {
    if (Deno.build.standalone) {
      return false;
    }
    return "transform";
  },
};

ObjectDefineProperty(process, "features", {
  __proto__: null,
  enumerable: true,
  writable: false,
  configurable: false,
  value: features,
});

// TODO(kt3k): Get the value from --no-deprecation flag.
process.noDeprecation = false;

process.moduleLoadList = [];

if (isWindows) {
  delete process.getgid;
  delete process.getuid;
  delete process.getegid;
  delete process.geteuid;
  delete process.getgroups;
}

ObjectDefineProperty(process, SymbolToStringTag, {
  __proto__: null,
  enumerable: false,
  writable: true,
  configurable: false,
  value: "process",
});

addReadOnlyProcessAlias("noDeprecation", "--no-deprecation");
addReadOnlyProcessAlias("throwDeprecation", "--throw-deprecation");

export const removeListener = process.removeListener;
export const removeAllListeners = process.removeAllListeners;

let unhandledRejectionListenerCount = 0;
let rejectionHandledListenerCount = 0;
let uncaughtExceptionListenerCount = 0;
let uncaughtExceptionMonitorListenerCount = 0;
let beforeExitListenerCount = 0;
let exitListenerCount = 0;

addProcessListenerInternal(process, "newListener", (event: string) => {
  switch (event) {
    case "unhandledRejection":
      unhandledRejectionListenerCount++;
      break;
    case "rejectionHandled":
      rejectionHandledListenerCount++;
      break;
    case "uncaughtException":
      uncaughtExceptionListenerCount++;
      break;
    case "uncaughtExceptionMonitor":
      uncaughtExceptionMonitorListenerCount++;
      break;
    case "beforeExit":
      beforeExitListenerCount++;
      break;
    case "exit":
      exitListenerCount++;
      break;
    default:
      return;
  }
  synchronizeListeners();
}, false);

addProcessListenerInternal(process, "removeListener", (event: string) => {
  switch (event) {
    case "unhandledRejection":
      unhandledRejectionListenerCount--;
      break;
    case "rejectionHandled":
      rejectionHandledListenerCount--;
      break;
    case "uncaughtException":
      uncaughtExceptionListenerCount--;
      break;
    case "uncaughtExceptionMonitor":
      uncaughtExceptionMonitorListenerCount--;
      break;
    case "beforeExit":
      beforeExitListenerCount--;
      break;
    case "exit":
      exitListenerCount--;
      break;
    default:
      return;
  }
  synchronizeListeners();
}, false);

function processOnError(event: ErrorEvent) {
  if (typeof fatalExceptionHandler === "function") {
    if (fatalExceptionHandler(event.error)) {
      event.preventDefault();
    }
  } else {
    // Exit code 6: _fatalException is not a function
    // (kInvalidFatalExceptionMonkeyPatching in Node.js)
    process.exitCode = 6;
  }
}

function dispatchProcessBeforeExitEvent() {
  try {
    process.emit("beforeExit", process.exitCode || 0);
  } catch (_e) {
    // When 'beforeExit' throws, Node.js emits 'exit' and then terminates
    // with the current exitCode. The 'exit' handler can set exitCode to
    // override the exit status.
    if (process.exitCode == null) {
      process.exitCode = 1;
    }
    dispatchProcessExitEvent();
    Deno.exit(process.exitCode || 0);
  }
  core.processTicksAndRejections();
  return core.eventLoopHasMoreWork();
}

function dispatchProcessExitEvent() {
  if (!process._exiting) {
    process._exiting = true;
    process.emit("exit", process.exitCode || 0);
  }
}

function synchronizeListeners() {
  // Install special "unhandledrejection" handler, that will be called
  // last.
  if (
    unhandledRejectionListenerCount > 0 ||
    uncaughtExceptionListenerCount > 0 ||
    uncaughtExceptionMonitorListenerCount > 0 ||
    _uncaughtExceptionCaptureFn !== null
  ) {
    internals.nodeProcessUnhandledRejectionCallback = (event) => {
      if (process.listenerCount("unhandledRejection") === 0) {
        // The Node.js default behavior is to raise an uncaught exception if
        // an unhandled rejection occurs and there are no unhandledRejection
        // listeners.

        let reason = event.reason;

        // The synchronous Module._load path in 01_require.js already invoked
        // process._fatalException for this error. Re-firing here would
        // double-emit 'uncaughtExceptionMonitor' (and 'uncaughtException')
        // for the same value. Skip and let Deno's default unhandled-rejection
        // handling print the error and terminate the runtime.
        if (
          reason !== null && typeof reason === "object" &&
          _dispatchedFatalErrors.has(reason)
        ) {
          return;
        }

        // If the rejection reason is not an Error, wrap it in an
        // ERR_UNHANDLED_REJECTION error, matching Node.js behavior.
        if (!ObjectPrototypeIsPrototypeOf(ErrorPrototype, reason)) {
          const message = "This error originated either by throwing " +
            "inside of an async function without a catch block, or by rejecting a " +
            "promise which was not handled with .catch(). The promise rejected with the" +
            ` reason "${reason}".`;
          const err = new Error(message);
          // deno-lint-ignore no-explicit-any
          (err as any).code = "ERR_UNHANDLED_REJECTION";
          // deno-lint-ignore no-explicit-any
          (err as any).reason = event.reason;
          ObjectDefineProperty(err, "name", {
            __proto__: null,
            value: "UnhandledPromiseRejection",
            writable: true,
            configurable: true,
          });
          reason = err;
        }

        // Only preventDefault if a registered handler (uncaughtException
        // listener or capture callback) actually consumed the error.
        // Otherwise we want the runtime to terminate normally.
        if (uncaughtExceptionHandler(reason, "unhandledRejection")) {
          event.preventDefault();
        }
        return;
      }

      event.preventDefault();
      emitProcessExceptionInternal(
        "unhandledRejection",
        event.reason,
        event.promise,
      );
    };
  } else {
    internals.nodeProcessUnhandledRejectionCallback = undefined;
  }

  // Install special "handledrejection" handler, that will be called
  // last.
  if (rejectionHandledListenerCount > 0) {
    internals.nodeProcessRejectionHandledCallback = (event) => {
      emitProcessExceptionInternal(
        "rejectionHandled",
        event.reason,
        event.promise,
      );
    };
  } else {
    internals.nodeProcessRejectionHandledCallback = undefined;
  }

  if (
    uncaughtExceptionListenerCount > 0 ||
    uncaughtExceptionMonitorListenerCount > 0 ||
    _uncaughtExceptionCaptureFn !== null
  ) {
    globalThis.addEventListener("error", processOnError);
  } else {
    globalThis.removeEventListener("error", processOnError);
  }
}

internals.dispatchProcessBeforeExitEvent = dispatchProcessBeforeExitEvent;
internals.dispatchProcessExitEvent = dispatchProcessExitEvent;

// Resolves the value for `process.argv[1]` from trusted bootstrap metadata or
// `Deno.mainModule`. Converting a `file:` URL to a path can throw (e.g.
// `URIError: URI malformed` when the path contains invalid percent-encoding),
// and this runs during bootstrap where an uncaught throw aborts the runtime
// with a panic. Fall back to the raw specifier so a non-decodable main module
// can't crash the process.
//
// Node workers do not expose their entry through `Deno.mainModule`. Their
// runtime-supplied module specifier must therefore win before the legacy cwd
// fallback. Calling public `Deno.cwd()` from worker bootstrap is both
// unnecessary and, under capsec, correctly rejected as unattributed
// runtime-control inspection.
// @ref LLP 0010#revision-11-patch-profile [implements] -- Trusted worker bootstrap consumes its private entry identity instead of bypassing package-facing cwd mediation.
function mainModuleArgv(
  workerModuleSpecifier: string | null,
): string {
  if (Deno.build.standalone) {
    return Deno.execPath();
  }
  const mainModule = workerModuleSpecifier ?? Deno.mainModule;
  if (mainModule?.startsWith("file:")) {
    try {
      return pathFromURL(new URL(mainModule));
    } catch {
      return mainModule;
    }
  }
  if (workerModuleSpecifier !== null) {
    return workerModuleSpecifier;
  }
  return join(Deno.cwd(), "$deno$node.mjs");
}

// Should be called only once, in `runtime/js/99_main.js` when the runtime is
// bootstrapped.
internals.__bootstrapNodeProcess = function (
  argv0Val: string | undefined,
  args: string[],
  denoVersions: Record<string, string>,
  nodeDebug: string,
  warmup = false,
  runningOnMainThread = true,
  moduleSpecifier: string | null = null,
) {
  if (!warmup) {
    // Idempotent: under node-defer this runs either from node:process's own
    // deferred trigger (process bootstrap) or from 01_require.js's initialize
    // (full bootstrap) -- whichever node module loads first. The second caller
    // must not re-run the process setup.
    if (internals.__nodeProcessBootstrapped) {
      return;
    }
    internals.__nodeProcessBootstrapped = true;
    // Register the stream-wrap GothamState (used by net/tcp/pipe handles and
    // process._getActiveHandles). Previously this ran in 01_require.js's
    // `initialize`; under node-defer that no longer auto-runs, and the op
    // panics ("StreamBaseState is not present") if a net handle is used before
    // it. It is self-contained (no node:module), so run it here as part of the
    // process bootstrap that node:process triggers on first node:* use.
    const { streamBaseState } = core.loadExtScript(
      "ext:deno_node/internal_binding/stream_wrap.ts",
    );
    op_stream_base_register_state(streamBaseState);
    argv0 = argv0Val || "";
    argv[0] = Deno.execPath();
    argv[1] = mainModuleArgv(moduleSpecifier);
    // Manually concatenate these arrays to avoid triggering the getter
    for (let i = 0; i < args.length; i++) {
      argv[i + 2] = args[i];
    }

    const denoVersionEntries = ObjectEntries(denoVersions);
    for (let i = 0; i < denoVersionEntries.length; i++) {
      const entry = denoVersionEntries[i];
      versions[entry[0]] = entry[1];
    }

    enableNextTick();

    // process.stdout / process.stderr are built lazily on first access.
    // Constructing them eagerly here pulls the node stream/net/tty closure
    // into the snapshot for every program (TTYWriteStream extends net.Socket;
    // the pipe path builds a node Writable). Most `deno run` invocations never
    // touch process.stdout (Deno's own `console` doesn't route through it), so
    // deferring construction keeps that closure out of the deserialized heap.
    const makeStdioWriteStream = (fd, ioStream, name) => {
      let s;
      if (ioStream.isTerminal()) {
        const { WriteStream } = lazyTtyMod();
        s = new WriteStream(fd);
        // For supporting legacy API we put the FD here.
        s.fd = fd;
        // Match Node.js: stdio streams are indestructible. Libraries like
        // mute-stream (@inquirer/prompts) call destroy()/end() on
        // process.stdout between prompts. `_isStdio` also prevents
        // Stream.pipe() from calling end() on stdout when a source ends.
        s._isStdio = true;
        s.destroySoon = s.destroy;
        s._destroy = function (err, cb) {
          cb(err);
          this._undestroy();
          if (!this._writableState.emitClose) {
            nextTick(() => this.emit("close"));
          }
        };
      } else {
        s = lazyStreamsMod().createWritableStdioStream(ioStream, name);
      }
      return s;
    };
    ObjectDefineProperty(process, "stdout", {
      __proto__: null,
      configurable: true,
      enumerable: true,
      get() {
        return stdout != null && !streamDelegates.has(stdout)
          ? stdout
          : (stdout = makeStdioWriteStream(1, io.stdout, "stdout"));
      },
      set(v) {
        stdout = v;
      },
    });
    ObjectDefineProperty(process, "stderr", {
      __proto__: null,
      configurable: true,
      enumerable: true,
      get() {
        return stderr != null && !streamDelegates.has(stderr)
          ? stderr
          : (stderr = makeStdioWriteStream(2, io.stderr, "stderr"));
      },
      set(v) {
        stderr = v;
      },
    });
    core.loadExtScript("ext:deno_node/internal/console/constructor.mjs")
      .bindStreamsLazy(globalThis.console, process);

    arch = arch_();
    platform = isWindows ? "win32" : Deno.build.os;
    pid = Deno.pid;
    ppid = Deno.ppid;
    execPath = Deno.execPath();
    initializeDebugEnv(nodeDebug);

    const title = getOptionValue("--title");
    if (title) {
      process.title = title;
    }

    if (getOptionValue("--warnings")) {
      process.on("warning", onWarning);
    }

    // Match Node's pre_execution.js: when --pending-deprecation is set, wrap
    // `process.binding` with a DEP0111 warning, and wrap the `uv` binding's
    // `errname` with DEP0119. See lib/internal/process/pre_execution.js and
    // src/uv.cc (`ErrName`) in the upstream Node.js source.
    if (getOptionValue("--pending-deprecation")) {
      const { deprecate } = lazyLoadUtil();
      const uvBinding = getBinding("uv");
      uvBinding.errname = deprecate(
        uvBinding.errname,
        "Directly calling process.binding('uv').errname(<val>) is being " +
          "deprecated. Please make sure to use util.getSystemErrorName() " +
          "instead.",
        "DEP0119",
      );
      process.binding = deprecate(
        process.binding,
        "process.binding() is deprecated. Please use public APIs instead.",
        "DEP0111",
      );
    }

    // process.stdin lazily - initStdin() pulls the stream machinery, so defer
    // it until process.stdin is actually accessed.
    let stdinInitialized = false;
    ObjectDefineProperty(process, "stdin", {
      __proto__: null,
      configurable: true,
      enumerable: true,
      get() {
        if (!stdinInitialized || streamDelegates.has(stdin)) {
          stdinInitialized = true;
          // Replace stdin if it is not a terminal.
          const newStdin = lazyStreamsMod().initStdin();
          if (newStdin) {
            stdin = newStdin;
          }
        }
        return stdin;
      },
      set(v) {
        stdinInitialized = true;
        stdin = v;
      },
    });

    // In worker threads, replace certain process functions with stubs
    // that throw ERR_WORKER_UNSUPPORTED_OPERATION and have .disabled = true.
    // Ref: https://github.com/nodejs/node/blob/main/lib/internal/bootstrap/switches/is_not_main_thread.js
    if (!runningOnMainThread) {
      const disabledFns = [
        "abort",
        "chdir",
        "send",
        "disconnect",
        "setuid",
        "seteuid",
        "setgid",
        "setegid",
        "setgroups",
        "initgroups",
      ];
      for (let i = 0; i < disabledFns.length; i++) {
        const fn = disabledFns[i];
        const stub = function () {
          throw new ERR_WORKER_UNSUPPORTED_OPERATION(
            `process.${fn}()`,
          );
        };
        stub.disabled = true;
        process[fn] = stub;
      }

      ObjectDefineProperty(process, "channel", {
        __proto__: null,
        get() {
          throw new ERR_WORKER_UNSUPPORTED_OPERATION("process.channel");
        },
        configurable: true,
      });
      ObjectDefineProperty(process, "connected", {
        __proto__: null,
        get() {
          throw new ERR_WORKER_UNSUPPORTED_OPERATION("process.connected");
        },
        configurable: true,
      });

      // Inspector control APIs are main-thread-only in Node; matches the
      // assertions in parallel/test-worker-unsupported-things.js.
      delete process._debugEnd;
      delete process._debugProcess;
    }

    // NOTE: we used to delete internals.__bootstrapNodeProcess here. Under
    // node-defer 01_require.js's deferred trigger calls `initialize()`
    // (which in turn calls this function) after the node:process self-trigger
    // ran. The idempotency guard above (`__nodeProcessBootstrapped`) handles
    // the double call; keeping the function reachable just avoids crashing
    // that second call with "undefined is not a function".
  } else {
    // Warmup, assuming stdin/stdout/stderr are all terminals. Loaded lazily
    // (the stream machinery is no longer statically imported); this branch
    // only runs if nodeBootstrap warmup is invoked.
    const streams = lazyStreamsMod();
    stdin = process.stdin = streams.initStdin(true);

    /** https://nodejs.org/api/process.html#process_process_stdout */
    stdout = process.stdout = streams.createWritableStdioStream(
      io.stdout,
      "stdout",
      true,
    );

    /** https://nodejs.org/api/process.html#process_process_stderr */
    stderr = process.stderr = streams.createWritableStdioStream(
      io.stderr,
      "stderr",
      true,
    );
  }
};

// node-defer: node:process is lazy_loaded_esm, so it evaluates on first node:*
// use rather than at snapshot bootstrap. By then 99_main has stashed the
// bootstrap args on `internals` (it found `globalThis.nodeBootstrap` undefined,
// since 01_require.js -- which sets it -- is also deferred). Run the process
// bootstrap now so process.stdout/argv/pid/etc. are wired.
//
// We call `__bootstrapNodeProcess` DIRECTLY rather than the full
// `nodeBootstrap`/`initialize`: `initialize` loads node:module, and doing that
// while node:process is still mid-evaluation re-pulls the node closure
// (cluster/etc.) which then captures this not-yet-finished module and TDZs.
// `__bootstrapNodeProcess` only touches the `process` object and installs LAZY
// stdio getters, so it loads no closure here; the stream machinery loads only
// when process.stdout is first accessed, by which point node:process is fully
// evaluated. The remaining init (worker_threads, cluster, stream_wrap) runs
// from 01_require.js's own deferred trigger when node:module is first loaded.
// `__nodeBootstrapArgs` is intentionally left set so that path can complete it.
if (internals.__nodeBootstrapArgs !== undefined) {
  const a = internals.__nodeBootstrapArgs;
  internals.__bootstrapNodeProcess(
    a.argv0,
    a.denoArgs,
    a.denoVersion,
    a.nodeDebug ?? "",
    false,
    a.runningOnMainThread,
    a.moduleSpecifier,
  );
  // NOTE: the full worker_threads init (`__initWorkerThreads`, which aliases
  // globalThis.MessageChannel/MessagePort to the node classes) is NOT run
  // here -- its `setupCrossThreadMessaging` captures node:process and hits a
  // mid-eval TDZ when invoked from inside node:process's own evaluation. It
  // is finished from 01_require.js's deferred trigger (bottom of file),
  // which only runs after node:process is fully evaluated.
}

export default process;
