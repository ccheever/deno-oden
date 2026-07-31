// Copyright 2018-2026 the Deno authors. MIT license.
// Copyright Joyent, Inc. and Node.js contributors. All rights reserved. MIT license.

import { core, internals, primordials } from "ext:core/mod.js";
// Capture before `core` can reach user code through the public Deno facade.
// Trusted process-event bookkeeping must not consult a mutable classifier.
const coreIsProxy = core.isProxy;
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

const {
  addEventListenerWithTableAccess,
  emitEventWithTableAccess,
  EventEmitter,
  eventListenerCountWithTableAccess,
  eventListenersWithTableAccess,
  initializeEventEmitterStorage,
  protectedEventEmitterEmit,
  removeAllEventListenersWithTableAccess,
  removeEveryEventListenerWithTableAccess,
  removeEventListenerWithTableAccess,
  setEventTableAccess,
} = core.loadExtScript("ext:deno_node/_events.mjs");
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
const {
  addSignalListener: addDenoSignalListener,
  addSignalListenerInternal: addDenoSignalListenerInternal,
  removeSignalListener: removeDenoSignalListener,
  removeSignalListenerInternal: removeDenoSignalListenerInternal,
} = core.loadExtScript("ext:deno_os/40_signals.js");

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
  ArrayPrototype,
  ArrayPrototypeFind,
  ArrayPrototypePush,
  ArrayPrototypeSlice,
  ArrayPrototypeUnshift,
  BigInt,
  Error,
  ErrorCaptureStackTrace,
  ErrorPrototype,
  Float64Array,
  FunctionPrototypeBind,
  FunctionPrototypeCall,
  MathFloor,
  MapPrototypeGetSize,
  Number,
  NumberIsFinite,
  NumberIsInteger,
  NumberMAX_SAFE_INTEGER,
  NumberPrototypeToFixed,
  ObjectCreate,
  ObjectDefineProperty,
  ObjectEntries,
  ObjectFreeze,
  ObjectHasOwn,
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
  ReflectIsExtensible,
  ReflectOwnKeys,
  ReflectPreventExtensions,
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
  // Resource, stdio terminal, and timer snapshots reveal process-wide
  // activity. Invoke the guarded resource-name helper first so the registered
  // boundary denies before any component is observed, then preserve the
  // public result order with its saved names.
  // @ref LLP 0019#runtime-and-memory-inspection [implements]
  const activeResourceNames = getActiveResourceNames();
  const result: string[] = [];
  for (const name of new SafeArrayIterator(getStdioActiveResources())) {
    ArrayPrototypePush(result, name);
  }
  for (const name of new SafeArrayIterator(activeResourceNames)) {
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

  initializeEventEmitterStorage(this);
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

function defineProcessPrototypeMethod(name: string, value: unknown) {
  ObjectDefineProperty(Process.prototype, name, {
    __proto__: null,
    configurable: true,
    enumerable: true,
    value,
    writable: true,
  });
}

// Deno's signal registry is a Set, whereas Node's process signal listeners are
// an ordered EventEmitter list that permits duplicates and prepending. Keep
// one closure-owned native dispatcher per signal and let the exact lexical
// process event table determine every delivery recipient and order.
type ProcessSignalRegistration = {
  count: number;
  dispatcher: () => void;
  event: string;
};
const processSignalRegistrations = new SafeMap<
  string,
  ProcessSignalRegistration
>();

function emitProcessSignalInternal(event: string) {
  const args = ObjectCreate(null);
  ObjectDefineProperty(args, "0", {
    __proto__: null,
    value: event,
  });
  ObjectDefineProperty(args, "length", {
    __proto__: null,
    value: 1,
  });
  return emitEventWithTableAccess(
    process,
    event,
    args,
    trustedProcessEventTableAccess,
  );
}

function prepareProcessSignalRegistration(
  event: string,
  listenerCount: number,
  trustedRuntime = false,
): ProcessSignalRegistration {
  let record = processSignalRegistrations.get(event);
  if (
    (listenerCount === 0 && record !== undefined) ||
    (listenerCount !== 0 &&
      (record === undefined || record.count !== listenerCount))
  ) {
    throw new TypeError("process signal registration is inexact before add");
  }
  if (record === undefined) {
    record = {
      __proto__: null,
      count: 0,
      dispatcher: () => emitProcessSignalInternal(event),
      event,
    };
    processSignalRegistrations.set(event, record);
  }
  if (record.count === 0) {
    const add = trustedRuntime
      ? addDenoSignalListenerInternal
      : addDenoSignalListener;
    try {
      add(event as Deno.Signal, record.dispatcher);
    } catch (error) {
      if (processSignalRegistrations.get(event) === record) {
        processSignalRegistrations.delete(event);
      }
      throw error;
    }
  }
  record.count++;
  return record;
}

function cancelProcessSignalRegistration(
  event: string,
  expected: ProcessSignalRegistration,
): void {
  const record = processSignalRegistrations.get(event);
  if (record !== expected || record.count === 0) {
    throw new TypeError("process signal registration changed during rollback");
  }
  if (record.count > 1) {
    record.count--;
    return;
  }
  removeDenoSignalListenerInternal(event as Deno.Signal, record.dispatcher);
  record.count = 0;
  if (processSignalRegistrations.get(event) === record) {
    processSignalRegistrations.delete(event);
  }
}

function prepareProcessSignalRemoval(
  event: string,
  listenerCount: number,
): ProcessSignalRegistration {
  const record = processSignalRegistrations.get(event);
  if (record === undefined || record.count !== listenerCount) {
    throw new TypeError("process signal registration is inexact");
  }
  return record;
}

function prepareProcessSignalAddition(table, event: string) {
  const store = requireDirectProcessEventTable(table);
  const stored = requireStoredProcessEventValue(table, event);
  const listenerCount = stored === undefined
    ? 0
    : typeof stored === "function"
    ? 1
    : requireStoredProcessEventListenerArray(table, event, stored);
  if (listenerCount === 0 && !ReflectIsExtensible(store)) {
    throw new TypeError(
      "process signal listener cannot be added to an inextensible table",
    );
  }
  requireCurrentProcessEventTable(store, table);
  return listenerCount;
}

function finishProcessSignalRemoval(
  event: string,
  expected: ProcessSignalRegistration,
  trustedRuntime = false,
): void {
  const record = processSignalRegistrations.get(event);
  if (record !== expected || record.count === 0) {
    throw new TypeError("process signal registration changed during removal");
  }
  if (record.count > 1) {
    record.count--;
    return;
  }
  const remove = trustedRuntime
    ? removeDenoSignalListenerInternal
    : removeDenoSignalListener;
  remove(event as Deno.Signal, record.dispatcher);
  record.count = 0;
  if (processSignalRegistrations.get(event) === record) {
    processSignalRegistrations.delete(event);
  }
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

// EventEmitter property access performs ToPropertyKey. Do that conversion
// exactly once, before any guard or one-shot internal authority is armed, and
// carry only the resulting primitive through the guarded table protocol.
// @ref LLP 0019#runtime-and-memory-inspection [implements]
// deno-lint-ignore no-explicit-any
function normalizeProcessEventKey(event: any): string | symbol {
  if (typeof event === "string" || typeof event === "symbol") return event;
  const holder = ObjectCreate(null);
  if (
    !ReflectDefineProperty(holder, event, {
      __proto__: null,
      value: true,
    })
  ) {
    throw new TypeError("process event name could not be normalized");
  }
  const keys = ReflectOwnKeys(holder);
  if (keys.length !== 1) {
    throw new TypeError("process event name normalization was inexact");
  }
  return keys[0] as string | symbol;
}

let trustedProcessMetaEmission;
let processEventTableAccess;
let trustedProcessEventTableAccess;
let processEmitInternal;
const processOnceListenerOriginals = new SafeWeakMap();

function createProcessEventApplyArguments(
  event: unknown,
  args: readonly unknown[],
) {
  const owned = ObjectCreate(null);
  ObjectDefineProperty(owned, "0", {
    __proto__: null,
    value: event,
  });
  for (let index = 0; index < args.length; index++) {
    ObjectDefineProperty(owned, index + 1, {
      __proto__: null,
      value: args[index],
    });
  }
  ObjectDefineProperty(owned, "length", {
    __proto__: null,
    value: args.length + 1,
  });
  return owned;
}

function emitTrustedProcessLifecycleMetaEvent(
  target,
  metaEvent: "newListener" | "removeListener",
  args,
) {
  if (
    target !== process || args.length !== 2 ||
    !isProtectedProcessMetaEvent(metaEvent) ||
    trustedProcessMetaEmission !== undefined ||
    processEmitInternal === undefined
  ) {
    throw new TypeError("invalid internal process lifecycle emission");
  }
  const expected = {
    __proto__: null,
    metaEvent,
    target,
    targetEvent: args[0],
    listener: args[1],
  };
  trustedProcessMetaEmission = expected;
  try {
    return FunctionPrototypeCall(
      processEmitInternal,
      target,
      metaEvent,
      args[0],
      args[1],
    );
  } finally {
    if (
      trustedProcessMetaEmission !== undefined &&
      trustedProcessMetaEmission !== expected
    ) {
      throw new TypeError("internal process lifecycle emission was replaced");
    }
    trustedProcessMetaEmission = undefined;
  }
}

function addProcessListenerInternal(
  target,
  event,
  listener,
  prepend,
  trustedRuntime = false,
) {
  validateFunction(listener, "listener");
  event = normalizeProcessEventKey(event);
  const eventTableAccess = trustedRuntime
    ? trustedProcessEventTableAccess
    : processEventTableAccess;
  if (trustedRuntime && target !== process) {
    throw new TypeError("trusted process event target is inexact");
  }
  if (target === process) {
    if (eventTableAccess === undefined) {
      throw new TypeError("process event table access is uninitialized");
    }
    return addEventListenerWithTableAccess(
      target,
      event,
      listener,
      prepend,
      eventTableAccess,
    );
  }
  return FunctionPrototypeCall(
    prepend
      ? EventEmitter.prototype.prependListener
      : EventEmitter.prototype.on,
    target,
    event,
    listener,
  );
}

function removeProcessListenerInternal(
  target,
  event,
  listener,
  trustedRuntime = false,
) {
  validateFunction(listener, "listener");
  event = normalizeProcessEventKey(event);
  const eventTableAccess = trustedRuntime
    ? trustedProcessEventTableAccess
    : processEventTableAccess;
  if (trustedRuntime && target !== process) {
    throw new TypeError("trusted process event target is inexact");
  }
  if (target === process) {
    if (eventTableAccess === undefined) {
      throw new TypeError("process event table access is uninitialized");
    }
    return removeEventListenerWithTableAccess(
      target,
      event,
      listener,
      eventTableAccess,
      false,
    );
  }
  return FunctionPrototypeCall(
    EventEmitter.prototype.removeListener,
    target,
    event,
    listener,
  );
}

/** https://nodejs.org/api/process.html#process_process_events */
defineProcessPrototypeMethod("on", function on(
  // deno-lint-ignore no-explicit-any
  this: any,
  event: string,
  // deno-lint-ignore no-explicit-any
  listener: (...args: any[]) => void,
) {
  validateFunction(listener, "listener");
  const eventKey = normalizeProcessEventKey(event);
  guardProcessExceptionEvent(eventKey, "process.on");
  guardProcessMetaEvent(eventKey, "process.on");
  if (
    this === process && typeof eventKey === "string" &&
    StringPrototypeStartsWith(eventKey, "SIG")
  ) {
    if (eventKey === "SIGBREAK" && Deno.build.os !== "windows") {
      // Ignores SIGBREAK if the platform is not windows.
    } else if (eventKey === "SIGTERM" && Deno.build.os === "windows") {
      // Ignores SIGTERM on windows.
    } else if (
      eventKey !== "SIGBREAK" && eventKey !== "SIGINT" &&
      eventKey !== "SIGWINCH" && Deno.build.os === "windows"
    ) {
      // TODO(#26331): Ignores all signals except SIGBREAK, SIGINT, and SIGWINCH on windows.
    } else {
      guardProcessSignalEvent(eventKey, "listen", "process.on");
      addProcessListenerInternal(this, eventKey, listener, false);
    }
  } else {
    addProcessListenerInternal(this, eventKey, listener, false);
  }

  return this;
});

defineProcessPrototypeMethod("off", function off(
  // deno-lint-ignore no-explicit-any
  this: any,
  event: string,
  // deno-lint-ignore no-explicit-any
  listener: (...args: any[]) => void,
) {
  validateFunction(listener, "listener");
  const eventKey = normalizeProcessEventKey(event);
  guardProcessExceptionEvent(eventKey, "process.off");
  guardProcessMetaEvent(eventKey, "process.off");
  if (
    this === process && typeof eventKey === "string" &&
    StringPrototypeStartsWith(eventKey, "SIG")
  ) {
    if (eventKey === "SIGBREAK" && Deno.build.os !== "windows") {
      // Ignores SIGBREAK if the platform is not windows.
    } else if (
      eventKey !== "SIGBREAK" && eventKey !== "SIGINT" &&
      eventKey !== "SIGWINCH" && Deno.build.os === "windows"
    ) {
      // Ignores all signals except SIGBREAK, SIGINT, and SIGWINCH on windows.
    } else {
      guardProcessSignalEvent(eventKey, "unlisten", "process.off");
      removeProcessListenerInternal(this, eventKey, listener);
    }
  } else {
    removeProcessListenerInternal(this, eventKey, listener);
  }

  return this;
});

defineProcessPrototypeMethod("emit", function emit(
  // deno-lint-ignore no-explicit-any
  this: any,
  event: string,
  // deno-lint-ignore no-explicit-any
  ...args: any[]
): boolean {
  const eventKey = normalizeProcessEventKey(event);
  guardProcessSignalEvent(eventKey, "emit", "process.emit");
  let trustedMetaEmission = false;
  if (isProtectedProcessMetaEvent(eventKey)) {
    const expected = trustedProcessMetaEmission;
    if (
      expected?.target === this &&
      expected?.metaEvent === eventKey &&
      args.length === 2 &&
      expected.targetEvent === args[0] &&
      expected.listener === args[1]
    ) {
      trustedProcessMetaEmission = undefined;
      trustedMetaEmission = true;
    } else {
      guardProcessMetaEvent(eventKey, `process.emit(${eventKey})`);
    }
  }
  guardProcessExceptionEvent(eventKey, "process.emit");
  if (this === process) {
    return emitEventWithTableAccess(
      this,
      eventKey,
      args,
      trustedMetaEmission
        ? trustedProcessEventTableAccess
        : processEventTableAccess,
    );
  }
  const emitArguments = createProcessEventApplyArguments(eventKey, args);
  return ReflectApply(protectedEventEmitterEmit, this, emitArguments);
});
processEmitInternal = Process.prototype.emit;

defineProcessPrototypeMethod("prependListener", function prependListener(
  // deno-lint-ignore no-explicit-any
  this: any,
  event: string,
  // deno-lint-ignore no-explicit-any
  listener: (...args: any[]) => void,
) {
  validateFunction(listener, "listener");
  const eventKey = normalizeProcessEventKey(event);
  guardProcessExceptionEvent(eventKey, "process.prependListener");
  guardProcessMetaEvent(eventKey, "process.prependListener");
  if (
    this === process && typeof eventKey === "string" &&
    StringPrototypeStartsWith(eventKey, "SIG")
  ) {
    if (eventKey === "SIGBREAK" && Deno.build.os !== "windows") {
      // Ignores SIGBREAK if the platform is not windows.
    } else {
      guardProcessSignalEvent(
        eventKey,
        "listen",
        "process.prependListener",
      );
      addProcessListenerInternal(this, eventKey, listener, true);
    }
  } else {
    addProcessListenerInternal(this, eventKey, listener, true);
  }

  return this;
});

function addProcessOnceListener(
  // deno-lint-ignore no-explicit-any
  target: any,
  event: string | symbol,
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
    try {
      removeProcessListenerInternal(target, event, wrapped, true);
    } catch (error) {
      fired = false;
      throw error;
    }
    return ReflectApply(listener, this, args);
  };
  ObjectDefineProperty(wrapped, "listener", {
    __proto__: null,
    configurable: true,
    enumerable: true,
    value: listener,
    writable: true,
  });
  processOnceListenerOriginals.set(wrapped, listener);
  addProcessListenerInternal(target, event, wrapped, prepend);
  return target;
}

defineProcessPrototypeMethod("once", function once(
  // deno-lint-ignore no-explicit-any
  this: any,
  event: string,
  // deno-lint-ignore no-explicit-any
  listener: (...args: any[]) => void,
) {
  validateFunction(listener, "listener");
  const eventKey = normalizeProcessEventKey(event);
  guardProcessExceptionEvent(eventKey, "process.once");
  guardProcessMetaEvent(eventKey, "process.once");
  if (this === process && isProcessSignalEvent(eventKey)) {
    if (
      (eventKey === "SIGBREAK" && Deno.build.os !== "windows") ||
      (Deno.build.os === "windows" &&
        (eventKey === "SIGTERM" ||
          (eventKey !== "SIGBREAK" && eventKey !== "SIGINT" &&
            eventKey !== "SIGWINCH")))
    ) {
      return this;
    }
    guardProcessSignalEvent(eventKey, "listen", "process.once");
    return addProcessOnceListener(this, eventKey, listener, false);
  }
  return this === process &&
      (isProtectedProcessExceptionEvent(eventKey) ||
        isProtectedProcessMetaEvent(eventKey))
    ? addProcessOnceListener(this, eventKey, listener, false)
    : FunctionPrototypeCall(
      EventEmitter.prototype.once,
      this,
      eventKey,
      listener,
    );
});

defineProcessPrototypeMethod(
  "prependOnceListener",
  function prependOnceListener(
    // deno-lint-ignore no-explicit-any
    this: any,
    event: string,
    // deno-lint-ignore no-explicit-any
    listener: (...args: any[]) => void,
  ) {
    validateFunction(listener, "listener");
    const eventKey = normalizeProcessEventKey(event);
    guardProcessExceptionEvent(eventKey, "process.prependOnceListener");
    guardProcessMetaEvent(eventKey, "process.prependOnceListener");
    if (this === process && isProcessSignalEvent(eventKey)) {
      if (
        (eventKey === "SIGBREAK" && Deno.build.os !== "windows") ||
        (Deno.build.os === "windows" && eventKey !== "SIGBREAK" &&
          eventKey !== "SIGINT" && eventKey !== "SIGWINCH")
      ) {
        return this;
      }
      guardProcessSignalEvent(
        eventKey,
        "listen",
        "process.prependOnceListener",
      );
      return addProcessOnceListener(this, eventKey, listener, true);
    }
    return this === process &&
        (isProtectedProcessExceptionEvent(eventKey) ||
          isProtectedProcessMetaEvent(eventKey))
      ? addProcessOnceListener(this, eventKey, listener, true)
      : FunctionPrototypeCall(
        EventEmitter.prototype.prependOnceListener,
        this,
        eventKey,
        listener,
      );
  },
);

// Capture the guarded implementations as real aliases. Dispatching through a
// mutable `this.on`/`this.off` property would let an unrelated replacement
// intercept protected listener values before the process-specific guard.
defineProcessPrototypeMethod("addListener", Process.prototype.on);
defineProcessPrototypeMethod("removeListener", Process.prototype.off);

defineProcessPrototypeMethod("removeAllListeners", function removeAllListeners(
  // deno-lint-ignore no-explicit-any
  event?: string | any,
) {
  const eventKey = arguments.length === 0
    ? undefined
    : normalizeProcessEventKey(event);
  if (arguments.length === 0) {
    op_oden_guard_deny_only_surface(
      "runtime",
      "inspect",
      "process-exception-listeners",
      "process.removeAllListeners",
    );
  } else {
    guardProcessExceptionEvent(eventKey, "process.removeAllListeners");
    guardProcessMetaEvent(eventKey, "process.removeAllListeners");
  }
  if (arguments.length === 0) {
    if (this === process) {
      return removeEveryEventListenerWithTableAccess(
        this,
        processEventTableAccess,
      );
    }
    return FunctionPrototypeCall(
      EventEmitter.prototype.removeAllListeners,
      this,
    );
  }
  if (
    this === process && typeof eventKey === "string" &&
    StringPrototypeStartsWith(eventKey, "SIG")
  ) {
    guardProcessSignalEvent(
      eventKey,
      "unlisten",
      "process.removeAllListeners",
    );
  }
  if (this === process) {
    return removeAllEventListenersWithTableAccess(
      this,
      eventKey,
      processEventTableAccess,
    );
  }
  return FunctionPrototypeCall(
    EventEmitter.prototype.removeAllListeners,
    this,
    eventKey,
  );
});

defineProcessPrototypeMethod("listeners", function listeners(event: string) {
  const eventKey = normalizeProcessEventKey(event);
  guardProcessEventObservation(eventKey, "process.listeners");
  if (this === process) {
    return eventListenersWithTableAccess(
      this,
      eventKey,
      true,
      processEventTableAccess,
    );
  }
  return FunctionPrototypeCall(
    EventEmitter.prototype.listeners,
    this,
    eventKey,
  );
});

defineProcessPrototypeMethod(
  "rawListeners",
  function rawListeners(event: string) {
    const eventKey = normalizeProcessEventKey(event);
    guardProcessEventObservation(eventKey, "process.rawListeners");
    if (this === process) {
      return eventListenersWithTableAccess(
        this,
        eventKey,
        false,
        processEventTableAccess,
      );
    }
    return FunctionPrototypeCall(
      EventEmitter.prototype.rawListeners,
      this,
      eventKey,
    );
  },
);

defineProcessPrototypeMethod("listenerCount", function listenerCount(
  event: string,
  // deno-lint-ignore no-explicit-any
  listener?: (...args: any[]) => void,
) {
  const eventKey = normalizeProcessEventKey(event);
  guardProcessEventObservation(eventKey, "process.listenerCount");
  if (this === process) {
    return eventListenerCountWithTableAccess(
      this,
      eventKey,
      listener,
      processEventTableAccess,
    );
  }
  return FunctionPrototypeCall(
    EventEmitter.prototype.listenerCount,
    this,
    eventKey,
    listener,
  );
});

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
    return addProcessListenerInternal(
      process,
      event,
      listener,
      prepend,
      true,
    );
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
    return removeProcessListenerInternal(process, event, listener, true);
  },
);
defineNodeProcessTrustedInternalValue(
  "nodeProcessReplaceEventTableInternal",
  function (token: unknown, value: unknown) {
    requireNodeProcessTrustedToken(token);
    replaceProcessEventTable(process, value, true);
  },
);

// Borrowing EventEmitter.prototype must not bypass the process-specific
// guards. Protect the sensitive keys in the backing event table as the final
// check; ordinary process events retain normal EventEmitter behavior.
// @ref LLP 0019#runtime-and-memory-inspection [implements]
function takeInitialProcessEventStorage() {
  const eventsDescriptor = ReflectGetOwnPropertyDescriptor(process, "_events");
  const countDescriptor = ReflectGetOwnPropertyDescriptor(
    process,
    "_eventsCount",
  );
  if (
    eventsDescriptor === undefined ||
    !ObjectHasOwn(eventsDescriptor, "value") ||
    eventsDescriptor.writable !== true ||
    eventsDescriptor.enumerable !== true ||
    eventsDescriptor.configurable !== true ||
    typeof eventsDescriptor.value !== "object" ||
    eventsDescriptor.value === null ||
    coreIsProxy(eventsDescriptor.value) ||
    ReflectGetPrototypeOf(eventsDescriptor.value) !== null ||
    ReflectOwnKeys(eventsDescriptor.value).length !== 0 ||
    countDescriptor === undefined ||
    !ObjectHasOwn(countDescriptor, "value") ||
    countDescriptor.value !== 0 ||
    countDescriptor.writable !== true ||
    countDescriptor.enumerable !== true ||
    countDescriptor.configurable !== true
  ) {
    throw new TypeError("initial process event storage is inexact");
  }
  return eventsDescriptor.value;
}

// deno-lint-ignore no-explicit-any
let processEventsStore: any = takeInitialProcessEventStorage();
// deno-lint-ignore no-explicit-any
let guardedProcessEvents: any;
let processEventsVisibleCount = 0;
const trustedProcessEventTables = new SafeWeakSet<object>();
trustedProcessEventTables.add(processEventsStore);
const processEventTableGuards = new SafeWeakSet<object>();

// deno-lint-ignore no-explicit-any
function wrapProcessEvents(store: any) {
  const guarded = new Proxy(store, {
    get(target, property, receiver) {
      guardProcessExceptionEvent(property, "process._events.get");
      guardProcessMetaEvent(property, "process._events.get");
      guardProcessSignalEvent(property, "inspect", "process._events.get");
      return snapshotPublicGuardedProcessEventValue(
        target,
        property,
        ReflectGet(target, property, receiver),
      );
    },
    set(target, property, value, receiver) {
      guardProcessExceptionEvent(property, "process._events.set");
      guardProcessMetaEvent(property, "process._events.set");
      guardProcessSignalEvent(property, "control", "process._events.set");
      if (
        isProtectedProcessExceptionEvent(property) ||
        isProcessSignalEvent(property)
      ) {
        throw new TypeError(
          "direct protected process-table mutation is refused",
        );
      }
      return ReflectSet(target, property, value, receiver);
    },
    getPrototypeOf(target) {
      op_oden_guard_deny_only_surface(
        "runtime",
        "inspect",
        "process-events",
        "process._events.getPrototypeOf",
      );
      return ReflectGetPrototypeOf(target);
    },
    setPrototypeOf(target, prototype) {
      op_oden_guard_deny_only_surface(
        "runtime",
        "inspect",
        "process-events",
        "process._events.setPrototypeOf",
      );
      if (prototype !== ReflectGetPrototypeOf(target)) {
        throw new TypeError(
          "process event-table prototype mutation is refused",
        );
      }
      return true;
    },
    isExtensible(target) {
      op_oden_guard_deny_only_surface(
        "runtime",
        "inspect",
        "process-events",
        "process._events.isExtensible",
      );
      return ReflectIsExtensible(target);
    },
    preventExtensions(target) {
      op_oden_guard_deny_only_surface(
        "runtime",
        "inspect",
        "process-events",
        "process._events.preventExtensions",
      );
      return ReflectPreventExtensions(target);
    },
    defineProperty(target, property, descriptor) {
      guardProcessExceptionEvent(property, "process._events.defineProperty");
      guardProcessMetaEvent(property, "process._events.defineProperty");
      guardProcessSignalEvent(
        property,
        "control",
        "process._events.defineProperty",
      );
      if (
        isProtectedProcessExceptionEvent(property) ||
        isProcessSignalEvent(property)
      ) {
        throw new TypeError(
          "direct protected process-table mutation is refused",
        );
      }
      return ReflectDefineProperty(target, property, descriptor);
    },
    deleteProperty(target, property) {
      guardProcessExceptionEvent(property, "process._events.deleteProperty");
      guardProcessMetaEvent(property, "process._events.deleteProperty");
      guardProcessSignalEvent(
        property,
        "control",
        "process._events.deleteProperty",
      );
      if (
        isProtectedProcessExceptionEvent(property) ||
        isProcessSignalEvent(property)
      ) {
        throw new TypeError(
          "direct protected process-table mutation is refused",
        );
      }
      return ReflectDeleteProperty(target, property);
    },
    has(target, property) {
      guardProcessExceptionEvent(property, "process._events.has");
      guardProcessMetaEvent(property, "process._events.has");
      guardProcessSignalEvent(property, "inspect", "process._events.has");
      return ReflectHas(target, property);
    },
    ownKeys(target) {
      // Even deciding which protected key-specific guard applies observes the
      // shared raw event table. Close that generic observation before any
      // ReflectHas/ReflectOwnKeys probe; the later bounded guards retain the
      // exact protected key or signal classification after root admission.
      // @ref LLP 0019#runtime-and-memory-inspection [implements]
      op_oden_guard_deny_only_surface(
        "runtime",
        "inspect",
        "process-events",
        "process._events.ownKeys",
      );
      const keys = ReflectOwnKeys(target);
      for (const key of new SafeArrayIterator(keys)) {
        guardProcessExceptionEvent(key, "process._events.ownKeys");
        guardProcessMetaEvent(key, "process._events.ownKeys");
        if (typeof key === "string" && StringPrototypeStartsWith(key, "SIG")) {
          guardProcessSignalEvent(key, "inspect", "process._events.ownKeys");
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
      const descriptor = ReflectGetOwnPropertyDescriptor(target, property);
      if (
        descriptor === undefined || !ObjectHasOwn(descriptor, "value") ||
        !ArrayIsArray(descriptor.value) ||
        !isProtectedProcessTableEvent(property) ||
        !trustedProcessEventTables.has(target)
      ) {
        return descriptor;
      }
      if (target !== processEventsStore) {
        throw new TypeError("stale process event-table guard refused");
      }
      if (
        descriptor.writable !== true || descriptor.configurable !== true
      ) {
        throw new TypeError(
          "protected process listener descriptor is not safely observable",
        );
      }
      return {
        __proto__: null,
        configurable: descriptor.configurable,
        enumerable: descriptor.enumerable,
        value: snapshotPublicGuardedProcessEventValue(
          target,
          property,
          descriptor.value,
        ),
        writable: descriptor.writable,
      };
    },
  });
  processEventTableGuards.add(guarded);
  return guarded;
}

guardedProcessEvents = wrapProcessEvents(processEventsStore);

function requireCurrentProcessEventTable(store, guarded) {
  if (processEventsStore !== store || guardedProcessEvents !== guarded) {
    throw new TypeError("internal process event table changed during access");
  }
}

function requireProcessEventTableHandle(table) {
  const store = processEventsStore;
  const guarded = guardedProcessEvents;
  if (table !== guarded) {
    throw new TypeError("invalid internal process event table");
  }
  requireCurrentProcessEventTable(store, guarded);
  return store;
}

function requireDirectProcessEventTable(table) {
  const store = requireProcessEventTableHandle(table);
  if (
    !trustedProcessEventTables.has(store) || coreIsProxy(store) ||
    ReflectGetPrototypeOf(store) !== null
  ) {
    throw new TypeError(
      "trusted process event table must be an owned direct null-prototype object",
    );
  }
  requireCurrentProcessEventTable(store, table);
  return store;
}

function isProtectedProcessTableEvent(event: unknown): boolean {
  return isProtectedProcessExceptionEvent(event) ||
    isProtectedProcessMetaEvent(event) ||
    isProcessSignalEvent(event);
}

function isProcessSignalEvent(event: unknown): boolean {
  return typeof event === "string" && StringPrototypeStartsWith(event, "SIG");
}

function validateDenseProcessEventListenerArray(
  listeners,
  allowArrayPrototype: boolean,
) {
  if (!ArrayIsArray(listeners) || coreIsProxy(listeners)) {
    throw new TypeError("process event listener list must be a direct Array");
  }
  const prototype = ReflectGetPrototypeOf(listeners);
  if (
    prototype !== null &&
    (!allowArrayPrototype || prototype !== ArrayPrototype)
  ) {
    throw new TypeError("process event listener list prototype is inexact");
  }
  const lengthDescriptor = ReflectGetOwnPropertyDescriptor(
    listeners,
    "length",
  );
  const length = lengthDescriptor?.value;
  if (
    !ObjectHasOwn(lengthDescriptor ?? ObjectCreate(null), "value") ||
    lengthDescriptor?.writable !== true ||
    lengthDescriptor?.enumerable !== false ||
    lengthDescriptor?.configurable !== false ||
    !NumberIsInteger(length) || length < 0 || length > NumberMAX_SAFE_INTEGER
  ) {
    throw new TypeError("process event listener list length is inexact");
  }
  for (let index = 0; index < length; index++) {
    const descriptor = ReflectGetOwnPropertyDescriptor(listeners, index);
    if (
      descriptor === undefined || !ObjectHasOwn(descriptor, "value") ||
      descriptor.writable !== true || descriptor.enumerable !== true ||
      descriptor.configurable !== true ||
      typeof descriptor.value !== "function"
    ) {
      throw new TypeError("process event listener list is not dense data");
    }
  }
  const warnedDescriptor = ReflectGetOwnPropertyDescriptor(
    listeners,
    "warned",
  );
  if (
    warnedDescriptor !== undefined &&
    (!ObjectHasOwn(warnedDescriptor, "value") ||
      warnedDescriptor.value !== true || warnedDescriptor.writable !== true ||
      warnedDescriptor.enumerable !== true ||
      warnedDescriptor.configurable !== true)
  ) {
    throw new TypeError("process event listener warning state is inexact");
  }
  const keys = ReflectOwnKeys(listeners);
  if (keys.length !== length + 1 + (warnedDescriptor === undefined ? 0 : 1)) {
    throw new TypeError("process event listener list has extra properties");
  }
  return length;
}

function canonicalizeProcessEventListenerArray(listeners) {
  validateDenseProcessEventListenerArray(listeners, true);
  if (ReflectGetPrototypeOf(listeners) !== null) {
    if (!ReflectSetPrototypeOf(listeners, null)) {
      throw new TypeError("process event listener list could not be isolated");
    }
  }
  validateDenseProcessEventListenerArray(listeners, false);
  return listeners;
}

function requireStoredProcessEventValue(table, property) {
  const store = requireDirectProcessEventTable(table);
  const descriptor = ReflectGetOwnPropertyDescriptor(store, property);
  requireCurrentProcessEventTable(store, table);
  if (descriptor === undefined) return undefined;
  if (
    !ObjectHasOwn(descriptor, "value") || descriptor.writable !== true ||
    descriptor.enumerable !== true || descriptor.configurable !== true
  ) {
    throw new TypeError("process event-table entry is not mutable data");
  }
  const value = descriptor.value;
  if (typeof value === "function") return value;
  validateDenseProcessEventListenerArray(value, false);
  return value;
}

function getPublicLifecycleProcessEventValue(table, property) {
  const store = requireProcessEventTableHandle(table);
  if (
    trustedProcessEventTables.has(store) && !coreIsProxy(store) &&
    ReflectGetPrototypeOf(store) === null
  ) {
    return requireStoredProcessEventValue(table, property);
  }
  if (coreIsProxy(store) || ReflectGetPrototypeOf(store) !== null) {
    const value = ReflectGet(table, property, table);
    requireCurrentProcessEventTable(store, table);
    return value;
  }
  const descriptor = ReflectGetOwnPropertyDescriptor(store, property);
  requireCurrentProcessEventTable(store, table);
  if (descriptor === undefined) return undefined;
  if (!ObjectHasOwn(descriptor, "value")) {
    throw new TypeError("public process lifecycle accessor refused");
  }
  return descriptor.value;
}

function requireStoredProcessEventListenerArray(
  table,
  property,
  listeners,
) {
  const stored = requireStoredProcessEventValue(table, property);
  if (stored !== listeners || typeof stored === "function") {
    throw new TypeError("process event listener list identity changed");
  }
  return validateDenseProcessEventListenerArray(listeners, false);
}

function requirePublicProcessEventValue(table, property, expected) {
  const store = requireProcessEventTableHandle(table);
  const actual = ReflectGet(table, property, table);
  requireCurrentProcessEventTable(store, table);
  if (actual !== expected) {
    throw new TypeError("public process event-table value changed");
  }
  return actual;
}

function unwrapProcessEventListener(listener) {
  const knownOriginal = processOnceListenerOriginals.get(listener);
  if (knownOriginal !== undefined) return knownOriginal;
  if (typeof listener !== "function" || coreIsProxy(listener)) return listener;
  const descriptor = ReflectGetOwnPropertyDescriptor(listener, "listener");
  return descriptor !== undefined && ObjectHasOwn(descriptor, "value") &&
      typeof descriptor.value === "function"
    ? descriptor.value
    : listener;
}

function snapshotDirectProcessEventListeners(table, property, handler) {
  const stored = requireStoredProcessEventValue(table, property);
  if (stored !== handler) {
    throw new TypeError("process event listener snapshot identity changed");
  }
  const snapshot: unknown[] = [];
  if (!ReflectSetPrototypeOf(snapshot, null)) {
    throw new TypeError("process event listener snapshot isolation failed");
  }
  if (typeof handler === "function") {
    ObjectDefineProperty(snapshot, "0", {
      __proto__: null,
      configurable: true,
      enumerable: true,
      value: handler,
      writable: true,
    });
    return snapshot;
  }
  const length = requireStoredProcessEventListenerArray(
    table,
    property,
    handler,
  );
  for (let index = 0; index < length; index++) {
    const descriptor = ReflectGetOwnPropertyDescriptor(handler, index);
    ObjectDefineProperty(snapshot, index, {
      __proto__: null,
      configurable: true,
      enumerable: true,
      value: descriptor.value,
      writable: true,
    });
  }
  requireStoredProcessEventListenerArray(table, property, handler);
  return snapshot;
}

function snapshotPublicGuardedProcessEventValue(target, property, value) {
  if (
    !ArrayIsArray(value) || !isProtectedProcessTableEvent(property) ||
    !trustedProcessEventTables.has(target)
  ) {
    return value;
  }
  if (target !== processEventsStore) {
    throw new TypeError("stale process event-table guard refused");
  }
  const snapshot = snapshotDirectProcessEventListeners(
    guardedProcessEvents,
    property,
    value,
  );
  if (!ReflectSetPrototypeOf(snapshot, ArrayPrototype)) {
    throw new TypeError("public process listener snapshot restore failed");
  }
  return snapshot;
}

function synchronizeDirectProcessEventCount(target, table) {
  if (target !== process) {
    throw new TypeError("invalid process event count target");
  }
  const store = requireDirectProcessEventTable(table);
  const count = ReflectOwnKeys(store).length;
  requireCurrentProcessEventTable(store, table);
  processEventsVisibleCount = count;
  requireCurrentProcessEventTable(store, table);
  return count;
}

function synchronizePublicProcessEventCount(target, table, delta) {
  if (target !== process) {
    throw new TypeError("invalid public process event count target");
  }
  const store = requireProcessEventTableHandle(table);
  let count;
  if (!coreIsProxy(store) && ReflectGetPrototypeOf(store) === null) {
    count = ReflectOwnKeys(store).length;
  } else {
    count = Number(processEventsVisibleCount) + delta;
  }
  requireCurrentProcessEventTable(store, table);
  processEventsVisibleCount = count;
  requireCurrentProcessEventTable(store, table);
  return count;
}

function isOwnedDirectProcessEventTable(table) {
  const store = requireProcessEventTableHandle(table);
  const direct = trustedProcessEventTables.has(store) && !coreIsProxy(store) &&
    ReflectGetPrototypeOf(store) === null;
  requireCurrentProcessEventTable(store, table);
  return direct;
}

function setDirectProcessEventTableValue(table, property, value) {
  const store = requireDirectProcessEventTable(table);
  const descriptor = ReflectGetOwnPropertyDescriptor(store, property);
  requireCurrentProcessEventTable(store, table);
  let written;
  if (descriptor === undefined) {
    if (!ReflectIsExtensible(store)) {
      throw new TypeError("trusted process event table is not extensible");
    }
    requireCurrentProcessEventTable(store, table);
    written = ReflectDefineProperty(store, property, {
      __proto__: null,
      configurable: true,
      enumerable: true,
      value,
      writable: true,
    });
  } else {
    if (
      !ObjectHasOwn(descriptor, "value") || descriptor.writable !== true ||
      descriptor.enumerable !== true || descriptor.configurable !== true
    ) {
      throw new TypeError("trusted process event-table write refused");
    }
    written = ReflectDefineProperty(store, property, {
      __proto__: null,
      value,
    });
  }
  requireCurrentProcessEventTable(store, table);
  if (!written) {
    throw new TypeError("trusted process event-table write refused");
  }
  return value;
}

function deleteDirectProcessEventTableValue(table, property) {
  const store = requireDirectProcessEventTable(table);
  const descriptor = ReflectGetOwnPropertyDescriptor(store, property);
  requireCurrentProcessEventTable(store, table);
  if (descriptor === undefined) return true;
  if (
    !ObjectHasOwn(descriptor, "value") || descriptor.writable !== true ||
    descriptor.enumerable !== true || descriptor.configurable !== true
  ) {
    throw new TypeError("trusted process event-table deletion refused");
  }
  const deleted = ReflectDeleteProperty(store, property);
  requireCurrentProcessEventTable(store, table);
  if (!deleted) {
    throw new TypeError("trusted process event-table deletion refused");
  }
  return true;
}

function replaceEmptyProcessEventTable(target, table, value) {
  if (target !== process) {
    throw new TypeError("invalid internal process event-table target");
  }
  const store = requireProcessEventTableHandle(table);

  // A forged public `_eventsCount` can request the last-listener branch, but
  // it cannot authorize replacement. Replace only an exact, non-exotic table
  // independently observed to be empty after the exact-key deletion. Exotic
  // public tables remain installed (and empty) instead of being generalized.
  if (coreIsProxy(store) || ReflectGetPrototypeOf(store) !== null) {
    requireCurrentProcessEventTable(store, table);
    return false;
  }
  const keys = ReflectOwnKeys(store);
  requireCurrentProcessEventTable(store, table);
  if (keys.length !== 0) return false;
  if (
    coreIsProxy(value) || ReflectGetPrototypeOf(value) !== null ||
    ReflectOwnKeys(value).length !== 0
  ) {
    throw new TypeError("invalid empty process event-table replacement");
  }
  requireCurrentProcessEventTable(store, table);
  replaceProcessEventTable(target, value, true);
  return true;
}

function replaceProcessEventTable(target, value, trustedReplacement = false) {
  if (target !== process) {
    throw new TypeError("invalid internal process event-table target");
  }
  if (value === guardedProcessEvents || value === processEventsStore) {
    return;
  }
  if (!trustedReplacement && processExceptionDispatchDepth !== 0) {
    throw new TypeError(
      "process event table cannot be replaced during trusted exception dispatch",
    );
  }
  if (!trustedReplacement && _uncaughtExceptionCaptureFn !== null) {
    throw new TypeError(
      "process event table cannot be replaced with an active uncaught-exception capture callback",
    );
  }
  if (MapPrototypeGetSize(processSignalRegistrations) !== 0) {
    throw new TypeError(
      "process event table cannot be replaced with active signal listeners",
    );
  }
  if (processEventTableGuards.has(value)) {
    throw new TypeError("process event-table guards cannot be installed");
  }
  const guarded = wrapProcessEvents(value);
  if (trustedReplacement) trustedProcessEventTables.add(value);
  processEventsStore = value;
  guardedProcessEvents = guarded;
  reconcileProcessExceptionRoutingAfterTableMutation(guarded);
}

// Public EventEmitter bookkeeping receives only this frozen lexical protocol.
// Lifecycle reads reconcile the raw table with its guarded epoch handle.
// Ordinary target-key operations traverse the actual guarded Proxy so public
// Proxy [[Get]]/[[Set]]/[[Delete]] semantics remain exact. Protected entries
// use descriptor-bounded direct operations only on the closure-owned table;
// root-replaced public tables retain their real Proxy semantics but never gain
// trusted-runtime qualification.
// No table authority is installed in ambient state while user code can run.
// @ref LLP 0019#runtime-and-memory-inspection [implements]
processEventTableAccess = ObjectFreeze({
  __proto__: null,
  normalizeType(type) {
    return normalizeProcessEventKey(type);
  },
  preflightType(type, operation) {
    guardProcessExceptionEvent(type, `EventEmitter.${operation}`);
    guardProcessMetaEvent(type, `EventEmitter.${operation}`);
    const signalAction = operation === "addListener" ||
        operation === "prependListener" || operation === "once" ||
        operation === "prependOnceListener"
      ? "listen"
      : operation === "removeListener" ||
          operation === "removeAllListeners"
      ? "unlisten"
      : operation === "emit"
      ? "emit"
      : "inspect";
    guardProcessSignalEvent(type, signalAction, `EventEmitter.${operation}`);
  },
  current(target) {
    if (target !== process) {
      throw new TypeError("invalid internal process event-table target");
    }
    const table = guardedProcessEvents;
    requireProcessEventTableHandle(table);
    return table;
  },
  get(table, property) {
    if (
      isProtectedProcessTableEvent(property) &&
      isOwnedDirectProcessEventTable(table)
    ) {
      return requireStoredProcessEventValue(table, property);
    }
    const store = requireProcessEventTableHandle(table);
    const value = ReflectGet(table, property, table);
    requireCurrentProcessEventTable(store, table);
    return value;
  },
  getLifecycle(table, property) {
    return getPublicLifecycleProcessEventValue(table, property);
  },
  set(table, property, value) {
    let storedValue = value;
    const protectedEvent = isProtectedProcessTableEvent(property);
    const ownedProtectedEvent = protectedEvent &&
      isOwnedDirectProcessEventTable(table);
    const store = ownedProtectedEvent
      ? requireDirectProcessEventTable(table)
      : requireProcessEventTableHandle(table);
    if (ownedProtectedEvent) {
      requireStoredProcessEventValue(table, property);
      if (typeof storedValue !== "function") {
        storedValue = canonicalizeProcessEventListenerArray(storedValue);
      }
    }
    if (ownedProtectedEvent) {
      return setDirectProcessEventTableValue(table, property, storedValue);
    }
    const written = ReflectSet(table, property, storedValue, table);
    requireCurrentProcessEventTable(store, table);
    if (!written) {
      throw new TypeError("internal process event-table write refused");
    }
    return storedValue;
  },
  delete(table, property) {
    const protectedEvent = isProtectedProcessTableEvent(property);
    const ownedProtectedEvent = protectedEvent &&
      isOwnedDirectProcessEventTable(table);
    const store = ownedProtectedEvent
      ? requireDirectProcessEventTable(table)
      : requireProcessEventTableHandle(table);
    if (ownedProtectedEvent) {
      requireStoredProcessEventValue(table, property);
      return deleteDirectProcessEventTableValue(table, property);
    }
    const deleted = ReflectDeleteProperty(table, property);
    requireCurrentProcessEventTable(store, table);
    if (!deleted) {
      throw new TypeError("internal process event-table deletion refused");
    }
    return true;
  },
  reconcile(table) {
    requireProcessEventTableHandle(table);
  },
  prepareAddition(target, table, property, _listener) {
    if (!isProcessSignalEvent(property)) return undefined;
    if (target !== process) {
      throw new TypeError("invalid public process signal target");
    }
    const listenerCount = prepareProcessSignalAddition(table, property);
    return prepareProcessSignalRegistration(property, listenerCount, false);
  },
  cancelAddition(target, table, property, _listener, registration) {
    if (registration === undefined) return;
    if (target !== process || !isProcessSignalEvent(property)) {
      throw new TypeError("invalid public process signal rollback");
    }
    requireDirectProcessEventTable(table);
    cancelProcessSignalRegistration(property, registration);
  },
  prepareValueMutation(table, property, value) {
    if (
      isProtectedProcessTableEvent(property) &&
      isOwnedDirectProcessEventTable(table)
    ) {
      if (requireStoredProcessEventValue(table, property) !== value) {
        throw new TypeError("process event-table value changed");
      }
    } else {
      requirePublicProcessEventValue(table, property, value);
    }
  },
  prepareRemoval(target, table, property, _listener) {
    if (!isProcessSignalEvent(property)) return undefined;
    if (target !== process) {
      throw new TypeError("invalid public process signal removal target");
    }
    const stored = requireStoredProcessEventValue(table, property);
    const listenerCount = typeof stored === "function"
      ? 1
      : requireStoredProcessEventListenerArray(table, property, stored);
    return prepareProcessSignalRemoval(property, listenerCount);
  },
  prepareListMutation(table, property, listeners) {
    if (
      isProtectedProcessTableEvent(property) &&
      isOwnedDirectProcessEventTable(table)
    ) {
      requireStoredProcessEventListenerArray(table, property, listeners);
    } else {
      requirePublicProcessEventValue(table, property, listeners);
    }
  },
  finishListMutation(table, property, listeners) {
    if (
      isProtectedProcessTableEvent(property) &&
      isOwnedDirectProcessEventTable(table)
    ) {
      requireStoredProcessEventListenerArray(table, property, listeners);
    } else {
      requirePublicProcessEventValue(table, property, listeners);
    }
  },
  finishRemoval(target, property, _listener, registration) {
    if (target !== process) {
      throw new TypeError("invalid public process event removal target");
    }
    if (isProcessSignalEvent(property)) {
      finishProcessSignalRemoval(property, registration, false);
    }
  },
  listenerMatches(table, property, stored, listener) {
    if (
      isProtectedProcessTableEvent(property) &&
      isOwnedDirectProcessEventTable(table)
    ) {
      requireDirectProcessEventTable(table);
      return stored === listener ||
        unwrapProcessEventListener(stored) === listener;
    }
    const matches = stored === listener || stored.listener === listener;
    requireProcessEventTableHandle(table);
    return matches;
  },
  unwrapListener(table, property, listener) {
    if (
      isProtectedProcessTableEvent(property) &&
      isOwnedDirectProcessEventTable(table)
    ) {
      requireDirectProcessEventTable(table);
      return unwrapProcessEventListener(listener);
    }
    const unwrapped = listener.listener ?? listener;
    requireProcessEventTableHandle(table);
    return unwrapped;
  },
  snapshot(table, property, handler) {
    if (
      isProtectedProcessTableEvent(property) &&
      isOwnedDirectProcessEventTable(table)
    ) {
      return snapshotDirectProcessEventListeners(table, property, handler);
    }
    requirePublicProcessEventValue(table, property, handler);
    const snapshot = typeof handler === "function"
      ? [handler]
      : ArrayPrototypeSlice(handler);
    requirePublicProcessEventValue(table, property, handler);
    return snapshot;
  },
  finishPublicListeners(listeners) {
    if (ReflectGetPrototypeOf(listeners) === null) {
      if (!ReflectSetPrototypeOf(listeners, ArrayPrototype)) {
        throw new TypeError("public process listener snapshot restore failed");
      }
    }
    return listeners;
  },
  keys(table) {
    const store = requireProcessEventTableHandle(table);
    const keys = ReflectOwnKeys(table);
    requireCurrentProcessEventTable(store, table);
    return keys;
  },
  incrementCount(target, table) {
    if (isOwnedDirectProcessEventTable(table)) {
      return synchronizeDirectProcessEventCount(target, table);
    }
    return synchronizePublicProcessEventCount(target, table, 1);
  },
  decrementCount(target, table) {
    if (isOwnedDirectProcessEventTable(table)) {
      return synchronizeDirectProcessEventCount(target, table);
    }
    return synchronizePublicProcessEventCount(target, table, -1);
  },
  listenerAdded(target, table, property, _listener) {
    commitProcessExceptionListenerMutation(target, table, property);
  },
  listenerRemoved(target, table, property, _listener) {
    commitProcessExceptionListenerMutation(target, table, property);
  },
  checkListenerLeak() {
    return true;
  },
  removeOnce(target, type, listener) {
    return removeProcessListenerInternal(
      target,
      type,
      listener,
      isProtectedProcessTableEvent(type),
    );
  },
  replace(target, table, value) {
    return replaceEmptyProcessEventTable(target, table, value);
  },
  emitLifecycle(target, type, args) {
    return emitTrustedProcessLifecycleMetaEvent(target, type, args);
  },
});
setEventTableAccess(process, processEventTableAccess);

// Trusted runtime bookkeeping is deliberately narrower than public process
// EventEmitter behavior. It refuses Proxies, prototypes, accessors, and
// inexact descriptors before mutation, then performs descriptor-only work on
// the same direct table epoch. This channel is used only by closure-token
// runtime hooks and protected once-listener cleanup; it never becomes release
// or package authority.
// @ref LLP 0019#runtime-and-memory-inspection [implements]
trustedProcessEventTableAccess = ObjectFreeze({
  __proto__: null,
  normalizeType(type) {
    return normalizeProcessEventKey(type);
  },
  preflightType(_type, _operation) {},
  current(target) {
    if (target !== process) {
      throw new TypeError("invalid trusted process event-table target");
    }
    const table = guardedProcessEvents;
    requireDirectProcessEventTable(table);
    return table;
  },
  get(table, property) {
    return requireStoredProcessEventValue(table, property);
  },
  getLifecycle(table, property) {
    return requireStoredProcessEventValue(table, property);
  },
  set(table, property, value) {
    if (typeof value !== "function") {
      value = canonicalizeProcessEventListenerArray(value);
    }
    return setDirectProcessEventTableValue(table, property, value);
  },
  delete(table, property) {
    return deleteDirectProcessEventTableValue(table, property);
  },
  reconcile(table) {
    requireDirectProcessEventTable(table);
  },
  prepareAddition(target, table, property, _listener) {
    if (!isProcessSignalEvent(property)) return undefined;
    if (target !== process) {
      throw new TypeError("invalid trusted process signal target");
    }
    const listenerCount = prepareProcessSignalAddition(table, property);
    return prepareProcessSignalRegistration(property, listenerCount, true);
  },
  cancelAddition(target, table, property, _listener, registration) {
    if (registration === undefined) return;
    if (target !== process || !isProcessSignalEvent(property)) {
      throw new TypeError("invalid trusted process signal rollback");
    }
    requireDirectProcessEventTable(table);
    cancelProcessSignalRegistration(property, registration);
  },
  prepareValueMutation(table, property, value) {
    if (requireStoredProcessEventValue(table, property) !== value) {
      throw new TypeError("trusted process event-table value changed");
    }
  },
  prepareRemoval(target, table, property, _listener) {
    if (!isProcessSignalEvent(property)) return undefined;
    if (target !== process) {
      throw new TypeError("invalid trusted process signal removal target");
    }
    const stored = requireStoredProcessEventValue(table, property);
    const listenerCount = typeof stored === "function"
      ? 1
      : requireStoredProcessEventListenerArray(table, property, stored);
    return prepareProcessSignalRemoval(property, listenerCount);
  },
  prepareListMutation(table, property, listeners) {
    requireStoredProcessEventListenerArray(table, property, listeners);
  },
  finishListMutation(table, property, listeners) {
    requireStoredProcessEventListenerArray(table, property, listeners);
  },
  finishRemoval(target, property, _listener, registration) {
    if (target !== process) {
      throw new TypeError("invalid trusted process event removal target");
    }
    if (isProcessSignalEvent(property)) {
      finishProcessSignalRemoval(property, registration, true);
    }
  },
  listenerMatches(table, _property, stored, listener) {
    requireDirectProcessEventTable(table);
    return stored === listener ||
      unwrapProcessEventListener(stored) === listener;
  },
  unwrapListener(table, _property, listener) {
    requireDirectProcessEventTable(table);
    return unwrapProcessEventListener(listener);
  },
  snapshot(table, property, handler) {
    return snapshotDirectProcessEventListeners(table, property, handler);
  },
  keys(table) {
    const store = requireDirectProcessEventTable(table);
    const keys = ReflectOwnKeys(store);
    requireCurrentProcessEventTable(store, table);
    return keys;
  },
  incrementCount(target, table) {
    return synchronizeDirectProcessEventCount(target, table);
  },
  decrementCount(target, table) {
    return synchronizeDirectProcessEventCount(target, table);
  },
  listenerAdded(target, table, property, _listener) {
    commitProcessExceptionListenerMutation(target, table, property);
  },
  listenerRemoved(target, table, property, _listener) {
    commitProcessExceptionListenerMutation(target, table, property);
  },
  checkListenerLeak() {
    return false;
  },
  replace(target, table, value) {
    requireDirectProcessEventTable(table);
    return replaceEmptyProcessEventTable(target, table, value);
  },
  emitLifecycle(target, type, args) {
    return emitTrustedProcessLifecycleMetaEvent(target, type, args);
  },
});

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
    replaceProcessEventTable(process, value);
  },
});

ObjectDefineProperty(process, "_eventsCount", {
  __proto__: null,
  configurable: false,
  enumerable: true,
  get() {
    op_oden_guard_deny_only_surface(
      "runtime",
      "inspect",
      "process-events",
      "process._eventsCount",
    );
    return processEventsVisibleCount;
  },
  set(value) {
    op_oden_guard_deny_only_surface(
      "runtime",
      "inspect",
      "process-events",
      "process._eventsCount=set",
    );
    processEventsVisibleCount = value;
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
  requireDirectProcessEventTable(guardedProcessEvents);
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
// Public event-table replacement is refused for the full trusted delivery so
// a reentrant monitor/listener cannot strand later fatal-path work on an
// unowned table epoch.
// @ref LLP 0019#runtime-and-memory-inspection [implements]
let processExceptionDispatchDepth = 0;
function emitProcessExceptionInternal(event: string, ...args: unknown[]) {
  processExceptionDispatchDepth++;
  try {
    return emitEventWithTableAccess(
      process,
      event,
      args,
      trustedProcessEventTableAccess,
    );
  } finally {
    processExceptionDispatchDepth--;
  }
}

function processExceptionListenerCountInternal(event: string) {
  return eventListenerCountWithTableAccess(
    process,
    event,
    undefined,
    trustedProcessEventTableAccess,
  );
}

// deno-lint-ignore no-explicit-any
function fatalExceptionImpl(err: any, fromPromise?: boolean) {
  // Accepted public replacement installs an unowned epoch whose protected
  // entries have no runtime authority. Capture registration and signal
  // listeners are already refused for that state, and replacement resets all
  // protected listener counts, so the unconditional CJS/REPL fatal entry must
  // report "unhandled" without traversing the public table or masking `err`.
  // @ref LLP 0019#runtime-and-memory-inspection [implements]
  if (!isOwnedDirectProcessEventTable(guardedProcessEvents)) return false;
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
ObjectDefineProperty(internals, "nodeProcessErrorCallback", {
  __proto__: null,
  configurable: false,
  enumerable: false,
  value: undefined,
  writable: true,
});

function isProcessExceptionRoutingEvent(event: unknown) {
  return event === "unhandledRejection" || event === "rejectionHandled" ||
    event === "uncaughtException" ||
    event === "uncaughtExceptionMonitor";
}

function directProcessExceptionListenerCount(table, event: string) {
  const stored = requireStoredProcessEventValue(table, event);
  return stored === undefined
    ? 0
    : typeof stored === "function"
    ? 1
    : requireStoredProcessEventListenerArray(table, event, stored);
}

// Public `_events` replacement can temporarily install an unowned table, but
// seeded values in that table are not runtime routing authority. Reconcile
// only an owned direct table after the EventEmitter mutation has committed;
// replacement resets all routing state before any later requalification.
// @ref LLP 0019#runtime-and-memory-inspection [implements]
function reconcileProcessExceptionRoutingAfterTableMutation(table) {
  requireProcessEventTableHandle(table);
  if (isOwnedDirectProcessEventTable(table)) {
    unhandledRejectionListenerCount = directProcessExceptionListenerCount(
      table,
      "unhandledRejection",
    );
    rejectionHandledListenerCount = directProcessExceptionListenerCount(
      table,
      "rejectionHandled",
    );
    uncaughtExceptionListenerCount = directProcessExceptionListenerCount(
      table,
      "uncaughtException",
    );
    uncaughtExceptionMonitorListenerCount = directProcessExceptionListenerCount(
      table,
      "uncaughtExceptionMonitor",
    );
  } else {
    unhandledRejectionListenerCount = 0;
    rejectionHandledListenerCount = 0;
    uncaughtExceptionListenerCount = 0;
    uncaughtExceptionMonitorListenerCount = 0;
  }
  synchronizeListeners();
  requireProcessEventTableHandle(table);
}

function commitProcessExceptionListenerMutation(
  target,
  table,
  event: unknown,
) {
  if (target !== process) {
    throw new TypeError("invalid process exception listener target");
  }
  requireProcessEventTableHandle(table);
  if (!isProcessExceptionRoutingEvent(event)) return;
  reconcileProcessExceptionRoutingAfterTableMutation(table);
}

function processOnError(error: unknown) {
  if (typeof fatalExceptionHandler === "function") {
    return !!fatalExceptionHandler(error);
  } else {
    // Exit code 6: _fatalException is not a function
    // (kInvalidFatalExceptionMonkeyPatching in Node.js)
    process.exitCode = 6;
  }
  return false;
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
    internals.nodeProcessUnhandledRejectionCallback = (promise, reason) => {
      if (processExceptionListenerCountInternal("unhandledRejection") === 0) {
        // The Node.js default behavior is to raise an uncaught exception if
        // an unhandled rejection occurs and there are no unhandledRejection
        // listeners.

        // The synchronous Module._load path in 01_require.js already invoked
        // process._fatalException for this error. Re-firing here would
        // double-emit 'uncaughtExceptionMonitor' (and 'uncaughtException')
        // for the same value. Skip and let Deno's default unhandled-rejection
        // handling print the error and terminate the runtime.
        if (
          reason !== null && typeof reason === "object" &&
          _dispatchedFatalErrors.has(reason)
        ) {
          return false;
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
          (err as any).reason = reason;
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
        return !!uncaughtExceptionHandler(reason, "unhandledRejection");
      }

      emitProcessExceptionInternal(
        "unhandledRejection",
        reason,
        promise,
      );
      return true;
    };
  } else {
    internals.nodeProcessUnhandledRejectionCallback = undefined;
  }

  // Install special "handledrejection" handler, that will be called
  // last.
  if (rejectionHandledListenerCount > 0) {
    internals.nodeProcessRejectionHandledCallback = (promise, reason) => {
      emitProcessExceptionInternal(
        "rejectionHandled",
        reason,
        promise,
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
    internals.nodeProcessErrorCallback = processOnError;
  } else {
    internals.nodeProcessErrorCallback = undefined;
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
