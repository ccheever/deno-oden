// Copyright 2018-2026 the Deno authors. MIT license.

// Oden capsec authority-flow surface (LLP 0001 Delegation and handles,
// ENG-23784): the `Deno.oden` namespace. A package mints an attenuated handle
// from a capability it holds, re-attenuates it (`scoped`), hands the carrier
// object across a package boundary, uses it inside a synchronous window
// (`use`), and revokes it (cascading through derived handles).
//
// Unforgeability: the host-side table (deno_permissions::oden_handle) is keyed
// by an unguessable 128-bit id. The id is captured only in the closures of a
// handle's own methods -- it is never a property of the carrier object, so user
// code cannot read, forge, or serialize it. Sharing authority means sharing the
// carrier object reference; a fabricated `{ use, scoped, revoke }` object has no
// id and its ops deny.
//
// Serialization posture (fail-closed): a handle carrier holds function
// properties, so `structuredClone`/`postMessage` throw (functions are not
// cloneable) and there is no id property to copy. Handles therefore transfer by
// same-isolate object reference only, never by serialization -- and workers,
// whose creation is default-denied for packages under enforce, cannot receive a
// live handle by message.
//
// This surface is installed only when capsec is armed (see
// odenMaybeInstallHandles in 99_main.js), so unarmed runs expose no new
// namespace and stay byte-identical to stock Deno.

(function () {
const { core, primordials } = __bootstrap;
const {
  op_oden_handle_mint,
  op_oden_handle_scoped,
  op_oden_handle_enter,
  op_oden_handle_exit,
  op_oden_handle_revoke,
  op_oden_compartment_endowments,
  op_oden_guard_surface,
  op_oden_attestation,
} = core.ops;
const {
  ArrayPrototypeFilter,
  ArrayPrototypeIncludes,
  ArrayPrototypePush,
  ObjectCreate,
  ObjectFreeze,
  ObjectDefineProperty,
  ObjectGetOwnPropertyDescriptor,
  ObjectHasOwn,
  Proxy,
  ReferenceError,
  ReflectDeleteProperty,
  ReflectApply,
  ReflectConstruct,
  ReflectGet,
  ReflectOwnKeys,
  StringPrototypeSplit,
  TypeError,
} = primordials;

// The real global is captured by trusted bootstrap before user code runs. A
// rewritten module receives a caller-checked Proxy over this captured object;
// it never reads authority-bearing values from a mutable user global.
// @ref LLP 0014#closing-the-dynamic-channels [implements]
const realGlobal = globalThis;
const realGlobalKeys = ReflectOwnKeys(realGlobal);
const records = ObjectCreate(null);
let guardsInstalled = false;

const helperName = "__oden_compartment_globals__";
const aliases = ObjectCreate(null);
aliases.globalThis = true;
aliases.global = true;
aliases.self = true;

// Authority-bearing names. A non-ambient principal sees one only when the
// Rust policy's endowment descriptor contains it. The families that are not
// yet in the shared v1 policy vocabulary remain fail-closed (never endowed).
const gated = ObjectCreate(null);
for (
  const name of [
    "BroadcastChannel",
    "EventSource",
    "WebSocket",
    "caches",
    "fetch",
    "localStorage",
    "sessionStorage",
  ]
) gated[name] = true;

// Namespace/escape-hatch globals never endowed to a package. `eval` is absent:
// the trusted V8 callback now rewrites its source through this same caller-
// derived record, so direct and indirect eval remain usable without recovering
// the realm's raw globals.
const never = ObjectCreate(null);
for (
  const name of [
    "Deno",
    "Worker",
    "alert",
    "confirm",
    "process",
    "prompt",
  ]
) never[name] = true;

function deniedGlobal(name) {
  return new ReferenceError(
    `Oden compartment: global "${name}" is not endowed for this principal`,
  );
}

function descriptorValue(object, key) {
  const descriptor = ObjectGetOwnPropertyDescriptor(object, key);
  if (!descriptor) return undefined;
  return {
    __proto__: null,
    value: ReflectGet(object, key, object),
    writable: true,
    enumerable: descriptor.enumerable,
    configurable: true,
  };
}

function makeNavigatorProxy(isAmbient, endowed) {
  const realNavigator = realGlobal.navigator;
  if (!realNavigator) return undefined;
  return new Proxy(ObjectCreate(null), {
    get(_target, key) {
      if (key === "gpu" && !isAmbient && !endowed["navigator.gpu"]) {
        throw deniedGlobal("navigator.gpu");
      }
      return ReflectGet(realNavigator, key, realNavigator);
    },
    has(_target, key) {
      return key !== "gpu" || isAmbient || endowed["navigator.gpu"] === true;
    },
    ownKeys() {
      const keys = ReflectOwnKeys(realNavigator);
      if (isAmbient || endowed["navigator.gpu"]) return keys;
      return ArrayPrototypeFilter(keys, (key) => key !== "gpu");
    },
    getOwnPropertyDescriptor(_target, key) {
      if (key === "gpu" && !isAmbient && !endowed["navigator.gpu"]) {
        return undefined;
      }
      return descriptorValue(realNavigator, key);
    },
  });
}

function makeCompartmentRecord(descriptor) {
  const parts = StringPrototypeSplit(descriptor, "\0");
  const principal = parts[0];
  const isAmbient = principal === "root" || principal === "runtime";
  const endowed = ObjectCreate(null);
  const names = StringPrototypeSplit(parts[1] || "", ",");
  for (let i = 0; i < names.length; i++) endowed[names[i]] = true;
  const local = ObjectCreate(null);
  let proxy;
  const navigatorProxy = makeNavigatorProxy(isAmbient, endowed);

  function visible(key) {
    if (typeof key !== "string") return false;
    if (key === helperName) return false;
    if (aliases[key]) return true;
    if (isAmbient) return true;
    if (never[key]) return false;
    if (gated[key]) return endowed[key] === true;
    return true;
  }

  proxy = new Proxy(local, {
    get(target, key) {
      if (ObjectHasOwn(target, key)) return ReflectGet(target, key, target);
      if (aliases[key]) return proxy;
      if (key === "navigator") return navigatorProxy;
      if (visible(key)) return ReflectGet(realGlobal, key, realGlobal);
      if (typeof key === "string" && (gated[key] || never[key])) {
        throw deniedGlobal(key);
      }
      return undefined;
    },
    has(target, key) {
      return ObjectHasOwn(target, key) || visible(key);
    },
    ownKeys(target) {
      const out = [];
      for (let i = 0; i < realGlobalKeys.length; i++) {
        const key = realGlobalKeys[i];
        if (visible(key)) ArrayPrototypePush(out, key);
      }
      const localKeys = ReflectOwnKeys(target);
      for (let i = 0; i < localKeys.length; i++) {
        const key = localKeys[i];
        if (!ArrayPrototypeIncludes(out, key)) ArrayPrototypePush(out, key);
      }
      return out;
    },
    getOwnPropertyDescriptor(target, key) {
      if (ObjectHasOwn(target, key)) {
        return ObjectGetOwnPropertyDescriptor(target, key);
      }
      if (aliases[key]) {
        return {
          __proto__: null,
          value: proxy,
          writable: true,
          enumerable: false,
          configurable: true,
        };
      }
      if (key === "navigator") {
        return {
          __proto__: null,
          value: navigatorProxy,
          writable: true,
          enumerable: true,
          configurable: true,
        };
      }
      return visible(key) ? descriptorValue(realGlobal, key) : undefined;
    },
    set(target, key, value) {
      ObjectDefineProperty(target, key, {
        __proto__: null,
        value,
        writable: true,
        enumerable: true,
        configurable: true,
      });
      return true;
    },
    defineProperty(target, key, descriptor) {
      ObjectDefineProperty(target, key, descriptor);
      return true;
    },
    deleteProperty(target, key) {
      return ReflectDeleteProperty(target, key);
    },
    getPrototypeOf() {
      return null;
    },
    setPrototypeOf() {
      return false;
    },
  });
  return proxy;
}

function compartmentGlobals() {
  const descriptor = op_oden_compartment_endowments();
  if (!ObjectHasOwn(records, descriptor)) {
    ObjectDefineProperty(records, descriptor, {
      __proto__: null,
      value: makeCompartmentRecord(descriptor),
      writable: false,
      enumerable: false,
      configurable: false,
    });
  }
  return records[descriptor];
}

function guardMethod(object, name, family, action, targetPrefix) {
  if (!object) return;
  const original = ReflectGet(object, name, object);
  if (typeof original !== "function") return;
  try {
    ObjectDefineProperty(object, name, {
      __proto__: null,
      value: function (...args) {
        const target = `${targetPrefix}:${String(args[0] ?? "*")}`;
        op_oden_guard_surface(family, action, target, targetPrefix);
        return ReflectApply(original, object, args);
      },
      writable: true,
      enumerable: false,
      configurable: true,
    });
  } catch {
    // If a host object cannot accept an own override, leave it for its native
    // op gate; the readiness manifest must not claim this JS seam as covered.
  }
}

// Default-closed ambient globals whose underlying Deno ops have no native
// per-package descriptor. Installed on every armed runtime, independent of the
// opt-in compartment rewrite. (ENG-23954, ENG-23957)
function installAmbientGuards() {
  if (guardsInstalled) return;
  guardsInstalled = true;

  const OriginalBroadcastChannel = realGlobal.BroadcastChannel;
  if (typeof OriginalBroadcastChannel === "function") {
    const guarded = new Proxy(OriginalBroadcastChannel, {
      construct(target, args, newTarget) {
        const name = String(args[0] ?? "");
        op_oden_guard_surface(
          "ipc",
          "broadcast",
          name,
          "BroadcastChannel",
        );
        return ReflectConstruct(target, args, newTarget);
      },
    });
    ObjectDefineProperty(
      realGlobal,
      "BroadcastChannel",
      core.propNonEnumerable(guarded),
    );
  }

  // Web Storage is guarded in ext/webstorage's Proxy traps. Defining own
  // methods here would itself route through Storage.defineProperty and create
  // string-valued storage entries rather than wrapping the native methods.
  const caches = realGlobal.caches;
  for (const method of ["match", "has", "keys"]) {
    guardMethod(caches, method, "storage", "read", "caches");
  }
  for (const method of ["open", "delete"]) {
    guardMethod(caches, method, "storage", "write", "caches");
  }
  const gpu = realGlobal.navigator && realGlobal.navigator.gpu;
  guardMethod(gpu, "requestAdapter", "gpu", "access", "navigator.gpu");
}

// Build a frozen carrier object for a handle id. The id lives only in these
// closures; the carrier exposes behavior, never the id.
function makeHandle(id, capability) {
  const handle = { __proto__: null };

  // Open a synchronous possession window: ops inside `fn` that fall within the
  // handle's attenuated scope are authorized regardless of the possessor's own
  // grants. The window is synchronous -- it closes when `fn` returns -- so an
  // async continuation scheduled inside `fn` does NOT inherit the authority
  // (that would be ambient authority; it fails closed instead).
  const use = (fn) => {
    if (typeof fn !== "function") {
      throw new TypeError("Deno.oden handle.use(fn): fn must be a function");
    }
    op_oden_handle_enter(id); // throws if revoked / forged / unknown
    try {
      return fn();
    } finally {
      op_oden_handle_exit();
    }
  };

  // Re-attenuate into a narrower child handle. Only narrows -- a capability
  // wider than this handle's is denied by the host.
  const scoped = (childCapability) =>
    makeHandle(op_oden_handle_scoped(id, childCapability), childCapability);

  // Revoke this handle and every handle transitively derived from it.
  const revoke = () => op_oden_handle_revoke(id);

  ObjectDefineProperty(handle, "use", core.propReadOnly(use));
  ObjectDefineProperty(handle, "scoped", core.propReadOnly(scoped));
  ObjectDefineProperty(handle, "revoke", core.propReadOnly(revoke));
  // The capability string is diagnostic only (it names no id); handy for audit
  // and tests. Read-only.
  ObjectDefineProperty(handle, "capability", core.propReadOnly(capability));
  return ObjectFreeze(handle);
}

// Mint a handle from a capability the acting principal holds (frame-checked by
// the host: a mint cannot exceed what the minter holds).
function mint(capability) {
  if (typeof capability !== "string") {
    throw new TypeError(
      "Deno.oden.mint(capability): capability must be a string",
    );
  }
  return makeHandle(op_oden_handle_mint(capability), capability);
}

const oden = { __proto__: null };
ObjectDefineProperty(oden, "mint", core.propReadOnly(mint));
ObjectDefineProperty(
  oden,
  "attest",
  core.propReadOnly(() => op_oden_attestation()),
);
ObjectFreeze(oden);

// Returned to 99_main.js (via loadExtScript) for conditional install onto the
// Deno namespace when capsec is armed.
return { oden, compartmentGlobals, installAmbientGuards };
})();
