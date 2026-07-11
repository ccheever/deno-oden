// Copyright 2018-2026 the Deno authors. MIT license.
// Copyright Joyent and Node contributors. All rights reserved. MIT license.

(function () {
const { core, primordials } = __bootstrap;
const { op_oden_guard_deny_only_surface } = core.ops;
// deno-lint-ignore camelcase
const async_wrap = core.loadExtScript(
  "ext:deno_node/internal_binding/async_wrap.ts",
);
const { ERR_ASYNC_CALLBACK } = core.loadExtScript(
  "ext:deno_node/internal/errors.ts",
);
const { asyncIdSymbol, ownerSymbol } = core.loadExtScript(
  "ext:deno_node/internal_binding/symbols.ts",
);
const {
  ArrayPrototypeIncludes,
  ArrayPrototypeIndexOf,
  ArrayPrototypePush,
  ArrayPrototypePop,
  ArrayPrototypeSlice,
  ArrayPrototypeSplice,
  FunctionPrototypeApply,
  ObjectKeys,
  SafeWeakMap,
  Symbol,
} = primordials;
const {
  AsyncVariable,
  getAsyncContext,
  kNoAsyncContextRestore,
  setAsyncContext,
} = core;

interface ActiveHooks {
  array: AsyncHook[];
  // deno-lint-ignore camelcase
  call_depth: number;
  // deno-lint-ignore camelcase
  tmp_array: AsyncHook[] | null;
  // deno-lint-ignore camelcase
  tmp_fields: number[] | null;
}

// Properties in active_hooks are used to keep track of the set of hooks being
// executed in case another hook is enabled/disabled. The new set of hooks is
// then restored once the active set of hooks is finished executing.
// deno-lint-ignore camelcase
const active_hooks: ActiveHooks = {
  // Array of all AsyncHooks that will be iterated whenever an async event
  // fires. Using var instead of (preferably const) in order to assign
  // active_hooks.tmp_array if a hook is enabled/disabled during hook
  // execution.
  array: [],
  // Use a counter to track nested calls of async hook callbacks and make sure
  // the active_hooks.array isn't altered mid execution.
  // deno-lint-ignore camelcase
  call_depth: 0,
  // Use to temporarily store and updated active_hooks.array if the user
  // enables or disables a hook while hooks are being processed. If a hook is
  // enabled() or disabled() during hook execution then the current set of
  // active hooks is duplicated and set equal to active_hooks.tmp_array. Any
  // subsequent changes are on the duplicated array. When all hooks have
  // completed executing active_hooks.tmp_array is assigned to
  // active_hooks.array.
  // deno-lint-ignore camelcase
  tmp_array: null,
  // Keep track of the field counts held in active_hooks.tmp_array. Because the
  // async_hook_fields can't be reassigned, store each uint32 in an array that
  // is written back to async_hook_fields when active_hooks.array is restored.
  // deno-lint-ignore camelcase
  tmp_fields: null,
};

const registerDestroyHook = async_wrap.registerDestroyHook;
const {
  async_hook_fields,
  // deno-lint-ignore camelcase
  asyncIdFields: async_id_fields,
  newAsyncId,
  constants,
} = async_wrap;

// Track execution context
const executionAsyncIdStack: number[] = [0];

function executionAsyncId(): number {
  return executionAsyncIdStack[executionAsyncIdStack.length - 1] || 0;
}

// Per-async-context "current resource" tracked via the AsyncVariable
// machinery (V8 ContinuationPreservedEmbedderData). This propagates across
// promises and await transitions automatically. The top-level resource is a
// shared singleton used before any specific resource has been entered.
// deno-lint-ignore no-explicit-any
const topLevelResource: any = { __proto__: null };
// deno-lint-ignore no-explicit-any
const executionResourceVariable: any = new AsyncVariable();

// deno-lint-ignore no-explicit-any
function executionAsyncResource(): any {
  const r = executionResourceVariable.get();
  return r === undefined ? topLevelResource : r;
}

// Enter a new "current resource" scope. The returned value is the previous
// async context snapshot that must be restored by exitAsyncResource.
// deno-lint-ignore no-explicit-any
function enterAsyncResource(resource: any): any {
  return executionResourceVariable.enter(resource);
}

// deno-lint-ignore no-explicit-any
function exitAsyncResource(previousContext: any): void {
  setAsyncContext(previousContext);
}

// deno-lint-ignore no-explicit-any
function enterAsyncResourceIfActive(resource: any): any {
  if (active_hooks.array.length > 0) {
    return executionResourceVariable.enter(resource);
  }
  return executionResourceVariable.enterIfActive(resource);
}

// deno-lint-ignore no-explicit-any
function exitAsyncResourceIfActive(previousContext: any): void {
  if (previousContext !== kNoAsyncContextRestore) {
    setAsyncContext(previousContext);
    return;
  }

  const currentContext = getAsyncContext();
  if (
    currentContext !== null &&
    currentContext !== undefined &&
    ObjectKeys(currentContext).length > 0
  ) {
    setAsyncContext(undefined);
  }
}

// Emit functions that work with the internal hook system
function emitBefore(asyncId: number): void {
  ArrayPrototypePush(executionAsyncIdStack, asyncId);

  // Call hooks if they exist
  const hooks = active_hooks.array;
  try {
    for (let i = 0; i < hooks.length; i++) {
      const hook = hooks[i];
      const before = hookStates.get(hook).before;
      if (before) {
        FunctionPrototypeApply(before, hook, [asyncId]);
      }
    }
  } catch (e) {
    // Clean up stack corruption on hook errors (Node.js pattern)
    if (executionAsyncIdStack.length > 1) {
      ArrayPrototypePop(executionAsyncIdStack);
    }
    throw e;
  }
}

function emitAfter(asyncId: number): void {
  // Call hooks if they exist
  const hooks = active_hooks.array;
  try {
    for (let i = 0; i < hooks.length; i++) {
      const hook = hooks[i];
      const after = hookStates.get(hook).after;
      if (after) {
        FunctionPrototypeApply(after, hook, [asyncId]);
      }
    }
  } finally {
    // Always pop stack even if hooks throw (Node.js pattern)
    if (executionAsyncIdStack.length > 1) {
      ArrayPrototypePop(executionAsyncIdStack);
    }
  }
}

function emitDestroy(asyncId: number): void {
  // Call hooks if they exist
  const hooks = active_hooks.array;
  for (let i = 0; i < hooks.length; i++) {
    const hook = hooks[i];
    const destroy = hookStates.get(hook).destroy;
    if (destroy) {
      FunctionPrototypeApply(destroy, hook, [asyncId]);
    }
  }
}
const {
  kInit,
  kBefore,
  kAfter,
  kDestroy,
  kPromiseResolve,
  kTotals,
  kCheck,
  kDefaultTriggerAsyncId,
  kStackLength,
} = constants;

// deno-lint-ignore camelcase
const resource_symbol = Symbol("resource");
// Alias to the same symbol used by `internal_binding/symbols.ts` so that
// `socket[asyncIdSymbol]` (set in net.ts/dgram.ts) and
// `socket[require('internal/async_hooks').symbols.async_id_symbol]`
// (read by Node test fixtures) refer to the same slot on objects.
// deno-lint-ignore camelcase
const async_id_symbol = asyncIdSymbol;
// deno-lint-ignore camelcase
const trigger_async_id_symbol = Symbol("trigger_async_id");
// deno-lint-ignore camelcase
const init_symbol = Symbol("init");
// deno-lint-ignore camelcase
const before_symbol = Symbol("before");
// deno-lint-ignore camelcase
const after_symbol = Symbol("after");
// deno-lint-ignore camelcase
const destroy_symbol = Symbol("destroy");
// deno-lint-ignore camelcase
const promise_resolve_symbol = Symbol("promiseResolve");

const symbols = {
  // deno-lint-ignore camelcase
  async_id_symbol,
  // deno-lint-ignore camelcase
  trigger_async_id_symbol,
  // deno-lint-ignore camelcase
  init_symbol,
  // deno-lint-ignore camelcase
  before_symbol,
  // deno-lint-ignore camelcase
  after_symbol,
  // deno-lint-ignore camelcase
  destroy_symbol,
  // deno-lint-ignore camelcase
  promise_resolve_symbol,
};

// deno-lint-ignore no-explicit-any
function lookupPublicResource(resource: any) {
  if (typeof resource !== "object" || resource === null) return resource;
  // TODO(addaleax): Merge this with owner_symbol and use it across all
  // AsyncWrap instances.
  const publicResource = resource[resource_symbol];
  if (publicResource !== undefined) {
    return publicResource;
  }
  return resource;
}

// Used by C++ to call all init() callbacks. Because some state can be setup
// from C++ there's no need to perform all the same operations as in
// emitInitScript.
function emitInitNative(
  asyncId: number,
  // deno-lint-ignore no-explicit-any
  type: any,
  triggerAsyncId: number,
  // deno-lint-ignore no-explicit-any
  resource: any,
) {
  active_hooks.call_depth += 1;
  resource = lookupPublicResource(resource);
  // Use a single try/catch for all hooks to avoid setting up one per iteration.
  try {
    for (let i = 0; i < active_hooks.array.length; i++) {
      const hook = active_hooks.array[i];
      const init = hookStates.get(hook).init;
      if (typeof init === "function") {
        FunctionPrototypeApply(
          init,
          hook,
          [asyncId, type, triggerAsyncId, resource],
        );
      }
    }
  } catch (e) {
    throw e;
  } finally {
    active_hooks.call_depth -= 1;
  }

  // Hooks can only be restored if there have been no recursive hook calls.
  // Also the active hooks do not need to be restored if enable()/disable()
  // weren't called during hook execution, in which case active_hooks.tmp_array
  // will be null.
  if (active_hooks.call_depth === 0 && active_hooks.tmp_array !== null) {
    restoreActiveHooks();
  }
}

function getHookArrays(): [AsyncHook[], number[] | Uint32Array] {
  if (active_hooks.call_depth === 0) {
    return [active_hooks.array, async_hook_fields];
  }
  // If this hook is being enabled while in the middle of processing the array
  // of currently active hooks then duplicate the current set of active hooks
  // and store this there. This shouldn't fire until the next time hooks are
  // processed.
  if (active_hooks.tmp_array === null) {
    storeActiveHooks();
  }
  return [active_hooks.tmp_array!, active_hooks.tmp_fields!];
}

function storeActiveHooks() {
  active_hooks.tmp_array = ArrayPrototypeSlice(active_hooks.array);
  // Don't want to make the assumption that kInit to kDestroy are indexes 0 to
  // 4. So do this the long way.
  active_hooks.tmp_fields = [];
  copyHooks(active_hooks.tmp_fields, async_hook_fields);
}

function copyHooks(
  destination: number[] | Uint32Array,
  source: number[] | Uint32Array,
) {
  destination[kInit] = source[kInit];
  destination[kBefore] = source[kBefore];
  destination[kAfter] = source[kAfter];
  destination[kDestroy] = source[kDestroy];
  destination[kPromiseResolve] = source[kPromiseResolve];
}

// Then restore the correct hooks array in case any hooks were added/removed
// during hook callback execution.
function restoreActiveHooks() {
  active_hooks.array = active_hooks.tmp_array!;
  copyHooks(async_hook_fields, active_hooks.tmp_fields!);

  active_hooks.tmp_array = null;
  active_hooks.tmp_fields = null;
}

// deno-lint-ignore no-unused-vars
let wantPromiseHook = false;
function enableHooks() {
  async_hook_fields[kCheck] += 1;

  // TODO(kt3k): Uncomment this
  // setCallbackTrampoline(callbackTrampoline);
}

function disableHooks() {
  async_hook_fields[kCheck] -= 1;

  wantPromiseHook = false;

  // TODO(kt3k): Uncomment the below
  // setCallbackTrampoline();

  // Delay the call to `disablePromiseHook()` because we might currently be
  // between the `before` and `after` calls of a Promise.
  // TODO(kt3k): Uncomment the below
  // enqueueMicrotask(disablePromiseHookIfNecessary);
}

// Return the triggerAsyncId meant for the constructor calling it. It's up to
// the user to safeguard this call and make sure it's zero'd out when the
// constructor is complete.
function getDefaultTriggerAsyncId() {
  const defaultTriggerAsyncId =
    async_id_fields[async_wrap.UidFields.kDefaultTriggerAsyncId];
  // If defaultTriggerAsyncId isn't set, use the executionAsyncId
  if (defaultTriggerAsyncId < 0) {
    return async_id_fields[async_wrap.UidFields.kExecutionAsyncId];
  }
  return defaultTriggerAsyncId;
}

function defaultTriggerAsyncIdScope(
  triggerAsyncId: number | undefined,
  // deno-lint-ignore no-explicit-any
  block: (...arg: any[]) => void,
  ...args: unknown[]
) {
  if (triggerAsyncId === undefined) {
    return FunctionPrototypeApply(block, null, args);
  }
  // CHECK(NumberIsSafeInteger(triggerAsyncId))
  // CHECK(triggerAsyncId > 0)
  const oldDefaultTriggerAsyncId = async_id_fields[kDefaultTriggerAsyncId];
  async_id_fields[kDefaultTriggerAsyncId] = triggerAsyncId;

  try {
    return FunctionPrototypeApply(block, null, args);
  } finally {
    async_id_fields[kDefaultTriggerAsyncId] = oldDefaultTriggerAsyncId;
  }
}

function hasHooks(key: number) {
  return async_hook_fields[key] > 0;
}

function enabledHooksExist() {
  return active_hooks.array.length > 0;
}

function hasAsyncIdStack() {
  return hasHooks(kStackLength);
}

type Fn = (...args: unknown[]) => unknown;

// Domain tracking is an implementation detail of the Node compatibility
// layer. Keep its hook on a closure-private path so a user-created AsyncHook
// cannot be enabled later by a less-trusted principal without a fresh check.
const internalHookToken = { __proto__: null };
const hookStates = new SafeWeakMap();

class AsyncHook {
  constructor({
    init,
    before,
    after,
    destroy,
    promiseResolve,
  }: {
    init: Fn;
    before: Fn;
    after: Fn;
    destroy: Fn;
    promiseResolve: Fn;
  }, trustedToken?: object) {
    if (init !== undefined && typeof init !== "function") {
      throw new ERR_ASYNC_CALLBACK("hook.init");
    }
    if (before !== undefined && typeof before !== "function") {
      throw new ERR_ASYNC_CALLBACK("hook.before");
    }
    if (after !== undefined && typeof after !== "function") {
      throw new ERR_ASYNC_CALLBACK("hook.after");
    }
    if (destroy !== undefined && typeof destroy !== "function") {
      throw new ERR_ASYNC_CALLBACK("hook.destroy");
    }
    if (promiseResolve !== undefined && typeof promiseResolve !== "function") {
      throw new ERR_ASYNC_CALLBACK("hook.promiseResolve");
    }

    hookStates.set(this, {
      __proto__: null,
      init,
      before,
      after,
      destroy,
      promiseResolve,
      trustedInternal: trustedToken === internalHookToken,
    });
  }

  enable() {
    const state = hookStates.get(this);
    if (!state.trustedInternal) {
      op_oden_guard_deny_only_surface(
        "runtime",
        "inspect",
        "async-hooks",
        "node:async_hooks.AsyncHook.enable",
      );
    }

    // The set of callbacks for a hook should be the same regardless of whether
    // enable()/disable() are run during their execution. The following
    // references are reassigned to the tmp arrays if a hook is currently being
    // processed.
    // deno-lint-ignore camelcase
    const { 0: hooks_array, 1: hook_fields } = getHookArrays();

    // Each hook is only allowed to be added once.
    if (ArrayPrototypeIncludes(hooks_array, this)) {
      return this;
    }

    // deno-lint-ignore camelcase
    const prev_kTotals = hook_fields[kTotals];

    // createHook() has already enforced that the callbacks are all functions,
    // so here simply increment the count of whether each callbacks exists or
    // not.
    hook_fields[kTotals] = hook_fields[kInit] += +!!state.init;
    hook_fields[kTotals] += hook_fields[kBefore] += +!!state.before;
    hook_fields[kTotals] += hook_fields[kAfter] += +!!state.after;
    hook_fields[kTotals] += hook_fields[kDestroy] += +!!state.destroy;
    hook_fields[kTotals] += hook_fields[kPromiseResolve] += +!!state
      .promiseResolve;
    ArrayPrototypePush(hooks_array, this);

    if (prev_kTotals === 0 && hook_fields[kTotals] > 0) {
      enableHooks();
    }

    // TODO(kt3k): Uncomment the below
    // updatePromiseHookMode();

    return this;
  }

  disable() {
    const state = hookStates.get(this);
    if (!state.trustedInternal) {
      op_oden_guard_deny_only_surface(
        "runtime",
        "inspect",
        "async-hooks",
        "node:async_hooks.AsyncHook.disable",
      );
    }

    // deno-lint-ignore camelcase
    const { 0: hooks_array, 1: hook_fields } = getHookArrays();

    const index = ArrayPrototypeIndexOf(hooks_array, this);
    if (index === -1) {
      return this;
    }

    // deno-lint-ignore camelcase
    const prev_kTotals = hook_fields[kTotals];

    hook_fields[kTotals] = hook_fields[kInit] -= +!!state.init;
    hook_fields[kTotals] += hook_fields[kBefore] -= +!!state.before;
    hook_fields[kTotals] += hook_fields[kAfter] -= +!!state.after;
    hook_fields[kTotals] += hook_fields[kDestroy] -= +!!state.destroy;
    hook_fields[kTotals] += hook_fields[kPromiseResolve] -= +!!state
      .promiseResolve;
    ArrayPrototypeSplice(hooks_array, index, 1);

    if (prev_kTotals > 0 && hook_fields[kTotals] === 0) {
      disableHooks();
    }

    return this;
  }
}

return {
  asyncIdSymbol,
  ownerSymbol,
  newAsyncId,
  emitInit: emitInitNative,
  constants,
  executionAsyncId,
  executionAsyncResource,
  enterAsyncResource,
  exitAsyncResource,
  enterAsyncResourceIfActive,
  exitAsyncResourceIfActive,
  emitBefore,
  emitAfter,
  emitDestroy,
  getDefaultTriggerAsyncId,
  defaultTriggerAsyncIdScope,
  enabledHooksExist,
  hasAsyncIdStack,
  AsyncHook,
  internalHookToken,
  registerDestroyHook,
  async_id_symbol,
  trigger_async_id_symbol,
  init_symbol,
  before_symbol,
  after_symbol,
  destroy_symbol,
  promise_resolve_symbol,
  symbols,
};
})();
