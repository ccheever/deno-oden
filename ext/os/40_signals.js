// Copyright 2018-2026 the Deno authors. MIT license.

(function () {
const { core, primordials } = __bootstrap;
const {
  op_oden_guard_deny_only_surface,
  op_signal_bind,
  op_signal_bind_internal,
  op_signal_poll,
  op_signal_unbind,
} = core.ops;
const {
  SafeSet,
  SafeSetIterator,
  SetPrototypeAdd,
  SetPrototypeDelete,
  TypeError,
} = primordials;

function bindSignal(signo, trustedInternal) {
  return trustedInternal ? op_signal_bind_internal(signo) : op_signal_bind(signo);
}

function pollSignal(rid) {
  const promise = op_signal_poll(rid);
  core.unrefOpPromise(promise);
  return promise;
}

function unbindSignal(rid) {
  op_signal_unbind(rid);
}

// Stores signal listeners and resource data. This has type of
// `Record<string, { rid: number | undefined, listeners: Set<() => void> }`
const signalData = { __proto__: null };

/** Gets the signal handlers and resource data of the given signal */
function getSignalData(signo) {
  return signalData[signo] ??
    (signalData[signo] = { rid: undefined, listeners: new SafeSet() });
}

function checkSignalListenerType(listener) {
  if (typeof listener !== "function") {
    throw new TypeError(
      `Signal listener must be a function. "${typeof listener}" is given.`,
    );
  }
}

function addSignalListenerImpl(signo, listener, trustedInternal) {
  checkSignalListenerType(listener);
  if (!trustedInternal) {
    op_oden_guard_deny_only_surface(
      "process",
      "signal",
      `listen:${signo}`,
      "Deno.addSignalListener/process.on(signal)",
    );
  }

  const sigData = getSignalData(signo);
  if (!sigData.rid) {
    // Bind before publishing the callback into shared state. A failed bind
    // must not leave a callback that a later trusted bind can activate.
    sigData.rid = bindSignal(signo, trustedInternal);
    loop(sigData);
  }
  SetPrototypeAdd(sigData.listeners, listener);
}

function removeSignalListenerImpl(signo, listener, trustedInternal) {
  checkSignalListenerType(listener);
  if (!trustedInternal) {
    op_oden_guard_deny_only_surface(
      "process",
      "signal",
      `unlisten:${signo}`,
      "Deno.removeSignalListener/process.off(signal)",
    );
  }

  const sigData = getSignalData(signo);
  SetPrototypeDelete(sigData.listeners, listener);

  if (sigData.listeners.size === 0 && sigData.rid) {
    unbindSignal(sigData.rid);
    sigData.rid = undefined;
  }
}

function addSignalListener(signo, listener) {
  return addSignalListenerImpl(signo, listener, false);
}

function removeSignalListener(signo, listener) {
  return removeSignalListenerImpl(signo, listener, false);
}

function addSignalListenerInternal(signo, listener) {
  return addSignalListenerImpl(signo, listener, true);
}

function removeSignalListenerInternal(signo, listener) {
  return removeSignalListenerImpl(signo, listener, true);
}

async function loop(sigData) {
  while (sigData.rid) {
    if (await pollSignal(sigData.rid)) {
      return;
    }
    for (const listener of new SafeSetIterator(sigData.listeners)) {
      listener();
    }
  }
}

return {
  addSignalListener,
  removeSignalListener,
  addSignalListenerInternal,
  removeSignalListenerInternal,
};
})();
