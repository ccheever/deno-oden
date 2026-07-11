// Copyright 2018-2026 the Deno authors. MIT license.
// Copyright Joyent and Node contributors. All rights reserved. MIT license.

// deno-lint-ignore-file ban-untagged-todo

(function () {
const { core, primordials } = __bootstrap;
const { op_oden_guard_deny_only_surface } = core.ops;
const { ERR_INVALID_ARG_TYPE } = core.loadExtScript(
  "ext:deno_node/internal/errors.ts",
);
const { nextTick } = core.loadExtScript("ext:deno_node/_next_tick.ts");
const { validateFunction } = core.loadExtScript(
  "ext:deno_node/internal/validators.mjs",
);

const {
  ArrayPrototypeAt,
  ArrayPrototypeIndexOf,
  ArrayPrototypePush,
  ArrayPrototypePushApply,
  ArrayPrototypeSlice,
  ArrayPrototypeSplice,
  ObjectDefineProperty,
  ObjectGetPrototypeOf,
  ObjectPrototypeIsPrototypeOf,
  ObjectSetPrototypeOf,
  PromisePrototype,
  PromisePrototypeThen,
  PromiseReject,
  PromiseResolve,
  ReflectApply,
  SafeArrayIterator,
  SafeFinalizationRegistry,
  SafeMap,
  SafeMapIterator,
  SafeWeakMap,
  SymbolHasInstance,
} = primordials;
const { WeakReference } = core.loadExtScript(
  "ext:deno_node/internal/util.mjs",
);

// Can't delete when weakref count reaches 0 as it could increment again.
// Only GC can be used as a valid time to clean up the channels map.
class WeakRefMap extends SafeMap {
  #finalizers = new SafeFinalizationRegistry((key) => {
    // Finalization can run after a new Channel for the same key has already
    // replaced the previous WeakRef (test-diagnostics-channel-gc-race-
    // condition exercises this race). Only drop the entry if the live
    // WeakRef is empty; otherwise the new Channel would be orphaned and
    // `channel(name)` would hand out a fresh one, breaking identity.
    if (!this.has(key)) this.delete(key);
  });

  set(key, value) {
    this.#finalizers.register(value, key);
    return super.set(key, new WeakReference(value));
  }

  get(key) {
    return super.get(key)?.get();
  }

  has(key) {
    return !!this.get(key);
  }

  incRef(key) {
    return super.get(key)?.incRef();
  }

  decRef(key) {
    return super.get(key)?.decRef();
  }
}

function markActive(channel) {
  const state = channelStates.get(channel);
  ObjectSetPrototypeOf(channel, ActiveChannel.prototype);
  state.subscribers = [];
  state.stores = new SafeMap();
}

function maybeMarkInactive(channel) {
  const state = channelStates.get(channel);
  // When there are no more active subscribers or bound, restore to fast prototype.
  if (!state.subscribers.length && !state.stores.size) {
    ObjectSetPrototypeOf(channel, Channel.prototype);
    state.subscribers = undefined;
    state.stores = undefined;
  }
}

function defaultTransform(data) {
  return data;
}

function wrapStoreRun(store, data, next, transform = defaultTransform) {
  return () => {
    let context;
    try {
      context = transform(data);
    } catch (err) {
      nextTick(() => {
        // TODO(bartlomieju): in Node.js this is using `triggerUncaughtException` API, need
        // to clarify if we need that or if just throwing the error is enough here.
        throw err;
        // triggerUncaughtException(err, false);
      });
      return next();
    }

    return store.run(context, next);
  };
}

function guardChannel(channel, api) {
  const state = channelStates.get(channel);
  op_oden_guard_deny_only_surface(
    "runtime",
    "inspect",
    String(state.name),
    api,
  );
}

function hasChannelSubscribers(channel) {
  return channelStates.get(channel).subscribers !== undefined;
}

function publishChannel(channel, data) {
  // Capture the subscriber array up front so that subscribe/unsubscribe calls
  // from inside a handler do not shift the snapshot being walked.
  const state = channelStates.get(channel);
  const subscribers = state.subscribers;
  for (let i = 0; i < (subscribers?.length || 0); i++) {
    try {
      const onMessage = subscribers[i];
      onMessage(data, state.name);
    } catch (err) {
      nextTick(() => {
        throw err;
      });
    }
  }
}

function runChannelStores(channel, data, fn, thisArg, args) {
  const state = channelStates.get(channel);
  let run = () => {
    publishChannel(channel, data);
    return ReflectApply(fn, thisArg, args);
  };

  for (const entry of new SafeMapIterator(state.stores ?? new SafeMap())) {
    const store = entry[0];
    const transform = entry[1];
    run = wrapStoreRun(store, data, run, transform);
  }

  return run();
}

class ActiveChannel {
  subscribe(subscription) {
    const state = channelStates.get(this);
    // @ref LLP 0019#runtime-and-memory-inspection [implements]
    op_oden_guard_deny_only_surface(
      "runtime",
      "inspect",
      String(state.name),
      "node:diagnostics_channel.subscribe",
    );
    validateFunction(subscription, "subscription");
    // Replace the subscriber array with a copy so any in-flight publish that
    // captured the previous reference keeps iterating over the snapshot
    // it started with.
    state.subscribers = ArrayPrototypeSlice(state.subscribers);
    ArrayPrototypePush(state.subscribers, subscription);
    channels.incRef(state.name);
  }

  unsubscribe(subscription) {
    const state = channelStates.get(this);
    op_oden_guard_deny_only_surface(
      "runtime",
      "inspect",
      String(state.name),
      "node:diagnostics_channel.unsubscribe",
    );
    const index = ArrayPrototypeIndexOf(state.subscribers, subscription);
    if (index === -1) return false;

    // Build a new array via slice + pushApply so a concurrent publish keeps
    // iterating over its original snapshot - matches Node and lets
    // unsubscribe-during-publish still deliver to the remaining subscribers
    // in that publish call.
    const before = ArrayPrototypeSlice(state.subscribers, 0, index);
    const after = ArrayPrototypeSlice(state.subscribers, index + 1);
    state.subscribers = before;
    ArrayPrototypePushApply(state.subscribers, after);

    channels.decRef(state.name);
    maybeMarkInactive(this);

    return true;
  }

  bindStore(store, transform) {
    const state = channelStates.get(this);
    op_oden_guard_deny_only_surface(
      "runtime",
      "inspect",
      String(state.name),
      "node:diagnostics_channel.bindStore",
    );
    const replacing = state.stores.has(store);
    if (!replacing) channels.incRef(state.name);
    state.stores.set(store, transform);
  }

  unbindStore(store) {
    const state = channelStates.get(this);
    op_oden_guard_deny_only_surface(
      "runtime",
      "inspect",
      String(state.name),
      "node:diagnostics_channel.unbindStore",
    );
    if (!state.stores.has(store)) {
      return false;
    }

    state.stores.delete(store);

    channels.decRef(state.name);
    maybeMarkInactive(this);

    return true;
  }

  get hasSubscribers() {
    guardChannel(this, "node:diagnostics_channel.hasSubscribers");
    return true;
  }

  publish(data) {
    guardChannel(this, "node:diagnostics_channel.publish");
    publishChannel(this, data);
  }

  runStores(data, fn, thisArg, ...args) {
    guardChannel(this, "node:diagnostics_channel.runStores");
    return runChannelStores(this, data, fn, thisArg, args);
  }
}

class Channel {
  constructor(name, trustedToken) {
    if (trustedToken !== internalChannelToken) {
      op_oden_guard_deny_only_surface(
        "runtime",
        "inspect",
        String(name),
        "node:diagnostics_channel.Channel",
      );
    }
    this._subscribers = undefined;
    this._stores = undefined;
    this.name = name;
    channelStates.set(this, {
      __proto__: null,
      name,
      subscribers: undefined,
      stores: undefined,
    });

    channels.set(name, this);
  }

  static [SymbolHasInstance](instance) {
    const prototype = ObjectGetPrototypeOf(instance);
    return prototype === Channel.prototype ||
      prototype === ActiveChannel.prototype;
  }

  subscribe(subscription) {
    guardChannel(this, "node:diagnostics_channel.subscribe");
    validateFunction(subscription, "subscription");
    markActive(this);
    this.subscribe(subscription);
  }

  unsubscribe() {
    return false;
  }

  bindStore(store, transform) {
    guardChannel(this, "node:diagnostics_channel.bindStore");
    markActive(this);
    this.bindStore(store, transform);
  }

  unbindStore() {
    return false;
  }

  get hasSubscribers() {
    guardChannel(this, "node:diagnostics_channel.hasSubscribers");
    return false;
  }

  publish() {
    guardChannel(this, "node:diagnostics_channel.publish");
  }

  runStores(_data, fn, thisArg, ...args) {
    guardChannel(this, "node:diagnostics_channel.runStores");
    return ReflectApply(fn, thisArg, args);
  }
}

const channels = new WeakRefMap();
const channelStates = new SafeWeakMap();
const internalChannelToken = { __proto__: null };
const internalChannelFacades = new SafeWeakMap();

function channelImpl(name, trustedInternal) {
  if (!trustedInternal) {
    op_oden_guard_deny_only_surface(
      "runtime",
      "inspect",
      String(name),
      "node:diagnostics_channel.channel",
    );
  }
  const ch = channels.get(name);
  if (ch) return ch;

  if (typeof name !== "string" && typeof name !== "symbol") {
    throw new ERR_INVALID_ARG_TYPE("channel", ["string", "symbol"], name);
  }

  return new Channel(
    name,
    trustedInternal ? internalChannelToken : undefined,
  );
}

function channel(name) {
  return channelImpl(name, false);
}

// Node's own instrumentation runs on behalf of the package that triggered it.
// Keep its publisher path closure-private so it can publish to a channel that
// root subscribed to without making the public Channel object a transferable
// bypass.
function channelInternal(name) {
  const ch = channelImpl(name, true);
  let facade = internalChannelFacades.get(ch);
  if (facade) return facade;
  facade = {
    __proto__: null,
    get hasSubscribers() {
      return hasChannelSubscribers(ch);
    },
    publish(data) {
      return publishChannel(ch, data);
    },
    runStores(data, fn, thisArg, ...args) {
      return runChannelStores(ch, data, fn, thisArg, args);
    },
  };
  internalChannelFacades.set(ch, facade);
  return facade;
}

function subscribe(name, subscription) {
  return channel(name).subscribe(subscription);
}

function unsubscribe(name, subscription) {
  return channel(name).unsubscribe(subscription);
}

function hasSubscribers(name) {
  op_oden_guard_deny_only_surface(
    "runtime",
    "inspect",
    String(name),
    "node:diagnostics_channel.hasSubscribers",
  );
  const ch = channels.get(name);
  if (!ch) return false;

  return ch.hasSubscribers;
}

const traceEvents = [
  "start",
  "end",
  "asyncStart",
  "asyncEnd",
  "error",
];

function assertChannel(value, name) {
  // Channel defines a custom [Symbol.hasInstance] (accepting both Channel and
  // ActiveChannel prototypes), so this instanceof must stay to preserve that
  // behavior; ObjectPrototypeIsPrototypeOf would bypass it.
  // deno-lint-ignore prefer-primordials
  if (!(value instanceof Channel)) {
    throw new ERR_INVALID_ARG_TYPE(name, ["Channel"], value);
  }
}

function tracingChannelFrom(nameOrChannels, name) {
  if (typeof nameOrChannels === "string") {
    return channel(`tracing:${nameOrChannels}:${name}`);
  }

  if (typeof nameOrChannels === "object" && nameOrChannels !== null) {
    const ch = nameOrChannels[name];
    assertChannel(ch, `nameOrChannels.${name}`);
    return ch;
  }

  throw new ERR_INVALID_ARG_TYPE("nameOrChannels", [
    "string",
    "object",
    "TracingChannel",
  ], nameOrChannels);
}

class TracingChannel {
  constructor(nameOrChannels, trustedToken) {
    const trustedInternal = trustedToken === internalChannelToken;
    for (const eventName of new SafeArrayIterator(traceEvents)) {
      ObjectDefineProperty(this, eventName, {
        __proto__: null,
        value: trustedInternal && typeof nameOrChannels === "string"
          ? channelInternal(`tracing:${nameOrChannels}:${eventName}`)
          : tracingChannelFrom(nameOrChannels, eventName),
      });
    }
  }

  get hasSubscribers() {
    return this.start.hasSubscribers ||
      this.end.hasSubscribers ||
      this.asyncStart.hasSubscribers ||
      this.asyncEnd.hasSubscribers ||
      this.error.hasSubscribers;
  }

  subscribe(handlers) {
    for (const name of new SafeArrayIterator(traceEvents)) {
      if (!handlers[name]) continue;

      this[name]?.subscribe(handlers[name]);
    }
  }

  unsubscribe(handlers) {
    let done = true;

    for (const name of new SafeArrayIterator(traceEvents)) {
      if (!handlers[name]) continue;

      if (!this[name]?.unsubscribe(handlers[name])) {
        done = false;
      }
    }

    return done;
  }

  traceSync(fn, context = { __proto__: null }, thisArg, ...args) {
    if (!this.hasSubscribers) {
      return ReflectApply(fn, thisArg, args);
    }

    const { start, end, error } = this;

    return start.runStores(context, () => {
      try {
        const result = ReflectApply(fn, thisArg, args);
        context.result = result;
        return result;
      } catch (err) {
        context.error = err;
        error.publish(context);
        throw err;
      } finally {
        end.publish(context);
      }
    });
  }

  tracePromise(fn, context = { __proto__: null }, thisArg, ...args) {
    if (!this.hasSubscribers) {
      return ReflectApply(fn, thisArg, args);
    }

    const { start, end, asyncStart, asyncEnd, error } = this;

    function reject(err) {
      context.error = err;
      error.publish(context);
      // Run (not just publish) the asyncStart stores so transforms bound via
      // bindStore are invoked. Promises have no "after" continuation point, so
      // the stores only wrap a no-op rather than the rest of the chain.
      asyncStart.runStores(context, () => {});
      // TODO: Is there a way to have asyncEnd _after_ the continuation?
      asyncEnd.publish(context);
      return PromiseReject(err);
    }

    function resolve(result) {
      context.result = result;
      asyncStart.runStores(context, () => {});
      // TODO: Is there a way to have asyncEnd _after_ the continuation?
      asyncEnd.publish(context);
      return result;
    }

    return start.runStores(context, () => {
      try {
        let promise = ReflectApply(fn, thisArg, args);
        // Convert thenables to native promises
        if (!ObjectPrototypeIsPrototypeOf(PromisePrototype, promise)) {
          promise = PromiseResolve(promise);
        }
        return PromisePrototypeThen(promise, resolve, reject);
      } catch (err) {
        context.error = err;
        error.publish(context);
        throw err;
      } finally {
        end.publish(context);
      }
    });
  }

  traceCallback(
    fn,
    position = -1,
    context = { __proto__: null },
    thisArg,
    ...args
  ) {
    if (!this.hasSubscribers) {
      return ReflectApply(fn, thisArg, args);
    }

    const { start, end, asyncStart, asyncEnd, error } = this;

    function wrappedCallback(err, res) {
      if (err) {
        context.error = err;
        error.publish(context);
      } else {
        context.result = res;
      }

      // Using runStores here enables manual context failure recovery
      asyncStart.runStores(context, () => {
        try {
          return ReflectApply(callback, this, arguments);
        } finally {
          asyncEnd.publish(context);
        }
      });
    }

    const callback = ArrayPrototypeAt(args, position);
    validateFunction(callback, "callback");
    ArrayPrototypeSplice(args, position, 1, wrappedCallback);

    return start.runStores(context, () => {
      try {
        return ReflectApply(fn, thisArg, args);
      } catch (err) {
        context.error = err;
        error.publish(context);
        throw err;
      } finally {
        end.publish(context);
      }
    });
  }
}

function tracingChannel(nameOrChannels) {
  op_oden_guard_deny_only_surface(
    "runtime",
    "inspect",
    String(nameOrChannels),
    "node:diagnostics_channel.tracingChannel",
  );
  return new TracingChannel(nameOrChannels);
}

function tracingChannelInternal(name) {
  return new TracingChannel(name, internalChannelToken);
}

return {
  default: {
    channel,
    hasSubscribers,
    subscribe,
    tracingChannel,
    unsubscribe,
    Channel,
  },
  channel,
  channelInternal,
  hasSubscribers,
  subscribe,
  tracingChannel,
  tracingChannelInternal,
  unsubscribe,
  Channel,
};
})();
