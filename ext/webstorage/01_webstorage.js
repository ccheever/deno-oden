// Copyright 2018-2026 the Deno authors. MIT license.

/// <reference path="../../core/internal.d.ts" />

(function () {
const { core, primordials } = __bootstrap;
const { op_oden_guard_surface, op_webstorage_iterate_keys, Storage } = core.ops;
const {
  SymbolFor,
  ObjectFromEntries,
  ObjectEntries,
  ReflectDefineProperty,
  ReflectDeleteProperty,
  FunctionPrototypeBind,
  ReflectHas,
  Proxy,
} = primordials;

function createStorage(persistent) {
  const storage = new Storage(persistent);
  const storageName = persistent ? "localStorage" : "sessionStorage";
  const guard = (action, target) =>
    op_oden_guard_surface("storage", action, `${storageName}:${target}`);

  const proxy = new Proxy(storage, {
    deleteProperty(target, key) {
      if (typeof key === "symbol") {
        return ReflectDeleteProperty(target, key);
      }
      guard("write", key);
      target.removeItem(key);
      return true;
    },

    defineProperty(target, key, descriptor) {
      if (typeof key === "symbol") {
        return ReflectDefineProperty(target, key, descriptor);
      }
      guard("write", key);
      target.setItem(key, descriptor.value);
      return true;
    },

    get(target, key) {
      if (typeof key === "symbol") {
        return target[key];
      }
      if (ReflectHas(target, key)) {
        const value = target[key];
        if (typeof value === "function") {
          const bound = FunctionPrototypeBind(value, target);
          switch (key) {
            case "getItem":
              return (itemKey) => {
                guard("read", itemKey);
                return bound(itemKey);
              };
            case "key":
              return (index) => {
                guard("read", `index:${index}`);
                return bound(index);
              };
            case "setItem":
              return (itemKey, itemValue) => {
                guard("write", itemKey);
                return bound(itemKey, itemValue);
              };
            case "removeItem":
              return (itemKey) => {
                guard("write", itemKey);
                return bound(itemKey);
              };
            case "clear":
              return () => {
                guard("write", "*");
                return bound();
              };
            default:
              return bound;
          }
        }
        if (key === "length") guard("read", "length");
        return value;
      }
      guard("read", key);
      return target.getItem(key) ?? undefined;
    },

    set(target, key, value) {
      if (typeof key === "symbol") {
        return ReflectDefineProperty(target, key, {
          __proto__: null,
          value,
          configurable: true,
        });
      }
      guard("write", key);
      target.setItem(key, value);
      return true;
    },

    has(target, key) {
      if (ReflectHas(target, key)) {
        return true;
      }
      if (typeof key === "string") guard("read", key);
      return typeof key === "string" &&
        typeof target.getItem(key) === "string";
    },

    ownKeys() {
      guard("read", "*");
      return op_webstorage_iterate_keys(storage);
    },

    getOwnPropertyDescriptor(target, key) {
      if (ReflectHas(target, key)) {
        return undefined;
      }
      if (typeof key === "symbol") {
        return undefined;
      }
      guard("read", key);
      const value = target.getItem(key);
      if (value === null) {
        return undefined;
      }
      return {
        value,
        enumerable: true,
        configurable: true,
        writable: true,
      };
    },
  });

  storage[SymbolFor("Deno.privateCustomInspect")] = function (
    inspect,
    inspectOptions,
  ) {
    return `Storage ${
      inspect({
        ...ObjectFromEntries(ObjectEntries(proxy)),
        length: this.length,
      }, inspectOptions)
    }`;
  };

  return proxy;
}

let localStorageStorage;
function localStorage() {
  if (!localStorageStorage) {
    localStorageStorage = createStorage(true);
  }
  return localStorageStorage;
}

let sessionStorageStorage;
function sessionStorage() {
  if (!sessionStorageStorage) {
    sessionStorageStorage = createStorage(false);
  }
  return sessionStorageStorage;
}

return { localStorage, sessionStorage, Storage };
})();
