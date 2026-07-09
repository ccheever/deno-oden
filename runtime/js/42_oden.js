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
} = core.ops;
const {
  ObjectFreeze,
  ObjectDefineProperty,
  TypeError,
} = primordials;

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
ObjectFreeze(oden);

// Returned to 99_main.js (via loadExtScript) for conditional install onto the
// Deno namespace when capsec is armed.
return { oden };
})();
