// Copyright 2018-2026 the Deno authors. MIT license.

//! Oden capsec authority-flow: handles and attenuators (LLP 0001 §Delegation
//! and handles, ENG-23784). The general form of the Phase-2 minimal transfer
//! primitive (`oden_capsec_transfer_resource`): a package attenuates a
//! capability it holds into an unforgeable handle and hands the *narrower* one
//! across a package boundary, so legitimate cross-package resource sharing
//! works without granting ambient authority.
//!
//! The model, per LLP 0001:
//! - **mint** is *frame-checked* — the minter must actually hold the authority
//!   at mint time (glue in `lib.rs` checks `Policy::grants`); a mint cannot
//!   exceed what the minter holds.
//! - **use** is *possession-checked, never frame-checked* — holding the handle
//!   is the authority, so no stack walk happens at use (the Java
//!   SecurityManager failure mode stays dodged). Possession is concrete: a use
//!   window pushes the handle's capability onto a thread-local for the
//!   synchronous duration of the possessor's callback, and the enforcement
//!   funnel consults it.
//! - **`scoped()`** re-attenuation only *narrows* — a child capability must be
//!   covered by its parent; over-broad re-widening is denied.
//! - **revocation cascades** through derived handles — revoking a handle
//!   revokes every handle transitively derived from it.
//! - **ids are unguessable** — a 128-bit CSPRNG value keyed into this host-side
//!   table. The JS object is only a carrier; a forged/guessed id names nothing.
//!
//! This module is the pure, unit-testable table + window. The glue that
//! resolves the acting principal, consults the policy for the frame-check, and
//! writes audit records lives in `lib.rs`. Everything here is inert unless the
//! glue is reached, which only happens when capsec is armed.
//! @ref llp/0001-adding-capability-security-to-deno.plan.md

use std::cell::RefCell;
use std::collections::HashMap;

use once_cell::sync::Lazy;
use parking_lot::Mutex;

use crate::oden_policy::Grant;
use crate::oden_policy::Request;
use crate::oden_policy::covers;

/// A minted authority handle: an attenuated capability bound to an unguessable
/// id, with a link to the handle it was derived from (for cascade revocation).
#[derive(Debug, Clone)]
pub struct HandleEntry {
  /// The principal label that minted this handle (audit / diagnostics only —
  /// never consulted at use; use is possession-checked).
  pub minter: String,
  /// The attenuated capability this handle carries.
  pub grant: Grant,
  /// Normalized capability string for audit and introspection.
  pub cap_str: String,
  /// The parent handle this was `scoped()` from, if any. `None` for a mint.
  pub parent: Option<u128>,
  /// Explicitly revoked (directly or by a cascade from an ancestor).
  pub revoked: bool,
  /// Possessor labels that have already opened a use window on this handle,
  /// so the boundary-crossing `transfer` audit record fires once per new
  /// possessor rather than on every use.
  pub seen_by: Vec<String>,
}

/// The result of validating a handle for a use/scoped/revoke operation.
#[derive(Debug, PartialEq, Eq)]
pub enum HandleLookup {
  /// The id is unknown — a forged/guessed id, or a stale one from before the
  /// table existed. Fail closed: it names no authority.
  Unknown,
  /// The handle (or an ancestor) has been revoked. Fail closed.
  Revoked,
  /// The handle is live; its attenuated capability is returned.
  Live {
    grant: Grant,
    cap_str: String,
    minter: String,
  },
}

pub struct HandleTable {
  map: HashMap<u128, HandleEntry>,
}

impl HandleTable {
  fn new() -> HandleTable {
    HandleTable {
      map: HashMap::new(),
    }
  }

  /// Insert a freshly-minted or scoped handle under its id.
  fn insert(
    &mut self,
    id: u128,
    minter: String,
    grant: Grant,
    cap_str: String,
    parent: Option<u128>,
  ) {
    self.map.insert(
      id,
      HandleEntry {
        minter,
        grant,
        cap_str,
        parent,
        revoked: false,
        seen_by: Vec::new(),
      },
    );
  }

  /// Walk the parent chain; true if this handle or any ancestor is revoked (or
  /// an ancestor id has vanished, which we treat as revoked — fail closed).
  fn any_ancestor_revoked(&self, id: u128) -> bool {
    let mut cur = Some(id);
    let mut guard = 0;
    while let Some(cid) = cur {
      guard += 1;
      if guard > 4096 {
        return true; // pathological cycle — fail closed
      }
      match self.map.get(&cid) {
        None => return true, // ancestor gone: fail closed
        Some(e) if e.revoked => return true,
        Some(e) => cur = e.parent,
      }
    }
    false
  }

  /// Look up a handle for use. Returns its attenuated capability if live.
  pub fn lookup(&self, id: u128) -> HandleLookup {
    match self.map.get(&id) {
      None => HandleLookup::Unknown,
      Some(e) => {
        if e.revoked || self.any_ancestor_revoked(id) {
          HandleLookup::Revoked
        } else {
          HandleLookup::Live {
            grant: e.grant.clone(),
            cap_str: e.cap_str.clone(),
            minter: e.minter.clone(),
          }
        }
      }
    }
  }

  /// The parent's attenuated capability, if the parent handle is live. Used to
  /// enforce that `scoped()` only narrows.
  pub fn parent_grant_if_live(&self, parent_id: u128) -> Option<Grant> {
    match self.lookup(parent_id) {
      HandleLookup::Live { grant, .. } => Some(grant),
      _ => None,
    }
  }

  /// Record that `possessor` has opened a use window on `id`. Returns true if
  /// this is the first time this possessor uses it *and* the possessor is not
  /// the minter — i.e. a genuine boundary crossing worth a `transfer` record.
  pub fn note_possessor(&mut self, id: u128, possessor: &str) -> bool {
    let Some(e) = self.map.get_mut(&id) else {
      return false;
    };
    if e.seen_by.iter().any(|p| p == possessor) {
      return false;
    }
    e.seen_by.push(possessor.to_string());
    possessor != e.minter
  }

  /// Revoke `id` and every handle transitively derived from it. Returns the
  /// list of (id, cap_str) actually revoked by this call (already-revoked
  /// handles are skipped) so the glue can emit one audit record each. The root
  /// id is first.
  pub fn revoke_cascade(&mut self, id: u128) -> Vec<(u128, String)> {
    if !self.map.contains_key(&id) {
      return Vec::new();
    }
    // Collect the transitive closure of descendants by parent-pointer walk.
    let mut targets: Vec<u128> = vec![id];
    let mut i = 0;
    while i < targets.len() {
      let cur = targets[i];
      for (cid, e) in self.map.iter() {
        if e.parent == Some(cur) && !targets.contains(cid) {
          targets.push(*cid);
        }
      }
      i += 1;
    }
    let mut out = Vec::new();
    for tid in targets {
      if let Some(e) = self.map.get_mut(&tid)
        && !e.revoked
      {
        e.revoked = true;
        out.push((tid, e.cap_str.clone()));
      }
    }
    out
  }

  #[cfg(test)]
  fn is_revoked(&self, id: u128) -> bool {
    self.map.get(&id).map(|e| e.revoked).unwrap_or(true)
  }
}

/// Process-global handle table. Keyed by unguessable id, so it is safe to share
/// across the isolate's packages: possession of the id (via the carrier object)
/// is the only way to name an entry.
static HANDLE_TABLE: Lazy<Mutex<HandleTable>> =
  Lazy::new(|| Mutex::new(HandleTable::new()));

pub fn with_table<R>(f: impl FnOnce(&mut HandleTable) -> R) -> R {
  f(&mut HANDLE_TABLE.lock())
}

/// A fresh unguessable 128-bit handle id from the OS CSPRNG. Guessing one is a
/// 2^-128 event, so a package cannot forge a handle it was not handed.
pub fn fresh_id() -> u128 {
  use rand::RngCore;
  let mut buf = [0u8; 16];
  rand::rngs::OsRng.fill_bytes(&mut buf);
  u128::from_le_bytes(buf)
}

pub fn insert_handle(
  minter: String,
  grant: Grant,
  cap_str: String,
  parent: Option<u128>,
) -> u128 {
  let id = fresh_id();
  with_table(|t| t.insert(id, minter, grant, cap_str, parent));
  id
}

// --- Possession window ------------------------------------------------------
// `use(fn)` opens a synchronous window: the handle's attenuated capability is
// pushed onto this thread-local for the duration of the possessor's callback,
// and the enforcement funnel (`oden_capsec_decide`) consults it. The window is
// synchronous by construction — the JS side pops it in a `finally` right after
// the callback returns — so an async continuation scheduled inside the callback
// does NOT inherit the handle authority (that would be ambient authority; it
// fails closed instead, consistent with the schedule-before-first-op residual).
thread_local! {
  static ACTIVE_HANDLES: RefCell<Vec<Grant>> = const { RefCell::new(Vec::new()) };
}

/// Push an attenuated capability onto the active-use window (enter).
pub fn push_active(grant: Grant) {
  ACTIVE_HANDLES.with(|h| h.borrow_mut().push(grant));
}

/// Pop the most recent active capability (exit). Balanced with `push_active`
/// by the JS `try/finally`.
pub fn pop_active() {
  ACTIVE_HANDLES.with(|h| {
    h.borrow_mut().pop();
  });
}

/// Does any capability in the active-use window cover this request? This is the
/// possession check made concrete: an op that the possessor's own grants would
/// deny is allowed iff a handle it is actively using covers it.
pub fn active_covers(req: &Request) -> bool {
  ACTIVE_HANDLES.with(|h| {
    let stack = h.borrow();
    stack.iter().any(|g| covers(std::slice::from_ref(g), req))
  })
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::oden_policy::Family;

  fn fs_grant(action: &str, scope: &str) -> Grant {
    Grant {
      family: Family::Fs,
      action: action.into(),
      scope: scope.into(),
    }
  }

  fn fs_req(action: &str, target: &str) -> Request {
    Request {
      family: Family::Fs,
      action: action.into(),
      target: target.into(),
    }
  }

  #[test]
  fn unknown_id_is_fail_closed() {
    let t = HandleTable::new();
    assert_eq!(t.lookup(0xdead_beef), HandleLookup::Unknown);
  }

  #[test]
  fn live_handle_returns_its_capability() {
    let mut t = HandleTable::new();
    t.insert(
      1,
      "dep-a".into(),
      fs_grant("read", "/s/pub"),
      "fs:read:/s/pub".into(),
      None,
    );
    match t.lookup(1) {
      HandleLookup::Live { grant, .. } => {
        assert_eq!(grant, fs_grant("read", "/s/pub"))
      }
      other => panic!("expected Live, got {other:?}"),
    }
  }

  #[test]
  fn revocation_cascades_through_derived_handles() {
    let mut t = HandleTable::new();
    // H1 (mint) -> H2 (scoped) -> H3 (scoped)
    t.insert(
      1,
      "dep-a".into(),
      fs_grant("read", "/s"),
      "fs:read:/s".into(),
      None,
    );
    t.insert(
      2,
      "dep-a".into(),
      fs_grant("read", "/s/pub"),
      "fs:read:/s/pub".into(),
      Some(1),
    );
    t.insert(
      3,
      "dep-a".into(),
      fs_grant("read", "/s/pub/a"),
      "fs:read:/s/pub/a".into(),
      Some(2),
    );
    // Revoking the root cascades to both descendants.
    let revoked = t.revoke_cascade(1);
    let ids: Vec<u128> = revoked.iter().map(|(id, _)| *id).collect();
    assert!(ids.contains(&1) && ids.contains(&2) && ids.contains(&3));
    assert_eq!(t.lookup(2), HandleLookup::Revoked);
    assert_eq!(t.lookup(3), HandleLookup::Revoked);
  }

  #[test]
  fn revoking_a_child_leaves_the_parent_live() {
    let mut t = HandleTable::new();
    t.insert(
      1,
      "dep-a".into(),
      fs_grant("read", "/s"),
      "fs:read:/s".into(),
      None,
    );
    t.insert(
      2,
      "dep-a".into(),
      fs_grant("read", "/s/pub"),
      "fs:read:/s/pub".into(),
      Some(1),
    );
    t.revoke_cascade(2);
    assert_eq!(t.lookup(2), HandleLookup::Revoked);
    assert!(matches!(t.lookup(1), HandleLookup::Live { .. }));
    assert!(!t.is_revoked(1));
  }

  #[test]
  fn transfer_record_fires_once_per_new_possessor() {
    let mut t = HandleTable::new();
    t.insert(
      1,
      "dep-a".into(),
      fs_grant("read", "/s/pub"),
      "fs:read:/s/pub".into(),
      None,
    );
    // Minter using its own handle is not a boundary crossing.
    assert!(!t.note_possessor(1, "dep-a"));
    // First cross-package use crosses the boundary.
    assert!(t.note_possessor(1, "dep-b"));
    // Repeat use by the same possessor does not re-fire.
    assert!(!t.note_possessor(1, "dep-b"));
  }

  #[test]
  fn active_window_covers_only_within_scope() {
    push_active(fs_grant("read", "/s/pub"));
    assert!(active_covers(&fs_req("read", "/s/pub/a")));
    assert!(!active_covers(&fs_req("read", "/s/secret")));
    // Wrong action is not covered.
    assert!(!active_covers(&fs_req("write", "/s/pub/a")));
    pop_active();
    // Popped: nothing is covered anymore.
    assert!(!active_covers(&fs_req("read", "/s/pub/a")));
  }
}
