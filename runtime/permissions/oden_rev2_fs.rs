// Copyright 2018-2026 the Deno authors. MIT license.

//! Dormant host-only checked filesystem-object foundation for CapSec Rev2.
//!
//! This module authenticates retained roots and produces source/root-bound
//! lexical and identity facts. It does not match policy, authorize an
//! operation, expose raw descriptors, perform mutations, or promote a backend
//! conformance cell. Symlink following is deliberately staged: discovery
//! yields a challenge, and traversal cannot continue until a one-use proof for
//! that exact challenge is consumed.
//!
//! Production checkpoint: operation sessions and continuation proofs have no
//! constructors until HostActor attribution and current-generation shared-core
//! re-entry are wired. Cross-root continuation recognizes only the exact
//! destination canonical-path spelling. Platform aliases, including APFS
//! case-folded or Unicode-equivalent spellings, refuse closed. Missing and
//! proposed children report `RequiresAtomicParentRelativeCommit`, but this
//! module deliberately exposes no executable mutation helper.
//!
//! @ref LLP 0019#paths [implements] -- Lexical occurrence and resolved object
//! identity are separate host facts, link following is staged before target
//! access, and retained handles couple observations to later host operations.
//! @ref LLP 0019#armed-identity-and-exact-linked-bindings [implements] -- Live
//! named roots and explicit root transitions are authenticated against the
//! exact C03-retained objects.
//! @ref LLP 0019#operation-scoped-positive-authority-provenance [constrained-by]
//! -- Checked facts and hop challenges are not reusable allow decisions.

#![allow(
  dead_code,
  reason = "ENG-24019 lands a dormant checked-object foundation before reviewed operation wiring"
)]

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::collections::VecDeque;
use std::ffi::CString;
use std::ffi::OsStr;
use std::ffi::OsString;
use std::fs::File;
use std::io;
use std::path::Component;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;

use serde_json::Value;
use serde_json::json;

#[cfg(unix)]
use std::os::fd::AsRawFd;
#[cfg(unix)]
use std::os::fd::FromRawFd;
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
#[cfg(unix)]
use std::os::unix::ffi::OsStringExt;
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

use crate::oden_rev2_context::OdenRev2FilesystemNativeCommitWitness;
use crate::oden_rev2_context::OdenRev2NamespaceGateToken;
use crate::oden_rev2_context::OdenRev2PlatformPath;
use crate::oden_rev2_context::OdenRev2RootBinding;
use crate::oden_rev2_permission::platform_path_value;
use crate::oden_rev2_permission::relative_platform_path;
use crate::oden_rev2_policy::OdenRev2RetainedObject;
use crate::oden_rev2_runtime::OdenRev2FilesystemCommittedWitness;
use crate::oden_rev2_runtime::OdenRev2FilesystemPendingWitness;
use crate::rev2::DecisionPolicyInput;
use crate::rev2::PathBindingInput;
use crate::rev2::ProvisionalResources;
use crate::rev2::StageRequest;
use crate::rev2::domain_digest;

const MAX_SYMLINK_TRAVERSALS: usize = 40;
const MAX_SYMLINK_BYTES: usize = 64 * 1024;
const MAX_ACTOR_PROVISIONAL_HANDLES: usize = 1024;
static NEXT_HOP_CHALLENGE: AtomicU64 = AtomicU64::new(1);
#[cfg(test)]
static NEXT_OPERATION_SESSION: AtomicU64 = AtomicU64::new(1);

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OdenRev2FsMkdirCommitFaultForTest {
  RaceExisting,
  UncertainAfterSyscall,
}

#[cfg(test)]
thread_local! {
  static ODEN_REV2_FS_MKDIR_COMMIT_FAULT_FOR_TEST: std::cell::Cell<Option<OdenRev2FsMkdirCommitFaultForTest>> = const { std::cell::Cell::new(None) };
  static ODEN_REV2_FS_LAST_RELEASED_HANDLES_FOR_TEST: std::cell::RefCell<Vec<std::sync::Weak<File>>> = const { std::cell::RefCell::new(Vec::new()) };
}

#[cfg(test)]
pub(crate) fn oden_rev2_fs_set_mkdir_commit_fault_for_test(
  fault: Option<OdenRev2FsMkdirCommitFaultForTest>,
) {
  ODEN_REV2_FS_MKDIR_COMMIT_FAULT_FOR_TEST.with(|current| current.set(fault));
}

#[cfg(test)]
pub(crate) fn oden_rev2_fs_take_last_released_handles_for_test()
-> Vec<std::sync::Weak<File>> {
  ODEN_REV2_FS_LAST_RELEASED_HANDLES_FOR_TEST
    .with(|handles| std::mem::take(&mut *handles.borrow_mut()))
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum OdenRev2FsError {
  #[error("Rev2 checked-object resolution is unsupported on this platform")]
  UnsupportedPlatform,
  #[error("invalid authenticated filesystem binding: {0}")]
  InvalidBinding(&'static str),
  #[error("invalid checked filesystem path: {0}")]
  InvalidPath(&'static str),
  #[error("the live named root no longer identifies the retained root")]
  RootReplacement,
  #[error("path resolution escaped the authenticated root")]
  RootEscape,
  #[error("path resolution exceeded the bounded symlink traversal limit")]
  SymlinkLimit,
  #[error("a non-final path component does not exist")]
  MissingAncestor,
  #[error("a filesystem entry changed between resolution stages")]
  ReplacementDuringResolution,
  #[error("the symlink continuation proof does not bind this exact hop")]
  HopAuthorizationMismatch,
  #[error(
    "the symlink continuation proof does not bind this operation session"
  )]
  OperationSessionMismatch,
  #[error("the target cannot be classified through a non-consuming open")]
  NonConsumingOpenUnsupported,
  #[error("the checked object cannot support operation {0}")]
  OperationUnsupported(&'static str),
  #[error(
    "the checked object does not authenticate the requested root transition"
  )]
  RootTransitionMismatch,
  #[error("filesystem observation failed during {operation}: {source}")]
  Io {
    operation: &'static str,
    #[source]
    source: io::Error,
  },
}

impl OdenRev2FsError {
  fn io(operation: &'static str, source: io::Error) -> Self {
    Self::Io { operation, source }
  }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OdenRev2FsFollowMode {
  FollowFinal,
  NoFollowFinal,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OdenRev2FsObjectKind {
  RegularFile,
  Directory,
  Symlink,
  Fifo,
  Socket,
  CharacterDevice,
  BlockDevice,
  Other,
}

impl OdenRev2FsObjectKind {
  fn is_special(self) -> bool {
    matches!(
      self,
      Self::Fifo
        | Self::Socket
        | Self::CharacterDevice
        | Self::BlockDevice
        | Self::Other
    )
  }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(crate) struct OdenRev2FsPlatformIdentity {
  device: u64,
  inode: u64,
}

impl OdenRev2FsPlatformIdentity {
  pub(crate) fn device(&self) -> u64 {
    self.device
  }

  pub(crate) fn inode(&self) -> u64 {
    self.inode
  }

  pub(crate) fn canonical_value(&self) -> String {
    format!("unix-dev-ino:{:016x}{:016x}", self.device, self.inode)
  }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct OdenRev2FsObservedMetadata {
  identity: OdenRev2FsPlatformIdentity,
  kind: OdenRev2FsObjectKind,
  link_count: u64,
  device_id: u64,
}

#[cfg(unix)]
impl OdenRev2FsObservedMetadata {
  fn from_stat(stat: &libc::stat) -> Self {
    Self {
      identity: OdenRev2FsPlatformIdentity {
        device: stat.st_dev as u64,
        inode: stat.st_ino as u64,
      },
      kind: object_kind(stat.st_mode as libc::mode_t),
      link_count: stat.st_nlink as u64,
      device_id: stat.st_rdev as u64,
    }
  }

  fn from_metadata(metadata: &std::fs::Metadata) -> Self {
    Self {
      identity: OdenRev2FsPlatformIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
      },
      kind: object_kind(metadata.mode() as libc::mode_t),
      link_count: metadata.nlink(),
      device_id: metadata.rdev(),
    }
  }
}

#[cfg(unix)]
fn object_kind(mode: libc::mode_t) -> OdenRev2FsObjectKind {
  match mode & libc::S_IFMT {
    libc::S_IFREG => OdenRev2FsObjectKind::RegularFile,
    libc::S_IFDIR => OdenRev2FsObjectKind::Directory,
    libc::S_IFLNK => OdenRev2FsObjectKind::Symlink,
    libc::S_IFIFO => OdenRev2FsObjectKind::Fifo,
    libc::S_IFSOCK => OdenRev2FsObjectKind::Socket,
    libc::S_IFCHR => OdenRev2FsObjectKind::CharacterDevice,
    libc::S_IFBLK => OdenRev2FsObjectKind::BlockDevice,
    _ => OdenRev2FsObjectKind::Other,
  }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OdenRev2FsCanonicalizerAdapter {
  LinuxFdRelativeV1,
  DarwinFdRelativeV1,
}

/// Opaque operation lifetime bound to the actor attribution and exact policy
/// generation vector observed before resolution begins. A session is reusable
/// across the staged hops of one operation, but its fact is copied into every
/// challenge and authorization proof so another actor/generation cannot reuse
/// them.
#[derive(Debug)]
pub(crate) struct OdenRev2FsOperationSession {
  fact: OdenRev2FsOperationSessionFact,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct OdenRev2FsOperationSessionFact {
  session_id: u64,
  actor_identity: String,
  generation_vector_token: String,
}

impl OdenRev2FsOperationSession {
  /// Seal one filesystem operation to the context-minted namespace token and
  /// the host-captured actor digest. Neither input can be supplied by JS, and
  /// the namespace token has no public constructor.
  pub(crate) fn capture_host(
    gate_token: &OdenRev2NamespaceGateToken,
    actor_identity: String,
  ) -> Result<Self, OdenRev2FsError> {
    if actor_identity.trim().is_empty() || actor_identity.len() > 1024 {
      return Err(OdenRev2FsError::InvalidBinding(
        "invalid operation actor identity",
      ));
    }
    let generation_vector_token = domain_digest(
      "oden:capsec:filesystem-operation-session:2",
      &json!({
        "actorIdentity": actor_identity,
        "generations": gate_token.generations(),
        "identity": gate_token.identity(),
        "sessionId": gate_token.sequence().to_string(),
      }),
    )
    .map_err(|_| {
      OdenRev2FsError::InvalidBinding("filesystem operation session digest")
    })?;
    Ok(Self {
      fact: OdenRev2FsOperationSessionFact {
        session_id: gate_token.sequence(),
        actor_identity,
        generation_vector_token,
      },
    })
  }

  pub(crate) fn fact(&self) -> &OdenRev2FsOperationSessionFact {
    &self.fact
  }

  fn matches_gate_token(
    &self,
    gate_token: &OdenRev2NamespaceGateToken,
  ) -> bool {
    if self.fact.session_id != gate_token.sequence() {
      return false;
    }
    domain_digest(
      "oden:capsec:filesystem-operation-session:2",
      &json!({
        "actorIdentity": self.fact.actor_identity,
        "generations": gate_token.generations(),
        "identity": gate_token.identity(),
        "sessionId": gate_token.sequence().to_string(),
      }),
    )
    .is_ok_and(|digest| digest == self.fact.generation_vector_token)
  }
}

impl OdenRev2FsOperationSessionFact {
  pub(crate) fn actor_identity(&self) -> &str {
    &self.actor_identity
  }

  pub(crate) fn generation_vector_token(&self) -> &str {
    &self.generation_vector_token
  }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct OdenRev2FsSourceRootFact {
  source_id: String,
  logical_root: String,
  root_binding_id: String,
  root_identity: OdenRev2FsPlatformIdentity,
  adapter: OdenRev2FsCanonicalizerAdapter,
}

impl OdenRev2FsSourceRootFact {
  pub(crate) fn source_id(&self) -> &str {
    &self.source_id
  }

  pub(crate) fn logical_root(&self) -> &str {
    &self.logical_root
  }

  pub(crate) fn root_binding_id(&self) -> &str {
    &self.root_binding_id
  }

  pub(crate) fn root_identity(&self) -> &OdenRev2FsPlatformIdentity {
    &self.root_identity
  }

  pub(crate) fn adapter(&self) -> OdenRev2FsCanonicalizerAdapter {
    self.adapter
  }
}

/// A lexical occurrence is source/root-bound input to the shared core. This
/// type intentionally has no exact/tree matching method: byte spelling alone
/// is not platform policy truth, and positive/negative polarity combines this
/// fact with independently authenticated identity facts in the shared core.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct OdenRev2FsLexicalFact {
  source_root: OdenRev2FsSourceRootFact,
  relative_path: PathBuf,
  follow_mode: OdenRev2FsFollowMode,
}

impl OdenRev2FsLexicalFact {
  pub(crate) fn source_root(&self) -> &OdenRev2FsSourceRootFact {
    &self.source_root
  }

  pub(crate) fn relative_path(&self) -> &Path {
    &self.relative_path
  }

  pub(crate) fn follow_mode(&self) -> OdenRev2FsFollowMode {
    self.follow_mode
  }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum OdenRev2FsIdentityState {
  Existing {
    identity: OdenRev2FsPlatformIdentity,
    kind: OdenRev2FsObjectKind,
  },
  NoFollowLink {
    identity: OdenRev2FsPlatformIdentity,
  },
  MissingParent {
    parent_identity: OdenRev2FsPlatformIdentity,
  },
  ProposedParent {
    parent_identity: OdenRev2FsPlatformIdentity,
    kind: OdenRev2FsProposedKind,
  },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct OdenRev2FsIdentityFact {
  source_root: OdenRev2FsSourceRootFact,
  state: OdenRev2FsIdentityState,
}

impl OdenRev2FsIdentityFact {
  pub(crate) fn source_root(&self) -> &OdenRev2FsSourceRootFact {
    &self.source_root
  }

  pub(crate) fn state(&self) -> &OdenRev2FsIdentityState {
    &self.state
  }

  pub(crate) fn object_identity(&self) -> Option<&OdenRev2FsPlatformIdentity> {
    match &self.state {
      OdenRev2FsIdentityState::Existing { identity, .. }
      | OdenRev2FsIdentityState::NoFollowLink { identity } => Some(identity),
      OdenRev2FsIdentityState::MissingParent { .. }
      | OdenRev2FsIdentityState::ProposedParent { .. } => None,
    }
  }
}

#[derive(Debug)]
struct OdenRev2FsRootState {
  source_id: String,
  logical_root: String,
  binding_id: String,
  canonical_path: Option<PathBuf>,
  identity: OdenRev2FsPlatformIdentity,
  adapter: OdenRev2FsCanonicalizerAdapter,
  retained: Arc<File>,
  named: Arc<File>,
}

/// An authenticated logical root backed by both the C03-retained descriptor
/// and an independently opened live name with the same platform identity.
#[derive(Debug)]
pub(crate) struct OdenRev2FsAuthenticatedRoot {
  state: Arc<OdenRev2FsRootState>,
}

impl OdenRev2FsAuthenticatedRoot {
  pub(crate) fn authenticate(
    binding: &OdenRev2RootBinding,
    retained: &OdenRev2RetainedObject,
  ) -> Result<Self, OdenRev2FsError> {
    if binding.binding_id() != retained.binding_id()
      || binding.source_id() != retained.source_id()
      || retained.role().is_some()
      || binding.principal() != retained.principal()
      || binding.object_identity().value() != retained.object_identity()
      || binding.binding_provenance_digest()
        != retained.provenance_digest().unwrap_or("")
    {
      return Err(OdenRev2FsError::InvalidBinding("binding mismatch"));
    }
    let canonical_path = platform_path(binding.canonical_path())?;
    if canonical_path != retained.canonical_path() {
      return Err(OdenRev2FsError::InvalidBinding("canonical path mismatch"));
    }
    let retained_file = retained
      .file()
      .try_clone()
      .map_err(|error| OdenRev2FsError::io("clone retained root", error))?;
    Self::authenticate_parts(
      binding.source_id().to_string(),
      binding.logical_root().to_string(),
      binding.binding_id().to_string(),
      canonical_path,
      binding.object_identity().value(),
      retained_file,
    )
  }

  fn authenticate_parts(
    source_id: String,
    logical_root: String,
    binding_id: String,
    canonical_path: PathBuf,
    expected_identity: &str,
    retained: File,
  ) -> Result<Self, OdenRev2FsError> {
    Self::authenticate_parts_with_path(
      source_id,
      logical_root,
      binding_id,
      Some(canonical_path),
      expected_identity,
      retained,
    )
  }

  /// Authenticate a candidate-only root directly from its retained
  /// descriptor. It carries no ambient pathname and therefore cannot claim
  /// named-root replacement coverage; those cases require an anchor-relative
  /// reopener before they can become executable.
  pub(crate) fn authenticate_descriptor_parts(
    source_id: String,
    logical_root: String,
    binding_id: String,
    expected_identity: &str,
    retained: File,
  ) -> Result<Self, OdenRev2FsError> {
    Self::authenticate_parts_with_path(
      source_id,
      logical_root,
      binding_id,
      None,
      expected_identity,
      retained,
    )
  }

  fn authenticate_parts_with_path(
    source_id: String,
    logical_root: String,
    binding_id: String,
    canonical_path: Option<PathBuf>,
    expected_identity: &str,
    retained: File,
  ) -> Result<Self, OdenRev2FsError> {
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
      let _ = (
        source_id,
        logical_root,
        binding_id,
        canonical_path,
        expected_identity,
        retained,
      );
      return Err(OdenRev2FsError::UnsupportedPlatform);
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
      if source_id.is_empty()
        || logical_root.is_empty()
        || binding_id.is_empty()
      {
        return Err(OdenRev2FsError::InvalidBinding("empty root identity"));
      }
      if canonical_path
        .as_ref()
        .is_some_and(|path| !path.is_absolute())
      {
        return Err(OdenRev2FsError::InvalidBinding(
          "root path must be absolute",
        ));
      }
      let retained_metadata =
        metadata_from_file(&retained, "stat retained root")?;
      if retained_metadata.kind != OdenRev2FsObjectKind::Directory
        || retained_metadata.identity.canonical_value() != expected_identity
      {
        return Err(OdenRev2FsError::InvalidBinding("retained root identity"));
      }
      let named = match canonical_path.as_ref() {
        Some(path) => open_absolute_non_consuming(path, true)
          .map_err(|error| OdenRev2FsError::io("open named root", error))?,
        None => retained.try_clone().map_err(|error| {
          OdenRev2FsError::io("clone descriptor root", error)
        })?,
      };
      let named_metadata = metadata_from_file(&named, "stat named root")?;
      if named_metadata.kind != OdenRev2FsObjectKind::Directory
        || named_metadata.identity != retained_metadata.identity
      {
        return Err(OdenRev2FsError::RootReplacement);
      }
      Ok(Self {
        state: Arc::new(OdenRev2FsRootState {
          source_id,
          logical_root,
          binding_id,
          canonical_path,
          identity: retained_metadata.identity,
          adapter: platform_adapter(),
          retained: Arc::new(retained),
          named: Arc::new(named),
        }),
      })
    }
  }

  pub(crate) fn source_root_fact(&self) -> OdenRev2FsSourceRootFact {
    source_root_fact(&self.state)
  }

  pub(crate) fn revalidate(&self) -> Result<(), OdenRev2FsError> {
    revalidate_root(&self.state)
  }

  pub(crate) fn begin_resolution(
    &self,
    operation_session: &OdenRev2FsOperationSession,
    lexical_path: &Path,
    follow_mode: OdenRev2FsFollowMode,
  ) -> Result<OdenRev2FsResolution, OdenRev2FsError> {
    self.revalidate()?;
    let lexical_components = checked_relative_components(lexical_path)?;
    let lexical_fact = OdenRev2FsLexicalFact {
      source_root: self.source_root_fact(),
      relative_path: components_path(&lexical_components),
      follow_mode,
    };
    Ok(OdenRev2FsResolution {
      root: Arc::clone(&self.state),
      operation_session: operation_session.fact.clone(),
      lexical_fact,
      pending: VecDeque::from(lexical_components),
      resolved: Vec::new(),
      directories: vec![Arc::clone(&self.state.named)],
      symlink_count: 0,
      authorized_hop_facts: Vec::new(),
      retained_edges: Vec::new(),
    })
  }

  /// Authenticate a root transition by exact directory identity, never by a
  /// lexical prefix. `checked` may itself be the result of authorized staged
  /// symlink hops; every retained path edge is revalidated first.
  pub(crate) fn authenticate_transition(
    &self,
    checked: &OdenRev2FsCheckedPath,
    destination: &Self,
  ) -> Result<OdenRev2FsRootTransitionFact, OdenRev2FsError> {
    self.revalidate()?;
    destination.revalidate()?;
    if checked.lexical_fact.source_root.root_binding_id != self.state.binding_id
      || checked.lexical_fact.source_root.source_id != self.state.source_id
    {
      return Err(OdenRev2FsError::RootTransitionMismatch);
    }
    checked.revalidate_retained_edges()?;
    let Some(existing) = checked.existing() else {
      return Err(OdenRev2FsError::RootTransitionMismatch);
    };
    if existing.metadata.kind != OdenRev2FsObjectKind::Directory
      || existing.metadata.identity != destination.state.identity
    {
      return Err(OdenRev2FsError::RootTransitionMismatch);
    }
    let relation = if self.state.identity == destination.state.identity {
      OdenRev2FsRootTransitionKind::SameObject
    } else {
      OdenRev2FsRootTransitionKind::VerifiedDirectoryTransition
    };
    Ok(OdenRev2FsRootTransitionFact {
      from: self.source_root_fact(),
      to: destination.source_root_fact(),
      relation,
      transition_identity: destination.state.identity.clone(),
      resolver_trace_path: checked.resolver_trace_path.clone(),
    })
  }
}

fn source_root_fact(state: &OdenRev2FsRootState) -> OdenRev2FsSourceRootFact {
  OdenRev2FsSourceRootFact {
    source_id: state.source_id.clone(),
    logical_root: state.logical_root.clone(),
    root_binding_id: state.binding_id.clone(),
    root_identity: state.identity.clone(),
    adapter: state.adapter,
  }
}

fn revalidate_root(state: &OdenRev2FsRootState) -> Result<(), OdenRev2FsError> {
  #[cfg(not(any(target_os = "linux", target_os = "macos")))]
  return Err(OdenRev2FsError::UnsupportedPlatform);
  #[cfg(any(target_os = "linux", target_os = "macos"))]
  {
    let retained = metadata_from_file(&state.retained, "stat retained root")?;
    let named_retained = metadata_from_file(&state.named, "stat named root")?;
    if retained.identity != state.identity
      || named_retained.identity != state.identity
      || retained.kind != OdenRev2FsObjectKind::Directory
      || named_retained.kind != OdenRev2FsObjectKind::Directory
    {
      return Err(OdenRev2FsError::RootReplacement);
    }
    if let Some(canonical_path) = state.canonical_path.as_ref() {
      let named = open_absolute_non_consuming(canonical_path, true)
        .map_err(|_| OdenRev2FsError::RootReplacement)?;
      let named = metadata_from_file(&named, "stat reopened root")?;
      if named.identity != state.identity
        || named.kind != OdenRev2FsObjectKind::Directory
      {
        return Err(OdenRev2FsError::RootReplacement);
      }
    }
    Ok(())
  }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct OdenRev2FsLinkHopFact {
  challenge_id: u64,
  operation_session: OdenRev2FsOperationSessionFact,
  source_root: OdenRev2FsSourceRootFact,
  resolved_parent: Vec<OsString>,
  resolver_trace_path: PathBuf,
  link_identity: OdenRev2FsPlatformIdentity,
  parent_identity: OdenRev2FsPlatformIdentity,
  opaque_target: PathBuf,
}

impl OdenRev2FsLinkHopFact {
  pub(crate) fn source_root(&self) -> &OdenRev2FsSourceRootFact {
    &self.source_root
  }

  pub(crate) fn operation_session(&self) -> &OdenRev2FsOperationSessionFact {
    &self.operation_session
  }

  pub(crate) fn resolver_trace_path(&self) -> &Path {
    &self.resolver_trace_path
  }

  pub(crate) fn link_identity(&self) -> &OdenRev2FsPlatformIdentity {
    &self.link_identity
  }

  pub(crate) fn parent_identity(&self) -> &OdenRev2FsPlatformIdentity {
    &self.parent_identity
  }

  pub(crate) fn opaque_target(&self) -> &Path {
    &self.opaque_target
  }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct OdenRev2FsAuthorizedLinkHopFact {
  hop: OdenRev2FsLinkHopFact,
  operation_session: OdenRev2FsOperationSessionFact,
  positive_source: OdenRev2FsSourceRootFact,
  root_transition: Option<OdenRev2FsRootTransitionFact>,
}

impl OdenRev2FsAuthorizedLinkHopFact {
  pub(crate) fn hop(&self) -> &OdenRev2FsLinkHopFact {
    &self.hop
  }

  pub(crate) fn positive_source(&self) -> &OdenRev2FsSourceRootFact {
    &self.positive_source
  }

  pub(crate) fn operation_session(&self) -> &OdenRev2FsOperationSessionFact {
    &self.operation_session
  }

  pub(crate) fn root_transition(
    &self,
  ) -> Option<&OdenRev2FsRootTransitionFact> {
    self.root_transition.as_ref()
  }
}

/// One-use host proof reserved for the future shared-core re-entry wiring.
/// There is deliberately no production constructor; consuming `resume`
/// prevents proof replay once that wiring exists.
#[derive(Debug)]
pub(crate) struct OdenRev2FsHopAuthorization {
  challenge_id: u64,
  link_identity: OdenRev2FsPlatformIdentity,
  operation_session: OdenRev2FsOperationSessionFact,
  positive_source: OdenRev2FsSourceRootFact,
}

/// One-use authorization for a symlink continuation that leaves the current
/// logical root and enters another independently authenticated root. The
/// platform adapter accepts only the exact destination spelling, not APFS or
/// other platform aliases. The proof also retains the exact destination root
/// identity and operation session. There is deliberately no production
/// constructor before shared-core re-entry is wired.
#[derive(Debug)]
pub(crate) struct OdenRev2FsRootTransitionAuthorization {
  challenge_id: u64,
  link_identity: OdenRev2FsPlatformIdentity,
  operation_session: OdenRev2FsOperationSessionFact,
  fact: OdenRev2FsRootTransitionFact,
  destination: Arc<OdenRev2FsRootState>,
  target_components: Vec<OsString>,
}

impl OdenRev2FsRootTransitionAuthorization {
  pub(crate) fn fact(&self) -> &OdenRev2FsRootTransitionFact {
    &self.fact
  }
}

/// Retained proof that one exact parent name still resolves to the exact
/// non-consuming child handle opened during resolution. Keeping every edge,
/// rather than only the final parent and object, lets consumption detect a
/// replacement anywhere in the root-to-leaf chain.
#[derive(Debug)]
struct OdenRev2FsRetainedEdge {
  metadata: OdenRev2FsObservedMetadata,
  parent: Arc<File>,
  leaf: OsString,
  child: Arc<File>,
}

impl OdenRev2FsRetainedEdge {
  fn revalidate(&self) -> Result<(), OdenRev2FsError> {
    let named = lstat_component(&self.parent, &self.leaf)?
      .ok_or(OdenRev2FsError::ReplacementDuringResolution)?;
    let retained =
      metadata_from_file(&self.child, "revalidate retained path edge")?;
    if named != self.metadata || retained != self.metadata {
      return Err(OdenRev2FsError::ReplacementDuringResolution);
    }
    Ok(())
  }

  fn revalidate_identity(&self) -> Result<(), OdenRev2FsError> {
    let named = lstat_component(&self.parent, &self.leaf)?
      .ok_or(OdenRev2FsError::ReplacementDuringResolution)?;
    let retained =
      metadata_from_file(&self.child, "revalidate retained path identity")?;
    if named.identity != self.metadata.identity
      || retained.identity != self.metadata.identity
      || named.kind != self.metadata.kind
      || retained.kind != self.metadata.kind
    {
      return Err(OdenRev2FsError::ReplacementDuringResolution);
    }
    Ok(())
  }
}

#[derive(Debug)]
pub(crate) struct OdenRev2FsResolution {
  root: Arc<OdenRev2FsRootState>,
  operation_session: OdenRev2FsOperationSessionFact,
  lexical_fact: OdenRev2FsLexicalFact,
  pending: VecDeque<OsString>,
  resolved: Vec<OsString>,
  directories: Vec<Arc<File>>,
  symlink_count: usize,
  authorized_hop_facts: Vec<OdenRev2FsAuthorizedLinkHopFact>,
  retained_edges: Vec<OdenRev2FsRetainedEdge>,
}

#[derive(Debug)]
pub(crate) enum OdenRev2FsResolutionStep {
  Complete(OdenRev2FsCheckedPath),
  AuthorizationRequired(OdenRev2FsPendingSymlink),
}

impl OdenRev2FsResolution {
  pub(crate) fn lexical_fact(&self) -> &OdenRev2FsLexicalFact {
    &self.lexical_fact
  }

  pub(crate) fn advance(
    self,
  ) -> Result<OdenRev2FsResolutionStep, OdenRev2FsError> {
    self.advance_with_hook(&mut |_, _| {})
  }

  fn advance_with_hook(
    mut self,
    hook: &mut dyn FnMut(OdenRev2FsResolveCheckpoint, &OsStr),
  ) -> Result<OdenRev2FsResolutionStep, OdenRev2FsError> {
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
      let _ = hook;
      return Err(OdenRev2FsError::UnsupportedPlatform);
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
      revalidate_root(&self.root)?;
      if self.pending.is_empty() {
        let root =
          self.root.named.try_clone().map_err(|error| {
            OdenRev2FsError::io("clone checked root", error)
          })?;
        let metadata = metadata_from_file(&root, "stat checked root")?;
        return Ok(OdenRev2FsResolutionStep::Complete(OdenRev2FsCheckedPath {
          root: self.root,
          operation_session: self.operation_session,
          lexical_fact: self.lexical_fact,
          resolver_trace_path: PathBuf::new(),
          target: OdenRev2FsCheckedTarget::Existing(OdenRev2FsExistingObject {
            metadata,
            parent: None,
            handle: Arc::new(root),
          }),
          authorized_hop_facts: self.authorized_hop_facts,
          retained_edges: self.retained_edges,
        }));
      }

      loop {
        let component = self
          .pending
          .pop_front()
          .expect("non-root resolution retains a pending component");
        let final_component = self.pending.is_empty();
        let parent = Arc::clone(
          self
            .directories
            .last()
            .expect("authenticated root remains in the directory stack"),
        );
        let observed = lstat_component(&parent, &component)?;
        let Some(observed) = observed else {
          hook(OdenRev2FsResolveCheckpoint::AfterMissing, &component);
          if lstat_component(&parent, &component)?.is_some() {
            return Err(OdenRev2FsError::ReplacementDuringResolution);
          }
          if !final_component {
            return Err(OdenRev2FsError::MissingAncestor);
          }
          self.resolved.push(component.clone());
          revalidate_root(&self.root)?;
          return Ok(OdenRev2FsResolutionStep::Complete(
            OdenRev2FsCheckedPath {
              root: self.root,
              operation_session: self.operation_session,
              lexical_fact: self.lexical_fact,
              resolver_trace_path: components_path(&self.resolved),
              target: OdenRev2FsCheckedTarget::Missing(
                OdenRev2FsMissingChild {
                  parent: verified_parent(parent)?,
                  leaf: component,
                },
              ),
              authorized_hop_facts: self.authorized_hop_facts,
              retained_edges: self.retained_edges,
            },
          ));
        };

        hook(OdenRev2FsResolveCheckpoint::AfterMetadata, &component);
        if observed.kind == OdenRev2FsObjectKind::Symlink {
          let target = readlink_component(&parent, &component)?;
          hook(OdenRev2FsResolveCheckpoint::AfterReadlink, &component);
          let after = lstat_component(&parent, &component)?
            .ok_or(OdenRev2FsError::ReplacementDuringResolution)?;
          if after != observed {
            return Err(OdenRev2FsError::ReplacementDuringResolution);
          }
          let link_handle =
            Arc::new(open_symlink_non_consuming(&parent, &component)?);
          if metadata_from_file(&link_handle, "stat retained symlink")?
            != observed
          {
            return Err(OdenRev2FsError::ReplacementDuringResolution);
          }

          if final_component
            && self.lexical_fact.follow_mode
              == OdenRev2FsFollowMode::NoFollowFinal
          {
            self.retained_edges.push(OdenRev2FsRetainedEdge {
              metadata: observed.clone(),
              parent: Arc::clone(&parent),
              leaf: component.clone(),
              child: Arc::clone(&link_handle),
            });
            self.resolved.push(component);
            revalidate_root(&self.root)?;
            return Ok(OdenRev2FsResolutionStep::Complete(
              OdenRev2FsCheckedPath {
                root: self.root,
                operation_session: self.operation_session,
                lexical_fact: self.lexical_fact,
                resolver_trace_path: components_path(&self.resolved),
                target: OdenRev2FsCheckedTarget::Link(
                  OdenRev2FsNoFollowLinkEntry {
                    metadata: observed,
                    parent: verified_parent(parent)?,
                    target,
                    handle: link_handle,
                  },
                ),
                authorized_hop_facts: self.authorized_hop_facts,
                retained_edges: self.retained_edges,
              },
            ));
          }

          self.symlink_count += 1;
          if self.symlink_count > MAX_SYMLINK_TRAVERSALS {
            return Err(OdenRev2FsError::SymlinkLimit);
          }
          let parent_metadata =
            metadata_from_file(&parent, "stat link parent")?;
          let mut trace = self.resolved.clone();
          trace.push(component.clone());
          let challenge = OdenRev2FsLinkHopFact {
            challenge_id: next_hop_challenge()?,
            operation_session: self.operation_session.clone(),
            source_root: source_root_fact(&self.root),
            resolved_parent: self.resolved.clone(),
            resolver_trace_path: components_path(&trace),
            link_identity: observed.identity.clone(),
            parent_identity: parent_metadata.identity,
            opaque_target: target.clone(),
          };
          return Ok(OdenRev2FsResolutionStep::AuthorizationRequired(
            OdenRev2FsPendingSymlink {
              continuation: self,
              challenge,
              metadata: observed,
              parent,
              leaf: component,
              target,
              handle: link_handle,
            },
          ));
        }

        let opened = open_component_non_consuming(
          &parent,
          &component,
          !final_component,
          observed.kind,
        )?;
        let opened_metadata =
          metadata_from_file(&opened, "stat opened component")?;
        if opened_metadata != observed {
          return Err(OdenRev2FsError::ReplacementDuringResolution);
        }
        if !final_component && observed.kind != OdenRev2FsObjectKind::Directory
        {
          return Err(OdenRev2FsError::InvalidPath(
            "non-final component is not a directory",
          ));
        }
        let opened = Arc::new(opened);
        self.retained_edges.push(OdenRev2FsRetainedEdge {
          metadata: observed.clone(),
          parent: Arc::clone(&parent),
          leaf: component.clone(),
          child: Arc::clone(&opened),
        });
        self.resolved.push(component);
        if final_component {
          revalidate_root(&self.root)?;
          return Ok(OdenRev2FsResolutionStep::Complete(
            OdenRev2FsCheckedPath {
              root: self.root,
              operation_session: self.operation_session,
              lexical_fact: self.lexical_fact,
              resolver_trace_path: components_path(&self.resolved),
              target: OdenRev2FsCheckedTarget::Existing(
                OdenRev2FsExistingObject {
                  metadata: observed,
                  parent: Some(verified_parent(parent)?),
                  handle: opened,
                },
              ),
              authorized_hop_facts: self.authorized_hop_facts,
              retained_edges: self.retained_edges,
            },
          ));
        }
        self.directories.push(opened);
      }
    }
  }
}

fn next_hop_challenge() -> Result<u64, OdenRev2FsError> {
  NEXT_HOP_CHALLENGE
    .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
      value.checked_add(1)
    })
    .map_err(|_| OdenRev2FsError::InvalidPath("hop challenge exhausted"))
}

#[cfg(test)]
fn next_operation_session() -> Result<u64, OdenRev2FsError> {
  NEXT_OPERATION_SESSION
    .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
      value.checked_add(1)
    })
    .map_err(|_| {
      OdenRev2FsError::InvalidBinding("operation session identity exhausted")
    })
}

#[derive(Debug)]
pub(crate) struct OdenRev2FsPendingSymlink {
  continuation: OdenRev2FsResolution,
  challenge: OdenRev2FsLinkHopFact,
  metadata: OdenRev2FsObservedMetadata,
  parent: Arc<File>,
  leaf: OsString,
  target: PathBuf,
  handle: Arc<File>,
}

impl OdenRev2FsPendingSymlink {
  pub(crate) fn challenge(&self) -> &OdenRev2FsLinkHopFact {
    &self.challenge
  }

  pub(crate) fn resume(
    mut self,
    authorization: OdenRev2FsHopAuthorization,
  ) -> Result<OdenRev2FsResolution, OdenRev2FsError> {
    self.validate_authorization(&authorization)?;
    self.revalidate_link_and_root()?;
    let normalized_target = normalize_symlink_target(
      self.continuation.root.canonical_path.as_deref(),
      &self.continuation.resolved,
      &self.target,
    )?;
    self.install_target(normalized_target);
    self.record_authorized_hop(authorization, None);
    Ok(self.continuation)
  }

  pub(crate) fn resume_with_authenticated_root_transition(
    mut self,
    authorization: OdenRev2FsHopAuthorization,
    transition: OdenRev2FsRootTransitionAuthorization,
  ) -> Result<OdenRev2FsResolution, OdenRev2FsError> {
    self.validate_authorization(&authorization)?;
    if transition.challenge_id != self.challenge.challenge_id
      || transition.link_identity != self.challenge.link_identity
      || transition.operation_session != self.challenge.operation_session
      || transition.fact.from != self.challenge.source_root
      || transition.fact.to != source_root_fact(&transition.destination)
      || transition.fact.transition_identity != transition.destination.identity
    {
      return Err(OdenRev2FsError::RootTransitionMismatch);
    }
    self.revalidate_link_and_root()?;
    revalidate_root(&transition.destination)?;
    self.continuation.root = Arc::clone(&transition.destination);
    self.continuation.directories =
      vec![Arc::clone(&transition.destination.named)];
    self.install_target(transition.target_components);
    self.record_authorized_hop(authorization, Some(transition.fact));
    Ok(self.continuation)
  }

  fn validate_authorization(
    &self,
    authorization: &OdenRev2FsHopAuthorization,
  ) -> Result<(), OdenRev2FsError> {
    if authorization.challenge_id != self.challenge.challenge_id
      || authorization.link_identity != self.challenge.link_identity
    {
      return Err(OdenRev2FsError::HopAuthorizationMismatch);
    }
    if authorization.operation_session != self.challenge.operation_session
      || authorization.operation_session != self.continuation.operation_session
    {
      return Err(OdenRev2FsError::OperationSessionMismatch);
    }
    Ok(())
  }

  fn revalidate_link_and_root(&self) -> Result<(), OdenRev2FsError> {
    let current = lstat_component(&self.parent, &self.leaf)?
      .ok_or(OdenRev2FsError::ReplacementDuringResolution)?;
    let retained = metadata_from_file(&self.handle, "revalidate symlink hop")?;
    if current != self.metadata || retained != self.metadata {
      return Err(OdenRev2FsError::ReplacementDuringResolution);
    }
    revalidate_root(&self.continuation.root)
  }

  fn install_target(&mut self, target_components: Vec<OsString>) {
    let mut next = VecDeque::from(target_components);
    next.append(&mut self.continuation.pending);
    self.continuation.pending = next;
    self.continuation.resolved.clear();
    self.continuation.directories.truncate(1);
  }

  fn record_authorized_hop(
    &mut self,
    authorization: OdenRev2FsHopAuthorization,
    root_transition: Option<OdenRev2FsRootTransitionFact>,
  ) {
    self.continuation.authorized_hop_facts.push(
      OdenRev2FsAuthorizedLinkHopFact {
        hop: self.challenge.clone(),
        operation_session: authorization.operation_session,
        positive_source: authorization.positive_source,
        root_transition,
      },
    );
    self
      .continuation
      .retained_edges
      .push(OdenRev2FsRetainedEdge {
        metadata: self.metadata.clone(),
        parent: Arc::clone(&self.parent),
        leaf: self.leaf.clone(),
        child: Arc::clone(&self.handle),
      });
  }
}

#[derive(Debug)]
struct OdenRev2FsVerifiedParent {
  metadata: OdenRev2FsObservedMetadata,
  handle: Arc<File>,
}

impl OdenRev2FsVerifiedParent {
  fn revalidate(&self) -> Result<(), OdenRev2FsError> {
    let retained =
      metadata_from_file(&self.handle, "revalidate verified parent")?;
    if retained != self.metadata
      || retained.kind != OdenRev2FsObjectKind::Directory
    {
      return Err(OdenRev2FsError::ReplacementDuringResolution);
    }
    Ok(())
  }

  fn revalidate_identity(&self) -> Result<(), OdenRev2FsError> {
    let retained =
      metadata_from_file(&self.handle, "revalidate verified parent identity")?;
    if retained.identity != self.metadata.identity
      || retained.kind != OdenRev2FsObjectKind::Directory
    {
      return Err(OdenRev2FsError::ReplacementDuringResolution);
    }
    Ok(())
  }
}

#[derive(Debug)]
pub(crate) struct OdenRev2FsExistingObject {
  metadata: OdenRev2FsObservedMetadata,
  parent: Option<OdenRev2FsVerifiedParent>,
  handle: Arc<File>,
}

impl OdenRev2FsExistingObject {
  pub(crate) fn identity(&self) -> &OdenRev2FsPlatformIdentity {
    &self.metadata.identity
  }

  pub(crate) fn kind(&self) -> OdenRev2FsObjectKind {
    self.metadata.kind
  }

  pub(crate) fn link_count(&self) -> u64 {
    self.metadata.link_count
  }

  pub(crate) fn has_verified_parent(&self) -> bool {
    self.parent.is_some()
  }
}

#[derive(Debug)]
pub(crate) struct OdenRev2FsNoFollowLinkEntry {
  metadata: OdenRev2FsObservedMetadata,
  parent: OdenRev2FsVerifiedParent,
  target: PathBuf,
  handle: Arc<File>,
}

impl OdenRev2FsNoFollowLinkEntry {
  pub(crate) fn identity(&self) -> &OdenRev2FsPlatformIdentity {
    &self.metadata.identity
  }

  pub(crate) fn target(&self) -> &Path {
    &self.target
  }
}

#[derive(Debug)]
pub(crate) struct OdenRev2FsMissingChild {
  parent: OdenRev2FsVerifiedParent,
  leaf: OsString,
}

impl OdenRev2FsMissingChild {
  pub(crate) fn parent_identity(&self) -> &OdenRev2FsPlatformIdentity {
    &self.parent.metadata.identity
  }

  pub(crate) fn leaf(&self) -> &OsStr {
    &self.leaf
  }

  fn revalidate_absent_with_hook(
    &self,
    hook: &mut dyn FnMut(OdenRev2FsUseCheckpoint, &OsStr),
  ) -> Result<(), OdenRev2FsError> {
    self.parent.revalidate()?;
    hook(OdenRev2FsUseCheckpoint::BeforeMissingLeaf, &self.leaf);
    if lstat_component(&self.parent.handle, &self.leaf)?.is_some() {
      return Err(OdenRev2FsError::ReplacementDuringResolution);
    }
    Ok(())
  }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OdenRev2FsProposedKind {
  RegularFile,
  Directory,
  UnixSocket,
  Other,
}

#[derive(Debug)]
pub(crate) struct OdenRev2FsProposedChild {
  parent: OdenRev2FsVerifiedParent,
  leaf: OsString,
  kind: OdenRev2FsProposedKind,
}

impl OdenRev2FsProposedChild {
  pub(crate) fn parent_identity(&self) -> &OdenRev2FsPlatformIdentity {
    &self.parent.metadata.identity
  }

  pub(crate) fn leaf(&self) -> &OsStr {
    &self.leaf
  }

  pub(crate) fn kind(&self) -> OdenRev2FsProposedKind {
    self.kind
  }
}

#[derive(Debug)]
enum OdenRev2FsCheckedTarget {
  Existing(OdenRev2FsExistingObject),
  Link(OdenRev2FsNoFollowLinkEntry),
  Missing(OdenRev2FsMissingChild),
  Proposed(OdenRev2FsProposedChild),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OdenRev2FsCheckedTargetKind {
  Existing,
  NoFollowLink,
  Missing,
  Proposed,
}

#[derive(Debug)]
pub(crate) enum OdenRev2FsMkdirCommitOutcome {
  Committed,
  NotCommitted(OdenRev2FsError),
  Uncertain(OdenRev2FsError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OdenRev2FsMkdirCommitState {
  NotAttempted,
  Committed,
  NotCommitted,
  Uncertain,
}

/// A proposed directory creation reduced to the retained parent and one leaf.
/// Construction performs the final checked-path validation; `commit` repeats
/// it immediately before `mkdirat` and never accepts an absolute pathname.
#[derive(Debug)]
pub(crate) struct OdenRev2FsPreparedMkdir {
  root: Arc<OdenRev2FsRootState>,
  operation_session: OdenRev2FsOperationSessionFact,
  parent: OdenRev2FsVerifiedParent,
  leaf: OsString,
  retained_edges: Vec<OdenRev2FsRetainedEdge>,
  commit_state: OdenRev2FsMkdirCommitState,
}

impl OdenRev2FsPreparedMkdir {
  pub(crate) fn revalidate_before_commit(
    &self,
    operation_session: &OdenRev2FsOperationSession,
  ) -> Result<(), OdenRev2FsError> {
    if self.operation_session != operation_session.fact {
      return Err(OdenRev2FsError::OperationSessionMismatch);
    }
    revalidate_root(&self.root)?;
    for edge in &self.retained_edges {
      edge.revalidate()?;
    }
    self.parent.revalidate()?;
    if lstat_component(&self.parent.handle, &self.leaf)?.is_some() {
      return Err(OdenRev2FsError::ReplacementDuringResolution);
    }
    Ok(())
  }

  fn commit(
    &mut self,
    operation_session: &OdenRev2FsOperationSession,
    mode: u32,
  ) -> OdenRev2FsMkdirCommitOutcome {
    if self.commit_state != OdenRev2FsMkdirCommitState::NotAttempted {
      self.commit_state = OdenRev2FsMkdirCommitState::Uncertain;
      return OdenRev2FsMkdirCommitOutcome::Uncertain(
        OdenRev2FsError::OperationUnsupported("mkdir-commit-already-attempted"),
      );
    }
    let outcome = (|| {
      if let Err(error) = self.revalidate_before_commit(operation_session) {
        return OdenRev2FsMkdirCommitOutcome::NotCommitted(error);
      }
      #[cfg(not(any(target_os = "linux", target_os = "macos")))]
      {
        let _ = mode;
        return OdenRev2FsMkdirCommitOutcome::NotCommitted(
          OdenRev2FsError::UnsupportedPlatform,
        );
      }
      #[cfg(any(target_os = "linux", target_os = "macos"))]
      {
        let leaf = match cstring(&self.leaf) {
          Ok(leaf) => leaf,
          Err(error) => {
            return OdenRev2FsMkdirCommitOutcome::NotCommitted(
              OdenRev2FsError::io("encode mkdir leaf", error),
            );
          }
        };
        #[cfg(test)]
        let fault = ODEN_REV2_FS_MKDIR_COMMIT_FAULT_FOR_TEST
          .with(|current| current.take());
        #[cfg(test)]
        if fault == Some(OdenRev2FsMkdirCommitFaultForTest::RaceExisting) {
          // Test-only external-writer simulation after final validation and
          // before the operation's own no-replace syscall.
          let injected = unsafe {
            libc::mkdirat(
              self.parent.handle.as_raw_fd(),
              leaf.as_ptr(),
              (mode & 0o777) as libc::mode_t,
            )
          };
          if injected != 0 {
            return OdenRev2FsMkdirCommitOutcome::Uncertain(
              OdenRev2FsError::io(
                "inject mkdir race",
                io::Error::last_os_error(),
              ),
            );
          }
        }
        // SAFETY: the retained parent descriptor and NUL-terminated single leaf
        // remain live. `mkdirat` is atomic and refuses an existing destination.
        let result = unsafe {
          libc::mkdirat(
            self.parent.handle.as_raw_fd(),
            leaf.as_ptr(),
            (mode & 0o777) as libc::mode_t,
          )
        };
        if result != 0 {
          let error = io::Error::last_os_error();
          if error.raw_os_error() == Some(libc::EEXIST) {
            return OdenRev2FsMkdirCommitOutcome::NotCommitted(
              OdenRev2FsError::ReplacementDuringResolution,
            );
          }
          return OdenRev2FsMkdirCommitOutcome::Uncertain(OdenRev2FsError::io(
            "mkdirat proposed child",
            error,
          ));
        }
        #[cfg(test)]
        if fault
          == Some(OdenRev2FsMkdirCommitFaultForTest::UncertainAfterSyscall)
        {
          return OdenRev2FsMkdirCommitOutcome::Uncertain(OdenRev2FsError::io(
            "injected ambiguous mkdir postcheck",
            io::Error::other("injected ambiguous mkdir postcheck"),
          ));
        }
        let postcheck = (|| {
          revalidate_root(&self.root)?;
          for edge in &self.retained_edges {
            // Creating a directory changes the immediate parent's link count.
            // After successful mkdir, retain identity/type coupling without
            // requiring pre-commit metadata bytes to remain identical.
            edge.revalidate_identity()?;
          }
          self.parent.revalidate_identity()?;
          let observed = lstat_component(&self.parent.handle, &self.leaf)?
            .ok_or(OdenRev2FsError::ReplacementDuringResolution)?;
          if observed.kind != OdenRev2FsObjectKind::Directory {
            return Err(OdenRev2FsError::ReplacementDuringResolution);
          }
          let retained = open_component_non_consuming(
            &self.parent.handle,
            &self.leaf,
            true,
            OdenRev2FsObjectKind::Directory,
          )?;
          if metadata_from_file(&retained, "postcheck mkdir child")? != observed
            || lstat_component(&self.parent.handle, &self.leaf)?
              != Some(observed)
          {
            return Err(OdenRev2FsError::ReplacementDuringResolution);
          }
          Ok(())
        })();
        match postcheck {
          Ok(()) => OdenRev2FsMkdirCommitOutcome::Committed,
          Err(error) => OdenRev2FsMkdirCommitOutcome::Uncertain(error),
        }
      }
    })();
    self.commit_state = match &outcome {
      OdenRev2FsMkdirCommitOutcome::Committed => {
        OdenRev2FsMkdirCommitState::Committed
      }
      OdenRev2FsMkdirCommitOutcome::NotCommitted(_) => {
        OdenRev2FsMkdirCommitState::NotCommitted
      }
      OdenRev2FsMkdirCommitOutcome::Uncertain(_) => {
        OdenRev2FsMkdirCommitState::Uncertain
      }
    };
    outcome
  }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OdenRev2FsOperation {
  ObserveMetadata,
  FollowedDataAccess,
  NoFollowLinkAccess,
  CreateOrReplaceChild,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OdenRev2FsOperationSupport {
  RetainedObjectObservation,
  RetainedLinkObservation,
  /// Status only: this module has no executable create/replace mutator.
  RequiresAtomicParentRelativeCommit,
  Unsupported(&'static str),
}

#[derive(Clone, Debug)]
pub(crate) struct OdenRev2FsMetadataObservation {
  identity_fact: OdenRev2FsIdentityFact,
  kind: OdenRev2FsObjectKind,
  link_count: u64,
  device_id: u64,
  metadata: std::fs::Metadata,
}

impl OdenRev2FsMetadataObservation {
  pub(crate) fn identity_fact(&self) -> &OdenRev2FsIdentityFact {
    &self.identity_fact
  }

  pub(crate) fn kind(&self) -> OdenRev2FsObjectKind {
    self.kind
  }

  pub(crate) fn into_metadata(self) -> std::fs::Metadata {
    self.metadata
  }
}

/// One checked occurrence. Raw handles remain private; callers get separate
/// lexical and identity facts and must use operation-specific consuming
/// helpers. `resolver_trace_path` is diagnostic provenance, not a policy
/// matching input.
#[derive(Debug)]
pub(crate) struct OdenRev2FsCheckedPath {
  root: Arc<OdenRev2FsRootState>,
  operation_session: OdenRev2FsOperationSessionFact,
  lexical_fact: OdenRev2FsLexicalFact,
  resolver_trace_path: PathBuf,
  target: OdenRev2FsCheckedTarget,
  authorized_hop_facts: Vec<OdenRev2FsAuthorizedLinkHopFact>,
  retained_edges: Vec<OdenRev2FsRetainedEdge>,
}

impl OdenRev2FsCheckedPath {
  pub(crate) fn operation_session(&self) -> &OdenRev2FsOperationSessionFact {
    &self.operation_session
  }

  pub(crate) fn lexical_fact(&self) -> &OdenRev2FsLexicalFact {
    &self.lexical_fact
  }

  pub(crate) fn identity_fact(&self) -> OdenRev2FsIdentityFact {
    let state = match &self.target {
      OdenRev2FsCheckedTarget::Existing(object) => {
        OdenRev2FsIdentityState::Existing {
          identity: object.metadata.identity.clone(),
          kind: object.metadata.kind,
        }
      }
      OdenRev2FsCheckedTarget::Link(link) => {
        OdenRev2FsIdentityState::NoFollowLink {
          identity: link.metadata.identity.clone(),
        }
      }
      OdenRev2FsCheckedTarget::Missing(child) => {
        OdenRev2FsIdentityState::MissingParent {
          parent_identity: child.parent.metadata.identity.clone(),
        }
      }
      OdenRev2FsCheckedTarget::Proposed(child) => {
        OdenRev2FsIdentityState::ProposedParent {
          parent_identity: child.parent.metadata.identity.clone(),
          kind: child.kind,
        }
      }
    };
    OdenRev2FsIdentityFact {
      source_root: source_root_fact(&self.root),
      state,
    }
  }

  pub(crate) fn parent_identity(&self) -> Option<&OdenRev2FsPlatformIdentity> {
    match &self.target {
      OdenRev2FsCheckedTarget::Existing(object) => object
        .parent
        .as_ref()
        .map(|parent| &parent.metadata.identity),
      OdenRev2FsCheckedTarget::Link(link) => {
        Some(&link.parent.metadata.identity)
      }
      OdenRev2FsCheckedTarget::Missing(child) => {
        Some(&child.parent.metadata.identity)
      }
      OdenRev2FsCheckedTarget::Proposed(child) => {
        Some(&child.parent.metadata.identity)
      }
    }
  }

  pub(crate) fn resolver_trace_path(&self) -> &Path {
    &self.resolver_trace_path
  }

  pub(crate) fn authorized_hops(&self) -> &[OdenRev2FsAuthorizedLinkHopFact] {
    &self.authorized_hop_facts
  }

  pub(crate) fn target_kind(&self) -> OdenRev2FsCheckedTargetKind {
    match &self.target {
      OdenRev2FsCheckedTarget::Existing(_) => {
        OdenRev2FsCheckedTargetKind::Existing
      }
      OdenRev2FsCheckedTarget::Link(_) => {
        OdenRev2FsCheckedTargetKind::NoFollowLink
      }
      OdenRev2FsCheckedTarget::Missing(_) => {
        OdenRev2FsCheckedTargetKind::Missing
      }
      OdenRev2FsCheckedTarget::Proposed(_) => {
        OdenRev2FsCheckedTargetKind::Proposed
      }
    }
  }

  pub(crate) fn existing(&self) -> Option<&OdenRev2FsExistingObject> {
    match &self.target {
      OdenRev2FsCheckedTarget::Existing(object) => Some(object),
      _ => None,
    }
  }

  pub(crate) fn no_follow_link(&self) -> Option<&OdenRev2FsNoFollowLinkEntry> {
    match &self.target {
      OdenRev2FsCheckedTarget::Link(link) => Some(link),
      _ => None,
    }
  }

  pub(crate) fn missing(&self) -> Option<&OdenRev2FsMissingChild> {
    match &self.target {
      OdenRev2FsCheckedTarget::Missing(child) => Some(child),
      _ => None,
    }
  }

  pub(crate) fn proposed(&self) -> Option<&OdenRev2FsProposedChild> {
    match &self.target {
      OdenRev2FsCheckedTarget::Proposed(child) => Some(child),
      _ => None,
    }
  }

  pub(crate) fn propose_child(
    self,
    operation_session: &OdenRev2FsOperationSession,
    kind: OdenRev2FsProposedKind,
  ) -> Result<Self, OdenRev2FsError> {
    self.propose_child_with_hook(operation_session, kind, &mut |_, _| {})
  }

  fn propose_child_with_hook(
    mut self,
    operation_session: &OdenRev2FsOperationSession,
    kind: OdenRev2FsProposedKind,
    hook: &mut dyn FnMut(OdenRev2FsUseCheckpoint, &OsStr),
  ) -> Result<Self, OdenRev2FsError> {
    self.require_operation_session(operation_session)?;
    let OdenRev2FsCheckedTarget::Missing(missing) = &self.target else {
      return Err(OdenRev2FsError::InvalidPath(
        "only a missing child may become proposed",
      ));
    };
    revalidate_root(&self.root)?;
    self.revalidate_retained_edges_with_hook(hook)?;
    missing.revalidate_absent_with_hook(hook)?;
    let OdenRev2FsCheckedTarget::Missing(missing) = self.target else {
      unreachable!("missing target validated above")
    };
    self.target = OdenRev2FsCheckedTarget::Proposed(OdenRev2FsProposedChild {
      parent: missing.parent,
      leaf: missing.leaf,
      kind,
    });
    Ok(self)
  }

  pub(crate) fn prepare_mkdir(
    self,
    operation_session: &OdenRev2FsOperationSession,
  ) -> Result<OdenRev2FsPreparedMkdir, OdenRev2FsError> {
    self.require_operation_session(operation_session)?;
    revalidate_root(&self.root)?;
    self.revalidate_retained_edges()?;
    let OdenRev2FsCheckedTarget::Proposed(child) = self.target else {
      return Err(OdenRev2FsError::OperationUnsupported(
        "mkdir-proposed-directory",
      ));
    };
    if child.kind != OdenRev2FsProposedKind::Directory {
      return Err(OdenRev2FsError::OperationUnsupported(
        "mkdir-proposed-directory",
      ));
    }
    child.parent.revalidate()?;
    if lstat_component(&child.parent.handle, &child.leaf)?.is_some() {
      return Err(OdenRev2FsError::ReplacementDuringResolution);
    }
    Ok(OdenRev2FsPreparedMkdir {
      root: self.root,
      operation_session: self.operation_session,
      parent: child.parent,
      leaf: child.leaf,
      retained_edges: self.retained_edges,
      commit_state: OdenRev2FsMkdirCommitState::NotAttempted,
    })
  }

  pub(crate) fn revalidate_binding(
    &self,
    operation_session: &OdenRev2FsOperationSession,
  ) -> Result<(), OdenRev2FsError> {
    self.require_operation_session(operation_session)?;
    revalidate_root(&self.root)?;
    self.revalidate_retained_edges()?;
    match &self.target {
      OdenRev2FsCheckedTarget::Existing(object) => {
        if metadata_from_file(&object.handle, "revalidate bound object")?
          != object.metadata
        {
          return Err(OdenRev2FsError::ReplacementDuringResolution);
        }
      }
      OdenRev2FsCheckedTarget::Link(link) => {
        let current = lstat_component(&link.parent.handle, &link_leaf(self)?)?
          .ok_or(OdenRev2FsError::ReplacementDuringResolution)?;
        if current != link.metadata
          || metadata_from_file(&link.handle, "revalidate bound link")?
            != link.metadata
        {
          return Err(OdenRev2FsError::ReplacementDuringResolution);
        }
      }
      OdenRev2FsCheckedTarget::Missing(child) => {
        child.revalidate_absent_with_hook(&mut |_, _| {})?;
      }
      OdenRev2FsCheckedTarget::Proposed(child) => {
        child.parent.revalidate()?;
        if lstat_component(&child.parent.handle, &child.leaf)?.is_some() {
          return Err(OdenRev2FsError::ReplacementDuringResolution);
        }
      }
    }
    Ok(())
  }

  pub(crate) fn operation_support(
    &self,
    operation: OdenRev2FsOperation,
  ) -> OdenRev2FsOperationSupport {
    match (operation, &self.target) {
      (
        OdenRev2FsOperation::ObserveMetadata,
        OdenRev2FsCheckedTarget::Existing(_),
      ) => OdenRev2FsOperationSupport::RetainedObjectObservation,
      (
        OdenRev2FsOperation::ObserveMetadata
        | OdenRev2FsOperation::NoFollowLinkAccess,
        OdenRev2FsCheckedTarget::Link(_),
      ) => OdenRev2FsOperationSupport::RetainedLinkObservation,
      (
        OdenRev2FsOperation::CreateOrReplaceChild,
        OdenRev2FsCheckedTarget::Missing(_)
        | OdenRev2FsCheckedTarget::Proposed(_),
      ) => OdenRev2FsOperationSupport::RequiresAtomicParentRelativeCommit,
      (OdenRev2FsOperation::FollowedDataAccess, _) => {
        OdenRev2FsOperationSupport::Unsupported(
          "data-operation-wiring-not-landed",
        )
      }
      _ => OdenRev2FsOperationSupport::Unsupported(
        "operation-not-valid-for-checked-target",
      ),
    }
  }

  #[cfg(unix)]
  fn observe_metadata(
    &self,
    operation_session: &OdenRev2FsOperationSession,
  ) -> Result<OdenRev2FsMetadataObservation, OdenRev2FsError> {
    self.observe_metadata_with_hook(operation_session, &mut |_, _| {})
  }

  #[cfg(unix)]
  fn observe_metadata_with_hook(
    &self,
    operation_session: &OdenRev2FsOperationSession,
    hook: &mut dyn FnMut(OdenRev2FsUseCheckpoint, &OsStr),
  ) -> Result<OdenRev2FsMetadataObservation, OdenRev2FsError> {
    self.require_operation_session(operation_session)?;
    revalidate_root(&self.root)?;
    self.revalidate_retained_edges_with_hook(hook)?;
    let (metadata, output) = match &self.target {
      OdenRev2FsCheckedTarget::Existing(object) => {
        let output = object.handle.metadata().map_err(|error| {
          OdenRev2FsError::io("read retained object metadata", error)
        })?;
        let current = OdenRev2FsObservedMetadata::from_metadata(&output);
        if current != object.metadata {
          return Err(OdenRev2FsError::ReplacementDuringResolution);
        }
        (current, output)
      }
      OdenRev2FsCheckedTarget::Link(link) => {
        let current = lstat_component(&link.parent.handle, &link_leaf(self)?)?
          .ok_or(OdenRev2FsError::ReplacementDuringResolution)?;
        let output = link.handle.metadata().map_err(|error| {
          OdenRev2FsError::io("read retained link metadata", error)
        })?;
        let retained = OdenRev2FsObservedMetadata::from_metadata(&output);
        if current != link.metadata || retained != link.metadata {
          return Err(OdenRev2FsError::ReplacementDuringResolution);
        }
        (retained, output)
      }
      OdenRev2FsCheckedTarget::Missing(_)
      | OdenRev2FsCheckedTarget::Proposed(_) => {
        return Err(OdenRev2FsError::OperationUnsupported(
          "metadata-existing-or-link",
        ));
      }
    };
    Ok(OdenRev2FsMetadataObservation {
      identity_fact: self.identity_fact(),
      kind: metadata.kind,
      link_count: metadata.link_count,
      device_id: metadata.device_id,
      metadata: output,
    })
  }

  #[cfg(not(unix))]
  fn observe_metadata(
    &self,
    _operation_session: &OdenRev2FsOperationSession,
  ) -> Result<OdenRev2FsMetadataObservation, OdenRev2FsError> {
    Err(OdenRev2FsError::UnsupportedPlatform)
  }

  #[cfg(unix)]
  fn consume_for_metadata(
    self,
    operation_session: &OdenRev2FsOperationSession,
  ) -> Result<OdenRev2FsMetadataObservation, OdenRev2FsError> {
    self.observe_metadata(operation_session)
  }

  #[cfg(unix)]
  fn consume_for_metadata_with_hook(
    self,
    operation_session: &OdenRev2FsOperationSession,
    hook: &mut dyn FnMut(OdenRev2FsUseCheckpoint, &OsStr),
  ) -> Result<OdenRev2FsMetadataObservation, OdenRev2FsError> {
    self.observe_metadata_with_hook(operation_session, hook)
  }

  #[cfg(not(unix))]
  fn consume_for_metadata(
    self,
    _operation_session: &OdenRev2FsOperationSession,
  ) -> Result<OdenRev2FsMetadataObservation, OdenRev2FsError> {
    Err(OdenRev2FsError::UnsupportedPlatform)
  }

  /// Consume an authorized final-missing observation without converting a
  /// missing ancestor or a raced replacement into caller-visible `ENOENT`.
  #[cfg(unix)]
  fn observe_missing(
    &self,
    operation_session: &OdenRev2FsOperationSession,
  ) -> Result<(), OdenRev2FsError> {
    self.require_operation_session(operation_session)?;
    revalidate_root(&self.root)?;
    self.revalidate_retained_edges()?;
    let OdenRev2FsCheckedTarget::Missing(missing) = &self.target else {
      return Err(OdenRev2FsError::OperationUnsupported(
        "final-missing-observation",
      ));
    };
    missing.revalidate_absent_with_hook(&mut |_, _| {})
  }

  #[cfg(not(unix))]
  fn observe_missing(
    &self,
    _operation_session: &OdenRev2FsOperationSession,
  ) -> Result<(), OdenRev2FsError> {
    Err(OdenRev2FsError::UnsupportedPlatform)
  }

  /// Consume an authorized final-missing observation without converting a
  /// missing ancestor or a raced replacement into caller-visible `ENOENT`.
  #[cfg(unix)]
  fn consume_missing(
    self,
    operation_session: &OdenRev2FsOperationSession,
  ) -> Result<(), OdenRev2FsError> {
    self.observe_missing(operation_session)
  }

  #[cfg(not(unix))]
  fn consume_missing(
    self,
    _operation_session: &OdenRev2FsOperationSession,
  ) -> Result<(), OdenRev2FsError> {
    Err(OdenRev2FsError::UnsupportedPlatform)
  }

  pub(crate) fn object_alias_fact(
    &self,
    other: &Self,
  ) -> Option<OdenRev2FsObjectAliasFact> {
    let left = self.identity_fact();
    let right = other.identity_fact();
    let left_identity = left.object_identity()?;
    let right_identity = right.object_identity()?;
    Some(OdenRev2FsObjectAliasFact {
      same_object: left_identity == right_identity,
      left,
      right,
    })
  }

  fn revalidate_retained_edges(&self) -> Result<(), OdenRev2FsError> {
    self.revalidate_retained_edges_with_hook(&mut |_, _| {})
  }

  fn revalidate_retained_edges_with_hook(
    &self,
    hook: &mut dyn FnMut(OdenRev2FsUseCheckpoint, &OsStr),
  ) -> Result<(), OdenRev2FsError> {
    for edge in &self.retained_edges {
      hook(OdenRev2FsUseCheckpoint::BeforeRetainedEdge, &edge.leaf);
      edge.revalidate()?;
    }
    Ok(())
  }

  fn require_operation_session(
    &self,
    operation_session: &OdenRev2FsOperationSession,
  ) -> Result<(), OdenRev2FsError> {
    if self.operation_session != operation_session.fact {
      return Err(OdenRev2FsError::OperationSessionMismatch);
    }
    Ok(())
  }
}

enum OdenRev2FsActorTarget {
  Checked(Box<OdenRev2FsCheckedPath>),
  PreparedMkdir(Box<OdenRev2FsPreparedMkdir>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OdenRev2FsActorOperation {
  ObserveMetadata,
  Mkdir,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum OdenRev2FsActorSourceClass {
  Negative,
  Floor,
  Ceiling,
}

pub(crate) struct OdenRev2FsActorSourceEvidence {
  binding: PathBindingInput,
  checked: OdenRev2FsCheckedPath,
  class: OdenRev2FsActorSourceClass,
  selector: crate::rev2::AuthoritySelectorInput,
}

impl OdenRev2FsActorSourceEvidence {
  pub(crate) fn new(
    binding: PathBindingInput,
    checked: OdenRev2FsCheckedPath,
    class: OdenRev2FsActorSourceClass,
    selector: crate::rev2::AuthoritySelectorInput,
  ) -> Self {
    Self {
      binding,
      checked,
      class,
      selector,
    }
  }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct OdenRev2FsActorSourceProvenance {
  class: OdenRev2FsActorSourceClass,
  selector: crate::rev2::AuthoritySelectorInput,
}

impl OdenRev2FsActorOperation {
  fn as_str(self) -> &'static str {
    match self {
      Self::ObserveMetadata => "observe-metadata",
      Self::Mkdir => "mkdir",
    }
  }
}

fn actor_effect_matches(
  request: &StageRequest,
  index: usize,
  edge_id: &str,
  effect_slot_id: &str,
  capability: &str,
) -> bool {
  request.effects.get(index).is_some_and(|effect| {
    effect.edge_id == edge_id
      && effect.effect_slot_id == effect_slot_id
      && effect.capability == capability
  })
}

fn classify_actor_request(
  request: &StageRequest,
) -> Result<OdenRev2FsActorOperation, OdenRev2FsError> {
  if request.effects.len() == 1
    && actor_effect_matches(
      request,
      0,
      "native-op:ext/fs/ops.rs#op_fs_lstat_sync",
      "native-op:ext/fs/ops.rs#op_fs_lstat_sync:effect-slot:0",
      "fs:list",
    )
  {
    return Ok(OdenRev2FsActorOperation::ObserveMetadata);
  }
  if request.effects.len() == 2
    && actor_effect_matches(
      request,
      0,
      "native-op:ext/fs/ops.rs#op_fs_mkdir_sync",
      "native-op:ext/fs/ops.rs#op_fs_mkdir_sync:effect-slot:0",
      "fs:write",
    )
    && actor_effect_matches(
      request,
      1,
      "native-op:ext/fs/ops.rs#op_fs_mkdir_sync",
      "native-op:ext/fs/ops.rs#op_fs_mkdir_sync:effect-slot:1",
      "fs:list",
    )
  {
    return Ok(OdenRev2FsActorOperation::Mkdir);
  }
  Err(OdenRev2FsError::InvalidBinding(
    "filesystem actor request does not match a closed adapter operation",
  ))
}

fn actor_platform_identity(identity: &OdenRev2FsPlatformIdentity) -> Value {
  json!({
    "kind": "platform-object",
    "value": identity.canonical_value(),
  })
}

fn actor_final_state(checked: &OdenRev2FsCheckedPath, proposed: bool) -> Value {
  match &checked.target {
    OdenRev2FsCheckedTarget::Existing(object) => json!({
      "kind": "existing",
      "identity": actor_platform_identity(&object.metadata.identity),
    }),
    OdenRev2FsCheckedTarget::Link(link) => json!({
      "kind": "link-entry",
      "identity": actor_platform_identity(&link.metadata.identity),
    }),
    OdenRev2FsCheckedTarget::Missing(_) => json!({
      "kind": if proposed { "proposed" } else { "missing" },
    }),
    OdenRev2FsCheckedTarget::Proposed(_) => json!({ "kind": "proposed" }),
  }
}

fn actor_occurrence(
  checked: &OdenRev2FsCheckedPath,
  effect_owner: &str,
  proposed: bool,
) -> Result<Value, OdenRev2FsError> {
  let lexical = checked.lexical_fact.relative_path();
  let parent =
    checked
      .parent_identity()
      .ok_or(OdenRev2FsError::InvalidBinding(
        "filesystem actor target has no verified parent",
      ))?;
  if lexical.as_os_str().is_empty() {
    return Err(OdenRev2FsError::InvalidBinding(
      "filesystem actor target has an empty occurrence",
    ));
  }
  Ok(json!({
    "effectOwner": effect_owner,
    "finalObjectState": actor_final_state(checked, proposed),
    "followMode": "no-follow-final",
    "lexicalPath": platform_path_value(lexical),
    "parentIdentity": actor_platform_identity(parent),
    "root": checked.lexical_fact.source_root.logical_root(),
    "rootBindingId": checked.lexical_fact.source_root.root_binding_id(),
  }))
}

fn validate_actor_request_target(
  operation: OdenRev2FsActorOperation,
  request: &StageRequest,
  checked: &OdenRev2FsCheckedPath,
) -> Result<(), OdenRev2FsError> {
  let valid = match operation {
    OdenRev2FsActorOperation::ObserveMetadata => {
      request.effects[0].occurrence
        == actor_occurrence(checked, &request.effects[0].effect_owner, false)?
    }
    OdenRev2FsActorOperation::Mkdir => {
      request.effects[0].occurrence
        == actor_occurrence(
          checked,
          &request.effects[0].effect_owner,
          checked.target_kind() == OdenRev2FsCheckedTargetKind::Missing,
        )?
        && request.effects[1].occurrence
          == actor_occurrence(checked, &request.effects[1].effect_owner, false)?
    }
  };
  if valid {
    Ok(())
  } else {
    Err(OdenRev2FsError::InvalidBinding(
      "filesystem actor request occurrence does not match its checked target",
    ))
  }
}

fn expected_actor_path_binding(
  checked: &OdenRev2FsCheckedPath,
  occurrence_root_binding_id: &str,
) -> PathBindingInput {
  let state = checked.identity_fact();
  match state.state() {
    OdenRev2FsIdentityState::Existing { identity, .. }
    | OdenRev2FsIdentityState::NoFollowLink { identity } => PathBindingInput {
      source_id: checked.lexical_fact.source_root.source_id().to_string(),
      root_binding_id: occurrence_root_binding_id.to_string(),
      final_object_identities: vec![actor_platform_identity(identity)],
      parent_identities: Vec::new(),
    },
    OdenRev2FsIdentityState::MissingParent { parent_identity }
    | OdenRev2FsIdentityState::ProposedParent {
      parent_identity, ..
    } => PathBindingInput {
      source_id: checked.lexical_fact.source_root.source_id().to_string(),
      root_binding_id: occurrence_root_binding_id.to_string(),
      final_object_identities: Vec::new(),
      parent_identities: vec![actor_platform_identity(parent_identity)],
    },
  }
}

fn validate_actor_source_evidence(
  target: &OdenRev2FsCheckedPath,
  evidence: &OdenRev2FsActorSourceEvidence,
) -> Result<(), OdenRev2FsError> {
  if evidence
    .selector
    .resource
    .get("root")
    .and_then(Value::as_str)
    != Some(evidence.checked.lexical_fact.source_root.logical_root())
  {
    return Err(OdenRev2FsError::InvalidBinding(
      "filesystem source selector root does not match its checked graph",
    ));
  }
  let selector_relative =
    relative_platform_path(evidence.selector.resource.get("path").ok_or(
      OdenRev2FsError::InvalidBinding("filesystem source selector has no path"),
    )?)
    .map_err(|_| {
      OdenRev2FsError::InvalidBinding(
        "filesystem source selector path is invalid",
      )
    })?;
  let valid_path = match evidence.class {
    OdenRev2FsActorSourceClass::Negative => {
      evidence.checked.lexical_fact.relative_path() == selector_relative
    }
    OdenRev2FsActorSourceClass::Floor | OdenRev2FsActorSourceClass::Ceiling => {
      match (
        evidence.checked.root.canonical_path.as_ref(),
        target.root.canonical_path.as_ref(),
      ) {
        (Some(source), Some(target_root)) => {
          source.join(evidence.checked.lexical_fact.relative_path())
            == target_root.join(target.lexical_fact.relative_path())
        }
        _ => {
          evidence.checked.lexical_fact.source_root
            == target.lexical_fact.source_root
            && evidence.checked.lexical_fact.relative_path()
              == target.lexical_fact.relative_path()
        }
      }
    }
  };
  if valid_path {
    Ok(())
  } else {
    Err(OdenRev2FsError::InvalidBinding(
      "filesystem source checked path does not match its selector provenance",
    ))
  }
}

/// Callback-free, single-owner filesystem inventory sealed before the first
/// HostActor authorization. The inventory owns every operation-local checked
/// graph; `Arc<File>` aliases may exist only inside this aggregate and are
/// represented by one opaque provisional ID per unique allocation.
///
/// @ref LLP 0019#filesystem-actor-resource-ownership-checkpoint-eng-24019
/// [implements]
pub(crate) struct OdenRev2FsActorInventory {
  operation_id: String,
  operation: OdenRev2FsActorOperation,
  bound_request: StageRequest,
  bound_path_bindings: Vec<PathBindingInput>,
  bound_source_provenance: BTreeMap<String, OdenRev2FsActorSourceProvenance>,
  operation_session: OdenRev2FsOperationSessionFact,
  target: Option<OdenRev2FsActorTarget>,
  sources: Vec<OdenRev2FsCheckedPath>,
  sealed_handles: BTreeMap<usize, String>,
  released: bool,
}

impl OdenRev2FsActorInventory {
  pub(crate) fn seal(
    operation_id: impl Into<String>,
    request: &StageRequest,
    operation_session: &OdenRev2FsOperationSession,
    target: OdenRev2FsCheckedPath,
    sources: Vec<OdenRev2FsActorSourceEvidence>,
  ) -> Result<Self, OdenRev2FsError> {
    let operation_id = operation_id.into();
    let operation = classify_actor_request(request)?;
    if operation_id.trim().is_empty() || operation_id.len() > 1024 {
      return Err(OdenRev2FsError::InvalidBinding(
        "invalid filesystem actor inventory identity",
      ));
    }
    if target.operation_session() != operation_session.fact()
      || sources.iter().any(|evidence| {
        evidence.checked.operation_session() != operation_session.fact()
      })
    {
      return Err(OdenRev2FsError::OperationSessionMismatch);
    }
    validate_actor_request_target(operation, request, &target)?;
    if sources.is_empty() {
      return Err(OdenRev2FsError::InvalidBinding(
        "filesystem actor inventory has no checked source evidence",
      ));
    }
    let occurrence_root_binding_id = target
      .lexical_fact
      .source_root
      .root_binding_id()
      .to_string();
    let mut bound_path_bindings =
      BTreeMap::<(String, String), PathBindingInput>::new();
    let mut bound_source_provenance = BTreeMap::new();
    for evidence in &sources {
      validate_actor_source_evidence(&target, evidence)?;
      if evidence.binding
        != expected_actor_path_binding(
          &evidence.checked,
          &occurrence_root_binding_id,
        )
      {
        return Err(OdenRev2FsError::InvalidBinding(
          "filesystem source binding does not match its checked graph",
        ));
      }
      let key = (
        evidence.binding.source_id.clone(),
        evidence.binding.root_binding_id.clone(),
      );
      if bound_path_bindings
        .insert(key, evidence.binding.clone())
        .is_some_and(|prior| prior != evidence.binding)
      {
        return Err(OdenRev2FsError::InvalidBinding(
          "filesystem source bindings are ambiguous",
        ));
      }
      let provenance = OdenRev2FsActorSourceProvenance {
        class: evidence.class,
        selector: evidence.selector.clone(),
      };
      if bound_source_provenance
        .insert(evidence.binding.source_id.clone(), provenance.clone())
        .is_some_and(|prior| prior != provenance)
      {
        return Err(OdenRev2FsError::InvalidBinding(
          "filesystem source provenance is ambiguous",
        ));
      }
    }
    let mut inventory = Self {
      operation_id,
      operation,
      bound_request: request.clone(),
      bound_path_bindings: bound_path_bindings.into_values().collect(),
      bound_source_provenance,
      operation_session: operation_session.fact().clone(),
      target: Some(OdenRev2FsActorTarget::Checked(Box::new(target))),
      sources: sources
        .into_iter()
        .map(|evidence| evidence.checked)
        .collect(),
      sealed_handles: BTreeMap::new(),
      released: false,
    };
    if !inventory.owns_all_graphs_exclusively() {
      return Err(OdenRev2FsError::InvalidBinding(
        "filesystem actor inventory has an external strong owner",
      ));
    }
    let handles = inventory.current_handle_keys();
    if handles.is_empty() || handles.len() > MAX_ACTOR_PROVISIONAL_HANDLES {
      return Err(OdenRev2FsError::InvalidBinding(
        "filesystem actor inventory is empty or exceeds its bound",
      ));
    }
    for (slot, handle) in handles.into_iter().enumerate() {
      let id = domain_digest(
        "oden:capsec:filesystem-provisional-resource:2",
        &json!({
          "actorIdentity": inventory.operation_session.actor_identity,
          "generationVectorToken": inventory.operation_session.generation_vector_token,
          "operationKind": inventory.operation.as_str(),
          "operationId": inventory.operation_id,
          "sessionId": inventory.operation_session.session_id.to_string(),
          "slot": slot.to_string(),
        }),
      )
      .map_err(|_| {
        OdenRev2FsError::InvalidBinding(
          "filesystem provisional resource identity",
        )
      })?;
      inventory.sealed_handles.insert(handle, id);
    }
    Ok(inventory)
  }

  pub(crate) fn binds(&self, operation_id: &str, actor_id: &str) -> bool {
    self.operation_id == operation_id
      && self.operation_session.actor_identity == actor_id
  }

  pub(crate) fn operation(&self) -> OdenRev2FsActorOperation {
    self.operation
  }

  pub(crate) fn bound_request(&self) -> &StageRequest {
    &self.bound_request
  }

  pub(crate) fn path_bindings(&self) -> &[PathBindingInput] {
    &self.bound_path_bindings
  }

  pub(crate) fn binds_policy(&self, policy: &DecisionPolicyInput) -> bool {
    if policy.path_bindings != self.bound_path_bindings {
      return false;
    }
    let capabilities = self
      .bound_request
      .effects
      .iter()
      .map(|effect| effect.capability.as_str())
      .collect::<BTreeSet<_>>();
    let is_relevant_path = |selector: &crate::rev2::AuthoritySelectorInput| {
      capabilities.contains(selector.capability.as_str())
        && selector.resource.get("root").is_some()
        && selector.resource.get("path").is_some()
    };
    let mut expected = BTreeMap::new();
    let mut unambiguous = true;
    {
      let mut add = |named: &crate::rev2::NamedSelectorInput,
                     class: OdenRev2FsActorSourceClass| {
        if is_relevant_path(&named.selector)
          && expected
            .insert(named.source_id.clone(), (class, named.selector.clone()))
            .is_some()
        {
          unambiguous = false;
        }
      };
      for named in policy
        .process_denials
        .iter()
        .chain(&policy.principal_denials)
      {
        add(named, OdenRev2FsActorSourceClass::Negative);
      }
      for named in &policy.escalation_ceiling {
        add(named, OdenRev2FsActorSourceClass::Ceiling);
      }
      for named in &policy.static_floor {
        add(named, OdenRev2FsActorSourceClass::Floor);
      }
    }
    if !unambiguous
      || policy
        .session_revocations
        .iter()
        .chain(&policy.session_grants)
        .chain(&policy.implicit_self)
        .any(|named| is_relevant_path(&named.selector))
      || policy
        .handles
        .iter()
        .any(|handle| is_relevant_path(&handle.selector))
      || policy
        .protected_exceptions
        .iter()
        .any(|protected| is_relevant_path(&protected.selector))
      || policy
        .compatibility_dispositions
        .iter()
        .any(|disposition| is_relevant_path(&disposition.selector))
      || expected.len() != self.bound_source_provenance.len()
    {
      return false;
    }
    expected.into_iter().all(|(source_id, (class, selector))| {
      self
        .bound_source_provenance
        .get(&source_id)
        .is_some_and(|provenance| {
          provenance.class == class && provenance.selector == selector
        })
    })
  }

  pub(crate) fn target_kind(
    &self,
  ) -> Result<OdenRev2FsCheckedTargetKind, OdenRev2FsError> {
    match self.target.as_ref() {
      Some(OdenRev2FsActorTarget::Checked(checked)) => {
        Ok(checked.target_kind())
      }
      Some(OdenRev2FsActorTarget::PreparedMkdir(_)) => {
        Ok(OdenRev2FsCheckedTargetKind::Proposed)
      }
      None => Err(OdenRev2FsError::OperationUnsupported(
        "filesystem actor inventory released",
      )),
    }
  }

  pub(crate) fn revalidate_sources(
    &self,
    operation_session: &OdenRev2FsOperationSession,
  ) -> Result<(), OdenRev2FsError> {
    self.require_session(operation_session)?;
    for checked in &self.sources {
      checked.revalidate_binding(operation_session)?;
    }
    Ok(())
  }

  pub(crate) fn revalidate_target(
    &self,
    operation_session: &OdenRev2FsOperationSession,
  ) -> Result<(), OdenRev2FsError> {
    self.require_session(operation_session)?;
    match self.target.as_ref() {
      Some(OdenRev2FsActorTarget::Checked(checked)) => {
        checked.revalidate_binding(operation_session)
      }
      Some(OdenRev2FsActorTarget::PreparedMkdir(prepared)) => {
        prepared.revalidate_before_commit(operation_session)
      }
      None => Err(OdenRev2FsError::OperationUnsupported(
        "filesystem actor inventory released",
      )),
    }
  }

  pub(crate) fn observe_metadata(
    &self,
    operation_session: &OdenRev2FsOperationSession,
    _witness: &OdenRev2FilesystemPendingWitness,
  ) -> Result<OdenRev2FsMetadataObservation, OdenRev2FsError> {
    self.require_session(operation_session)?;
    if self.operation != OdenRev2FsActorOperation::ObserveMetadata {
      return Err(OdenRev2FsError::OperationUnsupported(
        "filesystem actor operation does not observe metadata",
      ));
    }
    let Some(OdenRev2FsActorTarget::Checked(checked)) = self.target.as_ref()
    else {
      return Err(OdenRev2FsError::OperationUnsupported(
        "filesystem metadata target is unavailable",
      ));
    };
    checked.observe_metadata(operation_session)
  }

  pub(crate) fn observe_missing(
    &self,
    operation_session: &OdenRev2FsOperationSession,
    _witness: &OdenRev2FilesystemPendingWitness,
  ) -> Result<(), OdenRev2FsError> {
    self.require_session(operation_session)?;
    if self.operation != OdenRev2FsActorOperation::ObserveMetadata {
      return Err(OdenRev2FsError::OperationUnsupported(
        "filesystem actor operation does not observe missing entries",
      ));
    }
    let Some(OdenRev2FsActorTarget::Checked(checked)) = self.target.as_ref()
    else {
      return Err(OdenRev2FsError::OperationUnsupported(
        "filesystem missing target is unavailable",
      ));
    };
    checked.observe_missing(operation_session)
  }

  pub(crate) fn prepare_mkdir(
    &mut self,
    operation_session: &OdenRev2FsOperationSession,
    _witness: &OdenRev2FilesystemPendingWitness,
  ) -> Result<(), OdenRev2FsError> {
    self.require_session(operation_session)?;
    if self.operation != OdenRev2FsActorOperation::Mkdir {
      return Err(OdenRev2FsError::OperationUnsupported(
        "filesystem actor operation does not prepare mkdir",
      ));
    }
    let Some(OdenRev2FsActorTarget::Checked(checked)) = self.target.take()
    else {
      return Err(OdenRev2FsError::OperationUnsupported(
        "filesystem mkdir target is unavailable",
      ));
    };
    let proposed = (*checked)
      .propose_child(operation_session, OdenRev2FsProposedKind::Directory)?;
    let prepared = proposed.prepare_mkdir(operation_session)?;
    self.target =
      Some(OdenRev2FsActorTarget::PreparedMkdir(Box::new(prepared)));
    if !self.is_intact() {
      return Err(OdenRev2FsError::InvalidBinding(
        "filesystem inventory changed during mkdir preparation",
      ));
    }
    Ok(())
  }

  pub(crate) fn commit_mkdir(
    &mut self,
    operation_session: &OdenRev2FsOperationSession,
    mode: u32,
    _witness: &OdenRev2FilesystemCommittedWitness,
    native_commit_witness: &OdenRev2FilesystemNativeCommitWitness<'_>,
  ) -> OdenRev2FsMkdirCommitOutcome {
    if let Err(error) = self.require_session(operation_session) {
      return OdenRev2FsMkdirCommitOutcome::NotCommitted(error);
    }
    if self.operation != OdenRev2FsActorOperation::Mkdir {
      return OdenRev2FsMkdirCommitOutcome::NotCommitted(
        OdenRev2FsError::OperationUnsupported(
          "filesystem actor operation does not commit mkdir",
        ),
      );
    }
    if !operation_session.matches_gate_token(native_commit_witness.gate_token())
    {
      return OdenRev2FsMkdirCommitOutcome::NotCommitted(
        OdenRev2FsError::OperationSessionMismatch,
      );
    }
    let Some(OdenRev2FsActorTarget::PreparedMkdir(prepared)) =
      self.target.as_mut()
    else {
      return OdenRev2FsMkdirCommitOutcome::NotCommitted(
        OdenRev2FsError::OperationUnsupported(
          "filesystem mkdir target is not prepared",
        ),
      );
    };
    prepared.commit(operation_session, mode)
  }

  pub(crate) fn is_intact(&self) -> bool {
    !self.released
      && self.target.is_some()
      && self.owns_all_graphs_exclusively()
      && self.current_handle_keys()
        == self.sealed_handles.keys().copied().collect()
  }

  pub(crate) fn completion_ready(&self) -> bool {
    match (self.operation, self.target.as_ref()) {
      (
        OdenRev2FsActorOperation::ObserveMetadata,
        Some(OdenRev2FsActorTarget::Checked(_)),
      ) => true,
      (
        OdenRev2FsActorOperation::Mkdir,
        Some(OdenRev2FsActorTarget::Checked(checked)),
      ) => matches!(
        checked.target_kind(),
        OdenRev2FsCheckedTargetKind::Existing
          | OdenRev2FsCheckedTargetKind::NoFollowLink
      ),
      (
        OdenRev2FsActorOperation::Mkdir,
        Some(OdenRev2FsActorTarget::PreparedMkdir(prepared)),
      ) => prepared.commit_state == OdenRev2FsMkdirCommitState::Committed,
      _ => false,
    }
  }

  #[cfg(test)]
  pub(crate) fn provisional_handle_count(&self) -> usize {
    self.sealed_handles.len()
  }

  #[cfg(test)]
  pub(crate) fn provisional_weak_handles(&self) -> Vec<std::sync::Weak<File>> {
    let mut handles = BTreeMap::new();
    self.visit_handles(&mut |handle| {
      handles
        .entry(Arc::as_ptr(handle) as usize)
        .or_insert_with(|| Arc::downgrade(handle));
    });
    handles.into_values().collect()
  }

  #[cfg(test)]
  fn visited_handle_reference_count(&self) -> usize {
    let mut count = 0;
    self.visit_handles(&mut |_| count += 1);
    count
  }

  fn require_session(
    &self,
    operation_session: &OdenRev2FsOperationSession,
  ) -> Result<(), OdenRev2FsError> {
    if self.released || self.operation_session != *operation_session.fact() {
      return Err(OdenRev2FsError::OperationSessionMismatch);
    }
    Ok(())
  }

  fn current_handle_keys(&self) -> BTreeSet<usize> {
    let mut handles = BTreeSet::new();
    self.visit_handles(&mut |handle| {
      handles.insert(Arc::as_ptr(handle) as usize);
    });
    handles
  }

  fn owns_all_graphs_exclusively(&self) -> bool {
    let mut roots =
      BTreeMap::<usize, (usize, std::sync::Weak<OdenRev2FsRootState>)>::new();
    self.visit_root_states(&mut |root| {
      let entry = roots
        .entry(Arc::as_ptr(root) as usize)
        .or_insert_with(|| (0, Arc::downgrade(root)));
      entry.0 += 1;
    });
    if roots
      .values()
      .any(|(owners, root)| root.strong_count() != *owners)
    {
      return false;
    }

    let mut handles = BTreeMap::<usize, (usize, std::sync::Weak<File>)>::new();
    self.visit_handles(&mut |handle| {
      let entry = handles
        .entry(Arc::as_ptr(handle) as usize)
        .or_insert_with(|| (0, Arc::downgrade(handle)));
      entry.0 += 1;
    });
    handles
      .values()
      .all(|(owners, handle)| handle.strong_count() == *owners)
  }

  fn visit_root_states(
    &self,
    visitor: &mut dyn FnMut(&Arc<OdenRev2FsRootState>),
  ) {
    if let Some(target) = self.target.as_ref() {
      match target {
        OdenRev2FsActorTarget::Checked(checked) => visitor(&checked.root),
        OdenRev2FsActorTarget::PreparedMkdir(prepared) => {
          visitor(&prepared.root)
        }
      }
    }
    for checked in &self.sources {
      visitor(&checked.root);
    }
  }

  fn visit_handles(&self, visitor: &mut dyn FnMut(&Arc<File>)) {
    let mut visited_roots = BTreeSet::new();
    if let Some(target) = self.target.as_ref() {
      match target {
        OdenRev2FsActorTarget::Checked(checked) => {
          visit_checked_handles(checked, &mut visited_roots, visitor)
        }
        OdenRev2FsActorTarget::PreparedMkdir(prepared) => {
          visit_prepared_mkdir_handles(prepared, &mut visited_roots, visitor)
        }
      }
    }
    for checked in &self.sources {
      visit_checked_handles(checked, &mut visited_roots, visitor);
    }
  }
}

impl ProvisionalResources for OdenRev2FsActorInventory {
  fn held_ids(&self) -> Vec<String> {
    if self.released {
      return Vec::new();
    }
    if !self.is_intact() {
      return vec![String::new()];
    }
    self.sealed_handles.values().cloned().collect()
  }

  fn release_all(&mut self) -> Vec<String> {
    if self.released {
      return Vec::new();
    }
    #[cfg(test)]
    let weak_handles = self.provisional_weak_handles();
    let released = self.sealed_handles.values().cloned().collect();
    self.target = None;
    self.sources.clear();
    self.released = true;
    #[cfg(test)]
    ODEN_REV2_FS_LAST_RELEASED_HANDLES_FOR_TEST.with(|handles| {
      *handles.borrow_mut() = weak_handles;
    });
    released
  }
}

impl Drop for OdenRev2FsActorInventory {
  fn drop(&mut self) {
    // This aggregate is callback-free, so unwind and abandoned-actor cleanup
    // can close the exact sealed inventory synchronously and idempotently.
    let _ = self.release_all();
  }
}

fn visit_root_handles(
  root: &OdenRev2FsRootState,
  visitor: &mut dyn FnMut(&Arc<File>),
) {
  visitor(&root.retained);
  visitor(&root.named);
}

fn visit_edge_handles(
  edges: &[OdenRev2FsRetainedEdge],
  visitor: &mut dyn FnMut(&Arc<File>),
) {
  for edge in edges {
    visitor(&edge.parent);
    visitor(&edge.child);
  }
}

fn visit_checked_handles(
  checked: &OdenRev2FsCheckedPath,
  visited_roots: &mut BTreeSet<usize>,
  visitor: &mut dyn FnMut(&Arc<File>),
) {
  if visited_roots.insert(Arc::as_ptr(&checked.root) as usize) {
    visit_root_handles(&checked.root, visitor);
  }
  visit_edge_handles(&checked.retained_edges, visitor);
  match &checked.target {
    OdenRev2FsCheckedTarget::Existing(object) => {
      if let Some(parent) = object.parent.as_ref() {
        visitor(&parent.handle);
      }
      visitor(&object.handle);
    }
    OdenRev2FsCheckedTarget::Link(link) => {
      visitor(&link.parent.handle);
      visitor(&link.handle);
    }
    OdenRev2FsCheckedTarget::Missing(child) => visitor(&child.parent.handle),
    OdenRev2FsCheckedTarget::Proposed(child) => visitor(&child.parent.handle),
  }
}

fn visit_prepared_mkdir_handles(
  prepared: &OdenRev2FsPreparedMkdir,
  visited_roots: &mut BTreeSet<usize>,
  visitor: &mut dyn FnMut(&Arc<File>),
) {
  if visited_roots.insert(Arc::as_ptr(&prepared.root) as usize) {
    visit_root_handles(&prepared.root, visitor);
  }
  visit_edge_handles(&prepared.retained_edges, visitor);
  visitor(&prepared.parent.handle);
}

fn link_leaf(
  checked: &OdenRev2FsCheckedPath,
) -> Result<OsString, OdenRev2FsError> {
  checked
    .resolver_trace_path
    .file_name()
    .map(OsStr::to_os_string)
    .ok_or(OdenRev2FsError::InvalidPath("link entry has no leaf"))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct OdenRev2FsObjectAliasFact {
  left: OdenRev2FsIdentityFact,
  right: OdenRev2FsIdentityFact,
  same_object: bool,
}

impl OdenRev2FsObjectAliasFact {
  pub(crate) fn left(&self) -> &OdenRev2FsIdentityFact {
    &self.left
  }

  pub(crate) fn right(&self) -> &OdenRev2FsIdentityFact {
    &self.right
  }

  pub(crate) fn same_object(&self) -> bool {
    self.same_object
  }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OdenRev2FsRootTransitionKind {
  SameObject,
  VerifiedDirectoryTransition,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct OdenRev2FsRootTransitionFact {
  from: OdenRev2FsSourceRootFact,
  to: OdenRev2FsSourceRootFact,
  relation: OdenRev2FsRootTransitionKind,
  transition_identity: OdenRev2FsPlatformIdentity,
  resolver_trace_path: PathBuf,
}

impl OdenRev2FsRootTransitionFact {
  pub(crate) fn from(&self) -> &OdenRev2FsSourceRootFact {
    &self.from
  }

  pub(crate) fn to(&self) -> &OdenRev2FsSourceRootFact {
    &self.to
  }

  pub(crate) fn relation(&self) -> OdenRev2FsRootTransitionKind {
    self.relation
  }

  pub(crate) fn transition_identity(&self) -> &OdenRev2FsPlatformIdentity {
    &self.transition_identity
  }

  pub(crate) fn resolver_trace_path(&self) -> &Path {
    &self.resolver_trace_path
  }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OdenRev2FsResolveCheckpoint {
  AfterMetadata,
  AfterReadlink,
  AfterMissing,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OdenRev2FsUseCheckpoint {
  BeforeRetainedEdge,
  BeforeMissingLeaf,
}

fn checked_relative_components(
  path: &Path,
) -> Result<Vec<OsString>, OdenRev2FsError> {
  if path.is_absolute() {
    return Err(OdenRev2FsError::InvalidPath(
      "path must be relative to its logical root",
    ));
  }
  let mut out = Vec::new();
  for component in path.components() {
    match component {
      Component::Normal(component) => out.push(component.to_os_string()),
      Component::CurDir if out.is_empty() => {}
      Component::CurDir => {
        return Err(OdenRev2FsError::InvalidPath(
          "path must be lexically canonical",
        ));
      }
      Component::ParentDir => return Err(OdenRev2FsError::RootEscape),
      Component::RootDir | Component::Prefix(_) => {
        return Err(OdenRev2FsError::InvalidPath(
          "path must be relative to its logical root",
        ));
      }
    }
  }
  Ok(out)
}

fn components_path(components: &[OsString]) -> PathBuf {
  let mut path = PathBuf::new();
  for component in components {
    path.push(component);
  }
  path
}

fn normalize_symlink_target(
  canonical_root: Option<&Path>,
  resolved_parent: &[OsString],
  target: &Path,
) -> Result<Vec<OsString>, OdenRev2FsError> {
  let (mut result, target) = if target.is_absolute() {
    let canonical_root = canonical_root.ok_or(OdenRev2FsError::RootEscape)?;
    let relative = target
      .strip_prefix(canonical_root)
      .map_err(|_| OdenRev2FsError::RootEscape)?;
    (Vec::new(), relative)
  } else {
    (resolved_parent.to_vec(), target)
  };
  for component in target.components() {
    match component {
      Component::Normal(component) => result.push(component.to_os_string()),
      Component::CurDir => {}
      Component::ParentDir => {
        if result.pop().is_none() {
          return Err(OdenRev2FsError::RootEscape);
        }
      }
      Component::RootDir | Component::Prefix(_) => {
        return Err(OdenRev2FsError::RootEscape);
      }
    }
  }
  Ok(result)
}

/// Compute the platform adapter's absolute lexical candidate without opening
/// the target. Unlike same-root normalization this may leave the source root;
/// callers must bind the result to a separately authenticated destination.
fn lexical_absolute_symlink_target(
  canonical_root: &Path,
  resolved_parent: &[OsString],
  target: &Path,
) -> Result<PathBuf, OdenRev2FsError> {
  let candidate = if target.is_absolute() {
    target.to_path_buf()
  } else {
    canonical_root
      .join(components_path(resolved_parent))
      .join(target)
  };
  let mut normalized = PathBuf::new();
  for component in candidate.components() {
    match component {
      Component::RootDir => normalized.push(Path::new("/")),
      Component::Normal(component) => normalized.push(component),
      Component::CurDir => {}
      Component::ParentDir => {
        if !normalized.pop() {
          return Err(OdenRev2FsError::RootEscape);
        }
      }
      Component::Prefix(_) => return Err(OdenRev2FsError::RootEscape),
    }
  }
  if !normalized.is_absolute() {
    return Err(OdenRev2FsError::RootEscape);
  }
  Ok(normalized)
}

fn platform_path(
  path: &OdenRev2PlatformPath,
) -> Result<PathBuf, OdenRev2FsError> {
  #[cfg(not(unix))]
  {
    let _ = path;
    Err(OdenRev2FsError::UnsupportedPlatform)
  }
  #[cfg(unix)]
  {
    Ok(match path {
      OdenRev2PlatformPath::Unicode(path) => PathBuf::from(path),
      OdenRev2PlatformPath::Bytes(path) => {
        PathBuf::from(OsString::from_vec(path.clone()))
      }
    })
  }
}

#[cfg(target_os = "linux")]
fn platform_adapter() -> OdenRev2FsCanonicalizerAdapter {
  OdenRev2FsCanonicalizerAdapter::LinuxFdRelativeV1
}

#[cfg(target_os = "macos")]
fn platform_adapter() -> OdenRev2FsCanonicalizerAdapter {
  OdenRev2FsCanonicalizerAdapter::DarwinFdRelativeV1
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn platform_adapter() -> OdenRev2FsCanonicalizerAdapter {
  unreachable!("unsupported platforms cannot authenticate a root")
}

#[cfg(unix)]
fn cstring(path: &OsStr) -> io::Result<CString> {
  CString::new(path.as_bytes())
    .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))
}

#[cfg(unix)]
fn open_absolute_non_consuming(
  path: &Path,
  directory: bool,
) -> io::Result<File> {
  if !path.is_absolute() {
    return Err(io::Error::from(io::ErrorKind::InvalidInput));
  }
  let path = cstring(path.as_os_str())?;
  let mut flags = non_consuming_flags() | libc::O_NOFOLLOW;
  if directory {
    flags |= libc::O_DIRECTORY;
  }
  // SAFETY: path is NUL-terminated; successful open returns a new descriptor.
  let fd = unsafe { libc::open(path.as_ptr(), flags) };
  if fd < 0 {
    Err(io::Error::last_os_error())
  } else {
    // SAFETY: fd was just returned by open and is uniquely owned.
    Ok(unsafe { File::from_raw_fd(fd) })
  }
}

#[cfg(unix)]
fn non_consuming_flags() -> libc::c_int {
  #[cfg(target_os = "linux")]
  {
    libc::O_PATH | libc::O_CLOEXEC
  }
  #[cfg(target_os = "macos")]
  {
    libc::O_EVTONLY | libc::O_NONBLOCK | libc::O_CLOEXEC
  }
  #[cfg(not(any(target_os = "linux", target_os = "macos")))]
  {
    libc::O_CLOEXEC
  }
}

#[cfg(unix)]
fn lstat_component(
  parent: &File,
  component: &OsStr,
) -> Result<Option<OdenRev2FsObservedMetadata>, OdenRev2FsError> {
  let component = cstring(component)
    .map_err(|error| OdenRev2FsError::io("encode path component", error))?;
  // SAFETY: parent and component are live; stat is writable for fstatat.
  let mut stat = unsafe { std::mem::zeroed::<libc::stat>() };
  let result = unsafe {
    libc::fstatat(
      parent.as_raw_fd(),
      component.as_ptr(),
      &mut stat,
      libc::AT_SYMLINK_NOFOLLOW,
    )
  };
  if result == 0 {
    Ok(Some(OdenRev2FsObservedMetadata::from_stat(&stat)))
  } else {
    let error = io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ENOENT) {
      Ok(None)
    } else {
      Err(OdenRev2FsError::io("lstat path component", error))
    }
  }
}

#[cfg(unix)]
fn open_component_non_consuming(
  parent: &File,
  component: &OsStr,
  directory: bool,
  kind: OdenRev2FsObjectKind,
) -> Result<File, OdenRev2FsError> {
  let component = cstring(component)
    .map_err(|error| OdenRev2FsError::io("encode path component", error))?;
  let mut flags = non_consuming_flags() | libc::O_NOFOLLOW;
  if directory {
    flags |= libc::O_DIRECTORY;
  }
  // SAFETY: parent and component remain live; successful openat owns fd.
  let fd =
    unsafe { libc::openat(parent.as_raw_fd(), component.as_ptr(), flags) };
  if fd < 0 {
    let error = io::Error::last_os_error();
    if kind.is_special()
      && matches!(
        error.raw_os_error(),
        Some(code)
          if code == libc::ENXIO
            || code == libc::ENODEV
            || code == libc::ENOTSUP
            || code == libc::EOPNOTSUPP
      )
    {
      return Err(OdenRev2FsError::NonConsumingOpenUnsupported);
    }
    Err(OdenRev2FsError::io("open path component", error))
  } else {
    // SAFETY: fd was just returned by openat and is uniquely owned.
    Ok(unsafe { File::from_raw_fd(fd) })
  }
}

#[cfg(target_os = "linux")]
fn open_symlink_non_consuming(
  parent: &File,
  component: &OsStr,
) -> Result<File, OdenRev2FsError> {
  open_component_non_consuming(
    parent,
    component,
    false,
    OdenRev2FsObjectKind::Symlink,
  )
}

#[cfg(target_os = "macos")]
fn open_symlink_non_consuming(
  parent: &File,
  component: &OsStr,
) -> Result<File, OdenRev2FsError> {
  let component = cstring(component)
    .map_err(|error| OdenRev2FsError::io("encode link component", error))?;
  // Darwin O_SYMLINK opens the link object itself. O_NOFOLLOW must not be
  // combined with it because O_NOFOLLOW requires ELOOP for a final symlink.
  let flags =
    libc::O_SYMLINK | libc::O_EVTONLY | libc::O_NONBLOCK | libc::O_CLOEXEC;
  // SAFETY: parent and component remain live; successful openat owns fd.
  let fd =
    unsafe { libc::openat(parent.as_raw_fd(), component.as_ptr(), flags) };
  if fd < 0 {
    Err(OdenRev2FsError::io(
      "open Darwin symlink object",
      io::Error::last_os_error(),
    ))
  } else {
    // SAFETY: fd was just returned by openat and is uniquely owned.
    Ok(unsafe { File::from_raw_fd(fd) })
  }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn open_symlink_non_consuming(
  _parent: &File,
  _component: &OsStr,
) -> Result<File, OdenRev2FsError> {
  Err(OdenRev2FsError::UnsupportedPlatform)
}

#[cfg(unix)]
fn readlink_component(
  parent: &File,
  component: &OsStr,
) -> Result<PathBuf, OdenRev2FsError> {
  let component = cstring(component)
    .map_err(|error| OdenRev2FsError::io("encode link component", error))?;
  let mut capacity = 256usize;
  loop {
    let mut buffer = vec![0u8; capacity];
    // SAFETY: parent/component are live and buffer is writable.
    let length = unsafe {
      libc::readlinkat(
        parent.as_raw_fd(),
        component.as_ptr(),
        buffer.as_mut_ptr().cast(),
        buffer.len(),
      )
    };
    if length < 0 {
      return Err(OdenRev2FsError::io(
        "read symlink",
        io::Error::last_os_error(),
      ));
    }
    let length = length as usize;
    if length < buffer.len() {
      buffer.truncate(length);
      return Ok(PathBuf::from(OsString::from_vec(buffer)));
    }
    if capacity >= MAX_SYMLINK_BYTES {
      return Err(OdenRev2FsError::InvalidPath("symlink target too long"));
    }
    capacity = (capacity * 2).min(MAX_SYMLINK_BYTES);
  }
}

#[cfg(unix)]
fn metadata_from_file(
  file: &File,
  operation: &'static str,
) -> Result<OdenRev2FsObservedMetadata, OdenRev2FsError> {
  file
    .metadata()
    .map(|metadata| OdenRev2FsObservedMetadata::from_metadata(&metadata))
    .map_err(|error| OdenRev2FsError::io(operation, error))
}

#[cfg(unix)]
fn verified_parent(
  handle: Arc<File>,
) -> Result<OdenRev2FsVerifiedParent, OdenRev2FsError> {
  let metadata = metadata_from_file(&handle, "stat verified parent")?;
  if metadata.kind != OdenRev2FsObjectKind::Directory {
    return Err(OdenRev2FsError::InvalidPath(
      "verified parent is not a directory",
    ));
  }
  Ok(OdenRev2FsVerifiedParent { metadata, handle })
}

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod tests {
  use super::*;
  use std::sync::atomic::AtomicU64;
  use std::sync::atomic::Ordering;

  static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

  struct TempRoot(PathBuf);

  impl TempRoot {
    fn new(label: &str) -> Self {
      let sequence = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
      let path = std::env::temp_dir().join(format!(
        "oden-rev2-fs-{label}-{}-{sequence}",
        std::process::id()
      ));
      std::fs::create_dir(&path).unwrap();
      Self(path)
    }
  }

  impl Drop for TempRoot {
    fn drop(&mut self) {
      let _ = std::fs::remove_dir_all(&self.0);
    }
  }

  fn test_root(
    path: &Path,
    source_id: &str,
    logical_root: &str,
    binding_id: &str,
  ) -> OdenRev2FsAuthenticatedRoot {
    let retained = open_absolute_non_consuming(path, true).unwrap();
    let identity = metadata_from_file(&retained, "test root metadata")
      .unwrap()
      .identity
      .canonical_value();
    OdenRev2FsAuthenticatedRoot::authenticate_parts(
      source_id.to_string(),
      logical_root.to_string(),
      binding_id.to_string(),
      path.to_path_buf(),
      &identity,
      retained,
    )
    .unwrap()
  }

  fn test_descriptor_root(
    path: &Path,
    source_id: &str,
    logical_root: &str,
    binding_id: &str,
  ) -> OdenRev2FsAuthenticatedRoot {
    let retained = open_absolute_non_consuming(path, true).unwrap();
    let identity =
      metadata_from_file(&retained, "test descriptor root metadata")
        .unwrap()
        .identity
        .canonical_value();
    OdenRev2FsAuthenticatedRoot::authenticate_descriptor_parts(
      source_id.to_string(),
      logical_root.to_string(),
      binding_id.to_string(),
      &identity,
      retained,
    )
    .unwrap()
  }

  fn test_session(label: &str) -> OdenRev2FsOperationSession {
    test_session_parts(format!("actor:{label}"), format!("generation:{label}"))
  }

  fn test_session_parts(
    actor_identity: String,
    generation_vector_token: String,
  ) -> OdenRev2FsOperationSession {
    OdenRev2FsOperationSession {
      fact: OdenRev2FsOperationSessionFact {
        session_id: next_operation_session().unwrap(),
        actor_identity,
        generation_vector_token,
      },
    }
  }

  fn test_mkdir_request(
    stage_id: &str,
    checked: &OdenRev2FsCheckedPath,
  ) -> StageRequest {
    let effect_owner = "owner:test";
    StageRequest {
      identity: crate::rev2::EngineIdentity::embedded(),
      stage_id: stage_id.to_string(),
      principals: Vec::new(),
      effects: vec![
        crate::rev2::EffectInput {
          identity: crate::rev2::EngineIdentity::embedded(),
          edge_id: "native-op:ext/fs/ops.rs#op_fs_mkdir_sync".to_string(),
          effect_slot_id:
            "native-op:ext/fs/ops.rs#op_fs_mkdir_sync:effect-slot:0".to_string(),
          capability: "fs:write".to_string(),
          effect_owner: effect_owner.to_string(),
          occurrence: actor_occurrence(
            checked,
            effect_owner,
            checked.target_kind() == OdenRev2FsCheckedTargetKind::Missing,
          )
          .unwrap(),
        },
        crate::rev2::EffectInput {
          identity: crate::rev2::EngineIdentity::embedded(),
          edge_id: "native-op:ext/fs/ops.rs#op_fs_mkdir_sync".to_string(),
          effect_slot_id:
            "native-op:ext/fs/ops.rs#op_fs_mkdir_sync:effect-slot:1".to_string(),
          capability: "fs:list".to_string(),
          effect_owner: effect_owner.to_string(),
          occurrence: actor_occurrence(checked, effect_owner, false).unwrap(),
        },
      ],
    }
  }

  fn test_actor_source_evidence(
    binding: PathBindingInput,
    checked: OdenRev2FsCheckedPath,
    class: OdenRev2FsActorSourceClass,
    capability: &str,
    selector_path: &Path,
  ) -> OdenRev2FsActorSourceEvidence {
    let selector = test_actor_source_selector(
      checked.lexical_fact().source_root().logical_root(),
      capability,
      selector_path,
    );
    OdenRev2FsActorSourceEvidence::new(binding, checked, class, selector)
  }

  fn test_actor_source_selector(
    logical_root: &str,
    capability: &str,
    selector_path: &Path,
  ) -> crate::rev2::AuthoritySelectorInput {
    crate::rev2::AuthoritySelectorInput {
      identity: crate::rev2::EngineIdentity::embedded(),
      principal: None,
      capability: capability.to_string(),
      resource: json!({
        "kind": "path-tree",
        "path": platform_path_value(selector_path),
        "root": logical_root,
      }),
    }
  }

  fn test_negative_policy(
    source_id: &str,
    selector: crate::rev2::AuthoritySelectorInput,
    path_bindings: Vec<PathBindingInput>,
  ) -> DecisionPolicyInput {
    DecisionPolicyInput {
      identity: crate::rev2::EngineIdentity::embedded(),
      mode: crate::rev2::Mode::Enforce,
      run_nonce: "run:filesystem-actor-test".to_string(),
      channel_epoch: "channel:filesystem-actor-test".to_string(),
      provenance: crate::rev2::OperationProvenanceContext {
        policy_digest: "policy:filesystem-actor-test".to_string(),
        armed_snapshot_digest: "snapshot:filesystem-actor-test".to_string(),
        quota_owner: crate::rev2::PrincipalRef {
          kind: crate::rev2::PrincipalKind::Runtime,
          key: "runtime:filesystem-actor-test".to_string(),
        },
        terminal_evidence_id: "terminal:filesystem-actor-test".to_string(),
      },
      generations: crate::rev2::Generations::default(),
      process_denials: vec![crate::rev2::NamedSelectorInput {
        source_id: source_id.to_string(),
        selector,
      }],
      principal_denials: Vec::new(),
      session_revocations: Vec::new(),
      escalation_ceiling: Vec::new(),
      static_floor: Vec::new(),
      handles: Vec::new(),
      session_grants: Vec::new(),
      implicit_self: Vec::new(),
      protected_exceptions: Vec::new(),
      compatibility_dispositions: Vec::new(),
      validated_receipt_row_digests: Vec::new(),
      path_bindings,
    }
  }

  fn test_hop_authorization(
    challenge: &OdenRev2FsLinkHopFact,
    operation_session: &OdenRev2FsOperationSession,
    positive_source: &OdenRev2FsSourceRootFact,
  ) -> OdenRev2FsHopAuthorization {
    OdenRev2FsHopAuthorization {
      challenge_id: challenge.challenge_id,
      link_identity: challenge.link_identity.clone(),
      operation_session: operation_session.fact.clone(),
      positive_source: positive_source.clone(),
    }
  }

  fn test_root_transition_authorization(
    challenge: &OdenRev2FsLinkHopFact,
    operation_session: &OdenRev2FsOperationSession,
    source: &OdenRev2FsAuthenticatedRoot,
    destination: &OdenRev2FsAuthenticatedRoot,
  ) -> Result<OdenRev2FsRootTransitionAuthorization, OdenRev2FsError> {
    if challenge.operation_session != operation_session.fact {
      return Err(OdenRev2FsError::OperationSessionMismatch);
    }
    source.revalidate()?;
    destination.revalidate()?;
    let source_fact = source.source_root_fact();
    let destination_fact = destination.source_root_fact();
    if challenge.source_root != source_fact
      || source_fact.adapter != destination_fact.adapter
    {
      return Err(OdenRev2FsError::RootTransitionMismatch);
    }
    let source_path = source
      .state
      .canonical_path
      .as_deref()
      .ok_or(OdenRev2FsError::RootTransitionMismatch)?;
    let destination_path = destination
      .state
      .canonical_path
      .as_deref()
      .ok_or(OdenRev2FsError::RootTransitionMismatch)?;
    if normalize_symlink_target(
      Some(source_path),
      &challenge.resolved_parent,
      &challenge.opaque_target,
    )
    .is_ok()
    {
      return Err(OdenRev2FsError::RootTransitionMismatch);
    }
    let absolute_target = lexical_absolute_symlink_target(
      source_path,
      &challenge.resolved_parent,
      &challenge.opaque_target,
    )?;
    let destination_relative =
      absolute_target
        .strip_prefix(destination_path)
        .map_err(|_| OdenRev2FsError::RootTransitionMismatch)?;
    let target_components =
      checked_relative_components(destination_relative)
        .map_err(|_| OdenRev2FsError::RootTransitionMismatch)?;
    let relation = if source.state.identity == destination.state.identity {
      OdenRev2FsRootTransitionKind::SameObject
    } else {
      OdenRev2FsRootTransitionKind::VerifiedDirectoryTransition
    };
    Ok(OdenRev2FsRootTransitionAuthorization {
      challenge_id: challenge.challenge_id,
      link_identity: challenge.link_identity.clone(),
      operation_session: operation_session.fact.clone(),
      fact: OdenRev2FsRootTransitionFact {
        from: source_fact,
        to: destination_fact,
        relation,
        transition_identity: destination.state.identity.clone(),
        resolver_trace_path: challenge.resolver_trace_path.clone(),
      },
      destination: Arc::clone(&destination.state),
      target_components,
    })
  }

  fn checked_without_hops(
    root: &OdenRev2FsAuthenticatedRoot,
    path: &Path,
    follow: OdenRev2FsFollowMode,
  ) -> OdenRev2FsCheckedPath {
    let session = test_session("without-hops");
    checked_without_hops_for_session(root, &session, path, follow)
  }

  fn checked_without_hops_for_session(
    root: &OdenRev2FsAuthenticatedRoot,
    session: &OdenRev2FsOperationSession,
    path: &Path,
    follow: OdenRev2FsFollowMode,
  ) -> OdenRev2FsCheckedPath {
    match root
      .begin_resolution(session, path, follow)
      .unwrap()
      .advance()
      .unwrap()
    {
      OdenRev2FsResolutionStep::Complete(checked) => checked,
      OdenRev2FsResolutionStep::AuthorizationRequired(_) => {
        panic!("test path unexpectedly required hop authorization")
      }
    }
  }

  fn checked_with_authorized_hops(
    root: &OdenRev2FsAuthenticatedRoot,
    path: &Path,
    follow: OdenRev2FsFollowMode,
  ) -> Result<OdenRev2FsCheckedPath, OdenRev2FsError> {
    let session = test_session("with-authorized-hops");
    let mut resolution = root.begin_resolution(&session, path, follow)?;
    loop {
      match resolution.advance()? {
        OdenRev2FsResolutionStep::Complete(checked) => return Ok(checked),
        OdenRev2FsResolutionStep::AuthorizationRequired(pending) => {
          let proof = test_hop_authorization(
            pending.challenge(),
            &session,
            &root.source_root_fact(),
          );
          resolution = pending.resume(proof)?;
        }
      }
    }
  }

  #[test]
  fn lexical_and_identity_facts_remain_separate_and_source_root_bound() {
    let root = TempRoot::new("facts");
    std::fs::create_dir(root.0.join("data")).unwrap();
    std::fs::write(root.0.join("data/file"), b"data").unwrap();
    let floor =
      test_root(&root.0, "floor:path-read", "$PROJECT", "binding:floor");
    let denial =
      test_root(&root.0, "deny:path-read", "$PROJECT", "binding:deny");
    let floor_checked = checked_without_hops(
      &floor,
      Path::new("data/file"),
      OdenRev2FsFollowMode::FollowFinal,
    );
    let denial_checked = checked_without_hops(
      &denial,
      Path::new("data/file"),
      OdenRev2FsFollowMode::FollowFinal,
    );

    assert_eq!(
      floor_checked.lexical_fact().source_root().source_id(),
      "floor:path-read"
    );
    assert_eq!(
      denial_checked
        .identity_fact()
        .source_root()
        .root_binding_id(),
      "binding:deny"
    );
    assert_eq!(
      floor_checked.lexical_fact().relative_path(),
      Path::new("data/file")
    );
    let alias = floor_checked.object_alias_fact(&denial_checked).unwrap();
    assert!(alias.same_object());
    assert_ne!(
      alias.left().source_root().root_binding_id(),
      alias.right().source_root().root_binding_id()
    );
  }

  #[test]
  fn no_hop_checked_path_retains_and_requires_exact_operation_session() {
    let root = TempRoot::new("no-hop-session");
    std::fs::write(root.0.join("file"), b"data").unwrap();
    let authenticated =
      test_root(&root.0, "floor:path-read", "$PROJECT", "binding:project");
    let session = test_session("no-hop-right");
    let wrong_session = test_session("no-hop-wrong");
    let checked = checked_without_hops_for_session(
      &authenticated,
      &session,
      Path::new("file"),
      OdenRev2FsFollowMode::FollowFinal,
    );
    assert_eq!(checked.operation_session(), session.fact());
    assert!(matches!(
      checked.consume_for_metadata(&wrong_session),
      Err(OdenRev2FsError::OperationSessionMismatch)
    ));

    let checked = checked_without_hops_for_session(
      &authenticated,
      &session,
      Path::new("file"),
      OdenRev2FsFollowMode::FollowFinal,
    );
    assert_eq!(
      checked.consume_for_metadata(&session).unwrap().kind(),
      OdenRev2FsObjectKind::RegularFile
    );
  }

  #[test]
  fn metadata_race_hook_detects_replaced_normal_ancestor() {
    let root = TempRoot::new("consume-ancestor-replacement");
    std::fs::create_dir_all(root.0.join("ancestor/child")).unwrap();
    std::fs::write(root.0.join("ancestor/child/file"), b"old").unwrap();
    let authenticated =
      test_root(&root.0, "floor:path-list", "$PROJECT", "binding:project");
    let session = test_session("consume-ancestor-replacement");
    let checked = checked_without_hops_for_session(
      &authenticated,
      &session,
      Path::new("ancestor/child/file"),
      OdenRev2FsFollowMode::NoFollowFinal,
    );
    let mut replaced = false;
    let result = checked.consume_for_metadata_with_hook(
      &session,
      &mut |checkpoint, leaf| {
        if !replaced
          && checkpoint == OdenRev2FsUseCheckpoint::BeforeRetainedEdge
          && leaf == OsStr::new("ancestor")
        {
          std::fs::rename(
            root.0.join("ancestor"),
            root.0.join("displaced-ancestor"),
          )
          .unwrap();
          std::fs::create_dir(root.0.join("ancestor")).unwrap();
          replaced = true;
        }
      },
    );
    assert!(replaced);
    assert!(matches!(
      result,
      Err(OdenRev2FsError::ReplacementDuringResolution)
    ));
  }

  #[test]
  fn metadata_race_hook_detects_replaced_final_regular_file() {
    let root = TempRoot::new("consume-final-replacement");
    std::fs::write(root.0.join("file"), b"old").unwrap();
    let authenticated =
      test_root(&root.0, "floor:path-list", "$PROJECT", "binding:project");
    let session = test_session("consume-final-replacement");
    let checked = checked_without_hops_for_session(
      &authenticated,
      &session,
      Path::new("file"),
      OdenRev2FsFollowMode::NoFollowFinal,
    );
    let mut replaced = false;
    let result = checked.consume_for_metadata_with_hook(
      &session,
      &mut |checkpoint, leaf| {
        if !replaced
          && checkpoint == OdenRev2FsUseCheckpoint::BeforeRetainedEdge
          && leaf == OsStr::new("file")
        {
          std::fs::rename(root.0.join("file"), root.0.join("old-file"))
            .unwrap();
          std::fs::write(root.0.join("file"), b"new").unwrap();
          replaced = true;
        }
      },
    );
    assert!(replaced);
    assert!(matches!(
      result,
      Err(OdenRev2FsError::ReplacementDuringResolution)
    ));
  }

  #[test]
  fn proposal_race_hook_detects_missing_leaf_becoming_present() {
    let root = TempRoot::new("propose-missing-present");
    std::fs::create_dir(root.0.join("parent")).unwrap();
    let authenticated =
      test_root(&root.0, "floor:path-write", "$PROJECT", "binding:project");
    let session = test_session("propose-missing-present");
    let checked = checked_without_hops_for_session(
      &authenticated,
      &session,
      Path::new("parent/new"),
      OdenRev2FsFollowMode::NoFollowFinal,
    );
    let mut created = false;
    let result = checked.propose_child_with_hook(
      &session,
      OdenRev2FsProposedKind::RegularFile,
      &mut |checkpoint, leaf| {
        if !created
          && checkpoint == OdenRev2FsUseCheckpoint::BeforeMissingLeaf
          && leaf == OsStr::new("new")
        {
          std::fs::write(root.0.join("parent/new"), b"new").unwrap();
          created = true;
        }
      },
    );
    assert!(created);
    assert!(matches!(
      result,
      Err(OdenRev2FsError::ReplacementDuringResolution)
    ));
  }

  #[test]
  fn missing_child_proposal_revalidates_its_complete_ancestor_chain() {
    let root = TempRoot::new("propose-ancestor-replacement");
    std::fs::create_dir_all(root.0.join("ancestor/parent")).unwrap();
    let authenticated =
      test_root(&root.0, "floor:path-write", "$PROJECT", "binding:project");
    let session = test_session("propose-ancestor-replacement");
    let checked = checked_without_hops_for_session(
      &authenticated,
      &session,
      Path::new("ancestor/parent/new"),
      OdenRev2FsFollowMode::NoFollowFinal,
    );
    let mut replaced = false;
    let result = checked.propose_child_with_hook(
      &session,
      OdenRev2FsProposedKind::RegularFile,
      &mut |checkpoint, leaf| {
        if !replaced
          && checkpoint == OdenRev2FsUseCheckpoint::BeforeRetainedEdge
          && leaf == OsStr::new("ancestor")
        {
          std::fs::rename(
            root.0.join("ancestor"),
            root.0.join("displaced-ancestor"),
          )
          .unwrap();
          std::fs::create_dir(root.0.join("ancestor")).unwrap();
          replaced = true;
        }
      },
    );
    assert!(replaced);
    assert!(matches!(
      result,
      Err(OdenRev2FsError::ReplacementDuringResolution)
    ));
  }

  #[test]
  fn metadata_race_hook_detects_swapped_final_link() {
    use std::os::unix::fs::symlink;

    let root = TempRoot::new("consume-link-swap");
    std::fs::write(root.0.join("first"), b"first").unwrap();
    std::fs::write(root.0.join("second"), b"second").unwrap();
    symlink("first", root.0.join("alias")).unwrap();
    let authenticated =
      test_root(&root.0, "floor:path-list", "$PROJECT", "binding:project");
    let session = test_session("consume-link-swap");
    let checked = checked_without_hops_for_session(
      &authenticated,
      &session,
      Path::new("alias"),
      OdenRev2FsFollowMode::NoFollowFinal,
    );
    let mut replaced = false;
    let result = checked.consume_for_metadata_with_hook(
      &session,
      &mut |checkpoint, leaf| {
        if !replaced
          && checkpoint == OdenRev2FsUseCheckpoint::BeforeRetainedEdge
          && leaf == OsStr::new("alias")
        {
          std::fs::rename(root.0.join("alias"), root.0.join("old-alias"))
            .unwrap();
          symlink("second", root.0.join("alias")).unwrap();
          replaced = true;
        }
      },
    );
    assert!(replaced);
    assert!(matches!(
      result,
      Err(OdenRev2FsError::ReplacementDuringResolution)
    ));
  }

  #[test]
  fn final_symlink_stops_before_target_open_until_proof_is_consumed() {
    use std::os::unix::fs::symlink;

    let root = TempRoot::new("staged-final");
    std::fs::write(root.0.join("target"), b"data").unwrap();
    symlink("target", root.0.join("alias")).unwrap();
    let authenticated =
      test_root(&root.0, "floor:path-read", "$PROJECT", "binding:project");
    let session = test_session("staged-final");
    let pending = match authenticated
      .begin_resolution(
        &session,
        Path::new("alias"),
        OdenRev2FsFollowMode::FollowFinal,
      )
      .unwrap()
      .advance()
      .unwrap()
    {
      OdenRev2FsResolutionStep::AuthorizationRequired(pending) => pending,
      OdenRev2FsResolutionStep::Complete(_) => panic!("follow opened target"),
    };
    assert_eq!(pending.challenge().opaque_target(), Path::new("target"));
    std::fs::remove_file(root.0.join("target")).unwrap();
    let proof = test_hop_authorization(
      pending.challenge(),
      &session,
      &authenticated.source_root_fact(),
    );
    let checked = match pending.resume(proof).unwrap().advance().unwrap() {
      OdenRev2FsResolutionStep::Complete(checked) => checked,
      OdenRev2FsResolutionStep::AuthorizationRequired(_) => {
        panic!("one-hop target requested another proof")
      }
    };
    assert_eq!(checked.target_kind(), OdenRev2FsCheckedTargetKind::Missing);
    assert_eq!(checked.authorized_hops().len(), 1);
  }

  #[test]
  fn every_ancestor_symlink_requires_its_own_exact_proof() {
    use std::os::unix::fs::symlink;

    let root = TempRoot::new("staged-ancestor");
    std::fs::create_dir(root.0.join("real")).unwrap();
    std::fs::write(root.0.join("real/file"), b"data").unwrap();
    symlink("middle", root.0.join("first")).unwrap();
    symlink("real", root.0.join("middle")).unwrap();
    let authenticated =
      test_root(&root.0, "floor:path-read", "$PROJECT", "binding:project");
    let session = test_session("staged-ancestor");
    let first = match authenticated
      .begin_resolution(
        &session,
        Path::new("first/file"),
        OdenRev2FsFollowMode::FollowFinal,
      )
      .unwrap()
      .advance()
      .unwrap()
    {
      OdenRev2FsResolutionStep::AuthorizationRequired(pending) => pending,
      _ => panic!("first hop was not staged"),
    };
    let proof = test_hop_authorization(
      first.challenge(),
      &session,
      &authenticated.source_root_fact(),
    );
    let second = match first.resume(proof).unwrap().advance().unwrap() {
      OdenRev2FsResolutionStep::AuthorizationRequired(pending) => pending,
      _ => panic!("second hop was not staged"),
    };
    let proof = test_hop_authorization(
      second.challenge(),
      &session,
      &authenticated.source_root_fact(),
    );
    let checked = match second.resume(proof).unwrap().advance().unwrap() {
      OdenRev2FsResolutionStep::Complete(checked) => checked,
      _ => panic!("authorized target did not complete"),
    };
    assert_eq!(checked.authorized_hops().len(), 2);
    assert_eq!(checked.resolver_trace_path(), Path::new("real/file"));
  }

  #[test]
  fn consumed_challenge_proof_cannot_replay_against_another_discovery() {
    use std::os::unix::fs::symlink;

    let root = TempRoot::new("wrong-proof");
    std::fs::write(root.0.join("target"), b"data").unwrap();
    symlink("target", root.0.join("alias")).unwrap();
    let authenticated =
      test_root(&root.0, "floor:path-read", "$PROJECT", "binding:project");
    let session = test_session("wrong-proof");
    let pending_one = match authenticated
      .begin_resolution(
        &session,
        Path::new("alias"),
        OdenRev2FsFollowMode::FollowFinal,
      )
      .unwrap()
      .advance()
      .unwrap()
    {
      OdenRev2FsResolutionStep::AuthorizationRequired(pending) => pending,
      _ => unreachable!(),
    };
    let pending_two = match authenticated
      .begin_resolution(
        &session,
        Path::new("alias"),
        OdenRev2FsFollowMode::FollowFinal,
      )
      .unwrap()
      .advance()
      .unwrap()
    {
      OdenRev2FsResolutionStep::AuthorizationRequired(pending) => pending,
      _ => unreachable!(),
    };
    let accepted = test_hop_authorization(
      pending_one.challenge(),
      &session,
      &authenticated.source_root_fact(),
    );
    let replay = test_hop_authorization(
      pending_one.challenge(),
      &session,
      &authenticated.source_root_fact(),
    );
    pending_one.resume(accepted).unwrap();
    assert!(matches!(
      pending_two.resume(replay),
      Err(OdenRev2FsError::HopAuthorizationMismatch)
    ));
  }

  #[test]
  fn hop_proof_rejects_actor_or_generation_session_mismatch() {
    use std::os::unix::fs::symlink;

    let root = TempRoot::new("wrong-session");
    std::fs::write(root.0.join("target"), b"data").unwrap();
    symlink("target", root.0.join("alias")).unwrap();
    let authenticated =
      test_root(&root.0, "floor:path-read", "$PROJECT", "binding:project");
    let original = test_session_parts(
      "actor:package-a".to_string(),
      "generation:rows-7".to_string(),
    );
    let mismatched = test_session_parts(
      "actor:package-b".to_string(),
      "generation:rows-8".to_string(),
    );
    let pending = match authenticated
      .begin_resolution(
        &original,
        Path::new("alias"),
        OdenRev2FsFollowMode::FollowFinal,
      )
      .unwrap()
      .advance()
      .unwrap()
    {
      OdenRev2FsResolutionStep::AuthorizationRequired(pending) => pending,
      _ => unreachable!(),
    };
    assert_eq!(
      pending.challenge().operation_session().actor_identity(),
      "actor:package-a"
    );
    assert_eq!(
      pending
        .challenge()
        .operation_session()
        .generation_vector_token(),
      "generation:rows-7"
    );
    let wrong = test_hop_authorization(
      pending.challenge(),
      &mismatched,
      &authenticated.source_root_fact(),
    );
    assert!(matches!(
      pending.resume(wrong),
      Err(OdenRev2FsError::OperationSessionMismatch)
    ));
  }

  #[test]
  fn authenticated_root_transition_resumes_relative_and_absolute_link_escapes()
  {
    use std::os::unix::fs::symlink;

    let parent = TempRoot::new("continuation-transition");
    let source_path = parent.0.join("source");
    let destination_path = parent.0.join("destination");
    std::fs::create_dir(&source_path).unwrap();
    std::fs::create_dir(&destination_path).unwrap();
    std::fs::write(destination_path.join("file"), b"data").unwrap();
    symlink("../destination/file", source_path.join("relative")).unwrap();
    symlink(destination_path.join("file"), source_path.join("absolute"))
      .unwrap();
    let source =
      test_root(&source_path, "floor:source", "$PROJECT", "binding:source");
    let destination = test_root(
      &destination_path,
      "floor:destination",
      "$PACKAGE",
      "binding:destination",
    );

    for leaf in ["relative", "absolute"] {
      let session = test_session(leaf);
      let pending = match source
        .begin_resolution(
          &session,
          Path::new(leaf),
          OdenRev2FsFollowMode::FollowFinal,
        )
        .unwrap()
        .advance()
        .unwrap()
      {
        OdenRev2FsResolutionStep::AuthorizationRequired(pending) => pending,
        _ => panic!("cross-root link target was opened before authorization"),
      };
      let hop = test_hop_authorization(
        pending.challenge(),
        &session,
        &destination.source_root_fact(),
      );
      let transition = test_root_transition_authorization(
        pending.challenge(),
        &session,
        &source,
        &destination,
      )
      .unwrap();
      assert_eq!(
        transition.fact().to().root_binding_id(),
        "binding:destination"
      );
      let checked = match pending
        .resume_with_authenticated_root_transition(hop, transition)
        .unwrap()
        .advance()
        .unwrap()
      {
        OdenRev2FsResolutionStep::Complete(checked) => checked,
        _ => panic!("authorized cross-root target did not complete"),
      };
      assert_eq!(
        checked.identity_fact().source_root().root_binding_id(),
        "binding:destination"
      );
      assert_eq!(checked.resolver_trace_path(), Path::new("file"));
      assert!(checked.authorized_hops()[0].root_transition().is_some());
      assert_eq!(
        checked.authorized_hops()[0]
          .operation_session()
          .actor_identity(),
        format!("actor:{leaf}")
      );
    }
  }

  #[test]
  fn nested_hop_after_transition_challenges_against_current_root() {
    use std::os::unix::fs::symlink;

    let parent = TempRoot::new("transition-nested-hop");
    let source_path = parent.0.join("source");
    let destination_path = parent.0.join("destination");
    std::fs::create_dir(&source_path).unwrap();
    std::fs::create_dir(&destination_path).unwrap();
    std::fs::write(destination_path.join("file"), b"data").unwrap();
    symlink("file", destination_path.join("second")).unwrap();
    symlink("../destination/second", source_path.join("first")).unwrap();
    let source =
      test_root(&source_path, "floor:source", "$PROJECT", "binding:source");
    let destination = test_root(
      &destination_path,
      "floor:destination",
      "$PACKAGE",
      "binding:destination",
    );
    let session = test_session("transition-nested-hop");
    let first = match source
      .begin_resolution(
        &session,
        Path::new("first"),
        OdenRev2FsFollowMode::FollowFinal,
      )
      .unwrap()
      .advance()
      .unwrap()
    {
      OdenRev2FsResolutionStep::AuthorizationRequired(pending) => pending,
      _ => panic!("cross-root first hop was not staged"),
    };
    assert_eq!(
      first.challenge().source_root().root_binding_id(),
      "binding:source"
    );
    let first_hop = test_hop_authorization(
      first.challenge(),
      &session,
      &destination.source_root_fact(),
    );
    let transition = test_root_transition_authorization(
      first.challenge(),
      &session,
      &source,
      &destination,
    )
    .unwrap();
    let second = match first
      .resume_with_authenticated_root_transition(first_hop, transition)
      .unwrap()
      .advance()
      .unwrap()
    {
      OdenRev2FsResolutionStep::AuthorizationRequired(pending) => pending,
      _ => panic!("destination-root nested hop was not staged"),
    };
    assert_eq!(
      second.challenge().source_root().root_binding_id(),
      "binding:destination"
    );
    let second_hop = test_hop_authorization(
      second.challenge(),
      &session,
      &destination.source_root_fact(),
    );
    let checked = match second.resume(second_hop).unwrap().advance().unwrap() {
      OdenRev2FsResolutionStep::Complete(checked) => checked,
      _ => panic!("destination-root nested hop did not complete"),
    };
    assert_eq!(checked.authorized_hops().len(), 2);
    assert_eq!(
      checked.identity_fact().source_root().root_binding_id(),
      "binding:destination"
    );
    assert_eq!(checked.operation_session(), session.fact());
  }

  #[test]
  fn root_transition_proof_rejects_wrong_session_and_destination() {
    use std::os::unix::fs::symlink;

    let parent = TempRoot::new("transition-mismatch");
    let source_path = parent.0.join("source");
    let destination_path = parent.0.join("destination");
    let other_path = parent.0.join("other");
    std::fs::create_dir(&source_path).unwrap();
    std::fs::create_dir(&destination_path).unwrap();
    std::fs::create_dir(&other_path).unwrap();
    symlink("../destination/file", source_path.join("alias")).unwrap();
    symlink("../DESTINATION/file", source_path.join("alias-spelling")).unwrap();
    let source =
      test_root(&source_path, "floor:source", "$PROJECT", "binding:source");
    let destination = test_root(
      &destination_path,
      "floor:destination",
      "$PACKAGE",
      "binding:destination",
    );
    let other = test_root(&other_path, "floor:other", "$TMP", "binding:other");
    let session = test_session("transition-right");
    let wrong_session = test_session("transition-wrong");
    let pending = match source
      .begin_resolution(
        &session,
        Path::new("alias"),
        OdenRev2FsFollowMode::FollowFinal,
      )
      .unwrap()
      .advance()
      .unwrap()
    {
      OdenRev2FsResolutionStep::AuthorizationRequired(pending) => pending,
      _ => unreachable!(),
    };
    assert!(matches!(
      test_root_transition_authorization(
        pending.challenge(),
        &wrong_session,
        &source,
        &destination,
      ),
      Err(OdenRev2FsError::OperationSessionMismatch)
    ));
    assert!(matches!(
      test_root_transition_authorization(
        pending.challenge(),
        &session,
        &source,
        &other,
      ),
      Err(OdenRev2FsError::RootTransitionMismatch)
    ));

    // Even on a case-folded APFS volume, platform alias spelling is not a
    // transition proof. Only the exact retained destination spelling maps.
    let alias_spelling = match source
      .begin_resolution(
        &session,
        Path::new("alias-spelling"),
        OdenRev2FsFollowMode::FollowFinal,
      )
      .unwrap()
      .advance()
      .unwrap()
    {
      OdenRev2FsResolutionStep::AuthorizationRequired(pending) => pending,
      _ => unreachable!(),
    };
    assert!(matches!(
      test_root_transition_authorization(
        alias_spelling.challenge(),
        &session,
        &source,
        &destination,
      ),
      Err(OdenRev2FsError::RootTransitionMismatch)
    ));
  }

  #[test]
  fn link_replacement_and_root_escape_are_refused_at_resume() {
    use std::os::unix::fs::symlink;

    let parent = TempRoot::new("resume-refusal");
    let root_path = parent.0.join("root");
    std::fs::create_dir(&root_path).unwrap();
    std::fs::write(parent.0.join("outside"), b"outside").unwrap();
    symlink("target", root_path.join("replace")).unwrap();
    symlink("../outside", root_path.join("escape")).unwrap();
    let authenticated =
      test_root(&root_path, "floor:path-read", "$PROJECT", "binding:project");
    let session = test_session("resume-refusal");

    let replacement = match authenticated
      .begin_resolution(
        &session,
        Path::new("replace"),
        OdenRev2FsFollowMode::FollowFinal,
      )
      .unwrap()
      .advance()
      .unwrap()
    {
      OdenRev2FsResolutionStep::AuthorizationRequired(pending) => pending,
      _ => unreachable!(),
    };
    let proof = test_hop_authorization(
      replacement.challenge(),
      &session,
      &authenticated.source_root_fact(),
    );
    std::fs::remove_file(root_path.join("replace")).unwrap();
    symlink("other", root_path.join("replace")).unwrap();
    assert!(matches!(
      replacement.resume(proof),
      Err(OdenRev2FsError::ReplacementDuringResolution)
    ));

    let escape = match authenticated
      .begin_resolution(
        &session,
        Path::new("escape"),
        OdenRev2FsFollowMode::FollowFinal,
      )
      .unwrap()
      .advance()
      .unwrap()
    {
      OdenRev2FsResolutionStep::AuthorizationRequired(pending) => pending,
      _ => unreachable!(),
    };
    let proof = test_hop_authorization(
      escape.challenge(),
      &session,
      &authenticated.source_root_fact(),
    );
    assert!(matches!(
      escape.resume(proof),
      Err(OdenRev2FsError::RootEscape)
    ));
  }

  #[test]
  fn no_follow_link_retains_the_link_object_for_metadata() {
    use std::os::unix::fs::symlink;

    let root = TempRoot::new("nofollow");
    std::fs::write(root.0.join("target"), b"data").unwrap();
    symlink("target", root.0.join("alias")).unwrap();
    let authenticated =
      test_root(&root.0, "deny:path-read", "$PROJECT", "binding:deny");
    let session = test_session("nofollow-metadata");
    let checked = checked_without_hops_for_session(
      &authenticated,
      &session,
      Path::new("alias"),
      OdenRev2FsFollowMode::NoFollowFinal,
    );
    assert_eq!(
      checked.operation_support(OdenRev2FsOperation::NoFollowLinkAccess),
      OdenRev2FsOperationSupport::RetainedLinkObservation
    );
    assert_eq!(
      checked.no_follow_link().unwrap().target(),
      Path::new("target")
    );
    let observation = checked.consume_for_metadata(&session).unwrap();
    assert_eq!(observation.kind(), OdenRev2FsObjectKind::Symlink);
  }

  #[test]
  fn descriptor_root_revalidates_without_reopening_an_ambient_name() {
    let parent = TempRoot::new("descriptor-root");
    let path = parent.0.join("root");
    let moved = parent.0.join("moved");
    std::fs::create_dir(&path).unwrap();
    std::fs::write(path.join("entry"), b"retained").unwrap();
    let authenticated = test_descriptor_root(
      &path,
      "candidate:path-read",
      "$PROJECT",
      "binding:candidate",
    );

    std::fs::rename(&path, &moved).unwrap();
    std::fs::create_dir(&path).unwrap();
    authenticated.revalidate().unwrap();

    let session = test_session("descriptor-root");
    let checked = checked_without_hops_for_session(
      &authenticated,
      &session,
      Path::new("entry"),
      OdenRev2FsFollowMode::NoFollowFinal,
    );
    assert_eq!(
      checked.operation_support(OdenRev2FsOperation::ObserveMetadata),
      OdenRev2FsOperationSupport::RetainedObjectObservation
    );
  }

  #[test]
  fn root_replacement_is_detected_against_retained_identity() {
    let parent = TempRoot::new("root-replacement");
    let path = parent.0.join("root");
    let old = parent.0.join("old");
    std::fs::create_dir(&path).unwrap();
    let authenticated =
      test_root(&path, "floor:path-read", "$PROJECT", "binding:project");
    std::fs::rename(&path, &old).unwrap();
    std::fs::create_dir(&path).unwrap();
    assert!(matches!(
      authenticated.revalidate(),
      Err(OdenRev2FsError::RootReplacement)
    ));
  }

  #[test]
  fn root_transition_requires_exact_authenticated_directory_identity() {
    let root = TempRoot::new("root-transition");
    std::fs::create_dir(root.0.join("nested")).unwrap();
    std::fs::create_dir(root.0.join("other")).unwrap();
    let outer = test_root(&root.0, "floor:outer", "$PROJECT", "binding:outer");
    let inner = test_root(
      &root.0.join("nested"),
      "deny:inner",
      "$PACKAGE",
      "binding:inner",
    );
    let other = test_root(
      &root.0.join("other"),
      "deny:other",
      "$PACKAGE",
      "binding:other",
    );
    let checked = checked_without_hops(
      &outer,
      Path::new("nested"),
      OdenRev2FsFollowMode::NoFollowFinal,
    );
    let transition = outer.authenticate_transition(&checked, &inner).unwrap();
    assert_eq!(
      transition.relation(),
      OdenRev2FsRootTransitionKind::VerifiedDirectoryTransition
    );
    assert_eq!(transition.from().root_binding_id(), "binding:outer");
    assert_eq!(transition.to().root_binding_id(), "binding:inner");
    assert!(matches!(
      outer.authenticate_transition(&checked, &other),
      Err(OdenRev2FsError::RootTransitionMismatch)
    ));
  }

  #[test]
  fn missing_and_proposed_children_never_claim_safe_mutation() {
    let root = TempRoot::new("proposed");
    std::fs::create_dir(root.0.join("parent")).unwrap();
    let authenticated =
      test_root(&root.0, "floor:path-write", "$PROJECT", "binding:project");
    let session = test_session("proposed-child");
    let checked = checked_without_hops_for_session(
      &authenticated,
      &session,
      Path::new("parent/new"),
      OdenRev2FsFollowMode::NoFollowFinal,
    );
    assert_eq!(checked.missing().unwrap().leaf(), OsStr::new("new"));
    assert_eq!(
      checked.operation_support(OdenRev2FsOperation::CreateOrReplaceChild),
      OdenRev2FsOperationSupport::RequiresAtomicParentRelativeCommit
    );
    let wrong_session = test_session("proposed-child-wrong");
    assert!(matches!(
      checked
        .propose_child(&wrong_session, OdenRev2FsProposedKind::RegularFile),
      Err(OdenRev2FsError::OperationSessionMismatch)
    ));
    let checked = checked_without_hops_for_session(
      &authenticated,
      &session,
      Path::new("parent/new"),
      OdenRev2FsFollowMode::NoFollowFinal,
    );
    let proposed = checked
      .propose_child(&session, OdenRev2FsProposedKind::RegularFile)
      .unwrap();
    assert_eq!(
      proposed.operation_support(OdenRev2FsOperation::CreateOrReplaceChild),
      OdenRev2FsOperationSupport::RequiresAtomicParentRelativeCommit
    );
    assert!(matches!(
      proposed.operation_support(OdenRev2FsOperation::FollowedDataAccess),
      OdenRev2FsOperationSupport::Unsupported(_)
    ));
  }

  #[test]
  fn actor_inventory_rejects_request_target_and_source_substitution() {
    let root = TempRoot::new("actor-inventory-substitution");
    std::fs::create_dir(root.0.join("parent")).unwrap();
    let authenticated =
      test_root(&root.0, "floor:path-write", "$PROJECT", "binding:project");
    let session = test_session("actor-inventory-substitution");

    let omitted_target = checked_without_hops_for_session(
      &authenticated,
      &session,
      Path::new("parent/omitted"),
      OdenRev2FsFollowMode::NoFollowFinal,
    );
    let omitted_request = test_mkdir_request("stage:omitted", &omitted_target);
    assert!(matches!(
      OdenRev2FsActorInventory::seal(
        "operation:omitted",
        &omitted_request,
        &session,
        omitted_target,
        vec![],
      ),
      Err(OdenRev2FsError::InvalidBinding(
        "filesystem actor inventory has no checked source evidence"
      ))
    ));

    let request_target = checked_without_hops_for_session(
      &authenticated,
      &session,
      Path::new("parent/request-a"),
      OdenRev2FsFollowMode::NoFollowFinal,
    );
    let request = test_mkdir_request("stage:request-a", &request_target);
    let substituted_target = checked_without_hops_for_session(
      &authenticated,
      &session,
      Path::new("parent/target-b"),
      OdenRev2FsFollowMode::NoFollowFinal,
    );
    let substituted_source = checked_without_hops_for_session(
      &authenticated,
      &session,
      Path::new("parent/target-b"),
      OdenRev2FsFollowMode::NoFollowFinal,
    );
    let substituted_binding = expected_actor_path_binding(
      &substituted_source,
      substituted_target
        .lexical_fact()
        .source_root()
        .root_binding_id(),
    );
    let substituted_evidence = test_actor_source_evidence(
      substituted_binding,
      substituted_source,
      OdenRev2FsActorSourceClass::Floor,
      "fs:write",
      Path::new("parent/target-b"),
    );
    assert!(matches!(
      OdenRev2FsActorInventory::seal(
        "operation:target-substitution",
        &request,
        &session,
        substituted_target,
        vec![substituted_evidence],
      ),
      Err(OdenRev2FsError::InvalidBinding(
        "filesystem actor request occurrence does not match its checked target"
      ))
    ));
    drop(request_target);

    let binding_target = checked_without_hops_for_session(
      &authenticated,
      &session,
      Path::new("parent/binding"),
      OdenRev2FsFollowMode::NoFollowFinal,
    );
    let binding_source = checked_without_hops_for_session(
      &authenticated,
      &session,
      Path::new("parent/binding"),
      OdenRev2FsFollowMode::NoFollowFinal,
    );
    let binding_request = test_mkdir_request("stage:binding", &binding_target);
    let mut wrong_binding = expected_actor_path_binding(
      &binding_source,
      binding_target
        .lexical_fact()
        .source_root()
        .root_binding_id(),
    );
    wrong_binding.source_id = "source:substituted".to_string();
    let wrong_evidence = test_actor_source_evidence(
      wrong_binding,
      binding_source,
      OdenRev2FsActorSourceClass::Floor,
      "fs:write",
      Path::new("parent/binding"),
    );
    assert!(matches!(
      OdenRev2FsActorInventory::seal(
        "operation:binding-substitution",
        &binding_request,
        &session,
        binding_target,
        vec![wrong_evidence],
      ),
      Err(OdenRev2FsError::InvalidBinding(
        "filesystem source binding does not match its checked graph"
      ))
    ));

    let negative_target = checked_without_hops_for_session(
      &authenticated,
      &session,
      Path::new("parent/requested"),
      OdenRev2FsFollowMode::NoFollowFinal,
    );
    let negative_request =
      test_mkdir_request("stage:negative-substitution", &negative_target);
    let benign_source = checked_without_hops_for_session(
      &authenticated,
      &session,
      Path::new("parent/benign"),
      OdenRev2FsFollowMode::NoFollowFinal,
    );
    let benign_binding = expected_actor_path_binding(
      &benign_source,
      negative_target
        .lexical_fact()
        .source_root()
        .root_binding_id(),
    );
    let substituted_negative = test_actor_source_evidence(
      benign_binding,
      benign_source,
      OdenRev2FsActorSourceClass::Negative,
      "fs:write",
      Path::new("parent/denied"),
    );
    assert!(matches!(
      OdenRev2FsActorInventory::seal(
        "operation:negative-path-substitution",
        &negative_request,
        &session,
        negative_target,
        vec![substituted_negative],
      ),
      Err(OdenRev2FsError::InvalidBinding(
        "filesystem source checked path does not match its selector provenance"
      ))
    ));

    // A self-consistent fake source graph can pass sealing only with its own
    // fake provenance. The later exact policy projection must still reject a
    // same-source selector substitution from the real policy.
    let policy_authenticated = test_root(
      &root.0,
      "deny:policy-source",
      "$PROJECT",
      "binding:policy-project",
    );
    let policy_target = checked_without_hops_for_session(
      &policy_authenticated,
      &session,
      Path::new("parent/policy-requested"),
      OdenRev2FsFollowMode::NoFollowFinal,
    );
    let fake_source = checked_without_hops_for_session(
      &policy_authenticated,
      &session,
      Path::new("parent/policy-benign"),
      OdenRev2FsFollowMode::NoFollowFinal,
    );
    drop(policy_authenticated);
    let policy_request =
      test_mkdir_request("stage:policy-provenance", &policy_target);
    let fake_binding = expected_actor_path_binding(
      &fake_source,
      policy_target.lexical_fact().source_root().root_binding_id(),
    );
    let fake_evidence = test_actor_source_evidence(
      fake_binding,
      fake_source,
      OdenRev2FsActorSourceClass::Negative,
      "fs:write",
      Path::new("parent/policy-benign"),
    );
    let inventory = OdenRev2FsActorInventory::seal(
      "operation:policy-provenance",
      &policy_request,
      &session,
      policy_target,
      vec![fake_evidence],
    )
    .unwrap();
    let fake_policy = test_negative_policy(
      "deny:policy-source",
      test_actor_source_selector(
        "$PROJECT",
        "fs:write",
        Path::new("parent/policy-benign"),
      ),
      inventory.path_bindings().to_vec(),
    );
    assert!(inventory.binds_policy(&fake_policy));
    let real_policy = test_negative_policy(
      "deny:policy-source",
      test_actor_source_selector(
        "$PROJECT",
        "fs:write",
        Path::new("parent/policy-requested"),
      ),
      inventory.path_bindings().to_vec(),
    );
    assert!(!inventory.binds_policy(&real_policy));
  }

  #[test]
  fn actor_inventory_is_exact_stable_and_releasable_after_mkdir_prepare() {
    let root = TempRoot::new("actor-inventory-mkdir");
    std::fs::create_dir(root.0.join("parent")).unwrap();
    let externally_owned =
      test_root(&root.0, "floor:external", "$PROJECT", "binding:external");
    let external_session = test_session("actor-inventory-external");
    let external_target = checked_without_hops_for_session(
      &externally_owned,
      &external_session,
      Path::new("parent/new"),
      OdenRev2FsFollowMode::NoFollowFinal,
    );
    let external_source = checked_without_hops_for_session(
      &externally_owned,
      &external_session,
      Path::new("parent/new"),
      OdenRev2FsFollowMode::NoFollowFinal,
    );
    let external_request =
      test_mkdir_request("stage:external", &external_target);
    let external_binding = expected_actor_path_binding(
      &external_source,
      external_target
        .lexical_fact()
        .source_root()
        .root_binding_id(),
    );
    let external_evidence = test_actor_source_evidence(
      external_binding,
      external_source,
      OdenRev2FsActorSourceClass::Floor,
      "fs:write",
      Path::new("parent/new"),
    );
    assert!(matches!(
      OdenRev2FsActorInventory::seal(
        "operation:actor-inventory-external",
        &external_request,
        &external_session,
        external_target,
        vec![external_evidence],
      ),
      Err(OdenRev2FsError::InvalidBinding(
        "filesystem actor inventory has an external strong owner"
      ))
    ));
    drop(externally_owned);

    let authenticated =
      test_root(&root.0, "floor:path-write", "$PROJECT", "binding:project");
    let session = test_session("actor-inventory-mkdir");
    let target = checked_without_hops_for_session(
      &authenticated,
      &session,
      Path::new("parent/new"),
      OdenRev2FsFollowMode::NoFollowFinal,
    );
    let source = checked_without_hops_for_session(
      &authenticated,
      &session,
      Path::new("parent/new"),
      OdenRev2FsFollowMode::NoFollowFinal,
    );
    drop(authenticated);
    let request = test_mkdir_request("stage:actor-inventory-mkdir", &target);
    let source_binding = expected_actor_path_binding(
      &source,
      target.lexical_fact().source_root().root_binding_id(),
    );
    let source_evidence = test_actor_source_evidence(
      source_binding,
      source,
      OdenRev2FsActorSourceClass::Floor,
      "fs:write",
      Path::new("parent/new"),
    );
    let mut inventory = OdenRev2FsActorInventory::seal(
      "operation:actor-inventory-mkdir",
      &request,
      &session,
      target,
      vec![source_evidence],
    )
    .unwrap();
    assert!(inventory.binds(
      "operation:actor-inventory-mkdir",
      "actor:actor-inventory-mkdir"
    ));
    assert!(!inventory.binds("operation:wrong", "actor:actor-inventory-mkdir"));
    assert!(!inventory.binds("operation:actor-inventory-mkdir", "actor:wrong"));

    let sealed_ids = inventory.held_ids();
    let weak_handles = inventory.provisional_weak_handles();
    assert_eq!(
      sealed_ids.iter().collect::<BTreeSet<_>>().len(),
      sealed_ids.len()
    );
    assert_eq!(inventory.provisional_handle_count(), weak_handles.len());
    assert!(
      inventory.visited_handle_reference_count()
        > inventory.provisional_handle_count()
    );
    assert!(weak_handles.iter().all(|handle| handle.upgrade().is_some()));
    assert!(!inventory.completion_ready());

    let pending_witness = OdenRev2FilesystemPendingWitness::for_test();
    inventory.prepare_mkdir(&session, &pending_witness).unwrap();
    assert!(inventory.is_intact());
    assert!(!inventory.completion_ready());
    assert_eq!(inventory.held_ids(), sealed_ids);
    assert_eq!(
      inventory.target_kind().unwrap(),
      OdenRev2FsCheckedTargetKind::Proposed
    );

    assert_eq!(inventory.release_all(), sealed_ids);
    assert!(inventory.release_all().is_empty());
    assert!(weak_handles.iter().all(|handle| handle.upgrade().is_none()));
  }

  #[test]
  fn replacement_between_metadata_and_open_is_refused() {
    let root = TempRoot::new("stage-replacement");
    std::fs::write(root.0.join("victim"), b"old").unwrap();
    let authenticated =
      test_root(&root.0, "floor:path-read", "$PROJECT", "binding:project");
    let session = test_session("stage-replacement");
    let mut replaced = false;
    let result = authenticated
      .begin_resolution(
        &session,
        Path::new("victim"),
        OdenRev2FsFollowMode::FollowFinal,
      )
      .unwrap()
      .advance_with_hook(&mut |checkpoint, component| {
        if !replaced
          && checkpoint == OdenRev2FsResolveCheckpoint::AfterMetadata
          && component == OsStr::new("victim")
        {
          std::fs::rename(root.0.join("victim"), root.0.join("old")).unwrap();
          std::fs::write(root.0.join("victim"), b"new").unwrap();
          replaced = true;
        }
      });
    assert!(matches!(
      result,
      Err(OdenRev2FsError::ReplacementDuringResolution)
    ));
  }

  #[test]
  fn opaque_names_and_non_consuming_special_classification_survive() {
    use std::os::unix::ffi::OsStrExt;

    let root = TempRoot::new("opaque-special");
    #[cfg(target_os = "linux")]
    let name =
      OsString::from_vec(vec![b'o', b'p', b'a', b'q', b'u', b'e', 0xff]);
    #[cfg(target_os = "macos")]
    let name = OsString::from_vec(b"opaque-e\xcc\x81".to_vec());
    std::fs::write(root.0.join(&name), b"data").unwrap();
    let fifo = root.0.join("fifo");
    let fifo_path = cstring(fifo.as_os_str()).unwrap();
    // SAFETY: fifo_path is NUL-terminated and mkfifo does not retain it.
    assert_eq!(unsafe { libc::mkfifo(fifo_path.as_ptr(), 0o600) }, 0);
    let authenticated =
      test_root(&root.0, "floor:path-read", "$PROJECT", "binding:project");
    let opaque = checked_without_hops(
      &authenticated,
      Path::new(&name),
      OdenRev2FsFollowMode::FollowFinal,
    );
    assert_eq!(
      opaque.lexical_fact().relative_path().as_os_str().as_bytes(),
      name.as_os_str().as_bytes()
    );
    let fifo = checked_without_hops(
      &authenticated,
      Path::new("fifo"),
      OdenRev2FsFollowMode::FollowFinal,
    );
    assert_eq!(fifo.existing().unwrap().kind(), OdenRev2FsObjectKind::Fifo);
  }

  #[test]
  fn bounded_symlink_cycle_never_turns_into_monolithic_traversal() {
    use std::os::unix::fs::symlink;

    let root = TempRoot::new("cycle");
    symlink("b", root.0.join("a")).unwrap();
    symlink("a", root.0.join("b")).unwrap();
    let authenticated =
      test_root(&root.0, "floor:path-read", "$PROJECT", "binding:project");
    assert!(matches!(
      checked_with_authorized_hops(
        &authenticated,
        Path::new("a"),
        OdenRev2FsFollowMode::FollowFinal,
      ),
      Err(OdenRev2FsError::SymlinkLimit)
    ));
  }
}
