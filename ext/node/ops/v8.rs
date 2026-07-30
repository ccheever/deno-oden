// Copyright 2018-2026 the Deno authors. MIT license.

use std::borrow::Cow;
use std::cell::RefCell;
use std::collections::HashMap;
use std::ffi::c_void;
use std::io::Write as _;
use std::path::PathBuf;
use std::ptr::NonNull;
use std::rc::Rc;
use std::sync::atomic::AtomicBool;
#[cfg(test)]
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::time::Instant;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use deno_core::FastString;
use deno_core::GarbageCollected;
use deno_core::OpState;
use deno_core::convert::Uint8Array;
use deno_core::op2;
use deno_core::v8;
use deno_error::JsErrorBox;
use deno_permissions::PermissionsContainer;
use v8::ValueDeserializerHelper;
use v8::ValueSerializerHelper;

static EXPOSE_GC_FROM_SET_FLAGS: AtomicBool = AtomicBool::new(false);

// These mutation canaries are absent from production artifacts. They count
// actual native work only in deno_node's cfg(test) unit-test build.
#[cfg(test)]
static TAKE_HEAP_SNAPSHOT_CALL_COUNT: AtomicUsize = AtomicUsize::new(0);
#[cfg(test)]
static TAKE_HEAP_SNAPSHOT_CHUNK_COUNT: AtomicUsize = AtomicUsize::new(0);
#[cfg(test)]
static SET_FLAGS_WORK_COUNT: AtomicUsize = AtomicUsize::new(0);
#[cfg(test)]
static GET_HEAP_CODE_STATISTICS_WORK_COUNT: AtomicUsize = AtomicUsize::new(0);
#[cfg(test)]
static GET_HEAP_STATISTICS_WORK_COUNT: AtomicUsize = AtomicUsize::new(0);
#[cfg(test)]
static GET_HEAP_SPACE_STATISTICS_WORK_COUNT: AtomicUsize = AtomicUsize::new(0);
#[cfg(test)]
static QUERY_OBJECTS_SNAPSHOT_CHUNK_COUNT: AtomicUsize = AtomicUsize::new(0);
#[cfg(test)]
static NEAR_HEAP_LIMIT_CURRENT_DIR_COUNT: AtomicUsize = AtomicUsize::new(0);
#[cfg(test)]
static NEAR_HEAP_LIMIT_CHECK_WRITE_COUNT: AtomicUsize = AtomicUsize::new(0);
#[cfg(test)]
static NEAR_HEAP_LIMIT_CALLBACK_INSTALL_COUNT: AtomicUsize =
  AtomicUsize::new(0);
#[cfg(test)]
static GC_PROFILER_NEW_WORK_COUNT: AtomicUsize = AtomicUsize::new(0);
#[cfg(test)]
static GC_PROFILER_START_WORK_COUNT: AtomicUsize = AtomicUsize::new(0);
#[cfg(test)]
static GC_PROFILER_CALLBACK_INSTALL_COUNT: AtomicUsize = AtomicUsize::new(0);
#[cfg(test)]
static GC_PROFILER_STOP_WORK_COUNT: AtomicUsize = AtomicUsize::new(0);
#[cfg(test)]
static GC_PROFILER_ACTIVE_STATE_COUNT: AtomicUsize = AtomicUsize::new(0);

#[op2(fast)]
pub fn op_v8_cached_data_version_tag() -> u32 {
  v8::script_compiler::cached_data_version_tag()
}

#[op2(fast, stack_trace)]
pub fn op_v8_set_flags_from_string(
  #[string] flags: &str,
) -> Result<(), deno_permissions::PermissionCheckError> {
  // @ref LLP 0019#runtime-and-memory-inspection [implements]
  deno_permissions::oden_capsec_guard_deny_only_surface(
    "runtime",
    "inspect",
    "v8:set-flags",
    "node:v8.setFlagsFromString",
  )?;
  #[cfg(test)]
  SET_FLAGS_WORK_COUNT.fetch_add(1, Ordering::SeqCst);
  for flag in flags.split_ascii_whitespace() {
    match flag {
      "--expose_gc" | "--expose-gc" => {
        EXPOSE_GC_FROM_SET_FLAGS.store(true, Ordering::SeqCst);
      }
      "--noexpose_gc" | "--no-expose-gc" => {
        EXPOSE_GC_FROM_SET_FLAGS.store(false, Ordering::SeqCst);
      }
      _ => {}
    }
  }
  Ok(())
}

fn gc_callback(
  scope: &mut v8::PinScope,
  _args: v8::FunctionCallbackArguments,
  _rv: v8::ReturnValue,
) {
  scope.low_memory_notification();
}

pub fn install_gc_if_exposed<'s, 'i, T>(
  scope: &mut v8::PinScope<'s, 'i, T>,
  context: v8::Local<'s, v8::Context>,
) {
  if !EXPOSE_GC_FROM_SET_FLAGS.load(Ordering::SeqCst) {
    return;
  }

  let scope = &mut v8::ContextScope::new(scope, context);
  let global = context.global(scope);
  let key = v8::String::new_external_onebyte_static(scope, b"gc").unwrap();
  let template = v8::FunctionTemplate::new(scope, gc_callback);
  let function = template.get_function(scope).unwrap();
  function.set_name(key);
  global.set(scope, key.into(), function.into());
}

#[op2(fast)]
pub fn op_v8_get_heap_statistics(
  scope: &mut v8::PinScope<'_, '_>,
  #[buffer] buffer: &mut [f64],
) {
  #[cfg(test)]
  GET_HEAP_STATISTICS_WORK_COUNT.fetch_add(1, Ordering::SeqCst);
  let stats = scope.get_heap_statistics();

  buffer[0] = stats.total_heap_size() as f64;
  buffer[1] = stats.total_heap_size_executable() as f64;
  buffer[2] = stats.total_physical_size() as f64;
  buffer[3] = stats.total_available_size() as f64;
  buffer[4] = stats.used_heap_size() as f64;
  buffer[5] = stats.heap_size_limit() as f64;
  buffer[6] = stats.malloced_memory() as f64;
  buffer[7] = stats.peak_malloced_memory() as f64;
  buffer[8] = if stats.does_zap_garbage() { 1.0 } else { 0.0 };
  buffer[9] = stats.number_of_native_contexts() as f64;
  buffer[10] = stats.number_of_detached_contexts() as f64;
  buffer[11] = stats.total_global_handles_size() as f64;
  buffer[12] = stats.used_global_handles_size() as f64;
  buffer[13] = stats.external_memory() as f64;
  buffer[14] = stats.total_allocated_bytes() as f64;
}

#[op2(fast)]
#[smi]
pub fn op_v8_number_of_heap_spaces(scope: &mut v8::PinScope<'_, '_>) -> u32 {
  #[cfg(test)]
  GET_HEAP_SPACE_STATISTICS_WORK_COUNT.fetch_add(1, Ordering::SeqCst);
  scope.number_of_heap_spaces() as u32
}

#[op2]
#[string]
pub fn op_v8_update_heap_space_statistics(
  scope: &mut v8::PinScope<'_, '_>,
  #[buffer] buffer: &mut [f64],
  #[smi] space_index: u32,
) -> Option<String> {
  #[cfg(test)]
  GET_HEAP_SPACE_STATISTICS_WORK_COUNT.fetch_add(1, Ordering::SeqCst);
  let stats = scope.get_heap_space_statistics(space_index as usize)?;
  buffer[0] = stats.space_size() as f64;
  buffer[1] = stats.space_used_size() as f64;
  buffer[2] = stats.space_available_size() as f64;
  buffer[3] = stats.physical_space_size() as f64;
  Some(stats.space_name().to_string_lossy().into_owned())
}

#[op2(stack_trace)]
#[buffer]
pub fn op_v8_take_heap_snapshot(
  scope: &mut v8::PinScope<'_, '_>,
) -> Result<Vec<u8>, deno_permissions::PermissionCheckError> {
  deno_permissions::oden_capsec_guard_deny_only_surface(
    "runtime",
    "inspect",
    "v8:heap-snapshot",
    "node:v8.getHeapSnapshot/writeHeapSnapshot",
  )?;
  #[cfg(test)]
  TAKE_HEAP_SNAPSHOT_CALL_COUNT.fetch_add(1, Ordering::SeqCst);
  let mut buf = Vec::new();
  scope.take_heap_snapshot(|chunk| {
    #[cfg(test)]
    TAKE_HEAP_SNAPSHOT_CHUNK_COUNT.fetch_add(1, Ordering::SeqCst);
    buf.extend_from_slice(chunk);
    true
  });
  Ok(buf)
}

// --- setHeapSnapshotNearHeapLimit -----------------------------------------
//
// Implements `v8.setHeapSnapshotNearHeapLimit(limit)`. Installs a V8
// near-heap-limit callback that streams a `.heapsnapshot` file to disk (up to
// `limit` times) right before the process would OOM, mirroring Node's
// `Environment::NearHeapLimitCallback` (src/heap_utils.cc).

// State for the near-heap-limit snapshot callback. Leaked (never freed) so it
// outlives the isolate, which keeps the callback installed for the
// isolate/process lifetime.
struct HeapSnapshotNearHeapLimitState {
  // Raw isolate pointer captured at op-call time, used to take the snapshot
  // from within the extern "C" callback (which is not handed an isolate).
  isolate: v8::UnsafeRawIsolatePtr,
  limit: u32,
  taken: u32,
  // Reentrancy guard: taking a snapshot can trigger GC and re-enter the
  // callback; we must not recurse into another snapshot.
  processing: bool,
  dir: PathBuf,
  pid: u32,
  seq: u32,
}

// Howard Hinnant's civil-from-days algorithm: converts a count of days since
// the Unix epoch into a (year, month, day) tuple (UTC). Avoids pulling in a
// date/time dependency just to format the snapshot filename.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
  let z = z + 719468;
  let era = if z >= 0 { z } else { z - 146096 } / 146097;
  let doe = (z - era * 146097) as u64; // [0, 146096]
  let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365; // [0, 399]
  let y = yoe as i64 + era * 400;
  let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
  let mp = (5 * doy + 2) / 153; // [0, 11]
  let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
  let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
  let y = if m <= 2 { y + 1 } else { y };
  (y, m, d)
}

// Builds a filename matching Deno/Node's `writeHeapSnapshot` naming scheme:
// `Heap.<YYYYMMDD>.<HHMMSS>.<pid>.<threadId>.<seq(3 digits)>.heapsnapshot`.
//
// The thread id is hardcoded to 0, matching `writeHeapSnapshot` in v8.ts. In
// Node this slot is the worker's `threadId`, which isn't readily available to
// this native callback. As a result, two worker threads that OOM within the
// same second (each with its own `seq` starting at 0) can produce identical
// filenames and overwrite each other's snapshot. Plumbing the real `threadId`
// through would disambiguate them.
fn heap_snapshot_filename(pid: u32, seq: u32) -> String {
  let secs = SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .map(|d| d.as_secs())
    .unwrap_or_default();
  let days = (secs / 86400) as i64;
  let secs_of_day = secs % 86400;
  let (year, month, day) = civil_from_days(days);
  let hours = secs_of_day / 3600;
  let minutes = (secs_of_day % 3600) / 60;
  let seconds = secs_of_day % 60;
  format!(
    "Heap.{year:04}{month:02}{day:02}.{hours:02}{minutes:02}{seconds:02}.{pid}.0.{seq:03}.heapsnapshot"
  )
}

#[allow(
  clippy::print_stderr,
  reason = "Node prints the snapshot path to stderr unconditionally; \
   mirror that so the OOM diagnostic is always visible."
)]
extern "C" fn near_heap_limit_snapshot_callback(
  data: *mut c_void,
  current_heap_limit: usize,
  _initial_heap_limit: usize,
) -> usize {
  // SAFETY: `data` is the leaked `HeapSnapshotNearHeapLimitState` pointer
  // installed by `op_v8_set_heap_snapshot_near_heap_limit`. It outlives the
  // isolate, so this mutable reference is valid for the callback's duration
  // (V8 invokes near-heap-limit callbacks synchronously and non-concurrently).
  let state = unsafe { &mut *(data as *mut HeapSnapshotNearHeapLimitState) };

  // SAFETY: `state.isolate` was captured from the live isolate scope in the op
  // and the isolate is valid while this near-heap-limit callback runs. The
  // reconstructed `Isolate` is a non-owning handle (no Drop), used only for the
  // duration of this call.
  let mut isolate =
    unsafe { v8::Isolate::from_raw_isolate_ptr_unchecked(state.isolate) };

  // Give V8 headroom so it doesn't immediately OOM while we write the snapshot.
  // Mirrors Node returning `current_heap_limit + max_young_gen_size`: sum the
  // used size of the young-generation spaces.
  let mut young_headroom = 0usize;
  let nspaces = isolate.number_of_heap_spaces();
  for i in 0..nspaces {
    if let Some(s) = isolate.get_heap_space_statistics(i) {
      let name = s.space_name().to_string_lossy();
      if matches!(name.as_ref(), "new_space" | "new_large_object_space") {
        young_headroom = young_headroom.saturating_add(s.space_used_size());
      }
    }
  }
  // Guarantee a sane minimum floor so V8 has room to finish writing.
  const MIN_HEADROOM: usize = 4 * 1024 * 1024;
  let new_limit =
    current_heap_limit.saturating_add(young_headroom.max(MIN_HEADROOM));

  // Nested/reentrant call while a snapshot is being generated: give transient
  // room so V8 can finish writing without OOMing mid-snapshot.
  if state.processing {
    return new_limit;
  }
  // No more snapshots allowed: remove the callback and return the *unchanged*
  // heap limit so V8 proceeds to OOM normally. Mirrors Node, which removes its
  // callback and returns `current_heap_limit` once the budget is exhausted;
  // returning a raised limit here would let the heap grow unbounded and never
  // OOM.
  if state.taken >= state.limit {
    // SAFETY: removing the near-heap-limit callback from within the callback
    // is supported by V8 (Node does the same). Passing 0 leaves V8 to restore
    // the minimal viable limit for the current heap size.
    isolate
      .remove_near_heap_limit_callback(near_heap_limit_snapshot_callback, 0);
    return current_heap_limit;
  }

  state.processing = true;
  state.taken += 1;
  state.seq += 1;

  let filename = heap_snapshot_filename(state.pid, state.seq);
  let path = state.dir.join(&filename);

  match std::fs::File::create(&path) {
    Ok(file) => {
      log::info!("Writing heap snapshot to {}", path.display());
      let mut writer = std::io::BufWriter::new(file);
      let mut write_ok = true;
      // Stream chunks straight to disk instead of buffering the whole snapshot
      // in memory (which would OOM the very process we're trying to snapshot).
      isolate.take_heap_snapshot(|chunk| {
        if writer.write_all(chunk).is_err() {
          write_ok = false;
          return false;
        }
        true
      });
      if !write_ok || writer.flush().is_err() {
        log::error!("Failed to write heap snapshot to {}", path.display());
      }
    }
    Err(e) => {
      log::error!(
        "Failed to create heap snapshot file {}: {e}",
        path.display()
      );
    }
  }

  state.processing = false;
  new_limit
}

#[op2(nofast, stack_trace)]
pub fn op_v8_set_heap_snapshot_near_heap_limit(
  state: &mut OpState,
  scope: &mut v8::PinScope<'_, '_>,
  #[smi] limit: u32,
) -> Result<(), deno_permissions::PermissionCheckError> {
  deno_permissions::oden_capsec_guard_deny_only_surface(
    "runtime",
    "inspect",
    "v8:near-heap-limit-snapshot",
    "node:v8.setHeapSnapshotNearHeapLimit",
  )?;
  #[cfg(test)]
  NEAR_HEAP_LIMIT_CURRENT_DIR_COUNT.fetch_add(1, Ordering::SeqCst);
  let dir = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
  #[cfg(test)]
  NEAR_HEAP_LIMIT_CHECK_WRITE_COUNT.fetch_add(1, Ordering::SeqCst);
  let dir = state
    .borrow_mut::<PermissionsContainer>()
    .check_write(Cow::Owned(dir), "v8.setHeapSnapshotNearHeapLimit")?
    .into_owned_path();
  // SAFETY: capture the raw pointer of the current isolate so the extern "C"
  // callback (which is not passed an isolate) can take a snapshot. The isolate
  // outlives the callback, so the pointer stays valid whenever it runs.
  let isolate = unsafe { scope.as_raw_isolate_ptr() };
  let state = Box::new(HeapSnapshotNearHeapLimitState {
    isolate,
    limit,
    taken: 0,
    processing: false,
    dir,
    pid: std::process::id(),
    seq: 0,
  });
  // Leak the state so it outlives the isolate (see the struct doc comment).
  let data = Box::into_raw(state) as *mut c_void;
  scope.add_near_heap_limit_callback(near_heap_limit_snapshot_callback, data);
  #[cfg(test)]
  NEAR_HEAP_LIMIT_CALLBACK_INSTALL_COUNT.fetch_add(1, Ordering::SeqCst);
  Ok(())
}

// Walks the V8 heap snapshot and counts nodes that look like instances of a
// class whose constructor name matches `ctor_name`. Used by `util.queryObjects`
// / `v8.queryObjects` to implement `{ format: 'count' }` without exposing
// `HeapProfiler::QueryObjects` (which the rusty_v8 crate does not bind).
//
// Limitation: matches by the immediate constructor name only, so instances of
// subclasses of `ctor` won't be counted. This is sufficient for Node's leak
// tests (which check direct instances of `Channel`, `SourceTextModule`, ...).
#[op2(nofast, stack_trace)]
#[smi]
pub fn op_v8_query_objects_count(
  scope: &mut v8::PinScope<'_, '_>,
  #[string] ctor_name: &str,
) -> Result<u32, deno_permissions::PermissionCheckError> {
  deno_permissions::oden_capsec_guard_deny_only_surface(
    "runtime",
    "inspect",
    "v8:query-objects",
    "node:v8.queryObjects",
  )?;
  use deno_core::serde_json;
  use deno_core::serde_json::Value;

  let mut buf = Vec::new();
  scope.take_heap_snapshot(|chunk| {
    #[cfg(test)]
    QUERY_OBJECTS_SNAPSHOT_CHUNK_COUNT.fetch_add(1, Ordering::SeqCst);
    buf.extend_from_slice(chunk);
    true
  });
  if buf.is_empty() {
    return Ok(0);
  }

  let snapshot: Value = match serde_json::from_slice(&buf) {
    Ok(v) => v,
    Err(_) => return Ok(0),
  };

  let meta = match snapshot.get("snapshot").and_then(|s| s.get("meta")) {
    Some(m) => m,
    None => return Ok(0),
  };
  let node_fields = match meta.get("node_fields").and_then(|f| f.as_array()) {
    Some(a) => a,
    None => return Ok(0),
  };
  let node_field_count = node_fields.len();
  if node_field_count == 0 {
    return Ok(0);
  }
  let type_field_index = node_fields.iter().position(|f| f == "type");
  let name_field_index = node_fields.iter().position(|f| f == "name");
  let (Some(type_field_index), Some(name_field_index)) =
    (type_field_index, name_field_index)
  else {
    return Ok(0);
  };

  // `node_types` is an array where the entry at `type_field_index` is the
  // list of named type variants (the rest are scalars like "string"/"number").
  let object_type_index = match meta
    .get("node_types")
    .and_then(|t| t.as_array())
    .and_then(|t| t.get(type_field_index))
    .and_then(|t| t.as_array())
  {
    Some(types) => match types.iter().position(|t| t == "object") {
      Some(i) => i as u64,
      None => return Ok(0),
    },
    None => return Ok(0),
  };

  let nodes = match snapshot.get("nodes").and_then(|n| n.as_array()) {
    Some(a) => a,
    None => return Ok(0),
  };
  let strings = match snapshot.get("strings").and_then(|s| s.as_array()) {
    Some(a) => a,
    None => return Ok(0),
  };

  let mut count: u32 = 0;
  for chunk in nodes.chunks_exact(node_field_count) {
    let Some(ty) = chunk[type_field_index].as_u64() else {
      continue;
    };
    if ty != object_type_index {
      continue;
    }
    let Some(name_idx) = chunk[name_field_index].as_u64() else {
      continue;
    };
    let Some(name) = strings.get(name_idx as usize).and_then(|s| s.as_str())
    else {
      continue;
    };
    if name == ctor_name {
      count = count.saturating_add(1);
    }
  }
  Ok(count)
}

#[op2(fast)]
pub fn op_v8_get_heap_code_statistics(
  scope: &mut v8::PinScope<'_, '_>,
  #[buffer] buffer: &mut [f64],
) {
  #[cfg(test)]
  GET_HEAP_CODE_STATISTICS_WORK_COUNT.fetch_add(1, Ordering::SeqCst);
  if let Some(stats) = scope.get_heap_code_and_metadata_statistics() {
    buffer[0] = stats.code_and_metadata_size() as f64;
    buffer[1] = stats.bytecode_and_metadata_size() as f64;
    buffer[2] = stats.external_script_source_size() as f64;
    buffer[3] = stats.cpu_profiler_metadata_size() as f64;
  }
}

pub struct Serializer<'a> {
  delegate_state: Rc<SerializerDelegateState>,
  inner: v8::ValueSerializer<'a>,
}

struct SerializerDelegateState {
  obj: v8::TracedReference<v8::Object>,
}

pub struct SerializerDelegate {
  state: Rc<SerializerDelegateState>,
}

// SAFETY: we're sure this can be GCed
unsafe impl v8::cppgc::GarbageCollected for Serializer<'_> {
  fn trace(&self, visitor: &mut deno_core::v8::cppgc::Visitor) {
    visitor.trace(&self.delegate_state.obj);
  }

  fn get_name(&self) -> &'static std::ffi::CStr {
    c"Serializer"
  }
}

impl SerializerDelegate {
  fn obj<'s>(
    &self,
    scope: &mut v8::PinScope<'s, '_>,
  ) -> v8::Local<'s, v8::Object> {
    self.state.obj.get(scope).unwrap()
  }
}

impl v8::ValueSerializerImpl for SerializerDelegate {
  fn get_shared_array_buffer_id<'s>(
    &self,
    scope: &mut v8::PinScope<'s, '_>,
    shared_array_buffer: v8::Local<'s, v8::SharedArrayBuffer>,
  ) -> Option<u32> {
    let obj = self.obj(scope);
    let key = FastString::from_static("_getSharedArrayBufferId")
      .v8_string(scope)
      .unwrap()
      .into();
    if let Some(v) = obj.get(scope, key)
      && let Ok(fun) = v.try_cast::<v8::Function>()
    {
      return fun
        .call(scope, obj.into(), &[shared_array_buffer.into()])
        .and_then(|ret| ret.uint32_value(scope));
    }
    None
  }
  fn has_custom_host_object(&self, _isolate: &v8::Isolate) -> bool {
    false
  }
  fn throw_data_clone_error<'s>(
    &self,
    scope: &mut v8::PinScope<'s, '_>,
    message: v8::Local<'s, v8::String>,
  ) {
    let obj = self.obj(scope);
    let key = FastString::from_static("_getDataCloneError")
      .v8_string(scope)
      .unwrap()
      .into();
    if let Some(v) = obj.get(scope, key) {
      let fun = v
        .try_cast::<v8::Function>()
        .expect("_getDataCloneError should be a function");
      if let Some(error) = fun.call(scope, obj.into(), &[message.into()]) {
        scope.throw_exception(error);
        return;
      }
    }
    let error = v8::Exception::type_error(scope, message);
    scope.throw_exception(error);
  }

  fn write_host_object<'s>(
    &self,
    scope: &mut v8::PinScope<'s, '_>,
    object: v8::Local<'s, v8::Object>,
    _value_serializer: &dyn ValueSerializerHelper,
  ) -> Option<bool> {
    let obj = self.obj(scope);
    let key = FastString::from_static("_writeHostObject")
      .v8_string(scope)
      .unwrap()
      .into();
    if let Some(v) = obj.get(scope, key)
      && let Ok(v) = v.try_cast::<v8::Function>()
    {
      v.call(scope, obj.into(), &[object.into()])?;
      return Some(true);
    }

    None
  }

  fn is_host_object<'s>(
    &self,
    _scope: &mut v8::PinScope<'s, '_>,
    _object: v8::Local<'s, v8::Object>,
  ) -> Option<bool> {
    // should never be called because has_custom_host_object returns false
    None
  }
}

#[op2]
#[cppgc]
pub fn op_v8_new_serializer(
  scope: &mut v8::PinScope<'_, '_>,
  obj: v8::Local<v8::Object>,
) -> Serializer<'static> {
  let delegate_state = Rc::new(SerializerDelegateState {
    obj: v8::TracedReference::new(scope, obj),
  });
  let inner = v8::ValueSerializer::new(
    scope,
    Box::new(SerializerDelegate {
      state: delegate_state.clone(),
    }),
  );
  Serializer {
    inner,
    delegate_state,
  }
}

#[op2(fast)]
pub fn op_v8_set_treat_array_buffer_views_as_host_objects(
  #[cppgc] ser: &Serializer,
  value: bool,
) {
  ser
    .inner
    .set_treat_array_buffer_views_as_host_objects(value);
}

#[op2]
pub fn op_v8_release_buffer(#[cppgc] ser: &Serializer) -> Uint8Array {
  ser.inner.release().into()
}

#[op2(fast)]
pub fn op_v8_transfer_array_buffer(
  #[cppgc] ser: &Serializer,
  #[smi] id: u32,
  array_buffer: v8::Local<v8::ArrayBuffer>,
) {
  ser.inner.transfer_array_buffer(id, array_buffer);
}

#[op2(fast)]
pub fn op_v8_write_double(#[cppgc] ser: &Serializer, double: f64) {
  ser.inner.write_double(double);
}

#[op2(fast)]
pub fn op_v8_write_header(#[cppgc] ser: &Serializer) {
  ser.inner.write_header();
}

#[op2]
pub fn op_v8_write_raw_bytes(
  #[cppgc] ser: &Serializer,
  #[anybuffer] source: &[u8],
) {
  ser.inner.write_raw_bytes(source);
}

#[op2(fast)]
pub fn op_v8_write_uint32(#[cppgc] ser: &Serializer, num: u32) {
  ser.inner.write_uint32(num);
}

#[op2(fast)]
pub fn op_v8_write_uint64(#[cppgc] ser: &Serializer, hi: u32, lo: u32) {
  let num = ((hi as u64) << 32) | (lo as u64);
  ser.inner.write_uint64(num);
}

#[op2(nofast, reentrant)]
pub fn op_v8_write_value(
  scope: &mut v8::PinScope<'_, '_>,
  #[cppgc] ser: &Serializer,
  value: v8::Local<v8::Value>,
) {
  let context = scope.get_current_context();
  ser.inner.write_value(context, value);
}

struct DeserBuffer {
  ptr: Option<NonNull<u8>>,
  // Hold onto backing store to keep the underlying buffer
  // alive while we hold a reference to it.
  _backing_store: v8::SharedRef<v8::BackingStore>,
}

pub struct Deserializer<'a> {
  buf: DeserBuffer,
  delegate_state: Rc<DeserializerDelegateState>,
  inner: v8::ValueDeserializer<'a>,
}

// SAFETY: we're sure this can be GCed
unsafe impl deno_core::GarbageCollected for Deserializer<'_> {
  fn trace(&self, visitor: &mut deno_core::v8::cppgc::Visitor) {
    visitor.trace(&self.delegate_state.obj);
  }

  fn get_name(&self) -> &'static std::ffi::CStr {
    c"Deserializer"
  }
}

struct DeserializerDelegateState {
  obj: v8::TracedReference<v8::Object>,
}

pub struct DeserializerDelegate {
  state: Rc<DeserializerDelegateState>,
}

impl v8::ValueDeserializerImpl for DeserializerDelegate {
  fn read_host_object<'s>(
    &self,
    scope: &mut v8::PinScope<'s, '_>,
    _value_deserializer: &dyn v8::ValueDeserializerHelper,
  ) -> Option<v8::Local<'s, v8::Object>> {
    let obj = self.state.obj.get(scope).unwrap();
    let key = FastString::from_static("_readHostObject")
      .v8_string(scope)
      .unwrap()
      .into();
    let scope = std::pin::pin!(v8::AllowJavascriptExecutionScope::new(scope));
    let scope = &mut scope.init();
    if let Some(v) = obj.get(scope, key)
      && let Ok(v) = v.try_cast::<v8::Function>()
    {
      let result = v.call(scope, obj.into(), &[])?;
      match result.try_cast() {
        Ok(res) => return Some(res),
        Err(_) => {
          let msg =
            FastString::from_static("readHostObject must return an object")
              .v8_string(scope)
              .unwrap();
          let error = v8::Exception::type_error(scope, msg);
          scope.throw_exception(error);
          return None;
        }
      }
    }
    None
  }
}

#[op2]
#[cppgc]
pub fn op_v8_new_deserializer(
  scope: &mut v8::PinScope<'_, '_>,
  obj: v8::Local<v8::Object>,
  buffer: v8::Local<v8::ArrayBufferView>,
) -> Result<Deserializer<'static>, JsErrorBox> {
  let offset = buffer.byte_offset();
  let len = buffer.byte_length();
  let backing_store = buffer.get_backing_store().ok_or_else(|| {
    JsErrorBox::generic("deserialization buffer has no backing store")
  })?;
  let (buf_slice, buf_ptr) = if let Some(data) = backing_store.data() {
    // SAFETY: the offset is valid for the underlying buffer because we're getting it directly from v8
    let data_ptr = unsafe { data.as_ptr().cast::<u8>().add(offset) };
    (
      // SAFETY: the len is valid, from v8, and the data_ptr is valid (as above)
      unsafe { std::slice::from_raw_parts(data_ptr.cast_const().cast(), len) },
      Some(data.cast()),
    )
  } else {
    (&[] as &[u8], None::<NonNull<u8>>)
  };
  let delegate_state = Rc::new(DeserializerDelegateState {
    obj: v8::TracedReference::new(scope, obj),
  });
  let inner = v8::ValueDeserializer::new(
    scope,
    Box::new(DeserializerDelegate {
      state: delegate_state.clone(),
    }),
    buf_slice,
  );
  Ok(Deserializer {
    inner,
    delegate_state,
    buf: DeserBuffer {
      _backing_store: backing_store,
      ptr: buf_ptr,
    },
  })
}

#[op2(fast)]
pub fn op_v8_transfer_array_buffer_de(
  #[cppgc] deser: &Deserializer,
  #[smi] id: u32,
  array_buffer: v8::Local<v8::Value>,
) -> Result<(), deno_core::error::DataError> {
  if let Ok(shared_array_buffer) =
    array_buffer.try_cast::<v8::SharedArrayBuffer>()
  {
    deser
      .inner
      .transfer_shared_array_buffer(id, shared_array_buffer)
  }
  let array_buffer = array_buffer.try_cast::<v8::ArrayBuffer>()?;
  deser.inner.transfer_array_buffer(id, array_buffer);
  Ok(())
}

#[op2(fast)]
pub fn op_v8_read_double(
  #[cppgc] deser: &Deserializer,
) -> Result<f64, JsErrorBox> {
  let mut double = 0f64;
  if !deser.inner.read_double(&mut double) {
    return Err(JsErrorBox::type_error("ReadDouble() failed"));
  }
  Ok(double)
}

#[op2(nofast)]
pub fn op_v8_read_header(
  scope: &mut v8::PinScope<'_, '_>,
  #[cppgc] deser: &Deserializer,
) -> bool {
  let context = scope.get_current_context();
  let res = deser.inner.read_header(context);
  res.unwrap_or_default()
}

#[op2(fast)]
#[number]
pub fn op_v8_read_raw_bytes(
  #[cppgc] deser: &Deserializer,
  #[number] length: usize,
) -> usize {
  let Some(buf_ptr) = deser.buf.ptr else {
    return 0;
  };
  if let Some(buf) = deser.inner.read_raw_bytes(length) {
    let ptr = buf.as_ptr();
    (ptr as usize) - (buf_ptr.as_ptr() as usize)
  } else {
    0
  }
}

#[op2(fast)]
pub fn op_v8_read_uint32(
  #[cppgc] deser: &Deserializer,
) -> Result<u32, JsErrorBox> {
  let mut value = 0;
  if !deser.inner.read_uint32(&mut value) {
    return Err(JsErrorBox::type_error("ReadUint32() failed"));
  }

  Ok(value)
}

#[op2]
pub fn op_v8_read_uint64(
  #[cppgc] deser: &Deserializer,
) -> Result<(u32, u32), JsErrorBox> {
  let mut val = 0;
  if !deser.inner.read_uint64(&mut val) {
    return Err(JsErrorBox::type_error("ReadUint64() failed"));
  }

  Ok(((val >> 32) as u32, val as u32))
}

#[op2(fast)]
pub fn op_v8_get_wire_format_version(#[cppgc] deser: &Deserializer) -> u32 {
  deser.inner.get_wire_format_version()
}

#[op2(reentrant)]
pub fn op_v8_read_value<'s>(
  scope: &mut v8::PinScope<'s, '_>,
  #[cppgc] deser: &Deserializer,
) -> v8::Local<'s, v8::Value> {
  let context = scope.get_current_context();
  let val = deser.inner.read_value(context);
  val.unwrap_or_else(|| v8::null(scope).into())
}

// --- GCProfiler -----------------------------------------------------------
//
// Implements `v8.GCProfiler`, a thin per-instance recorder that hooks the
// V8 GC prologue/epilogue callbacks. Each active profiler captures heap and
// heap-space statistics on every GC and records the wall-clock cost.

#[derive(Default)]
struct GcProfilerRegistryInner {
  next_id: u64,
  // Profilers that have been started but not yet stopped.
  profilers: HashMap<u64, GcProfilerState>,
  callbacks_registered: bool,
}

struct GcProfilerRegistry {
  inner: Rc<RefCell<GcProfilerRegistryInner>>,
}

struct GcProfilerState {
  pending_before: Option<GcSnapshot>,
  pending_start: Option<Instant>,
  statistics: Vec<GcStat>,
}

#[derive(Clone)]
struct GcSnapshot {
  // total_heap_size, total_heap_size_executable, total_physical_size,
  // total_available_size, used_heap_size, heap_size_limit,
  // malloced_memory, peak_malloced_memory,
  // total_global_handles_size, used_global_handles_size, external_memory.
  heap: [f64; 11],
  spaces: Vec<HeapSpaceSnapshot>,
}

#[derive(Clone)]
struct HeapSpaceSnapshot {
  name: String,
  size: f64,
  used_size: f64,
  available_size: f64,
  physical_size: f64,
}

struct GcStat {
  gc_type: &'static str,
  // Cost in nanoseconds (matches Node.js).
  cost_ns: f64,
  before: GcSnapshot,
  after: GcSnapshot,
}

fn gc_type_name(gc_type: v8::GCType) -> &'static str {
  // V8 callbacks may surface combined flags (e.g. kGCTypeIncrementalMarking |
  // kGCTypeMarkSweepCompact). Pick the lowest-priority single bit so the
  // returned label is stable and informative.
  match gc_type {
    v8::GCType::kGCTypeScavenge => "Scavenge",
    v8::GCType::kGCTypeMinorMarkSweep => "MinorMarkSweep",
    v8::GCType::kGCTypeMarkSweepCompact => "MarkSweepCompact",
    v8::GCType::kGCTypeIncrementalMarking => "IncrementalMarking",
    v8::GCType::kGCTypeProcessWeakCallbacks => "ProcessWeakCallbacks",
    v8::GCType::kGCTypeAll => "All",
    _ => "Unknown",
  }
}

fn capture_snapshot(isolate: &mut v8::Isolate) -> GcSnapshot {
  let h = isolate.get_heap_statistics();
  let heap = [
    h.total_heap_size() as f64,
    h.total_heap_size_executable() as f64,
    h.total_physical_size() as f64,
    h.total_available_size() as f64,
    h.used_heap_size() as f64,
    h.heap_size_limit() as f64,
    h.malloced_memory() as f64,
    h.peak_malloced_memory() as f64,
    h.total_global_handles_size() as f64,
    h.used_global_handles_size() as f64,
    h.external_memory() as f64,
  ];
  let nspaces = isolate.number_of_heap_spaces();
  let mut spaces = Vec::with_capacity(nspaces);
  for i in 0..nspaces {
    if let Some(s) = isolate.get_heap_space_statistics(i) {
      spaces.push(HeapSpaceSnapshot {
        name: s.space_name().to_string_lossy().into_owned(),
        size: s.space_size() as f64,
        used_size: s.space_used_size() as f64,
        available_size: s.space_available_size() as f64,
        physical_size: s.physical_space_size() as f64,
      });
    }
  }
  GcSnapshot { heap, spaces }
}

fn registry_rc(
  isolate: &v8::Isolate,
) -> Option<Rc<RefCell<GcProfilerRegistryInner>>> {
  isolate
    .get_slot::<GcProfilerRegistry>()
    .map(|r| r.inner.clone())
}

extern "C" fn gc_prologue_callback(
  isolate: v8::UnsafeRawIsolatePtr,
  _gc_type: v8::GCType,
  _flags: v8::GCCallbackFlags,
  _data: *mut c_void,
) {
  // SAFETY: V8 guarantees the isolate is valid during this callback.
  let mut isolate =
    unsafe { v8::Isolate::from_raw_isolate_ptr_unchecked(isolate) };
  let Some(rc) = registry_rc(&isolate) else {
    return;
  };
  // Bail out fast if no profilers are active so we don't capture heap
  // statistics on every GC unnecessarily.
  if rc.borrow().profilers.is_empty() {
    return;
  }
  let snapshot = capture_snapshot(&mut isolate);
  let now = Instant::now();
  let mut inner = rc.borrow_mut();
  for state in inner.profilers.values_mut() {
    state.pending_before = Some(snapshot.clone());
    state.pending_start = Some(now);
  }
}

extern "C" fn gc_epilogue_callback(
  isolate: v8::UnsafeRawIsolatePtr,
  gc_type: v8::GCType,
  _flags: v8::GCCallbackFlags,
  _data: *mut c_void,
) {
  // SAFETY: V8 guarantees the isolate is valid during this callback.
  let mut isolate =
    unsafe { v8::Isolate::from_raw_isolate_ptr_unchecked(isolate) };
  let Some(rc) = registry_rc(&isolate) else {
    return;
  };
  if rc.borrow().profilers.is_empty() {
    return;
  }
  let snapshot = capture_snapshot(&mut isolate);
  let now = Instant::now();
  let gc_type_str = gc_type_name(gc_type);
  let mut inner = rc.borrow_mut();
  for state in inner.profilers.values_mut() {
    let (Some(before), Some(start)) =
      (state.pending_before.take(), state.pending_start.take())
    else {
      continue;
    };
    let cost_ns = now.saturating_duration_since(start).as_nanos() as f64;
    state.statistics.push(GcStat {
      gc_type: gc_type_str,
      cost_ns,
      before,
      after: snapshot.clone(),
    });
  }
}

fn ensure_registry(
  scope: &mut v8::PinScope<'_, '_>,
) -> Rc<RefCell<GcProfilerRegistryInner>> {
  if let Some(existing) = scope.get_slot::<GcProfilerRegistry>() {
    return existing.inner.clone();
  }
  let inner = Rc::new(RefCell::new(GcProfilerRegistryInner::default()));
  scope.set_slot(GcProfilerRegistry {
    inner: inner.clone(),
  });
  inner
}

fn ensure_callbacks_registered(
  scope: &mut v8::PinScope<'_, '_>,
  inner: &Rc<RefCell<GcProfilerRegistryInner>>,
) {
  if inner.borrow().callbacks_registered {
    return;
  }
  scope.add_gc_prologue_callback(
    gc_prologue_callback,
    std::ptr::null_mut(),
    v8::GCType::kGCTypeAll,
  );
  scope.add_gc_epilogue_callback(
    gc_epilogue_callback,
    std::ptr::null_mut(),
    v8::GCType::kGCTypeAll,
  );
  inner.borrow_mut().callbacks_registered = true;
  #[cfg(test)]
  GC_PROFILER_CALLBACK_INSTALL_COUNT.fetch_add(1, Ordering::SeqCst);
}

pub struct GcProfilerHandle {
  id: std::cell::Cell<Option<u64>>,
}

// SAFETY: GcProfilerHandle has no traceable references.
unsafe impl GarbageCollected for GcProfilerHandle {
  fn trace(&self, _visitor: &mut v8::cppgc::Visitor) {}

  fn get_name(&self) -> &'static std::ffi::CStr {
    c"GcProfilerHandle"
  }
}

#[op2(stack_trace)]
#[cppgc]
pub fn op_v8_gc_profiler_new()
-> Result<GcProfilerHandle, deno_permissions::PermissionCheckError> {
  deno_permissions::oden_capsec_guard_deny_only_surface(
    "runtime",
    "inspect",
    "v8:gc-profiler",
    "node:v8.GCProfiler",
  )?;
  #[cfg(test)]
  GC_PROFILER_NEW_WORK_COUNT.fetch_add(1, Ordering::SeqCst);
  Ok(GcProfilerHandle {
    id: std::cell::Cell::new(None),
  })
}

#[op2(fast, stack_trace)]
pub fn op_v8_gc_profiler_start(
  scope: &mut v8::PinScope<'_, '_>,
  #[cppgc] handle: &GcProfilerHandle,
) -> Result<(), deno_permissions::PermissionCheckError> {
  deno_permissions::oden_capsec_guard_deny_only_surface(
    "runtime",
    "inspect",
    "v8:gc-profiler-start",
    "node:v8.GCProfiler.start",
  )?;
  if handle.id.get().is_some() {
    return Ok(());
  }
  #[cfg(test)]
  GC_PROFILER_START_WORK_COUNT.fetch_add(1, Ordering::SeqCst);
  let inner = ensure_registry(scope);
  ensure_callbacks_registered(scope, &inner);
  let id = {
    let mut borrow = inner.borrow_mut();
    let id = borrow.next_id;
    borrow.next_id = borrow.next_id.wrapping_add(1);
    borrow.profilers.insert(
      id,
      GcProfilerState {
        pending_before: None,
        pending_start: None,
        statistics: Vec::new(),
      },
    );
    id
  };
  handle.id.set(Some(id));
  #[cfg(test)]
  GC_PROFILER_ACTIVE_STATE_COUNT.fetch_add(1, Ordering::SeqCst);
  Ok(())
}

#[op2(stack_trace)]
pub fn op_v8_gc_profiler_stop<'s>(
  scope: &mut v8::PinScope<'s, '_>,
  #[cppgc] handle: &GcProfilerHandle,
) -> Result<v8::Local<'s, v8::Value>, deno_permissions::PermissionCheckError> {
  deno_permissions::oden_capsec_guard_deny_only_surface(
    "runtime",
    "inspect",
    "v8:gc-profiler-stop",
    "node:v8.GCProfiler.stop",
  )?;
  #[cfg(test)]
  GC_PROFILER_STOP_WORK_COUNT.fetch_add(1, Ordering::SeqCst);
  let Some(id) = handle.id.take() else {
    return Ok(v8::null(scope).into());
  };
  let Some(inner) = scope
    .get_slot::<GcProfilerRegistry>()
    .map(|r| r.inner.clone())
  else {
    return Ok(v8::null(scope).into());
  };
  let state = inner.borrow_mut().profilers.remove(&id);
  let Some(state) = state else {
    return Ok(v8::null(scope).into());
  };
  #[cfg(test)]
  GC_PROFILER_ACTIVE_STATE_COUNT.fetch_sub(1, Ordering::SeqCst);
  Ok(build_report(scope, &state.statistics).into())
}

const HEAP_KEYS: &[&str] = &[
  "totalHeapSize",
  "totalHeapSizeExecutable",
  "totalPhysicalSize",
  "totalAvailableSize",
  "usedHeapSize",
  "heapSizeLimit",
  "mallocedMemory",
  "peakMallocedMemory",
  "totalGlobalHandlesSize",
  "usedGlobalHandlesSize",
  "externalMemory",
];

fn build_snapshot<'s>(
  scope: &mut v8::PinScope<'s, '_>,
  snap: &GcSnapshot,
) -> v8::Local<'s, v8::Object> {
  let obj = v8::Object::new(scope);

  let heap_stats = v8::Object::new(scope);
  for (i, key) in HEAP_KEYS.iter().enumerate() {
    let k = v8::String::new(scope, key).unwrap();
    let v = v8::Number::new(scope, snap.heap[i]);
    heap_stats.set(scope, k.into(), v.into());
  }
  let k = v8::String::new(scope, "heapStatistics").unwrap();
  obj.set(scope, k.into(), heap_stats.into());

  let spaces_array = v8::Array::new(scope, snap.spaces.len() as i32);
  for (i, space) in snap.spaces.iter().enumerate() {
    let space_obj = v8::Object::new(scope);
    let k = v8::String::new(scope, "spaceName").unwrap();
    let name = v8::String::new(scope, &space.name).unwrap();
    space_obj.set(scope, k.into(), name.into());
    for (name, value) in [
      ("spaceSize", space.size),
      ("spaceUsedSize", space.used_size),
      ("spaceAvailableSize", space.available_size),
      ("physicalSpaceSize", space.physical_size),
    ] {
      let k = v8::String::new(scope, name).unwrap();
      let v = v8::Number::new(scope, value);
      space_obj.set(scope, k.into(), v.into());
    }
    spaces_array.set_index(scope, i as u32, space_obj.into());
  }
  let k = v8::String::new(scope, "heapSpaceStatistics").unwrap();
  obj.set(scope, k.into(), spaces_array.into());

  obj
}

fn build_report<'s>(
  scope: &mut v8::PinScope<'s, '_>,
  stats: &[GcStat],
) -> v8::Local<'s, v8::Object> {
  let arr = v8::Array::new(scope, stats.len() as i32);
  for (i, stat) in stats.iter().enumerate() {
    let entry = v8::Object::new(scope);

    let k = v8::String::new(scope, "gcType").unwrap();
    let v = v8::String::new(scope, stat.gc_type).unwrap();
    entry.set(scope, k.into(), v.into());

    let k = v8::String::new(scope, "cost").unwrap();
    let v = v8::Number::new(scope, stat.cost_ns);
    entry.set(scope, k.into(), v.into());

    let before = build_snapshot(scope, &stat.before);
    let k = v8::String::new(scope, "beforeGC").unwrap();
    entry.set(scope, k.into(), before.into());

    let after = build_snapshot(scope, &stat.after);
    let k = v8::String::new(scope, "afterGC").unwrap();
    entry.set(scope, k.into(), after.into());

    arr.set_index(scope, i as u32, entry.into());
  }
  let wrapper = v8::Object::new(scope);
  let k = v8::String::new(scope, "statistics").unwrap();
  wrapper.set(scope, k.into(), arr.into());
  wrapper
}

#[cfg(test)]
mod native_capsec_tests {
  use std::fs::OpenOptions;
  use std::io::Write as _;
  use std::path::Path;
  use std::path::PathBuf;
  use std::process::Command;
  use std::process::Output;
  use std::sync::Arc;
  use std::sync::Mutex;
  use std::time::Duration;
  use std::time::Instant;

  use deno_core::JsRuntime;
  use deno_core::RuntimeOptions;
  use deno_permissions::Permissions;
  use deno_permissions::PermissionsContainer;
  use deno_permissions::RuntimePermissionDescriptorParser;
  use deno_resolver::npm::DenoInNpmPackageChecker;
  use deno_resolver::npm::NpmResolver;

  use super::*;

  deno_error::js_error_wrapper!(
    deno_ast::ParseDiagnostic,
    PublicV8FixtureParseDiagnostic,
    "SyntaxError"
  );
  deno_error::js_error_wrapper!(
    deno_ast::TranspileError,
    PublicV8FixtureTranspileError,
    "Error"
  );

  const NATIVE_V8_GUARD_CHILD: &str = "ODEN_NATIVE_V8_GUARD_CHILD";
  const NATIVE_V8_GUARD_TEST: &str = "native_v8_ops_recheck_actor_before_work";
  const REV2_V8_FIXTURE_CHILD: &str = "ODEN_REV2_V8_FIXTURE_CHILD";
  const REV2_V8_FIXTURE_OPERATION_ENV: &str = "ODEN_REV2_V8_FIXTURE_OPERATION";
  const REV2_V8_FIXTURE_CASE_ENV: &str = "ODEN_REV2_V8_FIXTURE_CASE_KIND";
  const REV2_V8_FIXTURE_TARGET_ENV: &str = "ODEN_REV2_V8_FIXTURE_TARGET";
  const REV2_V8_FIXTURE_MODE_ENV: &str = "ODEN_REV2_V8_FIXTURE_MODE";
  const REV2_V8_FIXTURE_REPORT_PREFIX: &str =
    "ODEN_REV2_V8_INSPECTION_FIXTURE_REPORT ";
  const REV2_V8_FIXTURE_TEST: &str =
    "ops::v8::native_capsec_tests::rev2_v8_inspection_fixture_case";
  const REV2_V8_FIXTURE_MODES: &[&str] = &["permissive", "audit", "enforce"];
  const REV2_V8_FIXTURE_CASE_KINDS: &[&str] = &[
    "deny-only-closed-or-absent",
    "staged-barrier:authorization",
    "staged-barrier:cancellation",
    "staged-barrier:cleanup",
  ];

  struct Rev2V8FixtureOperation {
    operation_id: &'static str,
    edge_id: &'static str,
    requirement_id: &'static str,
    denied_target: &'static str,
    authorization_assertion: &'static str,
    denied_no_work_assertion: &'static str,
    cleanup_assertion: &'static str,
    post_cleanup_no_work_assertion: &'static str,
  }

  const REV2_V8_FIXTURE_OPERATIONS: &[Rev2V8FixtureOperation] = &[
    Rev2V8FixtureOperation {
      operation_id: "set-flags-from-string",
      edge_id: "diagnostic-route:ext/node/ops/v8.rs#op_v8_set_flags_from_string",
      requirement_id: "fixture-requirement:diagnostic-route:ext/node/ops/v8.rs#op_v8_set_flags_from_string:complete",
      denied_target: "v8:set-flags",
      authorization_assertion: "guard-precedes-v8-flag-mutation",
      denied_no_work_assertion: "denied-attempt-adds-no-v8-flag-mutation",
      cleanup_assertion: "ambient-cleanup-restores-v8-flag",
      post_cleanup_no_work_assertion: "post-cleanup-denial-adds-no-v8-flag-mutation",
    },
    Rev2V8FixtureOperation {
      operation_id: "gc-profiler-new",
      edge_id: "diagnostic-route:ext/node/ops/v8.rs#op_v8_gc_profiler_new",
      requirement_id: "fixture-requirement:diagnostic-route:ext/node/ops/v8.rs#op_v8_gc_profiler_new:complete",
      denied_target: "v8:gc-profiler",
      authorization_assertion: "guard-precedes-gc-profiler-handle-allocation",
      denied_no_work_assertion: "denied-attempt-adds-no-gc-profiler-handle-allocation",
      cleanup_assertion: "explicit-root-stop-removes-active-profiler",
      post_cleanup_no_work_assertion: "post-cleanup-denial-adds-no-gc-profiler-handle-allocation",
    },
    Rev2V8FixtureOperation {
      operation_id: "gc-profiler-start",
      edge_id: "diagnostic-route:ext/node/ops/v8.rs#op_v8_gc_profiler_start",
      requirement_id: "fixture-requirement:diagnostic-route:ext/node/ops/v8.rs#op_v8_gc_profiler_start:complete",
      denied_target: "v8:gc-profiler-start",
      authorization_assertion: "guard-precedes-gc-profiler-start-work",
      denied_no_work_assertion: "denied-attempt-adds-no-gc-profiler-start-work",
      cleanup_assertion: "explicit-root-stop-removes-active-profiler",
      post_cleanup_no_work_assertion: "post-cleanup-denial-adds-no-gc-profiler-start-work",
    },
    Rev2V8FixtureOperation {
      operation_id: "gc-profiler-stop",
      edge_id: "diagnostic-route:ext/node/ops/v8.rs#op_v8_gc_profiler_stop",
      requirement_id: "fixture-requirement:diagnostic-route:ext/node/ops/v8.rs#op_v8_gc_profiler_stop:complete",
      denied_target: "v8:gc-profiler-stop",
      authorization_assertion: "guard-precedes-gc-profiler-stop-work",
      denied_no_work_assertion: "denied-attempt-adds-no-gc-profiler-stop-work",
      cleanup_assertion: "explicit-root-stop-removes-active-profiler",
      post_cleanup_no_work_assertion: "post-cleanup-denial-adds-no-gc-profiler-stop-work",
    },
    Rev2V8FixtureOperation {
      operation_id: "take-heap-snapshot",
      edge_id: "diagnostic-route:ext/node/ops/v8.rs#op_v8_take_heap_snapshot",
      requirement_id: "fixture-requirement:diagnostic-route:ext/node/ops/v8.rs#op_v8_take_heap_snapshot:complete",
      denied_target: "v8:heap-snapshot",
      authorization_assertion: "guard-precedes-heap-snapshot-native-work",
      denied_no_work_assertion: "denied-attempt-adds-no-heap-snapshot-native-work",
      cleanup_assertion: "ambient-synchronous-snapshot-call-returns",
      post_cleanup_no_work_assertion: "post-cleanup-denial-adds-no-heap-snapshot-native-work",
    },
    Rev2V8FixtureOperation {
      operation_id: "public-gc-profiler-dispose",
      edge_id: "diagnostic-route:ext/node/polyfills/v8.ts#node:v8.GCProfiler.dispose",
      requirement_id: "fixture-requirement:diagnostic-route:ext/node/polyfills/v8.ts#node:v8.GCProfiler.dispose:complete",
      denied_target: "node:v8.GCProfiler.dispose",
      authorization_assertion: "guard-precedes-public-wrapper-gc-profiler-dispose-native-work",
      denied_no_work_assertion: "denied-attempt-adds-no-public-wrapper-gc-profiler-dispose-native-work",
      cleanup_assertion: "explicit-root-stop-removes-active-profiler",
      post_cleanup_no_work_assertion: "post-cleanup-denial-adds-no-public-wrapper-gc-profiler-dispose-native-work",
    },
    Rev2V8FixtureOperation {
      operation_id: "public-gc-profiler-start",
      edge_id: "diagnostic-route:ext/node/polyfills/v8.ts#node:v8.GCProfiler.start",
      requirement_id: "fixture-requirement:diagnostic-route:ext/node/polyfills/v8.ts#node:v8.GCProfiler.start:complete",
      denied_target: "node:v8.GCProfiler.start",
      authorization_assertion: "guard-precedes-public-wrapper-gc-profiler-start-native-work",
      denied_no_work_assertion: "denied-attempt-adds-no-public-wrapper-gc-profiler-start-native-work",
      cleanup_assertion: "explicit-root-stop-removes-active-profiler",
      post_cleanup_no_work_assertion: "post-cleanup-denial-adds-no-public-wrapper-gc-profiler-start-native-work",
    },
    Rev2V8FixtureOperation {
      operation_id: "public-gc-profiler-stop",
      edge_id: "diagnostic-route:ext/node/polyfills/v8.ts#node:v8.GCProfiler.stop",
      requirement_id: "fixture-requirement:diagnostic-route:ext/node/polyfills/v8.ts#node:v8.GCProfiler.stop:complete",
      denied_target: "node:v8.GCProfiler.stop",
      authorization_assertion: "guard-precedes-public-wrapper-gc-profiler-stop-native-work",
      denied_no_work_assertion: "denied-attempt-adds-no-public-wrapper-gc-profiler-stop-native-work",
      cleanup_assertion: "explicit-root-stop-removes-active-profiler",
      post_cleanup_no_work_assertion: "post-cleanup-denial-adds-no-public-wrapper-gc-profiler-stop-native-work",
    },
    Rev2V8FixtureOperation {
      operation_id: "public-get-heap-code-statistics",
      edge_id: "diagnostic-route:ext/node/polyfills/v8.ts#node:v8.getHeapCodeStatistics",
      requirement_id: "fixture-requirement:diagnostic-route:ext/node/polyfills/v8.ts#node:v8.getHeapCodeStatistics:complete",
      denied_target: "node:v8.getHeapCodeStatistics",
      authorization_assertion: "guard-precedes-public-wrapper-get-heap-code-statistics-native-work",
      denied_no_work_assertion: "denied-attempt-adds-no-public-wrapper-get-heap-code-statistics-native-work",
      cleanup_assertion: "ambient-synchronous-inspection-call-returns",
      post_cleanup_no_work_assertion: "post-cleanup-denial-adds-no-public-wrapper-get-heap-code-statistics-native-work",
    },
    Rev2V8FixtureOperation {
      operation_id: "public-get-heap-snapshot",
      edge_id: "diagnostic-route:ext/node/polyfills/v8.ts#node:v8.getHeapSnapshot",
      requirement_id: "fixture-requirement:diagnostic-route:ext/node/polyfills/v8.ts#node:v8.getHeapSnapshot:complete",
      denied_target: "node:v8.getHeapSnapshot",
      authorization_assertion: "guard-precedes-public-wrapper-get-heap-snapshot-native-work",
      denied_no_work_assertion: "denied-attempt-adds-no-public-wrapper-get-heap-snapshot-native-work",
      cleanup_assertion: "fixture-runtime-drop-releases-heap-snapshot-state",
      post_cleanup_no_work_assertion: "post-cleanup-denial-adds-no-public-wrapper-get-heap-snapshot-native-work",
    },
    Rev2V8FixtureOperation {
      operation_id: "public-get-heap-space-statistics",
      edge_id: "diagnostic-route:ext/node/polyfills/v8.ts#node:v8.getHeapSpaceStatistics",
      requirement_id: "fixture-requirement:diagnostic-route:ext/node/polyfills/v8.ts#node:v8.getHeapSpaceStatistics:complete",
      denied_target: "node:v8.getHeapSpaceStatistics",
      authorization_assertion: "guard-precedes-public-wrapper-get-heap-space-statistics-native-work",
      denied_no_work_assertion: "denied-attempt-adds-no-public-wrapper-get-heap-space-statistics-native-work",
      cleanup_assertion: "ambient-synchronous-inspection-call-returns",
      post_cleanup_no_work_assertion: "post-cleanup-denial-adds-no-public-wrapper-get-heap-space-statistics-native-work",
    },
    Rev2V8FixtureOperation {
      operation_id: "public-get-heap-statistics",
      edge_id: "diagnostic-route:ext/node/polyfills/v8.ts#node:v8.getHeapStatistics",
      requirement_id: "fixture-requirement:diagnostic-route:ext/node/polyfills/v8.ts#node:v8.getHeapStatistics:complete",
      denied_target: "node:v8.getHeapStatistics",
      authorization_assertion: "guard-precedes-public-wrapper-get-heap-statistics-native-work",
      denied_no_work_assertion: "denied-attempt-adds-no-public-wrapper-get-heap-statistics-native-work",
      cleanup_assertion: "ambient-synchronous-inspection-call-returns",
      post_cleanup_no_work_assertion: "post-cleanup-denial-adds-no-public-wrapper-get-heap-statistics-native-work",
    },
    Rev2V8FixtureOperation {
      operation_id: "public-query-objects",
      edge_id: "diagnostic-route:ext/node/polyfills/v8.ts#node:v8.queryObjects",
      requirement_id: "fixture-requirement:diagnostic-route:ext/node/polyfills/v8.ts#node:v8.queryObjects:complete",
      denied_target: "node:v8.queryObjects",
      authorization_assertion: "guard-precedes-public-wrapper-query-objects-native-work",
      denied_no_work_assertion: "denied-attempt-adds-no-public-wrapper-query-objects-native-work",
      cleanup_assertion: "ambient-query-objects-control-returns",
      post_cleanup_no_work_assertion: "post-cleanup-denial-adds-no-public-wrapper-query-objects-native-work",
    },
    Rev2V8FixtureOperation {
      operation_id: "public-set-flags-from-string",
      edge_id: "diagnostic-route:ext/node/polyfills/v8.ts#node:v8.setFlagsFromString",
      requirement_id: "fixture-requirement:diagnostic-route:ext/node/polyfills/v8.ts#node:v8.setFlagsFromString:complete",
      denied_target: "node:v8.setFlagsFromString",
      authorization_assertion: "guard-precedes-public-wrapper-v8-flag-mutation",
      denied_no_work_assertion: "denied-attempt-adds-no-public-wrapper-v8-flag-mutation",
      cleanup_assertion: "ambient-cleanup-restores-v8-flag",
      post_cleanup_no_work_assertion: "post-cleanup-denial-adds-no-public-wrapper-v8-flag-mutation",
    },
    Rev2V8FixtureOperation {
      operation_id: "public-set-heap-snapshot-near-heap-limit",
      edge_id: "diagnostic-route:ext/node/polyfills/v8.ts#node:v8.setHeapSnapshotNearHeapLimit",
      requirement_id: "fixture-requirement:diagnostic-route:ext/node/polyfills/v8.ts#node:v8.setHeapSnapshotNearHeapLimit:complete",
      denied_target: "node:v8.setHeapSnapshotNearHeapLimit",
      authorization_assertion: "guard-precedes-public-wrapper-near-heap-limit-state",
      denied_no_work_assertion: "denied-attempt-adds-no-public-wrapper-near-heap-limit-state",
      cleanup_assertion: "fixture-runtime-drop-releases-near-heap-limit-wrapper-state",
      post_cleanup_no_work_assertion: "post-cleanup-denial-adds-no-public-wrapper-near-heap-limit-state",
    },
    Rev2V8FixtureOperation {
      operation_id: "public-startup-snapshot-add-deserialize-callback",
      edge_id: "diagnostic-route:ext/node/polyfills/v8.ts#node:v8.startupSnapshot.addDeserializeCallback",
      requirement_id: "fixture-requirement:diagnostic-route:ext/node/polyfills/v8.ts#node:v8.startupSnapshot.addDeserializeCallback:complete",
      denied_target: "node:v8.startupSnapshot.addDeserializeCallback",
      authorization_assertion: "guard-precedes-public-wrapper-startup-deserialize-callback-state",
      denied_no_work_assertion: "denied-attempt-adds-no-public-wrapper-startup-deserialize-callback-state",
      cleanup_assertion: "fixture-runtime-drop-releases-startup-snapshot-state",
      post_cleanup_no_work_assertion: "post-cleanup-denial-adds-no-public-wrapper-startup-deserialize-callback-state",
    },
    Rev2V8FixtureOperation {
      operation_id: "public-startup-snapshot-add-serialize-callback",
      edge_id: "diagnostic-route:ext/node/polyfills/v8.ts#node:v8.startupSnapshot.addSerializeCallback",
      requirement_id: "fixture-requirement:diagnostic-route:ext/node/polyfills/v8.ts#node:v8.startupSnapshot.addSerializeCallback:complete",
      denied_target: "node:v8.startupSnapshot.addSerializeCallback",
      authorization_assertion: "guard-precedes-public-wrapper-startup-serialize-callback-state",
      denied_no_work_assertion: "denied-attempt-adds-no-public-wrapper-startup-serialize-callback-state",
      cleanup_assertion: "fixture-runtime-drop-releases-startup-snapshot-state",
      post_cleanup_no_work_assertion: "post-cleanup-denial-adds-no-public-wrapper-startup-serialize-callback-state",
    },
    Rev2V8FixtureOperation {
      operation_id: "public-startup-snapshot-set-deserialize-main-function",
      edge_id: "diagnostic-route:ext/node/polyfills/v8.ts#node:v8.startupSnapshot.setDeserializeMainFunction",
      requirement_id: "fixture-requirement:diagnostic-route:ext/node/polyfills/v8.ts#node:v8.startupSnapshot.setDeserializeMainFunction:complete",
      denied_target: "node:v8.startupSnapshot.setDeserializeMainFunction",
      authorization_assertion: "guard-precedes-public-wrapper-startup-deserialize-main-state",
      denied_no_work_assertion: "denied-attempt-adds-no-public-wrapper-startup-deserialize-main-state",
      cleanup_assertion: "fixture-runtime-drop-releases-startup-snapshot-state",
      post_cleanup_no_work_assertion: "post-cleanup-denial-adds-no-public-wrapper-startup-deserialize-main-state",
    },
    Rev2V8FixtureOperation {
      operation_id: "public-stop-coverage",
      edge_id: "diagnostic-route:ext/node/polyfills/v8.ts#node:v8.stopCoverage",
      requirement_id: "fixture-requirement:diagnostic-route:ext/node/polyfills/v8.ts#node:v8.stopCoverage:complete",
      denied_target: "node:v8.stopCoverage",
      authorization_assertion: "guard-precedes-public-wrapper-stop-coverage-work",
      denied_no_work_assertion: "denied-attempt-adds-no-public-wrapper-stop-coverage-work",
      cleanup_assertion: "ambient-not-implemented-control-remains-reachable",
      post_cleanup_no_work_assertion: "post-cleanup-denial-adds-no-public-wrapper-stop-coverage-work",
    },
    Rev2V8FixtureOperation {
      operation_id: "public-take-coverage",
      edge_id: "diagnostic-route:ext/node/polyfills/v8.ts#node:v8.takeCoverage",
      requirement_id: "fixture-requirement:diagnostic-route:ext/node/polyfills/v8.ts#node:v8.takeCoverage:complete",
      denied_target: "node:v8.takeCoverage",
      authorization_assertion: "guard-precedes-public-wrapper-take-coverage-work",
      denied_no_work_assertion: "denied-attempt-adds-no-public-wrapper-take-coverage-work",
      cleanup_assertion: "ambient-not-implemented-control-remains-reachable",
      post_cleanup_no_work_assertion: "post-cleanup-denial-adds-no-public-wrapper-take-coverage-work",
    },
    Rev2V8FixtureOperation {
      operation_id: "public-write-heap-snapshot",
      edge_id: "diagnostic-route:ext/node/polyfills/v8.ts#node:v8.writeHeapSnapshot",
      requirement_id: "fixture-requirement:diagnostic-route:ext/node/polyfills/v8.ts#node:v8.writeHeapSnapshot:complete",
      denied_target: "node:v8.writeHeapSnapshot",
      authorization_assertion: "guard-precedes-public-wrapper-write-heap-snapshot-native-work",
      denied_no_work_assertion: "denied-attempt-adds-no-public-wrapper-write-heap-snapshot-native-work",
      cleanup_assertion: "fixture-runtime-drop-releases-heap-snapshot-state",
      post_cleanup_no_work_assertion: "post-cleanup-denial-adds-no-public-wrapper-write-heap-snapshot-native-work",
    },
  ];

  struct NativeV8TestRoot(PathBuf, Option<tempfile::TempDir>);

  impl NativeV8TestRoot {
    fn new(mode: &str) -> Self {
      let dir = tempfile::Builder::new()
        .prefix("oden-native-v8-")
        .tempdir()
        .unwrap();
      let metadata = std::fs::symlink_metadata(dir.path()).unwrap();
      assert!(
        metadata.is_dir() && !metadata.file_type().is_symlink(),
        "native V8 fixture root must be one newly created real directory"
      );
      let path = std::fs::canonicalize(dir.path()).unwrap();
      let policy_path = path.join("policy.json");
      let mut policy = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&policy_path)
        .unwrap();
      write!(policy, r#"{{"mode":"{mode}","grants":{{}}}}"#).unwrap();
      policy.sync_all().unwrap();
      let policy_metadata = std::fs::symlink_metadata(&policy_path).unwrap();
      assert!(
        policy_metadata.is_file() && !policy_metadata.file_type().is_symlink(),
        "native V8 fixture policy must be one newly created real file"
      );
      Self(path, Some(dir))
    }
  }

  impl Drop for NativeV8TestRoot {
    fn drop(&mut self) {
      let Some(dir) = self.1.take() else {
        return;
      };
      if let Err(error) = dir.close() {
        if std::thread::panicking() {
          eprintln!(
            "native V8 fixture cleanup also failed for {}: {error}",
            self.0.display()
          );
        } else {
          panic!(
            "native V8 fixture cleanup failed for {}: {error}",
            self.0.display()
          );
        }
      }
    }
  }

  fn set_actor(root: &Path, relative: &str) {
    let locator = deno_core::url::Url::from_file_path(root.join(relative))
      .unwrap()
      .to_string();
    deno_permissions::prompter::set_current_oden_stacktrace(Box::new(|| {
      Vec::new()
    }));
    deno_permissions::prompter::set_current_oden_cped_stack(None);
    deno_permissions::prompter::set_current_oden_cped_locator(Some(locator));
    deno_permissions::prompter::set_current_oden_trusted_host_actor(false);
  }

  fn run_native_v8_child(mut command: Command, root: &Path) -> Output {
    let stdout_path = root.join("native-v8-child.stdout");
    let stderr_path = root.join("native-v8-child.stderr");
    let stdout = OpenOptions::new()
      .write(true)
      .create_new(true)
      .open(&stdout_path)
      .unwrap();
    let stderr = OpenOptions::new()
      .write(true)
      .create_new(true)
      .open(&stderr_path)
      .unwrap();
    command.current_dir(root).stdout(stdout).stderr(stderr);
    let mut child = command.spawn().unwrap();
    let started = Instant::now();
    let timeout = Duration::from_secs(120);

    loop {
      if let Some(status) = child.try_wait().unwrap() {
        return Output {
          status,
          stdout: std::fs::read(&stdout_path).unwrap(),
          stderr: std::fs::read(&stderr_path).unwrap(),
        };
      }
      if started.elapsed() >= timeout {
        let _ = child.kill();
        let status = child.wait().unwrap();
        let stdout = std::fs::read(&stdout_path).unwrap();
        let stderr = std::fs::read(&stderr_path).unwrap();
        panic!(
          "native V8 guard child timed out after {timeout:?} ({status})\nstdout:\n{}\nstderr:\n{}",
          String::from_utf8_lossy(&stdout),
          String::from_utf8_lossy(&stderr),
        );
      }
      std::thread::sleep(Duration::from_millis(10));
    }
  }

  fn clear_native_v8_capsec_env(command: &mut Command) {
    for (key, _) in std::env::vars_os() {
      let key_text = key.to_string_lossy();
      if key_text.starts_with("ODEN_CAPSEC_")
        || key_text.starts_with("ODEN_REV2_V8_")
        || key_text.starts_with("ODEN_NATIVE_V8_GUARD_")
      {
        command.env_remove(key);
      }
    }
  }

  fn native_test_permissions(allow_all: bool) -> PermissionsContainer {
    let parser =
      RuntimePermissionDescriptorParser::new(sys_traits::impls::RealSys);
    let permissions = if allow_all {
      Permissions::allow_all()
    } else {
      Permissions::none_without_prompt()
    };
    PermissionsContainer::new(Arc::new(parser), permissions)
  }

  deno_core::extension!(
    native_v8_guard_test_ext,
    ops = [
      super::op_v8_set_flags_from_string,
      super::op_v8_take_heap_snapshot,
      super::op_v8_set_heap_snapshot_near_heap_limit,
      super::op_v8_query_objects_count,
      super::op_v8_gc_profiler_new,
      super::op_v8_gc_profiler_start,
      super::op_v8_gc_profiler_stop,
    ],
    state = |state| {
      state.put::<PermissionsContainer>(native_test_permissions(false));
    }
  );

  static PUBLIC_V8_WRAPPER_GUARD_CALL_COUNT: AtomicUsize = AtomicUsize::new(0);
  static PUBLIC_V8_WRAPPER_GUARD_CALLS: Mutex<
    Vec<(String, String, String, String)>,
  > = Mutex::new(Vec::new());

  #[op2(fast, stack_trace)]
  fn op_oden_guard_deny_only_surface(
    #[string] family: String,
    #[string] action: String,
    #[string] target: String,
    #[string] api_name: String,
  ) -> Result<(), deno_permissions::PermissionCheckError> {
    PUBLIC_V8_WRAPPER_GUARD_CALL_COUNT.fetch_add(1, Ordering::SeqCst);
    PUBLIC_V8_WRAPPER_GUARD_CALLS.lock().unwrap().push((
      family.clone(),
      action.clone(),
      target.clone(),
      api_name.clone(),
    ));
    deno_permissions::oden_capsec_guard_deny_only_surface(
      &family, &action, &target, &api_name,
    )
  }

  deno_core::extension!(
    public_v8_wrapper_guard_test_ext,
    ops = [op_oden_guard_deny_only_surface],
    state = |state| {
      state.put::<PermissionsContainer>(native_test_permissions(false));
    }
  );

  fn execute(runtime: &mut JsRuntime, name: &'static str, source: String) {
    runtime.execute_script(name, source).unwrap();
  }

  fn run_native_v8_guard_contract(root: &Path, mode: &str) {
    EXPOSE_GC_FROM_SET_FLAGS.store(false, Ordering::SeqCst);
    SET_FLAGS_WORK_COUNT.store(0, Ordering::SeqCst);
    GET_HEAP_CODE_STATISTICS_WORK_COUNT.store(0, Ordering::SeqCst);
    GET_HEAP_STATISTICS_WORK_COUNT.store(0, Ordering::SeqCst);
    GET_HEAP_SPACE_STATISTICS_WORK_COUNT.store(0, Ordering::SeqCst);
    TAKE_HEAP_SNAPSHOT_CALL_COUNT.store(0, Ordering::SeqCst);
    TAKE_HEAP_SNAPSHOT_CHUNK_COUNT.store(0, Ordering::SeqCst);
    QUERY_OBJECTS_SNAPSHOT_CHUNK_COUNT.store(0, Ordering::SeqCst);
    NEAR_HEAP_LIMIT_CURRENT_DIR_COUNT.store(0, Ordering::SeqCst);
    NEAR_HEAP_LIMIT_CHECK_WRITE_COUNT.store(0, Ordering::SeqCst);
    NEAR_HEAP_LIMIT_CALLBACK_INSTALL_COUNT.store(0, Ordering::SeqCst);
    GC_PROFILER_NEW_WORK_COUNT.store(0, Ordering::SeqCst);
    GC_PROFILER_START_WORK_COUNT.store(0, Ordering::SeqCst);
    GC_PROFILER_CALLBACK_INSTALL_COUNT.store(0, Ordering::SeqCst);
    GC_PROFILER_STOP_WORK_COUNT.store(0, Ordering::SeqCst);
    GC_PROFILER_ACTIVE_STATE_COUNT.store(0, Ordering::SeqCst);
    let tokio_runtime = tokio::runtime::Builder::new_current_thread()
      .enable_all()
      .build()
      .unwrap();
    let _tokio_guard = tokio_runtime.enter();
    let mut runtime = JsRuntime::new(RuntimeOptions {
      extensions: vec![native_v8_guard_test_ext::init()],
      ..Default::default()
    });

    // Create an unstarted handle under ambient root. The package's denied
    // start below is deliberately the first GC-profiler start in this fresh
    // isolate, so registry/callback initialization cannot be hidden by setup.
    set_actor(root, "main.ts");
    execute(
      &mut runtime,
      "file:///native_v8_guard_setup.js",
      r#"
      {
        const ops = Deno.core.ops;
        globalThis.startHandle = ops.op_v8_gc_profiler_new();
      }
      "#
      .to_string(),
    );

    set_actor(root, "node_modules/denied-native/index.cjs");
    execute(
      &mut runtime,
      "file:///native_v8_guard_denied.js",
      r#"
      {
        const ops = Deno.core.ops;
        function expectDenied(name, target, operation) {
          try {
            operation();
          } catch (error) {
            const message = String(error);
            const expected =
              `principal set [denied-native] may not use deny-only runtime:inspect:${target}`;
            if (!message.includes(expected)) {
              throw new Error(`${name} used the wrong actor or boundary: ${message}`);
            }
            return;
          }
          throw new Error(`${name} reached native work`);
        }
        expectDenied("op_v8_set_flags_from_string", "v8:set-flags", () =>
          ops.op_v8_set_flags_from_string("--expose-gc"));
        expectDenied("op_v8_take_heap_snapshot", "v8:heap-snapshot", () =>
          ops.op_v8_take_heap_snapshot());
        expectDenied(
          "op_v8_set_heap_snapshot_near_heap_limit",
          "v8:near-heap-limit-snapshot",
          () => ops.op_v8_set_heap_snapshot_near_heap_limit(0),
        );
        expectDenied("op_v8_query_objects_count", "v8:query-objects", () =>
          ops.op_v8_query_objects_count("Object"));
        expectDenied("op_v8_gc_profiler_new", "v8:gc-profiler", () =>
          ops.op_v8_gc_profiler_new());
        expectDenied("op_v8_gc_profiler_start", "v8:gc-profiler-start", () =>
          ops.op_v8_gc_profiler_start(startHandle));
      }
      "#
      .to_string(),
    );
    assert!(
      !EXPOSE_GC_FROM_SET_FLAGS.load(Ordering::SeqCst),
      "denied native flag mutation reached shared V8 state in {mode}"
    );
    assert_eq!(
      SET_FLAGS_WORK_COUNT.load(Ordering::SeqCst),
      0,
      "denied native flag mutation reached V8 flag work in {mode}"
    );
    assert_eq!(
      TAKE_HEAP_SNAPSHOT_CALL_COUNT.load(Ordering::SeqCst),
      0,
      "denied heap snapshot reached the native snapshot call in {mode}"
    );
    assert_eq!(
      TAKE_HEAP_SNAPSHOT_CHUNK_COUNT.load(Ordering::SeqCst),
      0,
      "denied heap snapshot reached native snapshot work in {mode}"
    );
    assert_eq!(
      QUERY_OBJECTS_SNAPSHOT_CHUNK_COUNT.load(Ordering::SeqCst),
      0,
      "denied queryObjects reached native snapshot work in {mode}"
    );
    assert_eq!(
      NEAR_HEAP_LIMIT_CURRENT_DIR_COUNT.load(Ordering::SeqCst),
      0,
      "near-heap guard ran after current_dir in {mode}"
    );
    assert_eq!(
      NEAR_HEAP_LIMIT_CHECK_WRITE_COUNT.load(Ordering::SeqCst),
      0,
      "near-heap guard ran after check_write in {mode}"
    );
    assert_eq!(
      NEAR_HEAP_LIMIT_CALLBACK_INSTALL_COUNT.load(Ordering::SeqCst),
      0,
      "denied near-heap operation installed its callback in {mode}"
    );
    assert_eq!(
      GC_PROFILER_NEW_WORK_COUNT.load(Ordering::SeqCst),
      1,
      "denied GC profiler new added native allocation work in {mode}"
    );
    assert_eq!(
      GC_PROFILER_START_WORK_COUNT.load(Ordering::SeqCst),
      0,
      "denied fresh-runtime GC profiler start reached registry work in {mode}"
    );
    assert_eq!(
      GC_PROFILER_CALLBACK_INSTALL_COUNT.load(Ordering::SeqCst),
      0,
      "denied fresh-runtime GC profiler start registered callbacks in {mode}"
    );
    // The denied near-heap attempt above ran with write permission denied, so
    // its exact capsec error plus zero current_dir/check_write counters proves
    // the native deny-only gate precedes cwd lookup, the substrate permission
    // check, and callback installation. Root controls may use the filesystem.
    runtime
      .op_state()
      .borrow_mut()
      .put::<PermissionsContainer>(native_test_permissions(true));

    set_actor(root, "main.ts");
    execute(
      &mut runtime,
      "file:///native_v8_guard_continuity.js",
      r#"
      {
        const ops = Deno.core.ops;
        const deniedStartReport = ops.op_v8_gc_profiler_stop(startHandle);
        if (deniedStartReport !== null) {
          throw new Error("denied GC profiler start mutated its handle");
        }
        const positiveHandle = ops.op_v8_gc_profiler_new();
        ops.op_v8_gc_profiler_start(positiveHandle);
        const positiveReport = ops.op_v8_gc_profiler_stop(positiveHandle);
        if (positiveReport === null) {
          throw new Error("fresh root GC profiler start/stop returned null");
        }
      }
      "#
      .to_string(),
    );
    assert!(
      GC_PROFILER_START_WORK_COUNT.load(Ordering::SeqCst) > 0,
      "fresh root GC profiler start did not reach registry work"
    );
    assert!(
      GC_PROFILER_CALLBACK_INSTALL_COUNT.load(Ordering::SeqCst) > 0,
      "fresh root GC profiler start did not install callbacks"
    );

    // Prepare a distinct, live handle only after the fresh-runtime start proof
    // above. The package stop must not consume it before root can collect it.
    execute(
      &mut runtime,
      "file:///native_v8_guard_prepare_stop.js",
      r#"
      {
        const ops = Deno.core.ops;
        globalThis.stopHandle = ops.op_v8_gc_profiler_new();
        ops.op_v8_gc_profiler_start(stopHandle);
      }
      "#
      .to_string(),
    );

    let stop_work_before = GC_PROFILER_STOP_WORK_COUNT.load(Ordering::SeqCst);
    set_actor(root, "node_modules/denied-native/index.cjs");
    execute(
      &mut runtime,
      "file:///native_v8_guard_denied_stop.js",
      r#"
      {
        const ops = Deno.core.ops;
        try {
          ops.op_v8_gc_profiler_stop(stopHandle);
        } catch (error) {
          const message = String(error);
          const expected =
            "principal set [denied-native] may not use deny-only runtime:inspect:v8:gc-profiler-stop";
          if (!message.includes(expected)) {
            throw new Error(`op_v8_gc_profiler_stop used the wrong actor or boundary: ${message}`);
          }
          globalThis.stopDenied = true;
        }
        if (!globalThis.stopDenied) {
          throw new Error("op_v8_gc_profiler_stop reached native work");
        }
      }
      "#
      .to_string(),
    );
    assert_eq!(
      GC_PROFILER_STOP_WORK_COUNT.load(Ordering::SeqCst),
      stop_work_before,
      "denied GC profiler stop reached native work in {mode}"
    );

    set_actor(root, "main.ts");
    execute(
      &mut runtime,
      "file:///native_v8_guard_stop_continuity.js",
      r#"
      {
        const stopReport = Deno.core.ops.op_v8_gc_profiler_stop(stopHandle);
        if (stopReport === null) {
          throw new Error("denied GC profiler stop consumed its native handle");
        }
      }
      "#
      .to_string(),
    );

    // One mode also proves that every raw native op remains usable by the
    // ambient runtime. The other two children focus on mutation-sensitive
    // package denial without paying for repeated heap snapshots.
    if mode == "audit" {
      execute(
        &mut runtime,
        "file:///native_v8_guard_positive.js",
        r#"
        {
          const ops = Deno.core.ops;
          ops.op_v8_set_flags_from_string("--expose-gc");
          const snapshot = ops.op_v8_take_heap_snapshot();
          if (snapshot.byteLength === 0) throw new Error("empty heap snapshot");
          const count = ops.op_v8_query_objects_count("Object");
          if (!Number.isInteger(count)) throw new Error("invalid object count");
          ops.op_v8_set_heap_snapshot_near_heap_limit(0);
          ops.op_v8_set_flags_from_string("--no-expose-gc");
        }
        "#
        .to_string(),
      );
      assert!(
        !EXPOSE_GC_FROM_SET_FLAGS.load(Ordering::SeqCst),
        "root positive control failed to restore the shared V8 flag"
      );
      assert!(
        TAKE_HEAP_SNAPSHOT_CALL_COUNT.load(Ordering::SeqCst) > 0,
        "root heap snapshot positive control did not enter native snapshot work"
      );
      assert!(
        TAKE_HEAP_SNAPSHOT_CHUNK_COUNT.load(Ordering::SeqCst) > 0,
        "root heap snapshot positive control did no native snapshot work"
      );
      assert!(
        QUERY_OBJECTS_SNAPSHOT_CHUNK_COUNT.load(Ordering::SeqCst) > 0,
        "root queryObjects positive control did no native snapshot work"
      );
      assert_eq!(
        NEAR_HEAP_LIMIT_CURRENT_DIR_COUNT.load(Ordering::SeqCst),
        1,
        "root near-heap positive control did not reach current_dir exactly once"
      );
      assert_eq!(
        NEAR_HEAP_LIMIT_CHECK_WRITE_COUNT.load(Ordering::SeqCst),
        1,
        "root near-heap positive control did not reach check_write exactly once"
      );
      assert_eq!(
        NEAR_HEAP_LIMIT_CALLBACK_INSTALL_COUNT.load(Ordering::SeqCst),
        1,
        "root near-heap positive control did not install exactly one callback"
      );
    }
    assert_eq!(
      GC_PROFILER_ACTIVE_STATE_COUNT.load(Ordering::SeqCst),
      0,
      "root GC profiler cleanup left an active state in {mode}"
    );
  }

  fn compiled_rev2_v8_fixture_target() -> Option<&'static str> {
    if cfg!(all(target_arch = "aarch64", target_os = "macos")) {
      Some("aarch64-apple-darwin")
    } else if cfg!(all(
      target_arch = "x86_64",
      target_os = "linux",
      target_env = "gnu"
    )) {
      Some("x86_64-unknown-linux-gnu")
    } else {
      None
    }
  }

  fn rev2_v8_fixture_operation(
    operation_id: &str,
  ) -> &'static Rev2V8FixtureOperation {
    let matches = REV2_V8_FIXTURE_OPERATIONS
      .iter()
      .filter(|operation| operation.operation_id == operation_id)
      .collect::<Vec<_>>();
    assert_eq!(
      matches.len(),
      1,
      "unknown or duplicate Rev2 V8 fixture operation {operation_id}"
    );
    matches[0]
  }

  fn rev2_v8_fixture_assertions(
    operation: &Rev2V8FixtureOperation,
    case_kind: &str,
  ) -> [&'static str; 2] {
    match case_kind {
      "deny-only-closed-or-absent" => [
        "constrained-package-denied",
        operation.denied_no_work_assertion,
      ],
      "staged-barrier:authorization" => [
        operation.authorization_assertion,
        operation.denied_no_work_assertion,
      ],
      "staged-barrier:cancellation" => [
        "denied-attempt-leaves-no-provisional-state",
        if matches!(
          operation.operation_id,
          "public-get-heap-snapshot" | "public-write-heap-snapshot"
        ) {
          "ambient-wrapper-native-work-remains-reachable"
        } else {
          "ambient-control-remains-usable"
        },
      ],
      "staged-barrier:cleanup" => [
        operation.cleanup_assertion,
        operation.post_cleanup_no_work_assertion,
      ],
      _ => panic!("unknown Rev2 V8 fixture case kind {case_kind}"),
    }
  }

  #[derive(Clone, Copy, Debug, Eq, PartialEq)]
  struct Rev2V8FixtureCanaries {
    public_wrapper_guard_calls: usize,
    expose_gc: bool,
    set_flags_work: usize,
    heap_code_statistics_work: usize,
    heap_statistics_work: usize,
    heap_space_statistics_work: usize,
    heap_snapshot_calls: usize,
    heap_snapshot_chunks: usize,
    query_objects_snapshot_chunks: usize,
    near_heap_limit_current_dir: usize,
    near_heap_limit_check_write: usize,
    near_heap_limit_callback_installs: usize,
    gc_profiler_new_work: usize,
    gc_profiler_start_work: usize,
    gc_profiler_callback_installs: usize,
    gc_profiler_stop_work: usize,
    gc_profiler_active_states: usize,
  }

  fn reset_rev2_v8_fixture_canaries() {
    PUBLIC_V8_WRAPPER_GUARD_CALL_COUNT.store(0, Ordering::SeqCst);
    PUBLIC_V8_WRAPPER_GUARD_CALLS.lock().unwrap().clear();
    EXPOSE_GC_FROM_SET_FLAGS.store(false, Ordering::SeqCst);
    SET_FLAGS_WORK_COUNT.store(0, Ordering::SeqCst);
    GET_HEAP_CODE_STATISTICS_WORK_COUNT.store(0, Ordering::SeqCst);
    GET_HEAP_STATISTICS_WORK_COUNT.store(0, Ordering::SeqCst);
    GET_HEAP_SPACE_STATISTICS_WORK_COUNT.store(0, Ordering::SeqCst);
    TAKE_HEAP_SNAPSHOT_CALL_COUNT.store(0, Ordering::SeqCst);
    TAKE_HEAP_SNAPSHOT_CHUNK_COUNT.store(0, Ordering::SeqCst);
    QUERY_OBJECTS_SNAPSHOT_CHUNK_COUNT.store(0, Ordering::SeqCst);
    NEAR_HEAP_LIMIT_CURRENT_DIR_COUNT.store(0, Ordering::SeqCst);
    NEAR_HEAP_LIMIT_CHECK_WRITE_COUNT.store(0, Ordering::SeqCst);
    NEAR_HEAP_LIMIT_CALLBACK_INSTALL_COUNT.store(0, Ordering::SeqCst);
    GC_PROFILER_NEW_WORK_COUNT.store(0, Ordering::SeqCst);
    GC_PROFILER_START_WORK_COUNT.store(0, Ordering::SeqCst);
    GC_PROFILER_CALLBACK_INSTALL_COUNT.store(0, Ordering::SeqCst);
    GC_PROFILER_STOP_WORK_COUNT.store(0, Ordering::SeqCst);
    GC_PROFILER_ACTIVE_STATE_COUNT.store(0, Ordering::SeqCst);
  }

  fn rev2_v8_fixture_canaries() -> Rev2V8FixtureCanaries {
    Rev2V8FixtureCanaries {
      public_wrapper_guard_calls: PUBLIC_V8_WRAPPER_GUARD_CALL_COUNT
        .load(Ordering::SeqCst),
      expose_gc: EXPOSE_GC_FROM_SET_FLAGS.load(Ordering::SeqCst),
      set_flags_work: SET_FLAGS_WORK_COUNT.load(Ordering::SeqCst),
      heap_code_statistics_work: GET_HEAP_CODE_STATISTICS_WORK_COUNT
        .load(Ordering::SeqCst),
      heap_statistics_work: GET_HEAP_STATISTICS_WORK_COUNT
        .load(Ordering::SeqCst),
      heap_space_statistics_work: GET_HEAP_SPACE_STATISTICS_WORK_COUNT
        .load(Ordering::SeqCst),
      heap_snapshot_calls: TAKE_HEAP_SNAPSHOT_CALL_COUNT.load(Ordering::SeqCst),
      heap_snapshot_chunks: TAKE_HEAP_SNAPSHOT_CHUNK_COUNT
        .load(Ordering::SeqCst),
      query_objects_snapshot_chunks: QUERY_OBJECTS_SNAPSHOT_CHUNK_COUNT
        .load(Ordering::SeqCst),
      near_heap_limit_current_dir: NEAR_HEAP_LIMIT_CURRENT_DIR_COUNT
        .load(Ordering::SeqCst),
      near_heap_limit_check_write: NEAR_HEAP_LIMIT_CHECK_WRITE_COUNT
        .load(Ordering::SeqCst),
      near_heap_limit_callback_installs: NEAR_HEAP_LIMIT_CALLBACK_INSTALL_COUNT
        .load(Ordering::SeqCst),
      gc_profiler_new_work: GC_PROFILER_NEW_WORK_COUNT.load(Ordering::SeqCst),
      gc_profiler_start_work: GC_PROFILER_START_WORK_COUNT
        .load(Ordering::SeqCst),
      gc_profiler_callback_installs: GC_PROFILER_CALLBACK_INSTALL_COUNT
        .load(Ordering::SeqCst),
      gc_profiler_stop_work: GC_PROFILER_STOP_WORK_COUNT.load(Ordering::SeqCst),
      gc_profiler_active_states: GC_PROFILER_ACTIVE_STATE_COUNT
        .load(Ordering::SeqCst),
    }
  }

  fn transpile_public_v8_fixture_source(
    specifier: deno_core::ModuleName,
    source: deno_core::ModuleCodeString,
  ) -> Result<
    (
      deno_core::ModuleCodeString,
      Option<deno_core::SourceMapData>,
    ),
    deno_error::JsErrorBox,
  > {
    if !specifier.ends_with(".ts") {
      return Ok((source, None));
    }
    let specifier_url = deno_core::url::Url::parse(&specifier).unwrap();
    let parsed = deno_ast::parse_module(deno_ast::ParseParams {
      specifier: specifier_url,
      text: source.into(),
      media_type: deno_ast::MediaType::TypeScript,
      capture_tokens: false,
      scope_analysis: false,
      maybe_syntax: None,
    })
    .map_err(|error| {
      deno_error::JsErrorBox::from_err(PublicV8FixtureParseDiagnostic(error))
    })?;
    let output = parsed
      .transpile(
        &deno_ast::TranspileOptions {
          imports_not_used_as_values: deno_ast::ImportsNotUsedAsValues::Remove,
          ..Default::default()
        },
        &deno_ast::TranspileModuleOptions::default(),
        &deno_ast::EmitOptions {
          source_map: deno_ast::SourceMapOption::None,
          ..Default::default()
        },
      )
      .map_err(|error| {
        deno_error::JsErrorBox::from_err(PublicV8FixtureTranspileError(error))
      })?
      .into_source();
    Ok((output.text.into(), None))
  }

  fn new_public_v8_wrapper_runtime() -> JsRuntime {
    let fs: deno_fs::FileSystemRc = Rc::new(deno_fs::RealFs);
    let runtime = JsRuntime::new(RuntimeOptions {
      extensions: vec![
        deno_webidl::deno_webidl::init(),
        deno_web::deno_web::init(
          deno_web::BlobStore::default_arc(),
          Default::default(),
          Default::default(),
          deno_web::InMemoryBroadcastChannel::default(),
        ),
        deno_io::deno_io::init(Some(Default::default())),
        deno_fs::deno_fs::init(fs.clone()),
        crate::deno_node::init::<
          DenoInNpmPackageChecker,
          NpmResolver<sys_traits::impls::RealSys>,
          sys_traits::impls::RealSys,
        >(None, fs),
        public_v8_wrapper_guard_test_ext::init(),
      ],
      extension_transpiler: Some(Rc::new(transpile_public_v8_fixture_source)),
      ..Default::default()
    });
    runtime
      .op_state()
      .borrow_mut()
      .put::<PermissionsContainer>(native_test_permissions(true));
    runtime
  }

  fn load_public_v8_wrapper(runtime: &mut JsRuntime, root: &Path) {
    set_actor(root, "main.ts");
    execute(
      runtime,
      "file:///rev2_public_v8_fixture_load.js",
      r#"
      {
        const webUrl =
          Deno.core.loadExtScript("ext:deno_web/00_url.js");
        globalThis.URL = webUrl.URL;
        globalThis.URLSearchParams = webUrl.URLSearchParams;
      }
      globalThis.rev2PublicV8 =
        Deno.core.loadExtScript("ext:deno_node/v8.ts");
      if (
        typeof rev2PublicV8.getHeapStatistics !== "function" ||
        typeof rev2PublicV8.GCProfiler !== "function" ||
        typeof rev2PublicV8.startupSnapshot !== "object"
      ) {
        throw new Error("the actual public node:v8 wrapper did not load");
      }
      "#
      .to_string(),
    );
  }

  fn assert_public_v8_guard_precedes_wrapper_mutation(
    operation: &Rev2V8FixtureOperation,
  ) {
    let source = include_str!("../polyfills/v8.ts");
    let (scope, operation_anchor, exact_guard_prefix) =
      match operation.operation_id {
        "public-gc-profiler-dispose" => (
          &source[source.find("class GCProfiler {").unwrap()
            ..source
              .find("// https://nodejs.org/api/v8.html#startup-snapshot-api")
              .unwrap()],
          "  [SymbolDispose]() {",
          r#"  [SymbolDispose]() {
    const state = gcProfilerStates.get(this);
    const handle = state.handle;
    if (handle === null) return undefined;
    guardV8("GCProfiler.dispose");"#,
        ),
        "public-gc-profiler-start" => (
          &source[source.find("class GCProfiler {").unwrap()
            ..source
              .find("// https://nodejs.org/api/v8.html#startup-snapshot-api")
              .unwrap()],
          "  start() {",
          r#"  start() {
    guardV8("GCProfiler.start");"#,
        ),
        "public-gc-profiler-stop" => (
          &source[source.find("class GCProfiler {").unwrap()
            ..source
              .find("// https://nodejs.org/api/v8.html#startup-snapshot-api")
              .unwrap()],
          "  stop() {",
          r#"  stop() {
    const state = gcProfilerStates.get(this);
    const handle = state.handle;
    if (handle === null) return undefined;
    guardV8("GCProfiler.stop");"#,
        ),
        "public-get-heap-code-statistics" => (
          source,
          "function getHeapCodeStatistics() {",
          r#"function getHeapCodeStatistics() {
  guardV8("getHeapCodeStatistics");"#,
        ),
        "public-get-heap-snapshot" => (
          source,
          "function getHeapSnapshot(",
          r#"function getHeapSnapshot(options?: Record<string, unknown>) {
  guardV8("getHeapSnapshot");"#,
        ),
        "public-get-heap-space-statistics" => (
          source,
          "function getHeapSpaceStatistics() {",
          r#"function getHeapSpaceStatistics() {
  guardV8("getHeapSpaceStatistics");"#,
        ),
        "public-get-heap-statistics" => (
          source,
          "function getHeapStatistics() {",
          r#"function getHeapStatistics() {
  guardV8("getHeapStatistics");"#,
        ),
        "public-query-objects" => (
          source,
          "function queryObjects(",
          r#"function queryObjects(
  ctor: { name?: string; prototype?: unknown },
  options:
    | { format?: "count" | "summary" }
    | undefined = undefined,
) {
  guardV8("queryObjects");"#,
        ),
        "public-set-flags-from-string" => (
          source,
          "function setFlagsFromString(",
          r#"function setFlagsFromString(flags: string) {
  guardV8("setFlagsFromString");"#,
        ),
        "public-set-heap-snapshot-near-heap-limit" => (
          source,
          "function setHeapSnapshotNearHeapLimit(",
          r#"function setHeapSnapshotNearHeapLimit(limit: number) {
  guardV8("setHeapSnapshotNearHeapLimit");"#,
        ),
        "public-startup-snapshot-add-deserialize-callback" => (
          source,
          "function startupSnapshotAddDeserializeCallback(",
          r#"function startupSnapshotAddDeserializeCallback(
  fn: SnapshotCallback,
  data?: unknown,
) {
  guardV8("startupSnapshot.addDeserializeCallback");"#,
        ),
        "public-startup-snapshot-add-serialize-callback" => (
          source,
          "function startupSnapshotAddSerializeCallback(",
          r#"function startupSnapshotAddSerializeCallback(
  fn: SnapshotCallback,
  data?: unknown,
) {
  guardV8("startupSnapshot.addSerializeCallback");"#,
        ),
        "public-startup-snapshot-set-deserialize-main-function" => (
          source,
          "function startupSnapshotSetDeserializeMainFunction(",
          r#"function startupSnapshotSetDeserializeMainFunction(
  fn: SnapshotCallback,
  data?: unknown,
) {
  guardV8("startupSnapshot.setDeserializeMainFunction");"#,
        ),
        "public-stop-coverage" => (
          source,
          "function stopCoverage() {",
          r#"function stopCoverage() {
  guardV8("stopCoverage");"#,
        ),
        "public-take-coverage" => (
          source,
          "function takeCoverage() {",
          r#"function takeCoverage() {
  guardV8("takeCoverage");"#,
        ),
        "public-write-heap-snapshot" => (
          source,
          "function writeHeapSnapshot(",
          r#"function writeHeapSnapshot(
  filename?: string,
  options?: Record<string, unknown>,
) {
  guardV8("writeHeapSnapshot");"#,
        ),
        _ => panic!(
          "unknown public Rev2 V8 fixture operation {}",
          operation.operation_id
        ),
      };
    assert_eq!(
      scope.matches(operation_anchor).count(),
      1,
      "{} public wrapper source anchor is not unique",
      operation.operation_id
    );
    assert!(
      scope.contains(exact_guard_prefix),
      "{} no longer has the exact guard-before-mutation source prefix",
      operation.operation_id
    );
  }

  fn assert_exact_public_v8_guard_call(
    operation: &Rev2V8FixtureOperation,
    call_index: usize,
  ) {
    let calls = PUBLIC_V8_WRAPPER_GUARD_CALLS.lock().unwrap();
    let call = calls
      .get(call_index)
      .unwrap_or_else(|| panic!("missing public guard call at {call_index}"));
    assert_eq!(
      call,
      &(
        "runtime".to_string(),
        "inspect".to_string(),
        operation.denied_target.to_string(),
        operation.denied_target.to_string(),
      ),
      "{} used an inexact public guard tuple",
      operation.operation_id
    );
  }

  fn assert_native_v8_fixture_path_absent(path: &Path, context: &str) {
    match std::fs::symlink_metadata(path) {
      Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
      Err(error) => {
        panic!(
          "{context}: could not establish absence for {}: {error}",
          path.display()
        )
      }
      Ok(metadata) => panic!(
        "{context}: {} exists as {:?}",
        path.display(),
        metadata.file_type()
      ),
    }
  }

  fn prepare_rev2_public_v8_fixture_state(
    runtime: &mut JsRuntime,
    root: &Path,
    operation_id: &str,
  ) {
    set_actor(root, "main.ts");
    match operation_id {
      "public-gc-profiler-start" => execute(
        runtime,
        "file:///rev2_public_v8_prepare_start.js",
        r#"
        globalThis.rev2PublicProfiler = new rev2PublicV8.GCProfiler();
        "#
        .to_string(),
      ),
      "public-gc-profiler-stop" | "public-gc-profiler-dispose" => execute(
        runtime,
        "file:///rev2_public_v8_prepare_live.js",
        r#"
        globalThis.rev2PublicProfiler = new rev2PublicV8.GCProfiler();
        rev2PublicProfiler.start();
        "#
        .to_string(),
      ),
      _ => {}
    }
  }

  fn deny_rev2_public_v8_fixture_operation(
    runtime: &mut JsRuntime,
    root: &Path,
    operation: &Rev2V8FixtureOperation,
  ) {
    let snapshot_path = root.join("denied-public-wrapper.heapsnapshot");
    assert_native_v8_fixture_path_absent(
      &snapshot_path,
      "before denied public V8 wrapper",
    );
    let snapshot_path_json =
      deno_core::serde_json::to_string(&snapshot_path.to_string_lossy())
        .unwrap();
    let body = match operation.operation_id {
      "public-gc-profiler-dispose" => {
        r#"expectDenied(() => rev2PublicProfiler[Symbol.dispose]());"#
          .to_string()
      }
      "public-gc-profiler-start" => {
        r#"expectDenied(() => rev2PublicProfiler.start());"#.to_string()
      }
      "public-gc-profiler-stop" => {
        r#"expectDenied(() => rev2PublicProfiler.stop());"#.to_string()
      }
      "public-get-heap-code-statistics" => {
        r#"expectDenied(() => rev2PublicV8.getHeapCodeStatistics());"#
          .to_string()
      }
      "public-get-heap-snapshot" => {
        r#"expectDenied(() => rev2PublicV8.getHeapSnapshot());"#.to_string()
      }
      "public-get-heap-space-statistics" => {
        r#"expectDenied(() => rev2PublicV8.getHeapSpaceStatistics());"#
          .to_string()
      }
      "public-get-heap-statistics" => {
        r#"expectDenied(() => rev2PublicV8.getHeapStatistics());"#.to_string()
      }
      "public-query-objects" => r#"
        class Rev2PublicQueryCanary {}
        expectDenied(() =>
          rev2PublicV8.queryObjects(
            Rev2PublicQueryCanary,
            { format: "count" },
          ));
        "#
      .to_string(),
      "public-set-flags-from-string" => r#"expectDenied(() =>
          rev2PublicV8.setFlagsFromString("--expose-gc"));"#
        .to_string(),
      "public-set-heap-snapshot-near-heap-limit" => r#"expectDenied(() =>
          rev2PublicV8.setHeapSnapshotNearHeapLimit(0));"#
        .to_string(),
      "public-startup-snapshot-add-deserialize-callback" => r#"
        expectDenied(() =>
          rev2PublicV8.startupSnapshot.addDeserializeCallback(() => {
            globalThis.rev2DeniedStartupCallbackRan = true;
          }));
        "#
      .to_string(),
      "public-startup-snapshot-add-serialize-callback" => r#"
        expectDenied(() =>
          rev2PublicV8.startupSnapshot.addSerializeCallback(() => {
            globalThis.rev2DeniedStartupCallbackRan = true;
          }));
        "#
      .to_string(),
      "public-startup-snapshot-set-deserialize-main-function" => r#"
        expectDenied(() =>
          rev2PublicV8.startupSnapshot.setDeserializeMainFunction(() => {
            globalThis.rev2DeniedStartupCallbackRan = true;
          }));
        "#
      .to_string(),
      "public-stop-coverage" => {
        r#"expectDenied(() => rev2PublicV8.stopCoverage());"#.to_string()
      }
      "public-take-coverage" => {
        r#"expectDenied(() => rev2PublicV8.takeCoverage());"#.to_string()
      }
      "public-write-heap-snapshot" => format!(
        "expectDenied(() => rev2PublicV8.writeHeapSnapshot({snapshot_path_json}));"
      ),
      _ => panic!(
        "unknown public Rev2 V8 fixture operation {}",
        operation.operation_id
      ),
    };
    execute(
      runtime,
      "file:///rev2_public_v8_fixture_denied.js",
      format!(
        r#"
        {{
          globalThis.rev2DeniedStartupCallbackRan = false;
          function expectDenied(action) {{
            try {{
              action();
            }} catch (error) {{
              const message = String(error);
              const expected =
                "principal set [denied-native] may not use deny-only runtime:inspect:{}";
              if (!message.includes(expected)) {{
                throw new Error(
                  `public wrapper used the wrong actor or boundary: ${{message}}`,
                );
              }}
              return;
            }}
            throw new Error("public wrapper reached post-guard work");
          }}
          {body}
          if (globalThis.rev2DeniedStartupCallbackRan) {{
            throw new Error("denied public wrapper committed startup state");
          }}
        }}
        "#,
        operation.denied_target,
      ),
    );
    assert_native_v8_fixture_path_absent(
      &snapshot_path,
      "after denied public V8 wrapper",
    );
  }

  fn cleanup_rev2_public_v8_fixture_state(
    runtime: &mut JsRuntime,
    root: &Path,
    operation_id: &str,
  ) {
    set_actor(root, "main.ts");
    match operation_id {
      "public-gc-profiler-start" => execute(
        runtime,
        "file:///rev2_public_v8_cleanup_start.js",
        r#"
        rev2PublicProfiler.start();
        if (rev2PublicProfiler.stop() === undefined) {
          throw new Error("denied public start mutated profiler state");
        }
        delete globalThis.rev2PublicProfiler;
        "#
        .to_string(),
      ),
      "public-gc-profiler-stop" | "public-gc-profiler-dispose" => execute(
        runtime,
        "file:///rev2_public_v8_cleanup_live.js",
        r#"
        if (rev2PublicProfiler.stop() === undefined) {
          throw new Error("denied public stop/dispose consumed profiler state");
        }
        delete globalThis.rev2PublicProfiler;
        "#
        .to_string(),
      ),
      _ => {}
    }
  }

  fn run_rev2_public_v8_positive_control(
    runtime: &mut JsRuntime,
    root: &Path,
    operation: &Rev2V8FixtureOperation,
  ) {
    set_actor(root, "main.ts");
    assert_eq!(
      std::fs::canonicalize(std::env::current_dir().unwrap()).unwrap(),
      root,
      "public V8 ambient control escaped its owned fixture cwd"
    );
    let before = rev2_v8_fixture_canaries();
    let positive_snapshot_path =
      root.join("positive-public-wrapper.heapsnapshot");
    assert_native_v8_fixture_path_absent(
      &positive_snapshot_path,
      "before ambient public V8 wrapper",
    );
    let positive_snapshot_path_json = deno_core::serde_json::to_string(
      &positive_snapshot_path.to_string_lossy(),
    )
    .unwrap();
    let source = match operation.operation_id {
      "public-gc-profiler-start" => r#"
        {
          const profiler = new rev2PublicV8.GCProfiler();
          profiler.start();
          if (profiler.stop() === undefined) {
            throw new Error("ambient public profiler start control failed");
          }
        }
        "#
      .to_string(),
      "public-gc-profiler-stop" => r#"
        {
          const profiler = new rev2PublicV8.GCProfiler();
          profiler.start();
          if (profiler.stop() === undefined) {
            throw new Error("ambient public profiler stop control failed");
          }
        }
        "#
      .to_string(),
      "public-gc-profiler-dispose" => r#"
        {
          const profiler = new rev2PublicV8.GCProfiler();
          profiler.start();
          if (profiler[Symbol.dispose]() !== undefined) {
            throw new Error("ambient public profiler dispose control failed");
          }
        }
        "#
      .to_string(),
      "public-get-heap-code-statistics" => r#"
        {
          const stats = rev2PublicV8.getHeapCodeStatistics();
          if (
            typeof stats !== "object" ||
            typeof stats.code_and_metadata_size !== "number"
          ) {
            throw new Error("ambient public heap-code control failed");
          }
        }
        "#
      .to_string(),
      "public-get-heap-snapshot" => r#"
        {
          try {
            const stream = rev2PublicV8.getHeapSnapshot();
            if (typeof stream?.destroy !== "function") {
              throw new Error("ambient public heap-snapshot control failed");
            }
            stream.destroy();
          } catch (error) {
            if (
              !String(error).includes(
                'Cannot resolve module "node:process"',
              )
            ) {
              throw error;
            }
            // The unit runtime deliberately has no CLI module resolver. The
            // native canary below must still prove that the actual wrapper
            // crossed its guard and completed heap-snapshot work first.
          }
        }
        "#
      .to_string(),
      "public-get-heap-space-statistics" => r#"
        {
          const stats = rev2PublicV8.getHeapSpaceStatistics();
          if (
            !Array.isArray(stats) ||
            stats.length === 0 ||
            typeof stats[0]?.space_size !== "number"
          ) {
            throw new Error("ambient public heap-space control failed");
          }
        }
        "#
      .to_string(),
      "public-get-heap-statistics" => r#"
        {
          const stats = rev2PublicV8.getHeapStatistics();
          if (
            typeof stats !== "object" ||
            typeof stats.total_heap_size !== "number"
          ) {
            throw new Error("ambient public heap-statistics control failed");
          }
        }
        "#
      .to_string(),
      "public-query-objects" => r#"
        {
          class Rev2PublicPositiveQueryCanary {}
          globalThis.rev2PublicPositiveQueryCanary =
            new Rev2PublicPositiveQueryCanary();
          const count = rev2PublicV8.queryObjects(
            Rev2PublicPositiveQueryCanary,
            { format: "count" },
          );
          if (!Number.isInteger(count) || count < 1) {
            throw new Error("ambient public queryObjects control failed");
          }
          delete globalThis.rev2PublicPositiveQueryCanary;
        }
        "#
      .to_string(),
      "public-set-flags-from-string" => r#"
        rev2PublicV8.setFlagsFromString("--expose-gc");
        rev2PublicV8.setFlagsFromString("--no-expose-gc");
        "#
      .to_string(),
      "public-set-heap-snapshot-near-heap-limit" => r#"
        rev2PublicV8.setHeapSnapshotNearHeapLimit(1);
        "#
      .to_string(),
      "public-startup-snapshot-set-deserialize-main-function" => r#"
        globalThis.rev2PositiveStartupMainCalls = 0;
        rev2PublicV8.startupSnapshot.setDeserializeMainFunction(() => {
          globalThis.rev2PositiveStartupMainCalls++;
        });
        if (rev2PositiveStartupMainCalls !== 1) {
          throw new Error("ambient startup main control did not run once");
        }
        "#
      .to_string(),
      "public-startup-snapshot-add-deserialize-callback" => r#"
        rev2PublicV8.startupSnapshot.addDeserializeCallback(() => {});
        "#
      .to_string(),
      "public-startup-snapshot-add-serialize-callback" => r#"
        rev2PublicV8.startupSnapshot.addSerializeCallback(() => {});
        "#
      .to_string(),
      "public-stop-coverage" => r#"
        try {
          rev2PublicV8.stopCoverage();
        } catch (error) {
          if (!String(error).includes("Not implemented")) throw error;
          globalThis.rev2PositiveCoverageControl = true;
        }
        if (!globalThis.rev2PositiveCoverageControl) {
          throw new Error("ambient stopCoverage did not reach its body");
        }
        "#
      .to_string(),
      "public-take-coverage" => r#"
        try {
          rev2PublicV8.takeCoverage();
        } catch (error) {
          if (!String(error).includes("Not implemented")) throw error;
          globalThis.rev2PositiveCoverageControl = true;
        }
        if (!globalThis.rev2PositiveCoverageControl) {
          throw new Error("ambient takeCoverage did not reach its body");
        }
        "#
      .to_string(),
      "public-write-heap-snapshot" => format!(
        r#"
        {{
          try {{
            const output =
              rev2PublicV8.writeHeapSnapshot({positive_snapshot_path_json});
            if (output !== {positive_snapshot_path_json}) {{
              throw new Error("ambient public writeHeapSnapshot returned the wrong path");
            }}
          }} catch (error) {{
            if (!String(error).includes("Cannot resolve module")) {{
              throw error;
            }}
            // The unit runtime deliberately has no CLI module resolver. The
            // native canary below must still prove that the actual wrapper
            // completed heap-snapshot work before this downstream refusal.
          }}
        }}
        "#
      ),
      _ => panic!(
        "unknown public Rev2 V8 fixture operation {}",
        operation.operation_id
      ),
    };
    execute(
      runtime,
      "file:///rev2_public_v8_fixture_positive.js",
      source,
    );
    let after = rev2_v8_fixture_canaries();
    let expected_guard_calls = if matches!(
      operation.operation_id,
      "public-gc-profiler-start"
        | "public-gc-profiler-stop"
        | "public-gc-profiler-dispose"
        | "public-set-flags-from-string"
    ) {
      2
    } else {
      1
    };
    assert_eq!(
      after.public_wrapper_guard_calls,
      before.public_wrapper_guard_calls + expected_guard_calls,
      "{} ambient control crossed an inexact number of public guards",
      operation.operation_id
    );
    let operation_guard_index = before.public_wrapper_guard_calls
      + usize::from(matches!(
        operation.operation_id,
        "public-gc-profiler-stop" | "public-gc-profiler-dispose"
      ));
    assert_exact_public_v8_guard_call(operation, operation_guard_index);
    match operation.operation_id {
      "public-gc-profiler-start"
      | "public-gc-profiler-stop"
      | "public-gc-profiler-dispose" => {
        assert!(
          after.gc_profiler_new_work > before.gc_profiler_new_work
            && after.gc_profiler_start_work > before.gc_profiler_start_work
            && after.gc_profiler_stop_work > before.gc_profiler_stop_work,
          "{} ambient control did not complete exact native profiler work",
          operation.operation_id
        );
        assert_eq!(
          after.gc_profiler_active_states, before.gc_profiler_active_states,
          "{} ambient control retained native profiler state",
          operation.operation_id
        );
      }
      "public-get-heap-code-statistics" => assert!(
        after.heap_code_statistics_work > before.heap_code_statistics_work,
        "ambient getHeapCodeStatistics did no native work"
      ),
      "public-get-heap-snapshot" | "public-write-heap-snapshot" => assert!(
        after.heap_snapshot_calls > before.heap_snapshot_calls
          && after.heap_snapshot_chunks > before.heap_snapshot_chunks,
        "{} ambient control did no native heap-snapshot work",
        operation.operation_id
      ),
      "public-get-heap-space-statistics" => assert!(
        after.heap_space_statistics_work > before.heap_space_statistics_work,
        "ambient getHeapSpaceStatistics did no native work"
      ),
      "public-get-heap-statistics" => assert!(
        after.heap_statistics_work > before.heap_statistics_work,
        "ambient getHeapStatistics did no native work"
      ),
      "public-query-objects" => assert!(
        after.query_objects_snapshot_chunks
          > before.query_objects_snapshot_chunks,
        "ambient queryObjects did no native snapshot work"
      ),
      "public-set-flags-from-string" => assert_eq!(
        after.set_flags_work,
        before.set_flags_work + 2,
        "ambient setFlagsFromString did not perform two exact flag mutations"
      ),
      "public-set-heap-snapshot-near-heap-limit" => {
        assert_eq!(
          after.near_heap_limit_current_dir,
          before.near_heap_limit_current_dir + 1,
          "ambient near-heap wrapper did not reach cwd capture exactly once"
        );
        assert_eq!(
          after.near_heap_limit_check_write,
          before.near_heap_limit_check_write + 1,
          "ambient near-heap wrapper did not reach write check exactly once"
        );
        assert_eq!(
          after.near_heap_limit_callback_installs,
          before.near_heap_limit_callback_installs + 1,
          "ambient near-heap wrapper did not install exactly one callback"
        );
      }
      "public-startup-snapshot-add-deserialize-callback"
      | "public-startup-snapshot-add-serialize-callback"
      | "public-startup-snapshot-set-deserialize-main-function"
      | "public-stop-coverage"
      | "public-take-coverage" => {}
      _ => unreachable!(),
    }
    if operation.operation_id == "public-write-heap-snapshot" {
      match std::fs::symlink_metadata(&positive_snapshot_path) {
        Ok(metadata) => {
          assert!(
            metadata.is_file()
              && !metadata.file_type().is_symlink()
              && metadata.len() > 0,
            "ambient writeHeapSnapshot did not create one real nonempty file"
          );
          std::fs::remove_file(&positive_snapshot_path).unwrap();
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
          // The minimal unit runtime may refuse its downstream node:fs module
          // resolution after the wrapper has completed native snapshot work.
        }
        Err(error) => panic!(
          "could not inspect ambient writeHeapSnapshot output {}: {error}",
          positive_snapshot_path.display()
        ),
      }
      assert_native_v8_fixture_path_absent(
        &positive_snapshot_path,
        "after ambient writeHeapSnapshot cleanup",
      );
    }
    assert!(
      !EXPOSE_GC_FROM_SET_FLAGS.load(Ordering::SeqCst),
      "ambient public wrapper control left the V8 expose-gc flag enabled"
    );
  }

  fn prepare_rev2_v8_fixture_handles(
    runtime: &mut JsRuntime,
    root: &Path,
    operation_id: &str,
  ) {
    set_actor(root, "main.ts");
    match operation_id {
      "gc-profiler-start" => execute(
        runtime,
        "file:///rev2_v8_fixture_prepare_start.js",
        r#"
        {
          const ops = Deno.core.ops;
          globalThis.rev2UnstartedHandle = ops.op_v8_gc_profiler_new();
          globalThis.rev2StartedHandle = ops.op_v8_gc_profiler_new();
          ops.op_v8_gc_profiler_start(rev2StartedHandle);
        }
        "#
        .to_string(),
      ),
      "gc-profiler-stop" => execute(
        runtime,
        "file:///rev2_v8_fixture_prepare_stop.js",
        r#"
        {
          const ops = Deno.core.ops;
          globalThis.rev2LiveStopHandle = ops.op_v8_gc_profiler_new();
          ops.op_v8_gc_profiler_start(rev2LiveStopHandle);
          globalThis.rev2UnstartedStopHandle =
            ops.op_v8_gc_profiler_new();
          globalThis.rev2StoppedStopHandle =
            ops.op_v8_gc_profiler_new();
          ops.op_v8_gc_profiler_start(rev2StoppedStopHandle);
          const stopped = ops.op_v8_gc_profiler_stop(
            rev2StoppedStopHandle,
          );
          if (stopped === null) {
            throw new Error("root could not prepare an already-stopped handle");
          }
        }
        "#
        .to_string(),
      ),
      _ => {}
    }
  }

  fn deny_rev2_v8_fixture_operation(
    runtime: &mut JsRuntime,
    operation: &Rev2V8FixtureOperation,
  ) {
    let body = match operation.operation_id {
      "set-flags-from-string" => {
        r#"expectDenied("op_v8_set_flags_from_string", () =>
          ops.op_v8_set_flags_from_string("--expose-gc"));"#
      }
      "gc-profiler-new" => {
        r#"expectDenied("op_v8_gc_profiler_new", () =>
          ops.op_v8_gc_profiler_new());"#
      }
      "gc-profiler-start" => {
        r#"
        expectDenied("op_v8_gc_profiler_start/unstarted", () =>
          ops.op_v8_gc_profiler_start(rev2UnstartedHandle));
        expectDenied("op_v8_gc_profiler_start/already-started", () =>
          ops.op_v8_gc_profiler_start(rev2StartedHandle));
        "#
      }
      "gc-profiler-stop" => {
        r#"
        expectDenied("op_v8_gc_profiler_stop/live", () =>
          ops.op_v8_gc_profiler_stop(rev2LiveStopHandle));
        expectDenied("op_v8_gc_profiler_stop/unstarted", () =>
          ops.op_v8_gc_profiler_stop(rev2UnstartedStopHandle));
        expectDenied("op_v8_gc_profiler_stop/already-stopped", () =>
          ops.op_v8_gc_profiler_stop(rev2StoppedStopHandle));
        "#
      }
      "take-heap-snapshot" => {
        r#"expectDenied("op_v8_take_heap_snapshot", () =>
          ops.op_v8_take_heap_snapshot());"#
      }
      _ => panic!(
        "unknown Rev2 V8 fixture operation {}",
        operation.operation_id
      ),
    };
    execute(
      runtime,
      "file:///rev2_v8_fixture_denied.js",
      format!(
        r#"
        {{
          const ops = Deno.core.ops;
          function expectDenied(name, action) {{
            try {{
              action();
            }} catch (error) {{
              const message = String(error);
              const expected =
                "principal set [denied-native] may not use deny-only runtime:inspect:{}";
              if (!message.includes(expected)) {{
                throw new Error(
                  `${{name}} used the wrong actor or boundary: ${{message}}`,
                );
              }}
              return;
            }}
            throw new Error(`${{name}} reached native work`);
          }}
          {body}
        }}
        "#,
        operation.denied_target,
      ),
    );
  }

  fn cleanup_rev2_v8_fixture_handles(
    runtime: &mut JsRuntime,
    root: &Path,
    operation_id: &str,
    start_unstarted: bool,
  ) {
    set_actor(root, "main.ts");
    match operation_id {
      "gc-profiler-start" => execute(
        runtime,
        "file:///rev2_v8_fixture_cleanup_start.js",
        format!(
          r#"
          {{
            const ops = Deno.core.ops;
            if ({start_unstarted}) {{
              ops.op_v8_gc_profiler_start(rev2UnstartedHandle);
              if (
                ops.op_v8_gc_profiler_stop(rev2UnstartedHandle) === null
              ) {{
                throw new Error(
                  "root could not start and stop the denied unstarted handle",
                );
              }}
            }} else if (
              ops.op_v8_gc_profiler_stop(rev2UnstartedHandle) !== null
            ) {{
              throw new Error("denied start mutated the unstarted handle");
            }}
            if (ops.op_v8_gc_profiler_stop(rev2StartedHandle) === null) {{
              throw new Error("denied idempotent start consumed the live handle");
            }}
            delete globalThis.rev2UnstartedHandle;
            delete globalThis.rev2StartedHandle;
          }}
          "#
        ),
      ),
      "gc-profiler-stop" => execute(
        runtime,
        "file:///rev2_v8_fixture_cleanup_stop.js",
        r#"
        {
          const ops = Deno.core.ops;
          if (ops.op_v8_gc_profiler_stop(rev2LiveStopHandle) === null) {
            throw new Error("denied stop consumed the live handle");
          }
          if (
            ops.op_v8_gc_profiler_stop(rev2UnstartedStopHandle) !== null
          ) {
            throw new Error("denied stop mutated the unstarted handle");
          }
          if (ops.op_v8_gc_profiler_stop(rev2StoppedStopHandle) !== null) {
            throw new Error("denied stop mutated the stopped handle");
          }
          delete globalThis.rev2LiveStopHandle;
          delete globalThis.rev2UnstartedStopHandle;
          delete globalThis.rev2StoppedStopHandle;
        }
        "#
        .to_string(),
      ),
      _ => {}
    }
  }

  fn run_rev2_v8_fixture_positive_control(
    runtime: &mut JsRuntime,
    root: &Path,
    operation_id: &str,
  ) {
    set_actor(root, "main.ts");
    match operation_id {
      "set-flags-from-string" => {
        execute(
          runtime,
          "file:///rev2_v8_fixture_positive_set_flags.js",
          r#"
          Deno.core.ops.op_v8_set_flags_from_string("--expose-gc");
          Deno.core.ops.op_v8_set_flags_from_string("--no-expose-gc");
          "#
          .to_string(),
        );
        assert!(
          !EXPOSE_GC_FROM_SET_FLAGS.load(Ordering::SeqCst),
          "root did not restore the V8 expose-gc flag"
        );
      }
      "gc-profiler-new" | "gc-profiler-start" | "gc-profiler-stop" => {
        execute(
          runtime,
          "file:///rev2_v8_fixture_positive_profiler.js",
          r#"
          {
            const ops = Deno.core.ops;
            const handle = ops.op_v8_gc_profiler_new();
            ops.op_v8_gc_profiler_start(handle);
            if (ops.op_v8_gc_profiler_stop(handle) === null) {
              throw new Error("root profiler lifecycle returned null");
            }
          }
          "#
          .to_string(),
        );
        assert_eq!(
          GC_PROFILER_ACTIVE_STATE_COUNT.load(Ordering::SeqCst),
          0,
          "explicit root stop left an active profiler state"
        );
      }
      "take-heap-snapshot" => execute(
        runtime,
        "file:///rev2_v8_fixture_positive_snapshot.js",
        r#"
        {
          let snapshot = Deno.core.ops.op_v8_take_heap_snapshot();
          if (snapshot.byteLength === 0) {
            throw new Error("root heap snapshot was empty");
          }
          snapshot = null;
        }
        "#
        .to_string(),
      ),
      _ => panic!("unknown Rev2 V8 fixture operation {operation_id}"),
    }
  }

  fn assert_rev2_v8_fixture_terminal_clean(operation_id: &str, mode: &str) {
    assert!(
      !EXPOSE_GC_FROM_SET_FLAGS.load(Ordering::SeqCst),
      "{operation_id}/{mode} left the V8 expose-gc flag enabled"
    );
    assert_eq!(
      GC_PROFILER_ACTIVE_STATE_COUNT.load(Ordering::SeqCst),
      0,
      "{operation_id}/{mode} left an active GC profiler state"
    );
  }

  fn run_rev2_public_v8_fixture_mode(
    root: &Path,
    operation: &Rev2V8FixtureOperation,
    case_kind: &str,
    mode: &str,
  ) {
    reset_rev2_v8_fixture_canaries();
    let tokio_runtime = tokio::runtime::Builder::new_current_thread()
      .enable_all()
      .build()
      .unwrap();
    let _tokio_guard = tokio_runtime.enter();
    let mut runtime = new_public_v8_wrapper_runtime();
    assert_public_v8_guard_precedes_wrapper_mutation(operation);
    load_public_v8_wrapper(&mut runtime, root);

    if case_kind == "staged-barrier:cleanup" {
      run_rev2_public_v8_positive_control(&mut runtime, root, operation);
      assert_rev2_v8_fixture_terminal_clean(operation.operation_id, mode);
    }
    prepare_rev2_public_v8_fixture_state(
      &mut runtime,
      root,
      operation.operation_id,
    );
    set_actor(root, "node_modules/denied-native/index.cjs");
    let before = rev2_v8_fixture_canaries();
    deny_rev2_public_v8_fixture_operation(&mut runtime, root, operation);
    let after = rev2_v8_fixture_canaries();
    assert_eq!(
      after.public_wrapper_guard_calls,
      before.public_wrapper_guard_calls + 1,
      "{} did not cross exactly one public guard in {case_kind}/{mode}",
      operation.operation_id
    );
    assert_exact_public_v8_guard_call(
      operation,
      before.public_wrapper_guard_calls,
    );
    assert_eq!(
      Rev2V8FixtureCanaries {
        public_wrapper_guard_calls: before.public_wrapper_guard_calls,
        ..after
      },
      before,
      "{} changed wrapper state or native work before denial in {case_kind}/{mode}",
      operation.operation_id
    );

    cleanup_rev2_public_v8_fixture_state(
      &mut runtime,
      root,
      operation.operation_id,
    );
    if case_kind == "staged-barrier:cancellation" {
      run_rev2_public_v8_positive_control(&mut runtime, root, operation);
    }
    assert_rev2_v8_fixture_terminal_clean(operation.operation_id, mode);
    drop(runtime);
    assert_eq!(
      GC_PROFILER_ACTIVE_STATE_COUNT.load(Ordering::SeqCst),
      0,
      "{} left native profiler state after runtime disposal in {mode}",
      operation.operation_id
    );
  }

  fn run_rev2_v8_inspection_fixture_mode(
    root: &Path,
    operation: &Rev2V8FixtureOperation,
    case_kind: &str,
    target: &str,
    mode: &str,
  ) -> [&'static str; 2] {
    assert_eq!(
      compiled_rev2_v8_fixture_target(),
      Some(target),
      "fixture target label does not match an exact supported compiled target"
    );
    assert!(
      REV2_V8_FIXTURE_MODES.contains(&mode),
      "fixture mode is not exact"
    );
    if operation.operation_id.starts_with("public-") {
      // @ref LLP 0019#runtime-and-memory-inspection [tests] -- Execute the
      // actual ext/node/polyfills/v8.ts public export. The test guard records
      // the exact wrapper target and delegates to the same deny-only
      // permissions primitive as the production runtime op; test-only
      // canaries prove no wrapper state or native work precedes denial.
      run_rev2_public_v8_fixture_mode(root, operation, case_kind, mode);
      return rev2_v8_fixture_assertions(operation, case_kind);
    }
    reset_rev2_v8_fixture_canaries();
    let tokio_runtime = tokio::runtime::Builder::new_current_thread()
      .enable_all()
      .build()
      .unwrap();
    let _tokio_guard = tokio_runtime.enter();
    let mut runtime = JsRuntime::new(RuntimeOptions {
      extensions: vec![native_v8_guard_test_ext::init()],
      ..Default::default()
    });

    // @ref LLP 0019#pre-promotion-conformance-candidate-execution [tests] --
    // These development-only cases bind one exact operation/case/target row
    // and exercise all three armed modes in distinct subprocesses. The
    // retained raw-native cases keep canaries immediately after each native
    // guard; start and stop also exercise live and null/idempotent handle fast
    // paths. Results remain unauthenticated and cannot change backend status.
    if case_kind == "staged-barrier:cleanup" {
      run_rev2_v8_fixture_positive_control(
        &mut runtime,
        root,
        operation.operation_id,
      );
      assert_rev2_v8_fixture_terminal_clean(operation.operation_id, mode);
    }

    prepare_rev2_v8_fixture_handles(&mut runtime, root, operation.operation_id);
    set_actor(root, "node_modules/denied-native/index.cjs");
    let before = rev2_v8_fixture_canaries();
    deny_rev2_v8_fixture_operation(&mut runtime, operation);
    let after = rev2_v8_fixture_canaries();
    assert_eq!(
      after, before,
      "{} native work changed across denied {case_kind}/{mode}",
      operation.operation_id
    );

    let start_unstarted = case_kind == "staged-barrier:cancellation";
    cleanup_rev2_v8_fixture_handles(
      &mut runtime,
      root,
      operation.operation_id,
      start_unstarted,
    );
    if case_kind == "staged-barrier:cancellation"
      && !matches!(
        operation.operation_id,
        "gc-profiler-start" | "gc-profiler-stop"
      )
    {
      run_rev2_v8_fixture_positive_control(
        &mut runtime,
        root,
        operation.operation_id,
      );
    }
    assert_rev2_v8_fixture_terminal_clean(operation.operation_id, mode);
    rev2_v8_fixture_assertions(operation, case_kind)
  }

  #[test]
  fn rev2_v8_fixture_compiled_target_mapping_is_closed() {
    if cfg!(all(target_arch = "aarch64", target_os = "macos")) {
      assert_eq!(
        compiled_rev2_v8_fixture_target(),
        Some("aarch64-apple-darwin")
      );
    } else if cfg!(all(
      target_arch = "x86_64",
      target_os = "linux",
      target_env = "gnu"
    )) {
      assert_eq!(
        compiled_rev2_v8_fixture_target(),
        Some("x86_64-unknown-linux-gnu")
      );
    } else {
      assert_eq!(compiled_rev2_v8_fixture_target(), None);
    }
  }

  fn write_rev2_v8_fixture_report(
    operation: &Rev2V8FixtureOperation,
    case_kind: &str,
    target: &str,
    assertions: &[&str],
  ) {
    let line =
      rev2_v8_fixture_report_line(operation, case_kind, target, assertions)
        + "\n";
    std::io::stderr().write_all(line.as_bytes()).unwrap();
  }

  fn rev2_v8_fixture_report_line(
    operation: &Rev2V8FixtureOperation,
    case_kind: &str,
    target: &str,
    assertions: &[&str],
  ) -> String {
    assert_eq!(assertions, rev2_v8_fixture_assertions(operation, case_kind));
    let case_id = format!("native-v8:{}:{case_kind}", operation.operation_id);
    let case_id_json = deno_core::serde_json::to_string(&case_id).unwrap();
    let operation_json =
      deno_core::serde_json::to_string(operation.operation_id).unwrap();
    let edge_json =
      deno_core::serde_json::to_string(operation.edge_id).unwrap();
    let requirement_json =
      deno_core::serde_json::to_string(operation.requirement_id).unwrap();
    let case_kind_json = deno_core::serde_json::to_string(case_kind).unwrap();
    let target_json = deno_core::serde_json::to_string(target).unwrap();
    let assertions_json = deno_core::serde_json::to_string(assertions).unwrap();
    format!(
      r#"{REV2_V8_FIXTURE_REPORT_PREFIX}{{"schema":"oden/capsec-native-v8-inspection-fixture-report/2","caseId":{case_id_json},"operationId":{operation_json},"edgeId":{edge_json},"requirementId":{requirement_json},"caseKind":{case_kind_json},"target":{target_json},"modes":["permissive","audit","enforce"],"assertions":{assertions_json},"executed":true,"nativeReleaseExecution":false,"authority":"development-fixture-execution-only"}}"#
    )
  }

  fn validate_rev2_v8_fixture_report_channels(
    stdout: &str,
    stderr: &str,
    expected_line: &str,
  ) -> Result<(), &'static str> {
    if stdout.contains(REV2_V8_FIXTURE_REPORT_PREFIX) {
      return Err("native fixture report appeared on stdout");
    }
    if stderr.matches(REV2_V8_FIXTURE_REPORT_PREFIX).count() != 1 {
      return Err("native fixture stderr did not contain exactly one marker");
    }
    if stderr.lines().filter(|line| *line == expected_line).count() != 1 {
      return Err("native fixture stderr lacked one exact full report line");
    }
    Ok(())
  }

  fn bounded_debug_output(text: &str) -> String {
    const MAX_CHARS: usize = 4096;
    let bounded = text.chars().take(MAX_CHARS).collect::<String>();
    let suffix = if text.chars().count() > MAX_CHARS {
      " [truncated]"
    } else {
      ""
    };
    format!("{bounded:?}{suffix}")
  }

  #[test]
  fn rev2_v8_fixture_report_channel_is_unambiguous() {
    let operation = rev2_v8_fixture_operation("set-flags-from-string");
    let assertions =
      rev2_v8_fixture_assertions(operation, "deny-only-closed-or-absent");
    let expected = rev2_v8_fixture_report_line(
      operation,
      "deny-only-closed-or-absent",
      "aarch64-apple-darwin",
      &assertions,
    );
    assert_eq!(
      validate_rev2_v8_fixture_report_channels(
        "running 1 test\n",
        &format!("{expected}\n"),
        &expected,
      ),
      Ok(())
    );
    assert!(
      validate_rev2_v8_fixture_report_channels(
        &format!("test fixture ... {expected}\n"),
        "",
        &expected,
      )
      .is_err()
    );
    assert!(
      validate_rev2_v8_fixture_report_channels(
        "",
        &format!("{expected} trailing\n"),
        &expected,
      )
      .is_err()
    );
    assert!(
      validate_rev2_v8_fixture_report_channels(
        "",
        &format!("{expected}\n{expected}\n"),
        &expected,
      )
      .is_err()
    );
  }

  #[test]
  fn rev2_v8_inspection_fixture_case() {
    let operation_id = std::env::var(REV2_V8_FIXTURE_OPERATION_ENV).ok();
    let case_kind = std::env::var(REV2_V8_FIXTURE_CASE_ENV).ok();
    let target = std::env::var(REV2_V8_FIXTURE_TARGET_ENV).ok();
    if std::env::var_os(REV2_V8_FIXTURE_CHILD).is_some() {
      let operation_id =
        operation_id.expect("Rev2 V8 fixture child operation is required");
      let case_kind =
        case_kind.expect("Rev2 V8 fixture child case kind is required");
      let target = target.expect("Rev2 V8 fixture child target is required");
      let mode = std::env::var(REV2_V8_FIXTURE_MODE_ENV)
        .expect("Rev2 V8 fixture child mode is required");
      let root = PathBuf::from(std::env::var_os("ODEN_CAPSEC_ROOT").unwrap());
      let operation = rev2_v8_fixture_operation(&operation_id);
      let assertions = run_rev2_v8_inspection_fixture_mode(
        &root, operation, &case_kind, &target, &mode,
      );
      assert_eq!(
        assertions,
        rev2_v8_fixture_assertions(operation, &case_kind)
      );
      return;
    }

    let requested = match (operation_id, case_kind, target) {
      (Some(operation_id), Some(case_kind), Some(target)) => {
        vec![(operation_id, case_kind, target)]
      }
      (None, None, None) => {
        let Some(target) = compiled_rev2_v8_fixture_target() else {
          return;
        };
        REV2_V8_FIXTURE_OPERATIONS
          .iter()
          .flat_map(|operation| {
            REV2_V8_FIXTURE_CASE_KINDS.iter().map(|case_kind| {
              (
                operation.operation_id.to_string(),
                case_kind.to_string(),
                target.to_string(),
              )
            })
          })
          .collect()
      }
      _ => {
        panic!(
          "Rev2 V8 fixture operation, case, and target labels must appear together"
        )
      }
    };
    for (operation_id, case_kind, target) in requested {
      let operation = rev2_v8_fixture_operation(&operation_id);
      for mode in REV2_V8_FIXTURE_MODES {
        let root = NativeV8TestRoot::new(mode);
        let mut command = Command::new(std::env::current_exe().unwrap());
        clear_native_v8_capsec_env(&mut command);
        command
          .arg(REV2_V8_FIXTURE_TEST)
          .args(["--exact", "--nocapture", "--test-threads=1"])
          .env(REV2_V8_FIXTURE_CHILD, "1")
          .env(REV2_V8_FIXTURE_OPERATION_ENV, &operation_id)
          .env(REV2_V8_FIXTURE_CASE_ENV, &case_kind)
          .env(REV2_V8_FIXTURE_TARGET_ENV, &target)
          .env(REV2_V8_FIXTURE_MODE_ENV, mode)
          .env("ODEN_CAPSEC_ROOT", &root.0)
          .env("ODEN_CAPSEC_POLICY", root.0.join("policy.json"));
        let output = run_native_v8_child(command, &root.0);
        assert!(
          output.status.success(),
          "Rev2 V8 fixture child failed for {target}/{operation_id}/{case_kind}/{mode}\nstdout={}\nstderr={}",
          bounded_debug_output(&String::from_utf8_lossy(&output.stdout)),
          bounded_debug_output(&String::from_utf8_lossy(&output.stderr)),
        );
        let stdout = String::from_utf8(output.stdout).unwrap();
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(
          !stdout.contains(REV2_V8_FIXTURE_REPORT_PREFIX)
            && !stderr.contains(REV2_V8_FIXTURE_REPORT_PREFIX),
          "mode child emitted a parent-owned fixture report"
        );
        std::io::stdout().write_all(stdout.as_bytes()).unwrap();
        std::io::stderr().write_all(stderr.as_bytes()).unwrap();
      }
      let assertions = rev2_v8_fixture_assertions(operation, &case_kind);
      write_rev2_v8_fixture_report(operation, &case_kind, &target, &assertions);
    }
  }

  // @ref LLP 0019#runtime-and-memory-inspection [tests] -- Register only the
  // raw native ops in a test runtime so the node:v8 guardV8 wrapper cannot
  // mask removal or reordering of any native deny-only boundary.
  #[test]
  fn native_v8_ops_recheck_actor_before_work() {
    if std::env::var_os(NATIVE_V8_GUARD_CHILD).is_some() {
      let root = PathBuf::from(std::env::var_os("ODEN_CAPSEC_ROOT").unwrap());
      let mode = std::env::var("ODEN_NATIVE_V8_GUARD_MODE").unwrap();
      run_native_v8_guard_contract(&root, &mode);
      return;
    }

    for mode in ["permissive", "audit", "enforce"] {
      let root = NativeV8TestRoot::new(mode);
      let mut command = Command::new(std::env::current_exe().unwrap());
      clear_native_v8_capsec_env(&mut command);
      command
        .arg(NATIVE_V8_GUARD_TEST)
        .args(["--nocapture", "--test-threads=1"])
        .env(NATIVE_V8_GUARD_CHILD, "1")
        .env("ODEN_NATIVE_V8_GUARD_MODE", mode)
        .env("ODEN_CAPSEC_ROOT", &root.0)
        .env("ODEN_CAPSEC_POLICY", root.0.join("policy.json"));
      let output = run_native_v8_child(command, &root.0);
      assert!(
        output.status.success(),
        "native V8 guard child failed in {mode}\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
      );
    }
  }
}
