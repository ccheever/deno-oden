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
  const REV2_V8_FIXTURE_CHILD_COMPLETION_PREFIX: &str =
    "ODEN_REV2_V8_INSPECTION_FIXTURE_CHILD_COMPLETE ";
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
    Rev2V8FixtureOperation {
      operation_id: "diagnostics-active-channel-bind-store",
      edge_id: "diagnostic-route:ext/node/polyfills/diagnostics_channel.js#ActiveChannel.bindStore",
      requirement_id: "fixture-requirement:diagnostic-route:ext/node/polyfills/diagnostics_channel.js#ActiveChannel.bindStore:complete",
      denied_target: "rev2-diagnostics:active-bind-store",
      authorization_assertion: "guard-precedes-diagnostics-active-bind-store-state",
      denied_no_work_assertion: "denied-attempt-adds-no-diagnostics-active-bind-store-state",
      cleanup_assertion: "explicit-root-unsubscribe-restores-inactive-diagnostics-channel",
      post_cleanup_no_work_assertion: "post-cleanup-denial-adds-no-diagnostics-active-bind-store-state",
    },
    Rev2V8FixtureOperation {
      operation_id: "diagnostics-active-channel-has-subscribers",
      edge_id: "diagnostic-route:ext/node/polyfills/diagnostics_channel.js#ActiveChannel.hasSubscribers",
      requirement_id: "fixture-requirement:diagnostic-route:ext/node/polyfills/diagnostics_channel.js#ActiveChannel.hasSubscribers:complete",
      denied_target: "rev2-diagnostics:active-has-subscribers",
      authorization_assertion: "guard-precedes-diagnostics-active-has-subscribers-observation",
      denied_no_work_assertion: "denied-attempt-adds-no-diagnostics-active-has-subscribers-observation",
      cleanup_assertion: "explicit-root-unsubscribe-restores-inactive-diagnostics-channel",
      post_cleanup_no_work_assertion: "post-cleanup-denial-adds-no-diagnostics-active-has-subscribers-observation",
    },
    Rev2V8FixtureOperation {
      operation_id: "diagnostics-active-channel-publish",
      edge_id: "diagnostic-route:ext/node/polyfills/diagnostics_channel.js#ActiveChannel.publish",
      requirement_id: "fixture-requirement:diagnostic-route:ext/node/polyfills/diagnostics_channel.js#ActiveChannel.publish:complete",
      denied_target: "rev2-diagnostics:active-publish",
      authorization_assertion: "guard-precedes-diagnostics-active-publish-delivery",
      denied_no_work_assertion: "denied-attempt-adds-no-diagnostics-active-publish-delivery",
      cleanup_assertion: "explicit-root-unsubscribe-restores-inactive-diagnostics-channel",
      post_cleanup_no_work_assertion: "post-cleanup-denial-adds-no-diagnostics-active-publish-delivery",
    },
    Rev2V8FixtureOperation {
      operation_id: "diagnostics-active-channel-run-stores",
      edge_id: "diagnostic-route:ext/node/polyfills/diagnostics_channel.js#ActiveChannel.runStores",
      requirement_id: "fixture-requirement:diagnostic-route:ext/node/polyfills/diagnostics_channel.js#ActiveChannel.runStores:complete",
      denied_target: "rev2-diagnostics:active-run-stores",
      authorization_assertion: "guard-precedes-diagnostics-active-run-stores-execution",
      denied_no_work_assertion: "denied-attempt-adds-no-diagnostics-active-run-stores-execution",
      cleanup_assertion: "explicit-root-unbind-restores-inactive-diagnostics-channel",
      post_cleanup_no_work_assertion: "post-cleanup-denial-adds-no-diagnostics-active-run-stores-execution",
    },
    Rev2V8FixtureOperation {
      operation_id: "diagnostics-active-channel-subscribe",
      edge_id: "diagnostic-route:ext/node/polyfills/diagnostics_channel.js#ActiveChannel.subscribe",
      requirement_id: "fixture-requirement:diagnostic-route:ext/node/polyfills/diagnostics_channel.js#ActiveChannel.subscribe:complete",
      denied_target: "rev2-diagnostics:active-subscribe",
      authorization_assertion: "guard-precedes-diagnostics-active-subscribe-state",
      denied_no_work_assertion: "denied-attempt-adds-no-diagnostics-active-subscribe-state",
      cleanup_assertion: "explicit-root-unsubscribe-and-unbind-restores-inactive-diagnostics-channel",
      post_cleanup_no_work_assertion: "post-cleanup-denial-adds-no-diagnostics-active-subscribe-state",
    },
    Rev2V8FixtureOperation {
      operation_id: "diagnostics-active-channel-unbind-store",
      edge_id: "diagnostic-route:ext/node/polyfills/diagnostics_channel.js#ActiveChannel.unbindStore",
      requirement_id: "fixture-requirement:diagnostic-route:ext/node/polyfills/diagnostics_channel.js#ActiveChannel.unbindStore:complete",
      denied_target: "rev2-diagnostics:active-unbind-store",
      authorization_assertion: "guard-precedes-diagnostics-active-unbind-store-state",
      denied_no_work_assertion: "denied-attempt-adds-no-diagnostics-active-unbind-store-state",
      cleanup_assertion: "explicit-root-unbind-restores-inactive-diagnostics-channel",
      post_cleanup_no_work_assertion: "post-cleanup-denial-adds-no-diagnostics-active-unbind-store-state",
    },
    Rev2V8FixtureOperation {
      operation_id: "diagnostics-active-channel-unsubscribe",
      edge_id: "diagnostic-route:ext/node/polyfills/diagnostics_channel.js#ActiveChannel.unsubscribe",
      requirement_id: "fixture-requirement:diagnostic-route:ext/node/polyfills/diagnostics_channel.js#ActiveChannel.unsubscribe:complete",
      denied_target: "rev2-diagnostics:active-unsubscribe",
      authorization_assertion: "guard-precedes-diagnostics-active-unsubscribe-state",
      denied_no_work_assertion: "denied-attempt-adds-no-diagnostics-active-unsubscribe-state",
      cleanup_assertion: "explicit-root-unsubscribe-restores-inactive-diagnostics-channel",
      post_cleanup_no_work_assertion: "post-cleanup-denial-adds-no-diagnostics-active-unsubscribe-state",
    },
    Rev2V8FixtureOperation {
      operation_id: "diagnostics-channel-bind-store",
      edge_id: "diagnostic-route:ext/node/polyfills/diagnostics_channel.js#Channel.bindStore",
      requirement_id: "fixture-requirement:diagnostic-route:ext/node/polyfills/diagnostics_channel.js#Channel.bindStore:complete",
      denied_target: "rev2-diagnostics:inactive-bind-store",
      authorization_assertion: "guard-precedes-diagnostics-inactive-bind-store-state",
      denied_no_work_assertion: "denied-attempt-adds-no-diagnostics-inactive-bind-store-state",
      cleanup_assertion: "explicit-root-unbind-restores-inactive-diagnostics-channel",
      post_cleanup_no_work_assertion: "post-cleanup-denial-adds-no-diagnostics-inactive-bind-store-state",
    },
    Rev2V8FixtureOperation {
      operation_id: "diagnostics-channel-constructor",
      edge_id: "diagnostic-route:ext/node/polyfills/diagnostics_channel.js#Channel.constructor",
      requirement_id: "fixture-requirement:diagnostic-route:ext/node/polyfills/diagnostics_channel.js#Channel.constructor:complete",
      denied_target: "rev2-diagnostics:channel-constructor",
      authorization_assertion: "guard-precedes-diagnostics-channel-constructor-state",
      denied_no_work_assertion: "denied-attempt-adds-no-diagnostics-channel-constructor-state",
      cleanup_assertion: "fixture-runtime-drop-releases-diagnostics-channel-state",
      post_cleanup_no_work_assertion: "post-cleanup-denial-adds-no-diagnostics-channel-constructor-state",
    },
    Rev2V8FixtureOperation {
      operation_id: "diagnostics-channel-has-subscribers",
      edge_id: "diagnostic-route:ext/node/polyfills/diagnostics_channel.js#Channel.hasSubscribers",
      requirement_id: "fixture-requirement:diagnostic-route:ext/node/polyfills/diagnostics_channel.js#Channel.hasSubscribers:complete",
      denied_target: "rev2-diagnostics:inactive-has-subscribers",
      authorization_assertion: "guard-precedes-diagnostics-inactive-has-subscribers-observation",
      denied_no_work_assertion: "denied-attempt-adds-no-diagnostics-inactive-has-subscribers-observation",
      cleanup_assertion: "ambient-diagnostics-control-remains-usable",
      post_cleanup_no_work_assertion: "post-cleanup-denial-adds-no-diagnostics-inactive-has-subscribers-observation",
    },
    Rev2V8FixtureOperation {
      operation_id: "diagnostics-channel-publish",
      edge_id: "diagnostic-route:ext/node/polyfills/diagnostics_channel.js#Channel.publish",
      requirement_id: "fixture-requirement:diagnostic-route:ext/node/polyfills/diagnostics_channel.js#Channel.publish:complete",
      denied_target: "rev2-diagnostics:inactive-publish",
      authorization_assertion: "guard-precedes-diagnostics-inactive-publish-delivery",
      denied_no_work_assertion: "denied-attempt-adds-no-diagnostics-inactive-publish-delivery",
      cleanup_assertion: "ambient-diagnostics-control-remains-usable",
      post_cleanup_no_work_assertion: "post-cleanup-denial-adds-no-diagnostics-inactive-publish-delivery",
    },
    Rev2V8FixtureOperation {
      operation_id: "diagnostics-channel-run-stores",
      edge_id: "diagnostic-route:ext/node/polyfills/diagnostics_channel.js#Channel.runStores",
      requirement_id: "fixture-requirement:diagnostic-route:ext/node/polyfills/diagnostics_channel.js#Channel.runStores:complete",
      denied_target: "rev2-diagnostics:inactive-run-stores",
      authorization_assertion: "guard-precedes-diagnostics-inactive-run-stores-execution",
      denied_no_work_assertion: "denied-attempt-adds-no-diagnostics-inactive-run-stores-execution",
      cleanup_assertion: "ambient-diagnostics-control-remains-usable",
      post_cleanup_no_work_assertion: "post-cleanup-denial-adds-no-diagnostics-inactive-run-stores-execution",
    },
    Rev2V8FixtureOperation {
      operation_id: "diagnostics-channel-subscribe",
      edge_id: "diagnostic-route:ext/node/polyfills/diagnostics_channel.js#Channel.subscribe",
      requirement_id: "fixture-requirement:diagnostic-route:ext/node/polyfills/diagnostics_channel.js#Channel.subscribe:complete",
      denied_target: "rev2-diagnostics:inactive-subscribe",
      authorization_assertion: "guard-precedes-diagnostics-inactive-subscribe-state",
      denied_no_work_assertion: "denied-attempt-adds-no-diagnostics-inactive-subscribe-state",
      cleanup_assertion: "explicit-root-unsubscribe-restores-inactive-diagnostics-channel",
      post_cleanup_no_work_assertion: "post-cleanup-denial-adds-no-diagnostics-inactive-subscribe-state",
    },
    Rev2V8FixtureOperation {
      operation_id: "diagnostics-channel",
      edge_id: "diagnostic-route:ext/node/polyfills/diagnostics_channel.js#channel",
      requirement_id: "fixture-requirement:diagnostic-route:ext/node/polyfills/diagnostics_channel.js#channel:complete",
      denied_target: "rev2-diagnostics:channel",
      authorization_assertion: "guard-precedes-diagnostics-channel-lookup-state",
      denied_no_work_assertion: "denied-attempt-adds-no-diagnostics-channel-lookup-state",
      cleanup_assertion: "fixture-runtime-drop-releases-diagnostics-channel-state",
      post_cleanup_no_work_assertion: "post-cleanup-denial-adds-no-diagnostics-channel-lookup-state",
    },
    Rev2V8FixtureOperation {
      operation_id: "diagnostics-has-subscribers",
      edge_id: "diagnostic-route:ext/node/polyfills/diagnostics_channel.js#hasSubscribers",
      requirement_id: "fixture-requirement:diagnostic-route:ext/node/polyfills/diagnostics_channel.js#hasSubscribers:complete",
      denied_target: "rev2-diagnostics:has-subscribers",
      authorization_assertion: "guard-precedes-diagnostics-has-subscribers-observation",
      denied_no_work_assertion: "denied-attempt-adds-no-diagnostics-has-subscribers-observation",
      cleanup_assertion: "explicit-root-unsubscribe-restores-inactive-diagnostics-channel",
      post_cleanup_no_work_assertion: "post-cleanup-denial-adds-no-diagnostics-has-subscribers-observation",
    },
    Rev2V8FixtureOperation {
      operation_id: "diagnostics-tracing-channel",
      edge_id: "diagnostic-route:ext/node/polyfills/diagnostics_channel.js#tracingChannel",
      requirement_id: "fixture-requirement:diagnostic-route:ext/node/polyfills/diagnostics_channel.js#tracingChannel:complete",
      denied_target: "rev2-diagnostics:tracing-channel",
      authorization_assertion: "guard-precedes-diagnostics-tracing-channel-state",
      denied_no_work_assertion: "denied-attempt-adds-no-diagnostics-tracing-channel-state",
      cleanup_assertion: "fixture-runtime-drop-releases-diagnostics-channel-state",
      post_cleanup_no_work_assertion: "post-cleanup-denial-adds-no-diagnostics-tracing-channel-state",
    },
    Rev2V8FixtureOperation {
      operation_id: "async-hooks-create-hook",
      edge_id: "diagnostic-route:ext/node/polyfills/async_hooks.ts#createHook",
      requirement_id: "fixture-requirement:diagnostic-route:ext/node/polyfills/async_hooks.ts#createHook:complete",
      denied_target: "async-hooks",
      authorization_assertion: "guard-precedes-async-hook-state-initialization-or-callback-read",
      denied_no_work_assertion: "denied-attempt-adds-no-async-hook-state-initialization-or-callback-read",
      cleanup_assertion: "explicit-root-resource-destroy-callback-and-hook-disable",
      post_cleanup_no_work_assertion: "post-cleanup-denial-adds-no-async-hook-state-initialization-or-callback-read",
    },
    Rev2V8FixtureOperation {
      operation_id: "async-hooks-execution-async-resource",
      edge_id: "diagnostic-route:ext/node/polyfills/async_hooks.ts#executionAsyncResource",
      requirement_id: "fixture-requirement:diagnostic-route:ext/node/polyfills/async_hooks.ts#executionAsyncResource:complete",
      denied_target: "async-resource",
      authorization_assertion: "guard-precedes-async-resource-observation",
      denied_no_work_assertion: "denied-attempt-adds-no-async-resource-observation",
      cleanup_assertion: "root-async-resource-before-function-after-destroy-order-and-hook-disable",
      post_cleanup_no_work_assertion: "post-cleanup-denial-adds-no-async-resource-observation",
    },
    Rev2V8FixtureOperation {
      operation_id: "async-hook-disable",
      edge_id: "diagnostic-route:ext/node/polyfills/internal/async_hooks.ts#AsyncHook.disable",
      requirement_id: "fixture-requirement:diagnostic-route:ext/node/polyfills/internal/async_hooks.ts#AsyncHook.disable:complete",
      denied_target: "async-hooks",
      authorization_assertion: "guard-precedes-async-hook-array-removal",
      denied_no_work_assertion: "denied-attempt-adds-no-async-hook-array-removal",
      cleanup_assertion: "explicit-root-resource-destroy-callback-and-hook-disable",
      post_cleanup_no_work_assertion: "post-cleanup-denial-adds-no-async-hook-array-removal",
    },
    Rev2V8FixtureOperation {
      operation_id: "async-hook-enable",
      edge_id: "diagnostic-route:ext/node/polyfills/internal/async_hooks.ts#AsyncHook.enable",
      requirement_id: "fixture-requirement:diagnostic-route:ext/node/polyfills/internal/async_hooks.ts#AsyncHook.enable:complete",
      denied_target: "async-hooks",
      authorization_assertion: "guard-precedes-async-hook-array-insertion",
      denied_no_work_assertion: "denied-attempt-adds-no-async-hook-array-insertion",
      cleanup_assertion: "explicit-root-resource-destroy-callback-and-hook-disable",
      post_cleanup_no_work_assertion: "post-cleanup-denial-adds-no-async-hook-array-insertion",
    },
    Rev2V8FixtureOperation {
      operation_id: "process-get-active-handles",
      edge_id: "diagnostic-route:ext/node/polyfills/internal/process/active_resources.ts#getActiveHandles",
      requirement_id: "fixture-requirement:diagnostic-route:ext/node/polyfills/internal/process/active_resources.ts#getActiveHandles:complete",
      denied_target: "process:active-handles",
      authorization_assertion: "guard-precedes-active-handle-observation",
      denied_no_work_assertion: "denied-attempt-adds-no-active-handle-observation",
      cleanup_assertion: "root-unregister-removes-tracked-handle",
      post_cleanup_no_work_assertion: "post-cleanup-denial-adds-no-active-handle-observation",
    },
    Rev2V8FixtureOperation {
      operation_id: "process-get-active-requests",
      edge_id: "diagnostic-route:ext/node/polyfills/internal/process/active_resources.ts#getActiveRequests",
      requirement_id: "fixture-requirement:diagnostic-route:ext/node/polyfills/internal/process/active_resources.ts#getActiveRequests:complete",
      denied_target: "process:active-requests",
      authorization_assertion: "guard-precedes-active-request-observation",
      denied_no_work_assertion: "denied-attempt-adds-no-active-request-observation",
      cleanup_assertion: "root-unregister-removes-tracked-request",
      post_cleanup_no_work_assertion: "post-cleanup-denial-adds-no-active-request-observation",
    },
    Rev2V8FixtureOperation {
      operation_id: "process-get-active-resource-names",
      edge_id: "diagnostic-route:ext/node/polyfills/internal/process/active_resources.ts#getActiveResourceNames",
      requirement_id: "fixture-requirement:diagnostic-route:ext/node/polyfills/internal/process/active_resources.ts#getActiveResourceNames:complete",
      denied_target: "process:active-resources",
      authorization_assertion: "guard-precedes-active-resource-name-observation",
      denied_no_work_assertion: "denied-attempt-adds-no-active-resource-name-observation",
      cleanup_assertion: "root-unregister-removes-all-tracked-resource-names",
      post_cleanup_no_work_assertion: "post-cleanup-denial-adds-no-active-resource-name-observation",
    },
    Rev2V8FixtureOperation {
      operation_id: "process-report-get-report",
      edge_id: "diagnostic-route:ext/node/polyfills/internal/process/report.ts#getReport",
      requirement_id: "fixture-requirement:diagnostic-route:ext/node/polyfills/internal/process/report.ts#getReport:complete",
      denied_target: "node:process.report.getReport",
      authorization_assertion: "guard-precedes-process-report-construction-work",
      denied_no_work_assertion: "denied-attempt-adds-no-process-report-construction-work",
      cleanup_assertion: "ambient-report-construction-remains-usable-with-exact-work-canaries",
      post_cleanup_no_work_assertion: "post-cleanup-denial-adds-no-process-report-construction-work",
    },
    Rev2V8FixtureOperation {
      operation_id: "process-report-write-report",
      edge_id: "diagnostic-route:ext/node/polyfills/internal/process/report.ts#writeReport",
      requirement_id: "fixture-requirement:diagnostic-route:ext/node/polyfills/internal/process/report.ts#writeReport:complete",
      denied_target: "node:process.report.writeReport",
      authorization_assertion: "guard-precedes-process-report-write-work",
      denied_no_work_assertion: "denied-attempt-adds-no-process-report-write-work",
      cleanup_assertion: "ambient-write-report-remains-side-effect-free",
      post_cleanup_no_work_assertion: "post-cleanup-denial-adds-no-process-report-write-work",
    },
    Rev2V8FixtureOperation {
      operation_id: "process-events-replacement",
      edge_id: "diagnostic-route:ext/node/polyfills/process.ts#Process._events-replacement",
      requirement_id: "fixture-requirement:diagnostic-route:ext/node/polyfills/process.ts#Process._events-replacement:complete",
      denied_target: "process-events",
      authorization_assertion: "guard-precedes-process-event-table-replacement",
      denied_no_work_assertion: "denied-attempt-adds-no-process-event-table-replacement",
      cleanup_assertion: "explicit-root-event-table-replacement-restores-usable-process-event-state",
      post_cleanup_no_work_assertion: "post-cleanup-denial-adds-no-process-event-table-replacement",
    },
    Rev2V8FixtureOperation {
      operation_id: "process-events-sensitive-table",
      edge_id: "diagnostic-route:ext/node/polyfills/process.ts#Process._events-sensitive-table",
      requirement_id: "fixture-requirement:diagnostic-route:ext/node/polyfills/process.ts#Process._events-sensitive-table:complete",
      denied_target: "uncaughtException",
      authorization_assertion: "guard-precedes-process-sensitive-event-table-observation-or-mutation",
      denied_no_work_assertion: "denied-attempt-adds-no-process-sensitive-event-table-observation-or-mutation",
      cleanup_assertion: "explicit-root-event-table-cleanup-restores-usable-process-event-state",
      post_cleanup_no_work_assertion: "post-cleanup-denial-adds-no-process-sensitive-event-table-observation-or-mutation",
    },
    Rev2V8FixtureOperation {
      operation_id: "process-add-listener-forwarder-runtime",
      edge_id: "diagnostic-route:ext/node/polyfills/process.ts#Process.addListener-forwarder-runtime",
      requirement_id: "fixture-requirement:diagnostic-route:ext/node/polyfills/process.ts#Process.addListener-forwarder-runtime:complete",
      denied_target: "uncaughtException",
      authorization_assertion: "guard-precedes-process-exception-listener-addition",
      denied_no_work_assertion: "denied-attempt-adds-no-process-exception-listener-addition",
      cleanup_assertion: "explicit-root-listener-removal-restores-process-event-state",
      post_cleanup_no_work_assertion: "post-cleanup-denial-adds-no-process-exception-listener-addition",
    },
    Rev2V8FixtureOperation {
      operation_id: "process-remove-listener-forwarder-runtime",
      edge_id: "diagnostic-route:ext/node/polyfills/process.ts#Process.removeListener-forwarder-runtime",
      requirement_id: "fixture-requirement:diagnostic-route:ext/node/polyfills/process.ts#Process.removeListener-forwarder-runtime:complete",
      denied_target: "uncaughtException",
      authorization_assertion: "guard-precedes-process-exception-listener-removal",
      denied_no_work_assertion: "denied-attempt-adds-no-process-exception-listener-removal",
      cleanup_assertion: "explicit-root-listener-removal-restores-process-event-state",
      post_cleanup_no_work_assertion: "post-cleanup-denial-adds-no-process-exception-listener-removal",
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
  static PROCESS_SIGNAL_BIND_COUNT: AtomicUsize = AtomicUsize::new(0);
  static PROCESS_SIGNAL_INTERNAL_BIND_COUNT: AtomicUsize = AtomicUsize::new(0);
  static PROCESS_SIGNAL_POLL_COUNT: AtomicUsize = AtomicUsize::new(0);
  static PROCESS_SIGNAL_UNBIND_COUNT: AtomicUsize = AtomicUsize::new(0);
  static PROCESS_SIGNAL_NEXT_RID: AtomicUsize = AtomicUsize::new(1);
  static PROCESS_SIGNAL_FAIL_NEXT_UNBIND: AtomicBool = AtomicBool::new(false);

  #[cfg(test)]
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

  // node:process imports this runtime-owned worker metric op even though the
  // five focused wrappers never call process.threadCpuUsage(). The isolated
  // deno_node unit runtime supplies a link-only test stub so the actual public
  // module can evaluate; any fixture call into it hard-fails.
  #[op2(fast)]
  fn op_current_thread_cpu_usage() {
    panic!("process fixture reached unrelated thread CPU usage work")
  }

  #[cfg(test)]
  #[op2(fast, stack_trace)]
  #[smi]
  fn op_signal_bind(#[string] _signal: &str) -> u32 {
    PROCESS_SIGNAL_BIND_COUNT.fetch_add(1, Ordering::SeqCst);
    PROCESS_SIGNAL_NEXT_RID.fetch_add(1, Ordering::SeqCst) as u32
  }

  #[op2(fast)]
  #[smi]
  fn op_signal_bind_internal(#[string] _signal: &str) -> u32 {
    PROCESS_SIGNAL_INTERNAL_BIND_COUNT.fetch_add(1, Ordering::SeqCst);
    PROCESS_SIGNAL_NEXT_RID.fetch_add(1, Ordering::SeqCst) as u32
  }

  #[op2]
  async fn op_signal_poll(#[smi] _rid: u32) -> bool {
    PROCESS_SIGNAL_POLL_COUNT.fetch_add(1, Ordering::SeqCst);
    std::future::pending::<bool>().await
  }

  #[op2(fast)]
  fn op_signal_unbind(#[smi] _rid: u32) -> Result<(), JsErrorBox> {
    PROCESS_SIGNAL_UNBIND_COUNT.fetch_add(1, Ordering::SeqCst);
    if PROCESS_SIGNAL_FAIL_NEXT_UNBIND.swap(false, Ordering::SeqCst) {
      return Err(JsErrorBox::generic(
        "injected process signal unbind failure",
      ));
    }
    Ok(())
  }

  deno_core::extension!(
    public_v8_wrapper_guard_test_ext,
    ops = [op_oden_guard_deny_only_surface, op_current_thread_cpu_usage,],
    esm_entry_point =
      "ext:public_v8_wrapper_guard_test_ext/process_events_test_bridge.js",
    esm = [
      "ext:public_v8_wrapper_guard_test_ext/process_events_test_bridge.js" = {
        source = r#"
          import { internals, primordials } from "ext:core/mod.js";

          const {
            ObjectCreate,
            ObjectDefineProperty,
            ObjectFreeze,
            ReflectApply,
          } = primordials;

          const bridge = ObjectCreate(null);
          ObjectDefineProperty(bridge, "dispatchUnhandledRejection", {
            __proto__: null,
            configurable: false,
            enumerable: true,
            value(reason, promise) {
              const callback = internals.nodeProcessUnhandledRejectionCallback;
              if (typeof callback !== "function") {
                throw new Error(
                  "node process unhandled-rejection callback was absent",
                );
              }
              return ReflectApply(
                  callback,
                  internals,
                  [promise, reason],
                )
                ? 1
                : 0;
            },
            writable: false,
          });
          ObjectDefineProperty(bridge, "dispatchGlobalError", {
            __proto__: null,
            configurable: false,
            enumerable: true,
            value(error) {
              const callback = internals.nodeProcessErrorCallback;
              if (typeof callback !== "function") {
                throw new Error(
                  "node process global error listener was absent",
                );
              }
              return ReflectApply(callback, internals, [error]) ? 1 : 0;
            },
            writable: false,
          });
          ObjectDefineProperty(bridge, "installTrustedProcessEventTable", {
            __proto__: null,
            configurable: false,
            enumerable: true,
            value(table) {
              const token = internals.nodeProcessTrustedToken;
              const replace =
                internals.nodeProcessReplaceEventTableInternal;
              if (token === undefined || typeof replace !== "function") {
                throw new Error(
                  "trusted process event-table fixture channel was absent",
                );
              }
              return ReflectApply(replace, internals, [token, table]);
            },
            writable: false,
          });
          ObjectDefineProperty(
            globalThis,
            "__rev2ProcessUnhandledRejectionFixture",
            {
              __proto__: null,
              configurable: false,
              enumerable: false,
              value: ObjectFreeze(bridge),
              writable: false,
            },
          );
        "#
      },
    ],
    state = |state| {
      state.put::<PermissionsContainer>(native_test_permissions(false));
    }
  );

  // The real node:os wrapper loaded by process.report references this lazy
  // scripts, but the focused deno_node unit-test runtime does not otherwise
  // depend on deno_os. None of their ops are exercised by these fixtures; the
  // scripts supply the actual osUptime export and immutable signal functions
  // that node:process captures while evaluating.
  deno_core::extension!(
    deno_os,
    ops = [
      op_signal_bind,
      op_signal_bind_internal,
      op_signal_poll,
      op_signal_unbind,
    ],
    lazy_loaded_js = [dir "../os", "30_os.js", "40_signals.js"]
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
    PROCESS_SIGNAL_BIND_COUNT.store(0, Ordering::SeqCst);
    PROCESS_SIGNAL_INTERNAL_BIND_COUNT.store(0, Ordering::SeqCst);
    PROCESS_SIGNAL_POLL_COUNT.store(0, Ordering::SeqCst);
    PROCESS_SIGNAL_UNBIND_COUNT.store(0, Ordering::SeqCst);
    PROCESS_SIGNAL_NEXT_RID.store(1, Ordering::SeqCst);
    PROCESS_SIGNAL_FAIL_NEXT_UNBIND.store(false, Ordering::SeqCst);
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
    if !specifier.ends_with(".ts") && !specifier.starts_with("node:") {
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

  fn new_public_v8_wrapper_runtime_with_extra_extensions(
    extra_extensions: Vec<deno_core::Extension>,
  ) -> JsRuntime {
    let fs: deno_fs::FileSystemRc = Rc::new(deno_fs::RealFs);
    let mut extensions = vec![
      deno_webidl::deno_webidl::init(),
      deno_web::deno_web::init(
        deno_web::BlobStore::default_arc(),
        Default::default(),
        Default::default(),
        deno_web::InMemoryBroadcastChannel::default(),
      ),
    ];
    extensions.extend(extra_extensions);
    extensions.extend([
      deno_io::deno_io::init(Some(Default::default())),
      deno_fs::deno_fs::init(fs.clone()),
      crate::deno_node::init::<
        DenoInNpmPackageChecker,
        NpmResolver<sys_traits::impls::RealSys>,
        sys_traits::impls::RealSys,
      >(None, fs),
      public_v8_wrapper_guard_test_ext::init(),
    ]);
    let runtime = JsRuntime::new(RuntimeOptions {
      extensions,
      extension_transpiler: Some(Rc::new(transpile_public_v8_fixture_source)),
      ..Default::default()
    });
    runtime
      .op_state()
      .borrow_mut()
      .put::<PermissionsContainer>(native_test_permissions(true));
    runtime
  }

  fn new_public_v8_wrapper_runtime() -> JsRuntime {
    new_public_v8_wrapper_runtime_with_extra_extensions(vec![deno_os::init()])
  }

  fn new_public_process_wrapper_runtime() -> JsRuntime {
    new_public_v8_wrapper_runtime()
  }

  fn load_public_v8_wrapper(runtime: &mut JsRuntime, root: &Path) {
    set_actor(root, "main.ts");
    execute(
      runtime,
      "file:///rev2_public_v8_fixture_load.js",
      r#"
      if (Deno.errors === undefined) {
        Object.defineProperty(Deno, "errors", {
          __proto__: null,
          configurable: true,
          value: Object.freeze({
            __proto__: null,
            NotCapable: class NotCapable extends Error {},
          }),
        });
      }
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

  fn load_public_diagnostics_wrapper(runtime: &mut JsRuntime, root: &Path) {
    set_actor(root, "main.ts");
    execute(
      runtime,
      "file:///rev2_public_diagnostics_fixture_load.js",
      r#"
      {
        const diagnostics = Deno.core.loadExtScript(
          "ext:deno_node/diagnostics_channel.js",
        );
        globalThis.rev2Diagnostics = Object.freeze({
          __proto__: null,
          channel: diagnostics.channel,
          hasSubscribers: diagnostics.hasSubscribers,
          subscribe: diagnostics.subscribe,
          tracingChannel: diagnostics.tracingChannel,
          unsubscribe: diagnostics.unsubscribe,
          Channel: diagnostics.Channel,
        });
      }
      if (
        typeof rev2Diagnostics.channel !== "function" ||
        typeof rev2Diagnostics.hasSubscribers !== "function" ||
        typeof rev2Diagnostics.tracingChannel !== "function" ||
        typeof rev2Diagnostics.Channel !== "function" ||
        Object.getPrototypeOf(rev2Diagnostics) !== null ||
        !Object.isFrozen(rev2Diagnostics) ||
        "channelInternal" in rev2Diagnostics ||
        "tracingChannelInternal" in rev2Diagnostics
      ) {
        throw new Error(
          "the exact public node:diagnostics_channel facade did not load",
        );
      }
      "#
      .to_string(),
    );
  }

  fn load_public_async_hooks_wrapper(runtime: &mut JsRuntime, root: &Path) {
    set_actor(root, "main.ts");
    execute(
      runtime,
      "file:///rev2_public_async_hooks_fixture_load.js",
      r#"
      {
        const asyncHooks = Deno.core.loadExtScript(
          "ext:deno_node/async_hooks.ts",
        );
        globalThis.rev2AsyncHooks = Object.freeze({
          __proto__: null,
          AsyncResource: asyncHooks.AsyncResource,
          createHook: asyncHooks.createHook,
          executionAsyncResource: asyncHooks.executionAsyncResource,
        });
      }
      if (
        typeof rev2AsyncHooks.AsyncResource !== "function" ||
        typeof rev2AsyncHooks.createHook !== "function" ||
        typeof rev2AsyncHooks.executionAsyncResource !== "function" ||
        Object.getPrototypeOf(rev2AsyncHooks) !== null ||
        !Object.isFrozen(rev2AsyncHooks) ||
        Object.keys(rev2AsyncHooks).length !== 3 ||
        "AsyncHook" in rev2AsyncHooks ||
        "createPublicHook" in rev2AsyncHooks ||
        "createInternalHook" in rev2AsyncHooks ||
        "internalHookToken" in rev2AsyncHooks ||
        "emitBefore" in rev2AsyncHooks ||
        "emitAfter" in rev2AsyncHooks
      ) {
        throw new Error(
          "the exact public node:async_hooks facade did not load",
        );
      }
      "#
      .to_string(),
    );
  }

  fn assert_public_async_hooks_guard_precedes_wrapper_work(
    operation: &Rev2V8FixtureOperation,
  ) {
    let public_source = include_str!("../polyfills/async_hooks.ts");
    let internal_source = include_str!("../polyfills/internal/async_hooks.ts");
    let require_source = include_str!("../polyfills/01_require.js");
    assert!(
      !require_source.contains(r#""internal/async_hooks": internalAsyncHooks"#),
      "the bare CJS internal/async_hooks builtin exposes privileged ext-script exports"
    );
    assert_eq!(
      require_source
        .matches(
          "Privileged async-hook factories and raw resource observers remain"
        )
        .count(),
      1,
      "the CJS internal/async_hooks absence boundary is not exact"
    );
    let (scope, operation_anchor, exact_guard_prefix) =
      match operation.operation_id {
        "async-hooks-create-hook" => (
          public_source,
          "function createHook(callbacks:",
          r#"function createHook(callbacks: {
  init?: (
    asyncId: number,
    type: string,
    triggerAsyncId: number,
    resource: unknown,
  ) => void;
  before?: (asyncId: number) => void;
  after?: (asyncId: number) => void;
  destroy?: (asyncId: number) => void;
  promiseResolve?: (asyncId: number) => void;
}) {
  // @ref LLP 0019#runtime-and-memory-inspection [implements]
  // Async hook callbacks observe activity across every principal in the shared
  // isolate, so the initial profile closes registration as runtime inspection.
  op_oden_guard_deny_only_surface(
    "runtime",
    "inspect",
    "async-hooks",
    "node:async_hooks.createHook",
  );
  return createPublicHook(callbacks);"#,
        ),
        "async-hooks-execution-async-resource" => (
          public_source,
          "function executionAsyncResource() {",
          r#"function executionAsyncResource() {
  // @ref LLP 0019#runtime-and-memory-inspection [implements]
  op_oden_guard_deny_only_surface(
    "runtime",
    "inspect",
    "async-resource",
    "node:async_hooks.executionAsyncResource",
  );
  return internalExecutionAsyncResource();"#,
        ),
        "async-hook-disable" => (
          internal_source,
          r#""node:async_hooks.AsyncHook.disable""#,
          r#"  disable() {
    // @ref LLP 0019#runtime-and-memory-inspection [implements]
    op_oden_guard_deny_only_surface(
      "runtime",
      "inspect",
      "async-hooks",
      "node:async_hooks.AsyncHook.disable",
    );
    return disableHook(this);"#,
        ),
        "async-hook-enable" => (
          internal_source,
          r#""node:async_hooks.AsyncHook.enable""#,
          r#"  enable() {
    // @ref LLP 0019#runtime-and-memory-inspection [implements]
    op_oden_guard_deny_only_surface(
      "runtime",
      "inspect",
      "async-hooks",
      "node:async_hooks.AsyncHook.enable",
    );
    return enableHook(this);"#,
        ),
        _ => panic!(
          "unknown public async_hooks fixture operation {}",
          operation.operation_id
        ),
      };
    assert_eq!(
      scope.matches(operation_anchor).count(),
      1,
      "{} async_hooks source anchor is not unique",
      operation.operation_id
    );
    assert!(
      scope.contains(exact_guard_prefix),
      "{} no longer guards before its first observable work",
      operation.operation_id
    );
    if operation.operation_id == "async-hooks-create-hook" {
      let inherited_constructor_prefix = r#"class AsyncHook implements HookInstance {
  constructor(callbacks: HookCallbacks, factoryToken?: object) {
    // @ref LLP 0019#runtime-and-memory-inspection [implements]
    if (factoryToken !== publicHookFactoryToken) {
      op_oden_guard_deny_only_surface(
        "runtime",
        "inspect",
        "async-hooks",
        "node:async_hooks.createHook",
      );
    }
    initializeHook(this, callbacks);"#;
      assert_eq!(
        internal_source
          .matches("class AsyncHook implements HookInstance {")
          .count(),
        1,
        "public AsyncHook implementation anchor is not unique"
      );
      assert!(
        internal_source.contains(inherited_constructor_prefix),
        "recovered public AsyncHook constructor no longer guards before callback reads or hook-state initialization"
      );
    }
  }

  fn load_public_process_active_resources_wrapper(
    runtime: &mut JsRuntime,
    root: &Path,
  ) {
    set_actor(root, "main.ts");
    let target = compiled_rev2_v8_fixture_target().expect(
      "process active-resource fixtures require an exact supported host",
    );
    execute(
      runtime,
      "file:///rev2_public_process_active_resources_fixture_load.js",
      r#"
      {
        const core = Deno.core;
        if (core.build.target !== "unknown") {
          throw new Error(
            "process active-resource fixture build info was already set",
          );
        }
        core.setBuildInfo("__REV2_PROCESS_ACTIVE_TARGET__");
        globalThis.Deno = Object.freeze({
          __proto__: null,
          core,
          build: core.build,
          pid: 4242,
          ppid: 4241,
          env: Object.freeze({
            __proto__: null,
            get() {
              return undefined;
            },
          }),
          cwd() {
            return "/rev2-process-active-fixture";
          },
          hostname() {
            return "rev2-process-active-host";
          },
          networkInterfaces() {
            return [];
          },
        });
        const activeResources = core.loadExtScript(
          "ext:deno_node/internal/process/active_resources.ts",
        );
        const processNamespace =
          core.createLazyLoader("node:process")();
        const processObject = processNamespace.default;
        let handle;
        let request;
        let retiredHandle;
        let retiredRequest;
        const facadeKeys = [
          "getActiveHandles",
          "getActiveRequests",
          "getActiveResourceNames",
        ];
        function isExactFrozenNullFacade(value, keys) {
          if (
            value === null ||
            typeof value !== "object" ||
            Object.getPrototypeOf(value) !== null ||
            !Object.isFrozen(value)
          ) {
            return false;
          }
          const ownKeys = Reflect.ownKeys(value);
          if (
            ownKeys.length !== keys.length ||
            ownKeys.some((key, index) => key !== keys[index])
          ) {
            return false;
          }
          return ownKeys.every((key) => {
            const descriptor = Object.getOwnPropertyDescriptor(value, key);
            return descriptor !== undefined &&
              "value" in descriptor &&
              descriptor.enumerable === true &&
              descriptor.configurable === false &&
              descriptor.writable === false;
          });
        }
        const facade = Object.freeze({
          __proto__: null,
          getActiveHandles: processObject._getActiveHandles,
          getActiveRequests: processObject._getActiveRequests,
          getActiveResourceNames: processObject.getActiveResourcesInfo,
        });
        const controller = Object.freeze({
          __proto__: null,
          seed() {
            if (handle !== undefined || request !== undefined) {
              throw new Error("active-resource fixture was already seeded");
            }
            handle = Object.freeze({
              __proto__: null,
              marker: "rev2-handle",
            });
            request = Object.freeze({
              __proto__: null,
              marker: "rev2-request",
            });
            activeResources.registerActiveHandle(
              handle,
              "Rev2FixtureHandleWrap",
            );
            activeResources.registerActiveRequest(
              request,
              "Rev2FixtureRequestWrap",
            );
          },
          clear() {
            if (handle === undefined || request === undefined) {
              throw new Error("active-resource fixture was not seeded");
            }
            activeResources.unregisterActiveHandle(handle);
            activeResources.unregisterActiveRequest(request);
            retiredHandle = handle;
            retiredRequest = request;
            handle = undefined;
            request = undefined;
          },
          assertState(seeded) {
            if (
              typeof seeded !== "boolean" ||
              (seeded && (handle === undefined || request === undefined)) ||
              (!seeded && (handle !== undefined || request !== undefined))
            ) {
              throw new Error("active-resource fixture state is inexact");
            }
          },
          assertResult(operationId, result, seeded) {
            if (
              typeof operationId !== "string" ||
              typeof seeded !== "boolean" ||
              !Array.isArray(result) ||
              Object.getPrototypeOf(result) !== Array.prototype
            ) {
              throw new Error("active-resource wrapper result shape is inexact");
            }
            function countExact(value) {
              let count = 0;
              for (const entry of result) {
                if (entry === value) {
                  count++;
                }
              }
              return count;
            }
            if (operationId === "process-get-active-handles") {
              const fixtureCount = countExact(
                seeded ? handle : retiredHandle,
              );
              if (
                (seeded && fixtureCount === 1) ||
                (!seeded &&
                  retiredHandle !== undefined &&
                  fixtureCount === 0)
              ) {
                return;
              }
              throw new Error(
                `active-handle wrapper retained an inexact fixture count: ${fixtureCount}`,
              );
            }
            if (operationId === "process-get-active-requests") {
              const fixtureCount = countExact(
                seeded ? request : retiredRequest,
              );
              if (
                (seeded && fixtureCount === 1) ||
                (!seeded &&
                  retiredRequest !== undefined &&
                  fixtureCount === 0)
              ) {
                return;
              }
              throw new Error(
                `active-request wrapper retained an inexact fixture count: ${fixtureCount}`,
              );
            }
            if (operationId === "process-get-active-resource-names") {
              if (result.some((name) => typeof name !== "string")) {
                throw new Error(
                  "active-resource name wrapper returned a non-string name",
                );
              }
              const handleCount = countExact("Rev2FixtureHandleWrap");
              const requestCount = countExact("Rev2FixtureRequestWrap");
              const ordered = result.indexOf("Rev2FixtureHandleWrap") <
                result.indexOf("Rev2FixtureRequestWrap");
              if (
                (seeded &&
                  handleCount === 1 &&
                  requestCount === 1 &&
                  ordered) ||
                (!seeded && handleCount === 0 && requestCount === 0)
              ) {
                return;
              }
              throw new Error(
                `active-resource name wrapper retained inexact fixture counts: ${handleCount}/${requestCount}`,
              );
            }
            throw new Error(
              `unknown active-resource fixture operation ${operationId}`,
            );
          },
        });
        const controllerKeys = [
          "seed",
          "clear",
          "assertState",
          "assertResult",
        ];
        if (
          !isExactFrozenNullFacade(facade, facadeKeys) ||
          !isExactFrozenNullFacade(controller, controllerKeys) ||
          processObject === null ||
          typeof processObject !== "object" ||
          facade.getActiveHandles !== activeResources.getActiveHandles ||
          facade.getActiveRequests !== activeResources.getActiveRequests ||
          facade.getActiveResourceNames !==
            processNamespace.getActiveResourcesInfo ||
          processObject.getActiveResourcesInfo !==
            processNamespace.getActiveResourcesInfo ||
          "constructor" in facade ||
          "prototype" in facade ||
          "__proto__" in facade ||
          "registerActiveHandle" in facade ||
          "registerActiveRequest" in facade ||
          "unregisterActiveHandle" in facade ||
          "unregisterActiveRequest" in facade
        ) {
          throw new Error(
            "the exact process active-resource facade did not load",
          );
        }
        const inherited = Object.create(facade);
        const constructorLaundered = Object.create(null);
        Object.defineProperties(constructorLaundered, {
          getActiveHandles: {
            value: facade.getActiveHandles,
            enumerable: true,
          },
          getActiveRequests: {
            value: facade.getActiveRequests,
            enumerable: true,
          },
          getActiveResourceNames: {
            value: facade.getActiveResourceNames,
            enumerable: true,
          },
          constructor: {
            value: function FixtureConstructor() {},
            enumerable: true,
          },
        });
        Object.freeze(constructorLaundered);
        const prototypeLaundered = Object.freeze(Object.create(
          { getActiveHandles: facade.getActiveHandles },
          {
            getActiveRequests: {
              value: facade.getActiveRequests,
              enumerable: true,
            },
            getActiveResourceNames: {
              value: facade.getActiveResourceNames,
              enumerable: true,
            },
          },
        ));
        if (
          isExactFrozenNullFacade(inherited, facadeKeys) ||
          isExactFrozenNullFacade(constructorLaundered, facadeKeys) ||
          isExactFrozenNullFacade(prototypeLaundered, facadeKeys)
        ) {
          throw new Error(
            "active-resource facade admitted inherited or constructor/prototype laundering",
          );
        }
        globalThis.rev2ProcessActiveResources = facade;
        globalThis.rev2ProcessActiveResourcesController = controller;
      }
      "#
      .replace("__REV2_PROCESS_ACTIVE_TARGET__", target),
    );
  }

  fn load_public_process_report_wrapper(runtime: &mut JsRuntime, root: &Path) {
    set_actor(root, "main.ts");
    let target = compiled_rev2_v8_fixture_target()
      .expect("process report fixtures require an exact supported host");
    execute(
      runtime,
      "file:///rev2_public_process_report_fixture_load.js",
      r#"
      {
        const core = Deno.core;
        if (core.build.target !== "unknown") {
          throw new Error("process report fixture build info was already set");
        }
        core.setBuildInfo("__REV2_PROCESS_REPORT_TARGET__");
        const work = {
          __proto__: null,
          cwdCalls: 0,
          hostnameCalls: 0,
          networkInterfaceCalls: 0,
        };
        const fixtureDeno = Object.freeze({
          __proto__: null,
          core,
          build: core.build,
          pid: 4242,
          ppid: 4241,
          env: Object.freeze({
            __proto__: null,
            get() {
              return undefined;
            },
          }),
          cwd() {
            work.cwdCalls++;
            return "/rev2-process-report-fixture";
          },
          hostname() {
            work.hostnameCalls++;
            return "rev2-process-report-host";
          },
          networkInterfaces() {
            work.networkInterfaceCalls++;
            return [];
          },
        });
        globalThis.Deno = fixtureDeno;
        const processNamespace =
          core.createLazyLoader("node:process")();
        const processObject = processNamespace.default;
        const reportModule = core.loadExtScript(
          "ext:deno_node/internal/process/report.ts",
        );
        const facadeKeys = ["getReport", "writeReport"];
        function isExactFrozenNullFacade(value, keys) {
          if (
            value === null ||
            typeof value !== "object" ||
            Object.getPrototypeOf(value) !== null ||
            !Object.isFrozen(value)
          ) {
            return false;
          }
          const ownKeys = Reflect.ownKeys(value);
          if (
            ownKeys.length !== keys.length ||
            ownKeys.some((key, index) => key !== keys[index])
          ) {
            return false;
          }
          return ownKeys.every((key) => {
            const descriptor = Object.getOwnPropertyDescriptor(value, key);
            return descriptor !== undefined &&
              "value" in descriptor &&
              descriptor.enumerable === true &&
              descriptor.configurable === false &&
              descriptor.writable === false;
          });
        }
        const facade = Object.freeze({
          __proto__: null,
          getReport: processObject.report.getReport,
          writeReport: processObject.report.writeReport,
        });
        const controller = Object.freeze({
          __proto__: null,
          reset() {
            work.cwdCalls = 0;
            work.hostnameCalls = 0;
            work.networkInterfaceCalls = 0;
          },
          assertCounts(cwdCalls, hostnameCalls, networkInterfaceCalls) {
            if (
              !Number.isSafeInteger(cwdCalls) ||
              !Number.isSafeInteger(hostnameCalls) ||
              !Number.isSafeInteger(networkInterfaceCalls) ||
              work.cwdCalls !== cwdCalls ||
              work.hostnameCalls !== hostnameCalls ||
              work.networkInterfaceCalls !== networkInterfaceCalls
            ) {
              throw new Error("process report work canaries are inexact");
            }
          },
        });
        const controllerKeys = ["reset", "assertCounts"];
        if (
          !isExactFrozenNullFacade(facade, facadeKeys) ||
          !isExactFrozenNullFacade(controller, controllerKeys) ||
          processObject === null ||
          typeof processObject !== "object" ||
          facade.getReport !== reportModule.report.getReport ||
          facade.writeReport !== reportModule.report.writeReport ||
          processObject.report !== reportModule.report ||
          Object.getPrototypeOf(fixtureDeno) !== null ||
          !Object.isFrozen(fixtureDeno) ||
          "constructor" in facade ||
          "prototype" in facade ||
          "__proto__" in facade ||
          "report" in facade ||
          "filename" in facade ||
          "directory" in facade
        ) {
          throw new Error("the exact process report facade did not load");
        }
        const inherited = Object.create(facade);
        const constructorLaundered = Object.create(null);
        Object.defineProperties(constructorLaundered, {
          getReport: {
            value: facade.getReport,
            enumerable: true,
          },
          writeReport: {
            value: facade.writeReport,
            enumerable: true,
          },
          constructor: {
            value: function FixtureConstructor() {},
            enumerable: true,
          },
        });
        Object.freeze(constructorLaundered);
        const prototypeLaundered = Object.freeze(Object.create(
          { getReport: facade.getReport },
          {
            writeReport: {
              value: facade.writeReport,
              enumerable: true,
            },
          },
        ));
        if (
          isExactFrozenNullFacade(inherited, facadeKeys) ||
          isExactFrozenNullFacade(constructorLaundered, facadeKeys) ||
          isExactFrozenNullFacade(prototypeLaundered, facadeKeys)
        ) {
          throw new Error(
            "process report facade admitted inherited or constructor/prototype laundering",
          );
        }
        globalThis.rev2ProcessReport = facade;
        globalThis.rev2ProcessReportController = controller;
      }
      "#
      .replace("__REV2_PROCESS_REPORT_TARGET__", target),
    );
  }

  fn load_public_process_events_wrapper(runtime: &mut JsRuntime, root: &Path) {
    set_actor(root, "main.ts");
    let target = compiled_rev2_v8_fixture_target()
      .expect("process event fixtures require an exact supported host");
    execute(
      runtime,
      "file:///rev2_public_process_events_fixture_load.js",
      r#"
      {
        const core = Deno.core;
        let mutableDenoSignalCalls = 0;
        if (core.build.target !== "unknown") {
          throw new Error("process event fixture build info was already set");
        }
        core.setBuildInfo("__REV2_PROCESS_EVENTS_TARGET__");
        globalThis.Deno = Object.freeze({
          __proto__: null,
          core,
          build: core.build,
          pid: 4242,
          ppid: 4241,
          env: Object.freeze({
            __proto__: null,
            get() {
              return undefined;
            },
          }),
          cwd() {
            return "/rev2-process-events-fixture";
          },
          hostname() {
            return "rev2-process-events-host";
          },
          networkInterfaces() {
            return [];
          },
          addSignalListener() {
            mutableDenoSignalCalls++;
          },
          removeSignalListener() {
            mutableDenoSignalCalls++;
          },
        });

        const { EventEmitter } = core.loadExtScript(
          "ext:deno_node/_events.mjs",
        );
        const retainedPoisonedEvents = Object.create(null);
        const originalEventEmitterInit = EventEmitter.init;
        let poisonedInitCalls = 0;
        let poisonedStorageCalls = 0;
        let poisonedMethodAccessorCalls = 0;
        const poisonedDescriptors = new Map();
        const storageNames = ["_events", "_eventsCount", "_maxListeners"];
        for (const name of storageNames) {
          const descriptor = Reflect.getOwnPropertyDescriptor(
            EventEmitter.prototype,
            name,
          );
          poisonedDescriptors.set(name, descriptor);
          Object.defineProperty(EventEmitter.prototype, name, {
            __proto__: null,
            configurable: true,
            get() {
              poisonedStorageCalls++;
              return name === "_events"
                ? retainedPoisonedEvents
                : descriptor?.value;
            },
            set(_value) {
              poisonedStorageCalls++;
            },
          });
        }
        const poisonedMethodNames = [
          "on",
          "off",
          "emit",
          "prependListener",
          "once",
          "prependOnceListener",
          "addListener",
          "removeListener",
          "removeAllListeners",
          "listeners",
          "rawListeners",
          "listenerCount",
        ];
        for (const name of poisonedMethodNames) {
          const descriptor = Reflect.getOwnPropertyDescriptor(
            EventEmitter.prototype,
            name,
          );
          poisonedDescriptors.set(name, descriptor);
          Object.defineProperty(EventEmitter.prototype, name, {
            __proto__: null,
            configurable: true,
            get() {
              poisonedMethodAccessorCalls++;
              return descriptor?.value;
            },
            set(_value) {
              poisonedMethodAccessorCalls++;
            },
          });
        }
        EventEmitter.init = function () {
          poisonedInitCalls++;
        };
        let processNamespace;
        try {
          processNamespace = core.createLazyLoader("node:process")();
        } finally {
          EventEmitter.init = originalEventEmitterInit;
          for (const [name, descriptor] of poisonedDescriptors) {
            Reflect.defineProperty(
              EventEmitter.prototype,
              name,
              descriptor,
            );
          }
        }
        const processObject = processNamespace.default;
        const exceptionFixture =
          globalThis.__rev2ProcessUnhandledRejectionFixture;
        function poisonedExceptionListener() {}
        retainedPoisonedEvents.uncaughtException = poisonedExceptionListener;
        if (
          poisonedInitCalls !== 0 ||
          poisonedStorageCalls !== 0 ||
          poisonedMethodAccessorCalls !== 0 ||
          processObject.rawListeners("uncaughtException").includes(
            poisonedExceptionListener,
          )
        ) {
          throw new Error(
            "lazy process initialization trusted poisoned EventEmitter state",
          );
        }
        const sentinelEvent = "rev2-fixture-sentinel";
        const ordinaryEvent = "rev2-fixture-ordinary";
        const reentrantAccessorEvent = "rev2-fixture-reentrant-accessor";
        const reentrantValueEvent = "rev2-fixture-reentrant-value";
        const getterAccessorEvent = Symbol("rev2-fixture-getter-accessor");
        const setterAccessorEvent = Symbol("rev2-fixture-setter-accessor");
        function sentinelListener() {}
        function ordinaryListener() {}
        let exceptionDeliveryCount = 0;
        function exceptionListener() {
          exceptionDeliveryCount++;
        }
        function metaListener() {}
        function candidateListener() {}

        let table;
        let guardedTable;
        let prepared = false;
        let getterAccessorReceiver;
        let setterAccessorReceiver;
        let reentrantAccessorMode;
        let reentrantAccessorReceiver;
        let reentrantValueMode;
        let reentrantValueReceiver;
        function reenterProtectedProcessEventSurface(mode, targetEvent) {
          if (mode === "table") {
            Reflect.defineProperty(
              processObject._events,
              "removeListener",
              {
                __proto__: null,
                value: candidateListener,
                writable: true,
                enumerable: true,
                configurable: true,
              },
            );
          } else if (mode === "emission") {
            processObject.emit(
              "removeListener",
              targetEvent,
              ordinaryListener,
            );
          } else {
            throw new Error("process event reentrant mode was absent");
          }
        }
        function getterAccessor() {
          getterAccessorReceiver = this;
          return this;
        }
        function setterAccessor() {
          setterAccessorReceiver = this;
        }
        function reentrantAccessor() {
          reentrantAccessorReceiver = this;
          reenterProtectedProcessEventSurface(
            reentrantAccessorMode,
            reentrantAccessorEvent,
          );
          return ordinaryListener;
        }
        const reentrantValueListener = new Proxy(
          function reentrantValueListenerTarget() {},
          {
            __proto__: null,
            get(target, property, receiver) {
              if (property === "listener") {
                reentrantValueReceiver = receiver;
                reenterProtectedProcessEventSurface(
                  reentrantValueMode,
                  reentrantValueEvent,
                );
                return ordinaryListener;
              }
              return Reflect.get(target, property, receiver);
            },
          },
        );
        const commits = {
          __proto__: null,
          replacement: 0,
          sensitive: 0,
          addition: 0,
          removal: 0,
        };

        function countExactListener(event, listener) {
          const value = table[event];
          if (value === listener) return 1;
          if (!Array.isArray(value)) return 0;
          let count = 0;
          for (const entry of value) {
            if (entry === listener) count++;
          }
          return count;
        }

        function installTable(nextTable = undefined, trusted = false) {
          nextTable ??= Object.create(null);
          if (trusted) {
            exceptionFixture.installTrustedProcessEventTable(nextTable);
          } else {
            processObject._events = nextTable;
          }
          table = nextTable;
          guardedTable = processObject._events;
          processObject.on(sentinelEvent, sentinelListener);
        }

        installTable(undefined, true);

        const facade = Object.freeze({
          __proto__: null,
          replaceEvents() {
            installTable(Object.create(null));
            commits.replacement++;
          },
          sensitiveGet() {
            const result = processObject._events.uncaughtException;
            commits.sensitive++;
            return result;
          },
          sensitiveSet() {
            processObject._events.uncaughtException = candidateListener;
            commits.sensitive++;
          },
          sensitiveDefineProperty() {
            Reflect.defineProperty(
              processObject._events,
              "uncaughtException",
              {
                __proto__: null,
                value: candidateListener,
                writable: true,
                enumerable: true,
                configurable: true,
              },
            );
            commits.sensitive++;
          },
          sensitiveDeleteProperty() {
            Reflect.deleteProperty(
              processObject._events,
              "uncaughtException",
            );
            commits.sensitive++;
          },
          sensitiveHas() {
            const result = "uncaughtException" in processObject._events;
            commits.sensitive++;
            return result;
          },
          sensitiveOwnKeys() {
            const result = Reflect.ownKeys(processObject._events);
            commits.sensitive++;
            return result;
          },
          sensitiveDescriptor() {
            const result = Reflect.getOwnPropertyDescriptor(
              processObject._events,
              "uncaughtException",
            );
            commits.sensitive++;
            return result;
          },
          sensitiveAccessorGetterReceiver() {
            const accessorReceiver =
              processObject._events[getterAccessorEvent];
            const result = accessorReceiver.uncaughtException;
            commits.sensitive++;
            return result;
          },
          sensitiveAccessorSetterReceiver() {
            processObject._events[setterAccessorEvent] = candidateListener;
            setterAccessorReceiver.uncaughtException = candidateListener;
            commits.sensitive++;
          },
          sensitiveGetPrototypeOf() {
            const result = Reflect.getPrototypeOf(processObject._events);
            commits.sensitive++;
            return result;
          },
          sensitiveSetPrototypeOf() {
            const prototype = Object.create(null);
            prototype.uncaughtException = candidateListener;
            const result = Reflect.setPrototypeOf(
              processObject._events,
              prototype,
            );
            commits.sensitive++;
            return result;
          },
          sensitiveIsExtensible() {
            const result = Reflect.isExtensible(processObject._events);
            commits.sensitive++;
            return result;
          },
          sensitivePreventExtensions() {
            const result = Reflect.preventExtensions(processObject._events);
            commits.sensitive++;
            return result;
          },
          sensitiveFreeze() {
            const result = Object.freeze(processObject._events);
            commits.sensitive++;
            return result;
          },
          sensitiveSeal() {
            const result = Object.seal(processObject._events);
            commits.sensitive++;
            return result;
          },
          sensitiveTrustedTableReentrancy() {
            reentrantAccessorMode = "table";
            try {
              processObject.off(
                reentrantAccessorEvent,
                candidateListener,
              );
              commits.sensitive++;
            } finally {
              reentrantAccessorMode = undefined;
            }
          },
          sensitiveTrustedEmissionReentrancy() {
            reentrantAccessorMode = "emission";
            try {
              processObject.off(
                reentrantAccessorEvent,
                candidateListener,
              );
              commits.sensitive++;
            } finally {
              reentrantAccessorMode = undefined;
            }
          },
          sensitiveReturnedTableReentrancy() {
            reentrantValueMode = "table";
            try {
              processObject.off(
                reentrantValueEvent,
                candidateListener,
              );
              commits.sensitive++;
            } finally {
              reentrantValueMode = undefined;
            }
          },
          sensitiveReturnedEmissionReentrancy() {
            reentrantValueMode = "emission";
            try {
              processObject.off(
                reentrantValueEvent,
                candidateListener,
              );
              commits.sensitive++;
            } finally {
              reentrantValueMode = undefined;
            }
          },
          borrowedRemoveException() {
            Reflect.apply(
              EventEmitter.prototype.removeListener,
              processObject,
              ["uncaughtException", exceptionListener],
            );
            commits.sensitive++;
          },
          borrowedRemoveMeta() {
            Reflect.apply(
              EventEmitter.prototype.removeListener,
              processObject,
              ["newListener", metaListener],
            );
            commits.sensitive++;
          },
          borrowedEmitException() {
            const result = Reflect.apply(
              EventEmitter.prototype.emit,
              processObject,
              [
                "uncaughtException",
                new Error("rev2 denied borrowed emit"),
              ],
            );
            commits.sensitive++;
            return result;
          },
          addListenerForwarder() {
            const result = processObject.addListener(
              "uncaughtException",
              exceptionListener,
            );
            if (result !== processObject) {
              throw new Error("process.addListener returned an inexact receiver");
            }
            commits.addition++;
          },
          addMetaListenerForwarder() {
            const result = processObject.addListener(
              "newListener",
              metaListener,
            );
            if (result !== processObject) {
              throw new Error(
                "process.addListener meta forwarder returned an inexact receiver",
              );
            }
            commits.addition++;
          },
          removeListenerForwarder() {
            const result = processObject.removeListener(
              "uncaughtException",
              exceptionListener,
            );
            if (result !== processObject) {
              throw new Error(
                "process.removeListener returned an inexact receiver",
              );
            }
            commits.removal++;
          },
          removeMetaListenerForwarder() {
            const result = processObject.removeListener(
              "newListener",
              metaListener,
            );
            if (result !== processObject) {
              throw new Error(
                "process.removeListener meta forwarder returned an inexact receiver",
              );
            }
            commits.removal++;
          },
        });

        function assertCounters(operationId, phase) {
          let replacement = 0;
          let addition = 0;
          let removal = 0;
          if (phase === "clean" || phase === "post-cleanup-denied") {
            if (operationId === "process-events-replacement") {
              replacement = 1;
            } else if (
              operationId === "process-add-listener-forwarder-runtime"
            ) {
              addition = 2;
            } else if (
              operationId === "process-remove-listener-forwarder-runtime"
            ) {
              removal = 2;
            }
          }
          if (
            commits.replacement !== replacement ||
            commits.sensitive !== 0 ||
            commits.addition !== addition ||
            commits.removal !== removal
          ) {
            throw new Error(
              `${operationId}/${phase} retained inexact process event work`,
            );
          }
        }

        function assertState(operationId, phase) {
          if (
            processObject._events !== guardedTable ||
            countExactListener(sentinelEvent, sentinelListener) !== 1
          ) {
            throw new Error(
              `${operationId}/${phase} changed the guarded event table`,
            );
          }
          const primarySeeded = phase === "denied" && (
            operationId === "process-events-sensitive-table" ||
            operationId === "process-remove-listener-forwarder-runtime"
          );
          const metaOnlySeeded = phase === "meta-only-own-keys";
          const exceptionCount = countExactListener(
            "uncaughtException",
            exceptionListener,
          );
          const metaCount = countExactListener("newListener", metaListener);
          const expectedExceptionCount = primarySeeded ? 1 : 0;
          const expectedMetaCount =
            (primarySeeded &&
                (operationId === "process-events-sensitive-table" ||
                  operationId ===
                    "process-remove-listener-forwarder-runtime")) ||
              metaOnlySeeded
              ? 1
              : 0;
          const expectedEventCount = 1 + expectedExceptionCount +
            expectedMetaCount;
          const keys = Reflect.ownKeys(table);
          const accessorsSeeded = primarySeeded &&
            operationId === "process-events-sensitive-table";
          const getterDescriptor = Reflect.getOwnPropertyDescriptor(
            table,
            getterAccessorEvent,
          );
          const setterDescriptor = Reflect.getOwnPropertyDescriptor(
            table,
            setterAccessorEvent,
          );
          const reentrantDescriptor = Reflect.getOwnPropertyDescriptor(
            table,
            reentrantAccessorEvent,
          );
          const reentrantValueDescriptor = Reflect.getOwnPropertyDescriptor(
            table,
            reentrantValueEvent,
          );
          const accessorStateIsExact = accessorsSeeded
            ? getterDescriptor?.get === getterAccessor &&
              getterDescriptor?.set === undefined &&
              getterDescriptor.enumerable === true &&
              getterDescriptor.configurable === true &&
              setterDescriptor?.get === undefined &&
              setterDescriptor?.set === setterAccessor &&
              setterDescriptor.enumerable === true &&
              setterDescriptor.configurable === true &&
              reentrantDescriptor?.get === reentrantAccessor &&
              reentrantDescriptor?.set === undefined &&
              reentrantDescriptor.enumerable === true &&
              reentrantDescriptor.configurable === true &&
              reentrantValueDescriptor?.value === reentrantValueListener &&
              reentrantValueDescriptor.writable === true &&
              reentrantValueDescriptor.enumerable === true &&
              reentrantValueDescriptor.configurable === true &&
              getterAccessorReceiver === guardedTable &&
              setterAccessorReceiver === guardedTable &&
              reentrantAccessorReceiver === guardedTable &&
              reentrantAccessorMode === undefined &&
              reentrantValueReceiver === reentrantValueListener &&
              reentrantValueMode === undefined
            : getterDescriptor === undefined &&
              setterDescriptor === undefined &&
              reentrantDescriptor === undefined &&
              reentrantValueDescriptor === undefined &&
              getterAccessorReceiver === undefined &&
              setterAccessorReceiver === undefined &&
              reentrantAccessorReceiver === undefined &&
              reentrantAccessorMode === undefined &&
              reentrantValueReceiver === undefined &&
              reentrantValueMode === undefined;
          if (
            exceptionCount !== expectedExceptionCount ||
            metaCount !== expectedMetaCount ||
            countExactListener("uncaughtException", candidateListener) !== 0 ||
            exceptionDeliveryCount !== 0 ||
            Object.getPrototypeOf(table) !== null ||
            !Object.isExtensible(table) ||
            !accessorStateIsExact ||
            keys.length !== expectedEventCount + (accessorsSeeded ? 4 : 0) ||
            !keys.includes(sentinelEvent) ||
            accessorsSeeded !== keys.includes(getterAccessorEvent) ||
            accessorsSeeded !== keys.includes(setterAccessorEvent) ||
            accessorsSeeded !== keys.includes(reentrantAccessorEvent) ||
            accessorsSeeded !== keys.includes(reentrantValueEvent) ||
            (expectedExceptionCount === 1) !==
              keys.includes("uncaughtException") ||
            (expectedMetaCount === 1) !== keys.includes("newListener")
          ) {
            throw new Error(
              `${operationId}/${phase} retained inexact process event state: ` +
                JSON.stringify({
                  accessorStateIsExact,
                  exceptionCount,
                  exceptionDeliveryCount,
                  expectedEventCount,
                  expectedExceptionCount,
                  expectedMetaCount,
                  extensible: Object.isExtensible(table),
                  keys: keys.map((key) => String(key)),
                  metaCount,
                  prototypeIsNull: Object.getPrototypeOf(table) === null,
                  sentinelCount: countExactListener(
                    sentinelEvent,
                    sentinelListener,
                  ),
                }),
            );
          }
          assertCounters(operationId, phase);
        }

        const controller = Object.freeze({
          __proto__: null,
          prepare(operationId) {
            if (prepared) {
              throw new Error("process event fixture was already prepared");
            }
            assertState(operationId, "initial");
            if (operationId === "process-events-sensitive-table") {
              processObject.on("uncaughtException", exceptionListener);
              processObject.on("newListener", metaListener);
              if (
                !Reflect.defineProperty(table, getterAccessorEvent, {
                  __proto__: null,
                  get: getterAccessor,
                  enumerable: true,
                  configurable: true,
                }) ||
                !Reflect.defineProperty(table, setterAccessorEvent, {
                  __proto__: null,
                  set: setterAccessor,
                  enumerable: true,
                  configurable: true,
                }) ||
                !Reflect.defineProperty(table, reentrantAccessorEvent, {
                  __proto__: null,
                  get: reentrantAccessor,
                  enumerable: true,
                  configurable: true,
                }) ||
                !Reflect.defineProperty(table, reentrantValueEvent, {
                  __proto__: null,
                  value: reentrantValueListener,
                  writable: true,
                  enumerable: true,
                  configurable: true,
                })
              ) {
                throw new Error(
                  "process event accessor fixture could not be seeded",
                );
              }
            } else if (
              operationId === "process-remove-listener-forwarder-runtime"
            ) {
              processObject.on("uncaughtException", exceptionListener);
              processObject.on("newListener", metaListener);
            } else if (
              operationId !== "process-events-replacement" &&
              operationId !== "process-add-listener-forwarder-runtime"
            ) {
              throw new Error(
                `unknown process event fixture operation ${operationId}`,
              );
            }
            prepared = true;
          },
          assertDenied(operationId) {
            if (!prepared) {
              throw new Error("process event fixture was not prepared");
            }
            assertState(operationId, "denied");
          },
          cleanup(operationId) {
            if (!prepared) {
              throw new Error("process event fixture was not prepared");
            }
            if (operationId === "process-events-replacement") {
              facade.replaceEvents();
            } else if (operationId === "process-events-sensitive-table") {
              Reflect.deleteProperty(table, getterAccessorEvent);
              Reflect.deleteProperty(table, setterAccessorEvent);
              Reflect.deleteProperty(table, reentrantAccessorEvent);
              Reflect.deleteProperty(table, reentrantValueEvent);
              getterAccessorReceiver = undefined;
              setterAccessorReceiver = undefined;
              reentrantAccessorReceiver = undefined;
              reentrantAccessorMode = undefined;
              reentrantValueReceiver = undefined;
              reentrantValueMode = undefined;
              processObject.off("uncaughtException", exceptionListener);
              processObject.off("newListener", metaListener);
            } else if (
              operationId === "process-add-listener-forwarder-runtime"
            ) {
              facade.addListenerForwarder();
              facade.addMetaListenerForwarder();
              processObject.off("uncaughtException", exceptionListener);
              processObject.off("newListener", metaListener);
            } else if (
              operationId === "process-remove-listener-forwarder-runtime"
            ) {
              facade.removeListenerForwarder();
              facade.removeMetaListenerForwarder();
            } else {
              throw new Error(
                `unknown process event fixture operation ${operationId}`,
              );
            }
            processObject.on(ordinaryEvent, ordinaryListener);
            if (countExactListener(ordinaryEvent, ordinaryListener) !== 1) {
              throw new Error("ordinary process event addition was unusable");
            }
            processObject.off(ordinaryEvent, ordinaryListener);
            if (countExactListener(ordinaryEvent, ordinaryListener) !== 0) {
              throw new Error("ordinary process event cleanup was unusable");
            }
            prepared = false;
            assertState(operationId, "clean");
          },
          assertClean(operationId) {
            if (prepared) {
              throw new Error("process event fixture remained prepared");
            }
            assertState(operationId, "clean");
          },
          assertPostCleanupDenied(operationId) {
            if (prepared) {
              throw new Error("process event fixture was re-prepared");
            }
            assertState(operationId, "post-cleanup-denied");
          },
          prepareMetaOnlyOwnKeys(operationId) {
            if (
              operationId !== "process-events-sensitive-table" || prepared
            ) {
              throw new Error(
                "process event meta-only fixture was inexactly prepared",
              );
            }
            assertState(operationId, "clean");
            processObject.on("newListener", metaListener);
            prepared = true;
            assertState(operationId, "meta-only-own-keys");
          },
          assertMetaOnlyOwnKeysDenied(operationId) {
            if (
              operationId !== "process-events-sensitive-table" || !prepared
            ) {
              throw new Error(
                "process event meta-only fixture was not prepared",
              );
            }
            assertState(operationId, "meta-only-own-keys");
          },
          cleanupMetaOnlyOwnKeys(operationId) {
            if (
              operationId !== "process-events-sensitive-table" || !prepared
            ) {
              throw new Error(
                "process event meta-only fixture was not prepared for cleanup",
              );
            }
            processObject.off("newListener", metaListener);
            prepared = false;
            assertState(operationId, "clean");
          },
          assertSignalContract() {
            if (prepared) {
              throw new Error("process signal fixture remained prepared");
            }
            assertState("process-events-sensitive-table", "clean");
            processObject.off(sentinelEvent, sentinelListener);

            function staleExceptionOne() {}
            function staleExceptionTwo() {}
            processObject.on("uncaughtException", staleExceptionOne);
            processObject.on("uncaughtException", staleExceptionTwo);
            const selfGuard = processObject._events;
            processObject._events = selfGuard;
            const selfSnapshot = processObject._events.uncaughtException;
            selfSnapshot.length = 0;
            if (
              processObject._events !== selfGuard ||
              processObject.listenerCount("uncaughtException") !== 2
            ) {
              throw new Error(
                "process event-table self-assignment exposed owned listeners",
              );
            }
            processObject._events = Object.create(null);
            let staleGuardRefused = false;
            try {
              processObject._events = selfGuard;
            } catch (error) {
              staleGuardRefused = error instanceof TypeError;
            }
            processObject._events = new Proxy(selfGuard, {
              __proto__: null,
            });
            let nestedStaleReadRefused = false;
            try {
              void processObject._events.uncaughtException;
            } catch (error) {
              nestedStaleReadRefused = error instanceof TypeError;
            }
            if (!staleGuardRefused || !nestedStaleReadRefused) {
              throw new Error("stale process event-table guard was reusable");
            }
            processObject._events = Object.create(null);

            function seededSignalOne() {}
            function seededSignalTwo() {}
            const seededSignalListeners = [
              seededSignalOne,
              seededSignalTwo,
            ];
            const seededSignalTable = Object.create(null);
            seededSignalTable.SIGUSR2 = seededSignalListeners;
            processObject._events = seededSignalTable;
            let seededSignalRemovalRefused = false;
            try {
              processObject.off("SIGUSR2", seededSignalTwo);
            } catch (error) {
              seededSignalRemovalRefused = error instanceof TypeError;
            }
            if (
              !seededSignalRemovalRefused ||
              seededSignalListeners.length !== 2 ||
              seededSignalListeners[0] !== seededSignalOne ||
              seededSignalListeners[1] !== seededSignalTwo
            ) {
              throw new Error(
                "unregistered process signal table mutated before refusal",
              );
            }
            processObject._events = Object.create(null);
            processObject.on(ordinaryEvent, ordinaryListener);
            processObject.off(ordinaryEvent, ordinaryListener);

            const delivered = [];
            function duplicate(signal) {
              delivered.push(`duplicate:${signal}`);
            }
            function prepended(signal) {
              delivered.push(`prepended:${signal}`);
            }
            function once(signal) {
              delivered.push(`once:${signal}`);
            }
            function borrowed(signal) {
              delivered.push(`borrowed:${signal}`);
            }

            processObject.on("SIGUSR2", duplicate);
            processObject.on("SIGUSR2", duplicate);
            processObject.prependListener("SIGUSR2", prepended);
            let mutableLifecycleForwarderCalls = 0;
            const ownOnDescriptor = Reflect.getOwnPropertyDescriptor(
              processObject,
              "on",
            );
            Object.defineProperty(processObject, "on", {
              __proto__: null,
              configurable: true,
              value() {
                mutableLifecycleForwarderCalls++;
                return this;
              },
              writable: true,
            });
            try {
              Reflect.apply(
                EventEmitter.prototype.once,
                processObject,
                ["SIGUSR2", once],
              );
            } finally {
              if (ownOnDescriptor === undefined) {
                Reflect.deleteProperty(processObject, "on");
              } else {
                Reflect.defineProperty(
                  processObject,
                  "on",
                  ownOnDescriptor,
                );
              }
            }
            Reflect.apply(
              EventEmitter.prototype.on,
              processObject,
              ["SIGUSR2", borrowed],
            );
            function tamperedOnce() {}
            const ownPrependDescriptor = Reflect.getOwnPropertyDescriptor(
              processObject,
              "prependListener",
            );
            Object.defineProperty(processObject, "prependListener", {
              __proto__: null,
              configurable: true,
              value() {
                mutableLifecycleForwarderCalls++;
                return this;
              },
              writable: true,
            });
            try {
              Reflect.apply(
                EventEmitter.prototype.prependOnceListener,
                processObject,
                ["SIGUSR2", tamperedOnce],
              );
            } finally {
              if (ownPrependDescriptor === undefined) {
                Reflect.deleteProperty(processObject, "prependListener");
              } else {
                Reflect.defineProperty(
                  processObject,
                  "prependListener",
                  ownPrependDescriptor,
                );
              }
            }
            const rawTamperedOnce = processObject.rawListeners("SIGUSR2")[0];
            rawTamperedOnce.listener = borrowed;
            if (
              mutableLifecycleForwarderCalls !== 0 ||
              processObject.listeners("SIGUSR2")[0] !== tamperedOnce
            ) {
              throw new Error(
                "borrowed lexical once used mutable forwarding or provenance",
              );
            }
            processObject.off("SIGUSR2", tamperedOnce);
            const exposedList = processObject._events.SIGUSR2;
            const exposedDescriptor = Reflect.getOwnPropertyDescriptor(
              processObject._events,
              "SIGUSR2",
            );
            if (
              !Array.isArray(exposedList) ||
              !Array.isArray(exposedDescriptor?.value) ||
              exposedList === exposedDescriptor.value
            ) {
              throw new Error("protected signal listener snapshots were absent");
            }
            exposedList.length = 0;
            exposedDescriptor.value.length = 0;
            let replacementRefused = false;
            let directMutationRefused = false;
            try {
              processObject._events = Object.create(null);
            } catch (error) {
              replacementRefused = error instanceof TypeError;
            }
            try {
              processObject._events.SIGUSR2 = borrowed;
            } catch (error) {
              directMutationRefused = error instanceof TypeError;
            }
            const listeners = processObject.listeners("SIGUSR2");
            if (
              !replacementRefused ||
              !directMutationRefused ||
              listeners.length !== 5 ||
              listeners[0] !== prepended ||
              listeners[1] !== duplicate ||
              listeners[2] !== duplicate ||
              listeners[3] !== once ||
              listeners[4] !== borrowed
            ) {
              throw new Error(
                "process signal listener order or duplicates were collapsed",
              );
            }
            if (!processObject.emit("SIGUSR2", "SIGUSR2")) {
              throw new Error("process signal table was not emitted");
            }
            if (
              delivered.join("|") !==
                "prepended:SIGUSR2|duplicate:SIGUSR2|duplicate:SIGUSR2|once:SIGUSR2|borrowed:SIGUSR2" ||
              processObject.listenerCount("SIGUSR2") !== 4
            ) {
              throw new Error(
                "process signal once/order delivery was inexact",
              );
            }
            Reflect.apply(
              EventEmitter.prototype.removeListener,
              processObject,
              ["SIGUSR2", duplicate],
            );
            if (processObject.listenerCount("SIGUSR2") !== 3) {
              throw new Error("borrowed signal removal was inexact");
            }
            Reflect.apply(
              EventEmitter.prototype.removeAllListeners,
              processObject,
              ["SIGUSR2"],
            );
            if (
              processObject.listenerCount("SIGUSR2") !== 0 ||
              mutableDenoSignalCalls !== 0
            ) {
              throw new Error(
                "signal cleanup used mutable Deno state or retained listeners",
              );
            }
            processObject._events = Object.create(null);
            processObject.on(ordinaryEvent, ordinaryListener);
            processObject.off(ordinaryEvent, ordinaryListener);
          },
          assertSignalUnbindFailureContract() {
            if (prepared) {
              throw new Error("process signal fixture remained prepared");
            }
            let delivered = 0;
            function retainedAfterFailure() {
              delivered++;
            }
            processObject.on("SIGUSR1", retainedAfterFailure);
            Object.preventExtensions(processObject._events);
            let unbindFailed = false;
            try {
              processObject.off("SIGUSR1", retainedAfterFailure);
            } catch (error) {
              unbindFailed = error instanceof Error &&
                error.message.includes("injected process signal unbind failure");
            }
            if (
              !unbindFailed ||
              processObject.listenerCount("SIGUSR1") !== 1 ||
              processObject.listeners("SIGUSR1")[0] !== retainedAfterFailure ||
              !processObject.emit("SIGUSR1", "SIGUSR1") ||
              delivered !== 1
            ) {
              throw new Error(
                "failed process signal unbind did not restore exact state",
              );
            }
            processObject.off("SIGUSR1", retainedAfterFailure);
            if (processObject.listenerCount("SIGUSR1") !== 0) {
              throw new Error("process signal unbind retry retained listener");
            }
            processObject._events = Object.create(null);
          },
          assertSignalAdditionPreflightContract() {
            if (prepared) {
              throw new Error("process signal fixture remained prepared");
            }
            Object.preventExtensions(processObject._events);
            function refusedSignalAddition() {}
            let additionRefused = false;
            try {
              processObject.on("SIGUSR1", refusedSignalAddition);
            } catch (error) {
              additionRefused = error instanceof TypeError;
            }
            if (
              !additionRefused ||
              processObject.listenerCount("SIGUSR1") !== 0
            ) {
              throw new Error(
                "inextensible process signal table crossed native bind",
              );
            }
            processObject._events = Object.create(null);
            processObject.on(ordinaryEvent, ordinaryListener);
            processObject.off(ordinaryEvent, ordinaryListener);
          },
          assertMixedOwnKeysContract() {
            let hasCalls = 0;
            let ownKeysCalls = 0;
            const mixedKeys = [
              "uncaughtException",
              "unhandledRejection",
              "newListener",
              "removeListener",
              "SIGUSR1",
              "SIGUSR2",
            ];
            const proxy = new Proxy(Object.create(null), {
              __proto__: null,
              has() {
                hasCalls++;
                return false;
              },
              ownKeys() {
                ownKeysCalls++;
                // The outer guarded Proxy takes the first snapshot. V8 then
                // queries the Proxy target once more for invariant checking;
                // make that second result disagree so the test proves only
                // the exact returned snapshot is exposed and guarded.
                return ownKeysCalls === 1 ? mixedKeys : ["ordinary"];
              },
            });
            processObject._events = proxy;
            const observed = Reflect.ownKeys(processObject._events);
            if (
              hasCalls !== 0 ||
              ownKeysCalls !== 2 ||
              observed.length !== mixedKeys.length ||
              observed.some((key, index) => key !== mixedKeys[index])
            ) {
              throw new Error(
                "mixed process ownKeys did not use one exact returned-key snapshot: " +
                  JSON.stringify({
                    hasCalls,
                    observed,
                    ownKeysCalls,
                  }),
              );
            }
            processObject._events = Object.create(null);
          },
        });

        function isExactFrozenNullFacade(value, keys) {
          if (
            value === null ||
            typeof value !== "object" ||
            Object.getPrototypeOf(value) !== null ||
            !Object.isFrozen(value)
          ) {
            return false;
          }
          const ownKeys = Reflect.ownKeys(value);
          if (
            ownKeys.length !== keys.length ||
            ownKeys.some((key, index) => key !== keys[index])
          ) {
            return false;
          }
          return ownKeys.every((key) => {
            const descriptor = Object.getOwnPropertyDescriptor(value, key);
            return descriptor !== undefined &&
              "value" in descriptor &&
              descriptor.enumerable === true &&
              descriptor.configurable === false &&
              descriptor.writable === false &&
              typeof descriptor.value === "function";
          });
        }

        const facadeKeys = [
          "replaceEvents",
          "sensitiveGet",
          "sensitiveSet",
          "sensitiveDefineProperty",
          "sensitiveDeleteProperty",
          "sensitiveHas",
          "sensitiveOwnKeys",
          "sensitiveDescriptor",
          "sensitiveAccessorGetterReceiver",
          "sensitiveAccessorSetterReceiver",
          "sensitiveGetPrototypeOf",
          "sensitiveSetPrototypeOf",
          "sensitiveIsExtensible",
          "sensitivePreventExtensions",
          "sensitiveFreeze",
          "sensitiveSeal",
          "sensitiveTrustedTableReentrancy",
          "sensitiveTrustedEmissionReentrancy",
          "sensitiveReturnedTableReentrancy",
          "sensitiveReturnedEmissionReentrancy",
          "borrowedRemoveException",
          "borrowedRemoveMeta",
          "borrowedEmitException",
          "addListenerForwarder",
          "addMetaListenerForwarder",
          "removeListenerForwarder",
          "removeMetaListenerForwarder",
        ];
        const controllerKeys = [
          "prepare",
          "assertDenied",
          "cleanup",
          "assertClean",
          "assertPostCleanupDenied",
          "prepareMetaOnlyOwnKeys",
          "assertMetaOnlyOwnKeysDenied",
          "cleanupMetaOnlyOwnKeys",
          "assertSignalContract",
          "assertSignalUnbindFailureContract",
          "assertSignalAdditionPreflightContract",
          "assertMixedOwnKeysContract",
        ];
        const forbiddenKeys = [
          "process",
          "events",
          "EventEmitter",
          "constructor",
          "prototype",
          "internals",
          "token",
          "__proto__",
        ];
        if (
          processObject === null ||
          typeof processObject !== "object" ||
          processObject !== processNamespace.default ||
          typeof EventEmitter !== "function" ||
          !isExactFrozenNullFacade(facade, facadeKeys) ||
          !isExactFrozenNullFacade(controller, controllerKeys) ||
          !isExactFrozenNullFacade(exceptionFixture, [
            "dispatchUnhandledRejection",
            "dispatchGlobalError",
            "installTrustedProcessEventTable",
          ]) ||
          forbiddenKeys.some((key) => key in facade || key in controller)
        ) {
          throw new Error("the exact process event fixture facade did not load");
        }
        globalThis.rev2ProcessEvents = facade;
        globalThis.rev2ProcessEventsController = controller;
      }
      "#
      .replace("__REV2_PROCESS_EVENTS_TARGET__", target),
    );
  }

  fn exact_process_source_block<'a>(
    source: &'a str,
    operation_id: &str,
    start_anchor: &str,
    end_anchor: &str,
  ) -> &'a str {
    assert_eq!(
      source.matches(start_anchor).count(),
      1,
      "{operation_id} source anchor is not unique"
    );
    let start = source.find(start_anchor).unwrap();
    let operation = &source[start..];
    let end = operation
      .find(end_anchor)
      .unwrap_or_else(|| panic!("{operation_id} source terminator is absent"));
    &operation[..end]
  }

  fn assert_exact_process_guard_prefix_before_work(
    source: &str,
    operation_id: &str,
    start_anchor: &str,
    end_anchor: &str,
    exact_guard_prefix: &str,
    work_anchor: &str,
  ) {
    let operation = exact_process_source_block(
      source,
      operation_id,
      start_anchor,
      end_anchor,
    );
    let guard_end = operation
      .find(exact_guard_prefix)
      .map(|index| index + exact_guard_prefix.len())
      .unwrap_or_else(|| panic!("{operation_id} lost its exact guard prefix"));
    let work_index = operation
      .find(work_anchor)
      .unwrap_or_else(|| panic!("{operation_id} lost its first work anchor"));
    assert!(
      guard_end <= work_index,
      "{operation_id} no longer guards before its first authority-bearing work"
    );
  }

  fn exact_process_reflect_call_offsets(source: &str) -> Vec<usize> {
    source
      .match_indices("Reflect")
      .filter_map(|(index, _)| {
        let suffix = &source[index..];
        let name_len = suffix
          .bytes()
          .take_while(|byte| byte.is_ascii_alphabetic())
          .count();
        (suffix.as_bytes().get(name_len) == Some(&b'(')).then_some(index)
      })
      .collect()
  }

  fn assert_all_exact_process_reflect_work_after_guard(
    source: &str,
    operation_id: &str,
    start_anchor: &str,
    end_anchor: &str,
    exact_guard_prefix: &str,
    expected_calls: &[(&str, usize)],
  ) {
    let operation = exact_process_source_block(
      source,
      operation_id,
      start_anchor,
      end_anchor,
    );
    let guard_end = operation
      .find(exact_guard_prefix)
      .map(|index| index + exact_guard_prefix.len())
      .unwrap_or_else(|| panic!("{operation_id} lost its exact guard prefix"));
    let reflect_calls = exact_process_reflect_call_offsets(operation);
    let expected_count: usize =
      expected_calls.iter().map(|(_, count)| *count).sum();
    assert_eq!(
      reflect_calls.len(),
      expected_count,
      "{operation_id} contains an unenumerated raw Reflect call"
    );
    for (exact_call, expected_call_count) in expected_calls {
      assert_eq!(
        operation.matches(exact_call).count(),
        *expected_call_count,
        "{operation_id} changed an exact raw Reflect call form"
      );
    }
    for work_index in reflect_calls {
      assert!(
        guard_end <= work_index,
        "{operation_id} performs raw Reflect work before its complete guard prefix"
      );
    }
  }

  fn assert_public_process_event_guard_precedes_wrapper_work(
    operation: &Rev2V8FixtureOperation,
  ) {
    let process_source = include_str!("../polyfills/process.ts");
    let event_emitter_source = include_str!("../polyfills/_events.mjs");
    let os_signal_source = include_str!("../../os/40_signals.js");
    let web_event_source = include_str!("../../web/02_event.js");
    let runtime_main_source = include_str!("../../../runtime/js/99_main.js");
    let event_table_start = process_source
      .find("function wrapProcessEvents(store: any) {")
      .expect("process event-table wrapper is present");
    let event_table_end = process_source[event_table_start..]
      .find("guardedProcessEvents = wrapProcessEvents(processEventsStore);")
      .map(|offset| event_table_start + offset)
      .expect("process event-table wrapper terminator is present");
    let event_table_source =
      &process_source[event_table_start..event_table_end];
    match operation.operation_id {
      "process-events-replacement" => {
        let exact_setter = r#"  set(value) {
    op_oden_guard_deny_only_surface(
      "runtime",
      "inspect",
      "process-events",
      "process._events=set",
    );
    replaceProcessEventTable(process, value);
  },"#;
        assert_eq!(
          process_source
            .matches("ObjectDefineProperty(process, \"_events\", {")
            .count(),
          1,
          "process event-table replacement property is not unique"
        );
        assert!(
          process_source.contains(exact_setter),
          "process event-table replacement no longer guards before retained replacement state"
        );
      }
      "process-events-sensitive-table" => {
        assert_eq!(
          event_table_source
            .matches("ReflectGet(target, property, receiver)")
            .count(),
          1,
          "process event-table reads must retain the guarded proxy receiver"
        );
        assert_eq!(
          event_table_source
            .matches("ReflectSet(target, property, value, receiver)")
            .count(),
          1,
          "process event-table writes must retain the guarded proxy receiver"
        );
        assert!(
          !event_table_source.contains("ReflectGet(target, property, target)")
            && !event_table_source
              .contains("ReflectSet(target, property, value, target)"),
          "process event-table accessors must never receive the raw backing table"
        );
        assert!(
          !process_source.contains("trustedProcessMetaTableAccess")
            && !process_source.contains("trustedProcessEventAccess")
            && !process_source.contains("hasTrustedMetaTableAccess")
            && !process_source
              .contains("withNonReentrantTrustedMetaTableAccess"),
          "process event-table authority must never occupy ambient state"
        );
        assert!(
          process_source.contains("processEventTableAccess = ObjectFreeze({",)
            && process_source
              .contains("trustedProcessEventTableAccess = ObjectFreeze({",)
            && process_source
              .contains("setEventTableAccess(process, processEventTableAccess);",)
            && process_source
              .contains("return addEventListenerWithTableAccess(",)
            && process_source
              .contains("return removeEventListenerWithTableAccess(",)
            && event_emitter_source
              .contains("function addEventListenerWithTableAccess(",)
            && event_emitter_source
              .contains("function removeEventListenerWithTableAccess(",)
            && event_emitter_source.contains(
              "eventTableAccess ??= WeakMapPrototypeGet(lexicalEventTableAccesses, target);",
            ),
          "process EventEmitter mutation lost its closure-private lexical table protocol"
        );
        let lexical_access_start = process_source
          .find("function requireCurrentProcessEventTable(store, guarded) {")
          .expect("process event-table identity reconciliation is present");
        let lexical_access_end = process_source[lexical_access_start..]
          .find("ObjectDefineProperty(process, \"_events\", {")
          .map(|offset| lexical_access_start + offset)
          .expect("process event-table lexical protocol terminator is present");
        let lexical_access_source =
          &process_source[lexical_access_start..lexical_access_end];
        assert!(
          process_source.contains("const coreIsProxy = core.isProxy;")
            && process_source.contains(
              "const trustedProcessEventTables = new SafeWeakSet<object>();",
            )
            && lexical_access_source.contains(
              "!trustedProcessEventTables.has(store) || coreIsProxy(store)",
            )
            && lexical_access_source.contains(
              "function validateDenseProcessEventListenerArray(",
            )
            && lexical_access_source.contains(
              "function snapshotDirectProcessEventListeners(",
            )
            && lexical_access_source.contains(
              "const written = ReflectSet(table, property, storedValue, table);",
            )
            && lexical_access_source.contains(
              "const deleted = ReflectDeleteProperty(table, property);",
            )
            && lexical_access_source.contains(
              "const descriptor = ReflectGetOwnPropertyDescriptor(store, property);",
            )
            && lexical_access_source.contains(
              "return snapshotDirectProcessEventListeners(table, property, handler);",
            )
            && lexical_access_source.contains(
              "return synchronizeDirectProcessEventCount(target, table);",
            )
            && lexical_access_source.contains(
              "return replaceEmptyProcessEventTable(target, table, value);",
            ),
          "lexical table access lost owned-table qualification, descriptor-only snapshots, guarded public mutation, or count/replacement reconciliation"
        );
        let get_trap = exact_process_source_block(
          event_table_source,
          operation.operation_id,
          "    get(target, property, receiver) {",
          "    set(target, property, value, receiver) {",
        );
        assert_eq!(
          exact_process_reflect_call_offsets(get_trap).len(),
          1,
          "process event-table get trap contains an alternate raw Reflect call"
        );
        assert_eq!(
          get_trap
            .matches("ReflectGet(target, property, receiver)")
            .count(),
          1,
          "process event-table get trap changed its exact guarded receiver form"
        );
        let exact_own_keys_guard = r#"      op_oden_guard_deny_only_surface(
        "runtime",
        "inspect",
        "process-events",
        "process._events.ownKeys",
      );"#;
        assert_all_exact_process_reflect_work_after_guard(
          event_table_source,
          operation.operation_id,
          "    ownKeys(target) {",
          "    getOwnPropertyDescriptor(target, property) {",
          exact_own_keys_guard,
          &[("ReflectOwnKeys(target)", 1)],
        );
        let guarded_traps = [
          (
            r#"      guardProcessExceptionEvent(property, "process._events.get");"#,
            "    set(target, property, value, receiver) {",
            r#"      guardProcessExceptionEvent(property, "process._events.get");
      guardProcessMetaEvent(property, "process._events.get");
      guardProcessSignalEvent(property, "inspect", "process._events.get");"#,
            "ReflectGet(target, property, receiver)",
          ),
          (
            "    set(target, property, value, receiver) {",
            "    getPrototypeOf(target) {",
            r#"      guardProcessExceptionEvent(property, "process._events.set");
      guardProcessMetaEvent(property, "process._events.set");
      guardProcessSignalEvent(property, "control", "process._events.set");"#,
            "ReflectSet(target, property, value, receiver)",
          ),
          (
            "    getPrototypeOf(target) {",
            "    setPrototypeOf(target, prototype) {",
            r#"      op_oden_guard_deny_only_surface(
        "runtime",
        "inspect",
        "process-events",
        "process._events.getPrototypeOf",
      );"#,
            "ReflectGetPrototypeOf(target)",
          ),
          (
            "    setPrototypeOf(target, prototype) {",
            "    isExtensible(target) {",
            r#"      op_oden_guard_deny_only_surface(
        "runtime",
        "inspect",
        "process-events",
        "process._events.setPrototypeOf",
      );"#,
            "ReflectGetPrototypeOf(target)",
          ),
          (
            "    isExtensible(target) {",
            "    preventExtensions(target) {",
            r#"      op_oden_guard_deny_only_surface(
        "runtime",
        "inspect",
        "process-events",
        "process._events.isExtensible",
      );"#,
            "ReflectIsExtensible(target)",
          ),
          (
            "    preventExtensions(target) {",
            "    defineProperty(target, property, descriptor) {",
            r#"      op_oden_guard_deny_only_surface(
        "runtime",
        "inspect",
        "process-events",
        "process._events.preventExtensions",
      );"#,
            "ReflectPreventExtensions(target)",
          ),
          (
            "    defineProperty(target, property, descriptor) {",
            "    deleteProperty(target, property) {",
            r#"      guardProcessExceptionEvent(property, "process._events.defineProperty");
      guardProcessMetaEvent(property, "process._events.defineProperty");
      guardProcessSignalEvent(
        property,
        "control",
        "process._events.defineProperty",
      );"#,
            "ReflectDefineProperty(target, property, descriptor)",
          ),
          (
            "    deleteProperty(target, property) {",
            "    has(target, property) {",
            r#"      guardProcessExceptionEvent(property, "process._events.deleteProperty");
      guardProcessMetaEvent(property, "process._events.deleteProperty");
      guardProcessSignalEvent(
        property,
        "control",
        "process._events.deleteProperty",
      );"#,
            "ReflectDeleteProperty(target, property)",
          ),
          (
            "    has(target, property) {",
            "    ownKeys(target) {",
            r#"      guardProcessExceptionEvent(property, "process._events.has");
      guardProcessMetaEvent(property, "process._events.has");
      guardProcessSignalEvent(property, "inspect", "process._events.has");"#,
            "ReflectHas(target, property)",
          ),
          (
            "    getOwnPropertyDescriptor(target, property) {",
            "  });",
            r#"      guardProcessExceptionEvent(
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
      );"#,
            "ReflectGetOwnPropertyDescriptor(target, property)",
          ),
        ];
        for (start_anchor, end_anchor, exact_guard_prefix, work_anchor) in
          guarded_traps
        {
          assert_all_exact_process_reflect_work_after_guard(
            event_table_source,
            operation.operation_id,
            start_anchor,
            end_anchor,
            exact_guard_prefix,
            &[(work_anchor, 1)],
          );
        }
        let protected_direct_mutation_refusal = r#"      if (
        isProtectedProcessExceptionEvent(property) ||
        isProcessSignalEvent(property)
      ) {
        throw new TypeError(
          "direct protected process-table mutation is refused",
        );
      }"#;
        let exact_prototype_refusal = r#"      if (prototype !== ReflectGetPrototypeOf(target)) {
        throw new TypeError(
          "process event-table prototype mutation is refused",
        );
      }
      return true;"#;
        assert_eq!(
          event_table_source
            .matches(protected_direct_mutation_refusal)
            .count(),
          3,
          "set, defineProperty, and deleteProperty must all refuse direct protected process-table mutation after their guards"
        );
        assert!(
          event_table_source.contains(exact_prototype_refusal)
            && !event_table_source.contains("ReflectSetPrototypeOf"),
          "process event-table prototype mutation must be observation-only after admission and refuse every actual change"
        );
        let add_listener_source = exact_process_source_block(
          event_emitter_source,
          operation.operation_id,
          "function _addListener(",
          "function addEventListenerWithTableAccess(",
        );
        let delivery_commit = add_listener_source
          .find("trackEventListener(target, type, listener, delivery);")
          .expect("EventEmitter addition lost delivery-provenance commit");
        let listener_added_commit = add_listener_source
          .find("eventTableAccess?.listenerAdded?.(target, events, type, listener);")
          .expect("EventEmitter addition lost post-commit process bookkeeping");
        let listener_leak_check = add_listener_source
          .find("if (existing !== undefined) {")
          .expect("EventEmitter addition lost post-commit listener leak check");
        assert_eq!(
          add_listener_source
            .matches("eventTableAccess?.listenerAdded?.")
            .count(),
          1,
          "EventEmitter addition must commit process bookkeeping exactly once"
        );
        assert!(
          delivery_commit < listener_added_commit
            && listener_added_commit < listener_leak_check,
          "process listener-add bookkeeping must follow storage/provenance commit and precede later user-observable leak work"
        );
        let remove_listener_source = exact_process_source_block(
          event_emitter_source,
          operation.operation_id,
          "function removeListenerExact(",
          "function removeEventListenerWithTableAccess(",
        );
        let exact_single_listener_removal_commit = r#"      deleteEventTableValue(events, type, eventTableAccess);
      const remaining = decrementEventTableCount(
        target,
        events,
        eventTableAccess,
      );
      eventTableAccess.listenerRemoved?.(target, events, type, list);
      if (remaining === 0) {"#;
        let exact_list_listener_removal_commit = r#"    if (list.length === 1) {
      setEventTableValue(events, type, list[0], eventTableAccess);
    }

    eventTableAccess?.listenerRemoved?.(target, events, type, removed);

    if (
      getLifecycleEventTableValue("#;
        assert_eq!(
          remove_listener_source
            .matches("listenerRemoved?.(target, events, type")
            .count(),
          2,
          "EventEmitter removal must commit process bookkeeping on both exact-listener branches"
        );
        assert!(
          remove_listener_source.contains(exact_single_listener_removal_commit)
            && remove_listener_source
              .contains(exact_list_listener_removal_commit),
          "process listener-removal bookkeeping must follow exact mutation and precede table replacement or public lifecycle delivery"
        );
        assert!(
          !process_source
            .contains("addProcessListenerInternal(process, \"newListener\"",)
            && !process_source.contains(
              "addProcessListenerInternal(process, \"removeListener\"",
            ),
          "process exception bookkeeping must not reside in replaceable public lifecycle-listener entries"
        );
        let borrowed_removal = r#"function removeListenerExact(
  target,
  type,
  listener,
  eventTableAccess = undefined,
  preflight = true,
) {
  eventTableAccess ??= WeakMapPrototypeGet(lexicalEventTableAccesses, target);
  checkListener(listener);
  if (eventTableAccess !== undefined) {
    type = eventTableAccess.normalizeType(type);
    if (preflight) {
      eventTableAccess.preflightType(type, "removeListener");
    }
  }

  const events = getEventTable(target, eventTableAccess);
  if (events === undefined) {
    return target;
  }

  const list = getEventTableValue(events, type, eventTableAccess);"#;
        assert!(
          process_source.contains(
            "Borrowing EventEmitter.prototype must not bypass the process-specific",
          ) && event_emitter_source.contains(borrowed_removal)
            && event_emitter_source.contains(
              "? target._events\n    : eventTableAccess.current(target);",
            )
            && event_emitter_source.contains(
              "eventTableAccess ??= WeakMapPrototypeGet(lexicalEventTableAccesses, target);",
            ),
          "borrowed EventEmitter removal no longer normalizes, preflights, and selects the lexical process table before mutation"
        );
        let trusted_meta_emission = r#"      expected.listener === args[1]
    ) {
      trustedProcessMetaEmission = undefined;
      trustedMetaEmission = true;"#;
        assert!(
          process_source.contains(trusted_meta_emission)
            && process_source
              .contains("? trustedProcessEventTableAccess\n        : processEventTableAccess",)
            && event_emitter_source
              .contains("function emitEventWithTableAccess(",),
          "trusted lifecycle emission must bind the exact listener, consume before dispatch, and select the direct lexical table protocol"
        );
        assert!(
          process_source.contains(
            "removeProcessListenerInternal(target, event, wrapped, true);",
          ) && process_source.contains(
            "finishProcessSignalRemoval(property, registration, true);",
          ) && process_source.contains(
            "removeSignalListenerInternal: removeDenoSignalListenerInternal,",
          ) && process_source
            .contains("dispatcher: () => emitProcessSignalInternal(event),",)
            && process_source.contains(
              "} catch (error) {\n      fired = false;\n      throw error;",
            )
            && process_source
              .contains("processOnceListenerOriginals.set(wrapped, listener);",)
            && process_source
              .contains("ObjectDefineProperty(wrapped, \"listener\", {",),
          "protected process once removal must select direct lexical cleanup, recover after refusal, and retain pollution-safe wrapper provenance"
        );
        let signal_removal = exact_process_source_block(
          os_signal_source,
          operation.operation_id,
          "function removeSignalListenerImpl(",
          "function addSignalListener(signo, listener) {",
        );
        let native_unbind = signal_removal
          .find("unbindSignal(rid);")
          .expect("signal removal lost its native unbind");
        let listener_delete = signal_removal
          .find("SetPrototypeDelete(sigData.listeners, listener);")
          .expect("signal removal lost its exact listener deletion");
        assert!(
          native_unbind < listener_delete
            && process_source.contains(
              "prepareProcessSignalRemoval(property, listenerCount);",
            )
            && event_emitter_source.contains(
              "preparedRemoval,\n      );\n      deleteEventTableValue(events, type, eventTableAccess);",
            ),
          "process signal removal must validate first, keep the dispatcher published until native unbind commits, and mutate the exact direct table only after teardown succeeds"
        );
        let exact_internal_exception_emit = r#"let processExceptionDispatchDepth = 0;
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
}"#;
        let exact_internal_exception_count = r#"function processExceptionListenerCountInternal(event: string) {
  return eventListenerCountWithTableAccess(
    process,
    event,
    undefined,
    trustedProcessEventTableAccess,
  );
}"#;
        assert!(
          process_source.contains(exact_internal_exception_emit)
            && process_source.contains(exact_internal_exception_count)
            && process_source.contains(
              "if (processExceptionListenerCountInternal(\"unhandledRejection\") === 0)",
            )
            && process_source.contains(
              "if (!isOwnedDirectProcessEventTable(guardedProcessEvents)) return false;",
            )
            && !process_source.contains(
              "process.listenerCount(\"unhandledRejection\")",
            )
            && !process_source.contains("ArrayPrototypeConcat"),
          "internal process exception dispatch/count must use direct lexical snapshots without concat, mutable public dispatch, or ambient one-shot table authority"
        );
        let exact_process_error_callback = r#"function processOnError(error: unknown) {
  if (typeof fatalExceptionHandler === "function") {
    return !!fatalExceptionHandler(error);
  } else {
    // Exit code 6: _fatalException is not a function
    // (kInvalidFatalExceptionMonkeyPatching in Node.js)
    process.exitCode = 6;
  }
  return false;
}"#;
        let exact_hidden_error_slot = r#"ObjectDefineProperty(internals, "nodeProcessErrorCallback", {
  __proto__: null,
  configurable: false,
  enumerable: false,
  value: undefined,
  writable: true,
});"#;
        let exact_capture_table_preflight = r#"  if (_uncaughtExceptionCaptureFn !== null) {
    throw new ERR_UNCAUGHT_EXCEPTION_CAPTURE_ALREADY_SET();
  }
  requireDirectProcessEventTable(guardedProcessEvents);
  _uncaughtExceptionCaptureFn = fn;
  synchronizeListeners();"#;
        assert!(
          process_source.contains(exact_process_error_callback)
            && process_source.contains(exact_hidden_error_slot)
            && process_source.contains(exact_capture_table_preflight)
            && process_source
              .contains("internals.nodeProcessErrorCallback = processOnError;")
            && process_source
              .contains("internals.nodeProcessErrorCallback = undefined;",)
            && !process_source.contains(
              "globalThis.addEventListener(\"error\", processOnError)",
            )
            && !process_source.contains(
              "globalThis.removeEventListener(\"error\", processOnError)",
            )
            && process_source.contains(
              "if (!trustedReplacement && _uncaughtExceptionCaptureFn !== null) {",
            )
            && process_source.contains(
              "process event table cannot be replaced with an active uncaught-exception capture callback",
            )
            && process_source.contains(
              "if (!trustedReplacement && processExceptionDispatchDepth !== 0) {",
            )
            && process_source.contains(
              "process event table cannot be replaced during trusted exception dispatch",
            ),
          "process fatal-error routing must use only the closure-private consumed-result callback slot"
        );
        let web_report_exception = exact_process_source_block(
          web_event_source,
          operation.operation_id,
          "function reportException(error) {",
          "function checkThis(thisArg) {",
        );
        let authentic_web_dispatch = web_report_exception
          .find("EventTargetPrototypeDispatchEvent,")
          .expect("web exception routing lost its retained dispatch method");
        let hidden_process_callback = web_report_exception
          .find("const nodeProcessErrorCallback = internals.nodeProcessErrorCallback;")
          .expect("web exception routing lost its closure-private process callback");
        let lexical_error_delivery = web_report_exception
          .find("processHandled = !!FunctionPrototypeCall(")
          .expect("web exception routing lost its private consumed result");
        let private_fallback = web_report_exception
          .find("if (!processHandled && !event[_canceledFlag]) {")
          .expect("web exception routing lost its private fallback decision");
        assert!(
          web_event_source.contains(
            "const EventTargetPrototypeDispatchEvent = EventTargetPrototype.dispatchEvent;",
          ) && authentic_web_dispatch < hidden_process_callback
            && hidden_process_callback < lexical_error_delivery
            && lexical_error_delivery < private_fallback
            && web_report_exception.contains(
              "      } finally {\n        // node:process installs this callback",
            )
            && web_report_exception.contains(
              "              internals,\n              error,\n            );",
            )
            && web_report_exception.contains(
              "    }\n  } finally {\n    reportExceptionStackedCalls--;\n  }\n}",
            )
            && !web_report_exception.contains("globalThis_.dispatchEvent")
            && !web_report_exception.contains("event.defaultPrevented")
            && !web_report_exception.contains(
              "              internals,\n              event,\n            );",
            ),
          "web exception routing must dispatch authentically, invoke the hidden process route in finally with the lexical error, decide fallback from closure-private state, and always clear recursion state"
        );
        let exact_private_event_dispatch = r#"function dispatchEventWithPrivateCancellation(target, dispatchedEvent) {
  FunctionPrototypeCall(
    EventTargetPrototypeDispatchEvent,
    target,
    dispatchedEvent,
  );
  return dispatchedEvent[_canceledFlag];
}"#;
        let runtime_unhandled_rejection = exact_process_source_block(
          runtime_main_source,
          operation.operation_id,
          "function processUnhandledPromiseRejection(promise, reason) {",
          "function processRejectionHandled(promise, reason) {",
        );
        let runtime_handled_rejection = exact_process_source_block(
          runtime_main_source,
          operation.operation_id,
          "function processRejectionHandled(promise, reason) {",
          "function dispatchLoadEvent() {",
        );
        let public_unhandled_dispatch = runtime_unhandled_rejection
          .find("publiclyHandled = event.dispatchEventWithPrivateCancellation(")
          .expect(
            "runtime unhandled-rejection route lost private cancellation",
          );
        let private_unhandled_dispatch = runtime_unhandled_rejection
          .find(
            "const callback = internals.nodeProcessUnhandledRejectionCallback;",
          )
          .expect("runtime unhandled-rejection route lost Node callback");
        let exact_unhandled_lexical_delivery = "processHandled = !!ReflectApply(callback, internals, [promise, reason]);";
        assert!(
          web_event_source.contains(exact_private_event_dispatch)
            && runtime_main_source.contains(
              "const event = core.loadExtScript(\"ext:deno_web/02_event.js\");",
            )
            && public_unhandled_dispatch < private_unhandled_dispatch
            && runtime_unhandled_rejection
              .contains(exact_unhandled_lexical_delivery)
            && runtime_unhandled_rejection.contains(
              "  } finally {\n    // Public listeners receive the PromiseRejectionEvent",
            )
            && runtime_unhandled_rejection
              .contains("return publiclyHandled || processHandled;")
            && !runtime_unhandled_rejection
              .contains("globalThis_.dispatchEvent(rejectionEvent)")
            && !runtime_unhandled_rejection.contains("defaultPrevented")
            && !runtime_unhandled_rejection.contains("callback(rejectionEvent)")
            && runtime_handled_rejection.contains(
              "event.dispatchEventWithPrivateCancellation(\n      globalThis_,\n      rejectionHandledEvent,\n    );",
            )
            && runtime_handled_rejection.contains(
              "  } finally {\n    // Preserve Web-before-Node ordering",
            )
            && runtime_handled_rejection.contains(
              "ReflectApply(callback, internals, [promise, reason]);",
            )
            && !runtime_handled_rejection
              .contains("globalThis_.dispatchEvent(rejectionHandledEvent)")
            && !runtime_handled_rejection
              .contains("callback(rejectionHandledEvent)")
            && process_source.contains(
              "internals.nodeProcessUnhandledRejectionCallback = (promise, reason) => {",
            )
            && process_source.contains(
              "internals.nodeProcessRejectionHandledCallback = (promise, reason) => {",
            )
            && !process_source.contains(
              "internals.nodeProcessUnhandledRejectionCallback = (event) => {",
            )
            && !process_source.contains(
              "internals.nodeProcessRejectionHandledCallback = (event) => {",
            ),
          "runtime promise-rejection routing must dispatch authentically, always deliver exact lexical inputs to Node after public dispatch, and retain cancellation/consumption privately"
        );
        let borrowed_emission = r#"function snapshotProtectedEventState(target, type) {
  const events = target._events;
  if (events === undefined) {
    return {
      errorMonitor: false,
      hasErrorListener: false,
      listeners: undefined,
    };
  }
  const handler = events[type];"#;
        let protected_emit_dispatch = r#"EventEmitter.prototype.emit = function emit(type, ...args) {
  const eventTableAccess = WeakMapPrototypeGet(
    lexicalEventTableAccesses,
    this,
  );
  if (eventTableAccess !== undefined) {
    type = eventTableAccess.normalizeType(type);
    eventTableAccess.preflightType(type, "emit");
    return emitEventWithTableAccess(this, type, args, eventTableAccess);
  }
  if (isProtectedEventEmitter(this)) {
    return emitProtectedEvent(this, type, args);
  }"#;
        assert!(
          event_emitter_source.contains(borrowed_emission)
            && event_emitter_source.contains(protected_emit_dispatch),
          "borrowed process EventEmitter emission no longer selects the normalized lexical snapshot before listener delivery"
        );
      }
      "process-add-listener-forwarder-runtime" => {
        assert!(
          process_source.contains(
            "defineProcessPrototypeMethod(\"addListener\", Process.prototype.on);",
          ),
          "process.addListener no longer retains the exact guarded process.on alias"
        );
        assert_exact_process_guard_prefix_before_work(
          process_source,
          operation.operation_id,
          "defineProcessPrototypeMethod(\"on\", function on(",
          "defineProcessPrototypeMethod(\"off\", function off(",
          r#") {
  validateFunction(listener, "listener");
  const eventKey = normalizeProcessEventKey(event);
  guardProcessExceptionEvent(eventKey, "process.on");
  guardProcessMetaEvent(eventKey, "process.on");"#,
          "addProcessListenerInternal(this, eventKey, listener, false);",
        );
      }
      "process-remove-listener-forwarder-runtime" => {
        assert!(
          process_source.contains(
            "defineProcessPrototypeMethod(\"removeListener\", Process.prototype.off);",
          ),
          "process.removeListener no longer retains the exact guarded process.off alias"
        );
        assert_exact_process_guard_prefix_before_work(
          process_source,
          operation.operation_id,
          "defineProcessPrototypeMethod(\"off\", function off(",
          "defineProcessPrototypeMethod(\"emit\", function emit(",
          r#") {
  validateFunction(listener, "listener");
  const eventKey = normalizeProcessEventKey(event);
  guardProcessExceptionEvent(eventKey, "process.off");
  guardProcessMetaEvent(eventKey, "process.off");"#,
          "removeProcessListenerInternal(this, eventKey, listener);",
        );
      }
      _ => panic!(
        "unknown public process event fixture operation {}",
        operation.operation_id
      ),
    }
  }

  fn assert_public_process_guard_precedes_wrapper_work(
    operation: &Rev2V8FixtureOperation,
  ) {
    let active_source =
      include_str!("../polyfills/internal/process/active_resources.ts");
    let process_source = include_str!("../polyfills/process.ts");
    let report_source = include_str!("../polyfills/internal/process/report.ts");
    let (scope, operation_anchor, exact_guard_prefix) =
      match operation.operation_id {
        "process-get-active-handles" => (
          active_source,
          "function getActiveHandles() {",
          r#"function getActiveHandles() {
  op_oden_guard_deny_only_surface(
    "runtime",
    "inspect",
    "process:active-handles",
    "process._getActiveHandles",
  );
  return snapshot(activeHandles);"#,
        ),
        "process-get-active-requests" => (
          active_source,
          "function getActiveRequests() {",
          r#"function getActiveRequests() {
  // Resource snapshots reveal handles and operations owned by other package
  // principals in the shared isolate.
  // @ref LLP 0019#runtime-and-memory-inspection [implements]
  op_oden_guard_deny_only_surface(
    "runtime",
    "inspect",
    "process:active-requests",
    "process._getActiveRequests",
  );
  return snapshot(activeRequests);"#,
        ),
        "process-get-active-resource-names" => (
          process_source,
          "export function getActiveResourcesInfo(): string[] {",
          r#"export function getActiveResourcesInfo(): string[] {
  // Resource, stdio terminal, and timer snapshots reveal process-wide
  // activity. Invoke the guarded resource-name helper first so the registered
  // boundary denies before any component is observed, then preserve the
  // public result order with its saved names.
  // @ref LLP 0019#runtime-and-memory-inspection [implements]
  const activeResourceNames = getActiveResourceNames();
  const result: string[] = [];"#,
        ),
        "process-report-get-report" => (
          report_source,
          "function getReport(_err) {",
          r#"function getReport(_err) {
  // @ref LLP 0019#runtime-and-memory-inspection [implements]
  op_oden_guard_deny_only_surface(
    "runtime",
    "inspect",
    "node:process.report.getReport",
    "process.report.getReport",
  );
  const os = lazyOs();"#,
        ),
        "process-report-write-report" => (
          report_source,
          "function writeReport(_filename, _err) {",
          r#"function writeReport(_filename, _err) {
  op_oden_guard_deny_only_surface(
    "runtime",
    "inspect",
    "node:process.report.writeReport",
    "process.report.writeReport",
  );
  return "";"#,
        ),
        _ => panic!(
          "unknown public process fixture operation {}",
          operation.operation_id
        ),
      };
    assert_eq!(
      scope.matches(operation_anchor).count(),
      1,
      "{} process wrapper source anchor is not unique",
      operation.operation_id
    );
    assert!(
      scope.contains(exact_guard_prefix),
      "{} no longer guards before its first observable work",
      operation.operation_id
    );
    if operation.operation_id == "process-get-active-resource-names" {
      assert!(
        active_source.contains(
          r#"function getActiveResourceNames() {
  op_oden_guard_deny_only_surface(
    "runtime",
    "inspect",
    "process:active-resources",
    "process.getActiveResourcesInfo",
  );
  const names: string[] = [];"#
        ),
        "{} no longer retains the exact direct-internal guard",
        operation.operation_id
      );
    }
    if rev2_process_fixture_is_active_resources(operation) {
      assert!(
        process_source.contains(
          r#"process.getActiveResourcesInfo = getActiveResourcesInfo;
process._getActiveRequests = getActiveRequests;
process._getActiveHandles = getActiveHandles;"#
        ),
        "{} public process facade selection drifted",
        operation.operation_id
      );
    }
  }

  fn assert_public_diagnostics_guard_precedes_wrapper_work(
    operation: &Rev2V8FixtureOperation,
  ) {
    let source = include_str!("../polyfills/diagnostics_channel.js");
    let active_scope = &source[source.find("class ActiveChannel {").unwrap()
      ..source.find("class Channel {").unwrap()];
    let channel_scope = &source[source.find("class Channel {").unwrap()
      ..source.find("const channels = new WeakRefMap();").unwrap()];
    let channel_impl_scope =
      &source[source.find("function channelImpl(").unwrap()
        ..source.find("function channel(name)").unwrap()];
    let has_subscribers_scope =
      &source[source.find("function hasSubscribers(name)").unwrap()
        ..source.find("const traceEvents =").unwrap()];
    let tracing_scope = &source[source
      .find("function tracingChannel(nameOrChannels)")
      .unwrap()
      ..source
        .find("function tracingChannelInternal(name)")
        .unwrap()];
    let (scope, operation_anchor, first_work) = match operation.operation_id {
      "diagnostics-active-channel-bind-store" => (
        active_scope,
        "  bindStore(store, transform) {",
        "    const replacing = state.stores.has(store);",
      ),
      "diagnostics-active-channel-has-subscribers" => {
        (active_scope, "  get hasSubscribers() {", "    return true;")
      }
      "diagnostics-active-channel-publish" => (
        active_scope,
        "  publish(data) {",
        "    publishChannel(this, data);",
      ),
      "diagnostics-active-channel-run-stores" => (
        active_scope,
        "  runStores(data, fn, thisArg, ...args) {",
        "    return runChannelStores(this, data, fn, thisArg, args);",
      ),
      "diagnostics-active-channel-subscribe" => (
        active_scope,
        "  subscribe(subscription) {",
        "    validateFunction(subscription, \"subscription\");",
      ),
      "diagnostics-active-channel-unbind-store" => (
        active_scope,
        "  unbindStore(store) {",
        "    if (!state.stores.has(store)) {",
      ),
      "diagnostics-active-channel-unsubscribe" => (
        active_scope,
        "  unsubscribe(subscription) {",
        "    const index = ArrayPrototypeIndexOf(",
      ),
      "diagnostics-channel-bind-store" => (
        channel_scope,
        "  bindStore(store, transform) {",
        "    markActive(this);",
      ),
      "diagnostics-channel-constructor" => (
        channel_scope,
        "  constructor(name, trustedToken) {",
        "    this._subscribers = undefined;",
      ),
      "diagnostics-channel-has-subscribers" => (
        channel_scope,
        "  get hasSubscribers() {",
        "    return false;",
      ),
      "diagnostics-channel-publish" => (channel_scope, "  publish() {", "  }"),
      "diagnostics-channel-run-stores" => (
        channel_scope,
        "  runStores(_data, fn, thisArg, ...args) {",
        "    return ReflectApply(fn, thisArg, args);",
      ),
      "diagnostics-channel-subscribe" => (
        channel_scope,
        "  subscribe(subscription) {",
        "    validateFunction(subscription, \"subscription\");",
      ),
      "diagnostics-channel" => (
        channel_impl_scope,
        "function channelImpl(name, trustedInternal) {",
        "  const ch = channels.get(name);",
      ),
      "diagnostics-has-subscribers" => (
        has_subscribers_scope,
        "function hasSubscribers(name) {",
        "  const ch = channels.get(name);",
      ),
      "diagnostics-tracing-channel" => (
        tracing_scope,
        "function tracingChannel(nameOrChannels) {",
        "  return new TracingChannel(nameOrChannels);",
      ),
      _ => panic!(
        "unknown public diagnostics fixture operation {}",
        operation.operation_id
      ),
    };
    assert_eq!(
      scope.matches(operation_anchor).count(),
      1,
      "{} diagnostics source anchor is not unique",
      operation.operation_id
    );
    let operation_source = &scope[scope.find(operation_anchor).unwrap()..];
    let guard_api =
      format!("\"{}\"", rev2_public_wrapper_guard_api_name(operation));
    let guard_index = operation_source.find(&guard_api).unwrap_or_else(|| {
      panic!(
        "{} no longer names its exact diagnostics guard API",
        operation.operation_id
      )
    });
    let work_index = operation_source.find(first_work).unwrap_or_else(|| {
      panic!(
        "{} no longer contains its exact first post-guard work",
        operation.operation_id
      )
    });
    assert!(
      guard_index < work_index,
      "{} no longer guards before its first wrapper work",
      operation.operation_id
    );
    assert!(
      source.contains(
        r#"function guardChannel(channel, api) {
  const state = channelStates.get(channel);
  op_oden_guard_deny_only_surface(
    "runtime",
    "inspect",
    String(state.name),
    api,
  );
}"#
      ),
      "diagnostics guard helper no longer uses the exact runtime:inspect tuple"
    );
    if operation.operation_id == "diagnostics-channel" {
      assert!(
        source.contains(
          r#"function channel(name) {
  return channelImpl(name, false);
}"#
        ),
        "public diagnostics channel no longer delegates exactly to the guarded helper"
      );
    }
    if operation.operation_id == "diagnostics-channel-publish" {
      assert!(
        channel_scope.contains(
          r#"  publish() {
    guardChannel(this, "node:diagnostics_channel.publish");
  }"#
        ),
        "inactive diagnostics publish no longer consists solely of its guard"
      );
    }
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

  fn rev2_public_wrapper_guard_api_name(
    operation: &Rev2V8FixtureOperation,
  ) -> &'static str {
    match operation.operation_id {
      "diagnostics-active-channel-bind-store"
      | "diagnostics-channel-bind-store" => {
        "node:diagnostics_channel.bindStore"
      }
      "diagnostics-active-channel-has-subscribers"
      | "diagnostics-channel-has-subscribers"
      | "diagnostics-has-subscribers" => {
        "node:diagnostics_channel.hasSubscribers"
      }
      "diagnostics-active-channel-publish" | "diagnostics-channel-publish" => {
        "node:diagnostics_channel.publish"
      }
      "diagnostics-active-channel-run-stores"
      | "diagnostics-channel-run-stores" => {
        "node:diagnostics_channel.runStores"
      }
      "diagnostics-active-channel-subscribe"
      | "diagnostics-channel-subscribe" => "node:diagnostics_channel.subscribe",
      "diagnostics-active-channel-unbind-store" => {
        "node:diagnostics_channel.unbindStore"
      }
      "diagnostics-active-channel-unsubscribe" => {
        "node:diagnostics_channel.unsubscribe"
      }
      "diagnostics-channel-constructor" => "node:diagnostics_channel.Channel",
      "diagnostics-channel" => "node:diagnostics_channel.channel",
      "diagnostics-tracing-channel" => {
        "node:diagnostics_channel.tracingChannel"
      }
      "async-hooks-create-hook" => "node:async_hooks.createHook",
      "async-hooks-execution-async-resource" => {
        "node:async_hooks.executionAsyncResource"
      }
      "async-hook-disable" => "node:async_hooks.AsyncHook.disable",
      "async-hook-enable" => "node:async_hooks.AsyncHook.enable",
      "process-get-active-handles" => "process._getActiveHandles",
      "process-get-active-requests" => "process._getActiveRequests",
      "process-get-active-resource-names" => "process.getActiveResourcesInfo",
      "process-report-get-report" => "process.report.getReport",
      "process-report-write-report" => "process.report.writeReport",
      "process-events-replacement" => "process._events=set",
      "process-add-listener-forwarder-runtime" => "process.on",
      "process-remove-listener-forwarder-runtime" => "process.off",
      _ => operation.denied_target,
    }
  }

  fn assert_exact_public_wrapper_guard_call(
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
        rev2_public_wrapper_guard_api_name(operation).to_string(),
      ),
      "{} used an inexact public guard tuple",
      operation.operation_id
    );
  }

  fn rev2_process_fixture_is_active_resources(
    operation: &Rev2V8FixtureOperation,
  ) -> bool {
    matches!(
      operation.operation_id,
      "process-get-active-handles"
        | "process-get-active-requests"
        | "process-get-active-resource-names"
    )
  }

  fn rev2_process_fixture_is_events(
    operation: &Rev2V8FixtureOperation,
  ) -> bool {
    matches!(
      operation.operation_id,
      "process-events-replacement"
        | "process-events-sensitive-table"
        | "process-add-listener-forwarder-runtime"
        | "process-remove-listener-forwarder-runtime"
    )
  }

  fn rev2_process_report_fixture_path(root: &Path) -> PathBuf {
    root.join("must-not-write-process-report.json")
  }

  fn prepare_rev2_public_process_fixture_state(
    runtime: &mut JsRuntime,
    root: &Path,
    operation: &Rev2V8FixtureOperation,
  ) {
    set_actor(root, "main.ts");
    if rev2_process_fixture_is_active_resources(operation) {
      execute(
        runtime,
        "file:///rev2_public_process_fixture_prepare_active.js",
        r#"
        rev2ProcessActiveResourcesController.seed();
        rev2ProcessActiveResourcesController.assertState(true);
        "#
        .to_string(),
      );
    } else {
      execute(
        runtime,
        "file:///rev2_public_process_fixture_prepare_report.js",
        r#"
        rev2ProcessReportController.reset();
        rev2ProcessReportController.assertCounts(0, 0, 0);
        "#
        .to_string(),
      );
      assert_native_v8_fixture_path_absent(
        &rev2_process_report_fixture_path(root),
        "process report fixture preparation",
      );
    }
  }

  fn assert_rev2_public_process_fixture_state(
    runtime: &mut JsRuntime,
    root: &Path,
    operation: &Rev2V8FixtureOperation,
    active_resources_seeded: bool,
    context: &'static str,
  ) {
    if rev2_process_fixture_is_active_resources(operation) {
      execute(
        runtime,
        context,
        format!(
          "rev2ProcessActiveResourcesController.assertState({active_resources_seeded});"
        ),
      );
    } else {
      execute(
        runtime,
        context,
        "rev2ProcessReportController.assertCounts(0, 0, 0);".to_string(),
      );
      assert_native_v8_fixture_path_absent(
        &rev2_process_report_fixture_path(root),
        "process report denied-state canary",
      );
    }
  }

  fn deny_rev2_public_process_fixture_operation(
    runtime: &mut JsRuntime,
    root: &Path,
    operation: &Rev2V8FixtureOperation,
  ) {
    set_actor(root, "node_modules/denied-native/index.cjs");
    let operation_id_json =
      deno_core::serde_json::to_string(operation.operation_id).unwrap();
    let denied_target_json =
      deno_core::serde_json::to_string(operation.denied_target).unwrap();
    let report_path_json = deno_core::serde_json::to_string(
      &rev2_process_report_fixture_path(root).to_string_lossy(),
    )
    .unwrap();
    execute(
      runtime,
      "file:///rev2_public_process_fixture_denied.js",
      format!(
        r#"
        {{
          const operationId = {operation_id_json};
          const reportPath = {report_path_json};
          function invoke() {{
            switch (operationId) {{
              case "process-get-active-handles":
                return rev2ProcessActiveResources.getActiveHandles();
              case "process-get-active-requests":
                return rev2ProcessActiveResources.getActiveRequests();
              case "process-get-active-resource-names":
                return rev2ProcessActiveResources.getActiveResourceNames();
              case "process-report-get-report":
                return rev2ProcessReport.getReport(undefined);
              case "process-report-write-report":
                return rev2ProcessReport.writeReport(reportPath, undefined);
              default:
                throw new Error(
                  `unknown process fixture operation ${{operationId}}`,
                );
            }}
          }}
          let denied = false;
          try {{
            invoke();
          }} catch (error) {{
            const message = String(error);
            const expected =
              `principal set [denied-native] may not use deny-only runtime:inspect:${{{denied_target_json}}}`;
            if (!message.includes(expected)) {{
              throw new Error(
                `${{operationId}} used the wrong actor or boundary: ${{message}}`,
              );
            }}
            denied = true;
          }}
          if (!denied) {{
            throw new Error(`${{operationId}} reached process wrapper work`);
          }}
        }}
        "#
      ),
    );
  }

  fn call_rev2_public_process_active_resources(
    runtime: &mut JsRuntime,
    root: &Path,
    operation: &Rev2V8FixtureOperation,
    seeded: bool,
    name: &'static str,
  ) {
    set_actor(root, "main.ts");
    let operation_id_json =
      deno_core::serde_json::to_string(operation.operation_id).unwrap();
    execute(
      runtime,
      name,
      format!(
        r#"
        {{
          const operationId = {operation_id_json};
          let result;
          switch (operationId) {{
            case "process-get-active-handles":
              result = rev2ProcessActiveResources.getActiveHandles();
              break;
            case "process-get-active-requests":
              result = rev2ProcessActiveResources.getActiveRequests();
              break;
            case "process-get-active-resource-names":
              result = rev2ProcessActiveResources.getActiveResourceNames();
              break;
            default:
              throw new Error(
                `unknown active-resource fixture operation ${{operationId}}`,
              );
          }}
          rev2ProcessActiveResourcesController.assertResult(
            operationId,
            result,
            {seeded},
          );
          rev2ProcessActiveResourcesController.assertState({seeded});
        }}
        "#
      ),
    );
  }

  fn call_rev2_public_process_report(
    runtime: &mut JsRuntime,
    root: &Path,
    operation: &Rev2V8FixtureOperation,
    name: &'static str,
  ) {
    set_actor(root, "main.ts");
    let operation_id_json =
      deno_core::serde_json::to_string(operation.operation_id).unwrap();
    let report_path = rev2_process_report_fixture_path(root);
    assert_native_v8_fixture_path_absent(
      &report_path,
      "before ambient process report control",
    );
    let report_path_json =
      deno_core::serde_json::to_string(&report_path.to_string_lossy()).unwrap();
    execute(
      runtime,
      name,
      format!(
        r#"
        {{
          const operationId = {operation_id_json};
          const reportPath = {report_path_json};
          rev2ProcessReportController.reset();
          if (operationId === "process-report-get-report") {{
            const result = rev2ProcessReport.getReport(undefined);
            if (
              result === null ||
              typeof result !== "object" ||
              result.header === null ||
              typeof result.header !== "object" ||
              result.header.reportVersion !== 3 ||
              result.header.event !== "JavaScript API" ||
              result.header.trigger !== "GetReport" ||
              result.header.processId !== 4242 ||
              result.header.cwd !== "/rev2-process-report-fixture" ||
              result.header.host !== "rev2-process-report-host" ||
              !Array.isArray(result.header.cpus) ||
              result.header.networkInterfaces === null ||
              typeof result.header.networkInterfaces !== "object" ||
              Object.keys(result.header.networkInterfaces).length !== 0 ||
              !Array.isArray(result.workers) ||
              result.workers.length !== 0
            ) {{
              throw new Error(
                "ambient process getReport returned an inexact report",
              );
            }}
            rev2ProcessReportController.assertCounts(1, 1, 1);
          }} else if (operationId === "process-report-write-report") {{
            const result = rev2ProcessReport.writeReport(
              reportPath,
              undefined,
            );
            if (result !== "") {{
              throw new Error(
                "ambient process writeReport returned an inexact result",
              );
            }}
            rev2ProcessReportController.assertCounts(0, 0, 0);
          }} else {{
            throw new Error(
              `unknown process report fixture operation ${{operationId}}`,
            );
          }}
          rev2ProcessReportController.reset();
          rev2ProcessReportController.assertCounts(0, 0, 0);
        }}
        "#
      ),
    );
    assert_native_v8_fixture_path_absent(
      &report_path,
      "after ambient process report control",
    );
  }

  fn cleanup_rev2_public_process_fixture_state(
    runtime: &mut JsRuntime,
    root: &Path,
    operation: &Rev2V8FixtureOperation,
  ) -> usize {
    if rev2_process_fixture_is_active_resources(operation) {
      call_rev2_public_process_active_resources(
        runtime,
        root,
        operation,
        true,
        "file:///rev2_public_process_fixture_cleanup_seeded.js",
      );
      set_actor(root, "main.ts");
      execute(
        runtime,
        "file:///rev2_public_process_fixture_clear.js",
        r#"
        rev2ProcessActiveResourcesController.clear();
        rev2ProcessActiveResourcesController.assertState(false);
        "#
        .to_string(),
      );
      call_rev2_public_process_active_resources(
        runtime,
        root,
        operation,
        false,
        "file:///rev2_public_process_fixture_cleanup_empty.js",
      );
      2
    } else {
      call_rev2_public_process_report(
        runtime,
        root,
        operation,
        "file:///rev2_public_process_fixture_cleanup_report.js",
      );
      1
    }
  }

  fn assert_rev2_public_process_guard_sequence(
    operation: &Rev2V8FixtureOperation,
    start: usize,
    expected_count: usize,
    context: &str,
  ) {
    let expected_call = (
      "runtime".to_string(),
      "inspect".to_string(),
      operation.denied_target.to_string(),
      rev2_public_wrapper_guard_api_name(operation).to_string(),
    );
    let expected = vec![expected_call; expected_count];
    let observed = {
      let calls = PUBLIC_V8_WRAPPER_GUARD_CALLS.lock().unwrap();
      calls[start..].to_vec()
    };
    assert_eq!(
      observed, expected,
      "{} used an inexact process wrapper guard sequence during {context}",
      operation.operation_id
    );
  }

  fn run_rev2_public_process_positive_control(
    runtime: &mut JsRuntime,
    root: &Path,
    operation: &Rev2V8FixtureOperation,
  ) {
    let before = rev2_v8_fixture_canaries();
    if rev2_process_fixture_is_active_resources(operation) {
      set_actor(root, "main.ts");
      execute(
        runtime,
        "file:///rev2_public_process_fixture_positive_seed.js",
        r#"
        rev2ProcessActiveResourcesController.seed();
        rev2ProcessActiveResourcesController.assertState(true);
        "#
        .to_string(),
      );
      call_rev2_public_process_active_resources(
        runtime,
        root,
        operation,
        true,
        "file:///rev2_public_process_fixture_positive_seeded.js",
      );
      set_actor(root, "main.ts");
      execute(
        runtime,
        "file:///rev2_public_process_fixture_positive_clear.js",
        r#"
        rev2ProcessActiveResourcesController.clear();
        rev2ProcessActiveResourcesController.assertState(false);
        "#
        .to_string(),
      );
      call_rev2_public_process_active_resources(
        runtime,
        root,
        operation,
        false,
        "file:///rev2_public_process_fixture_positive_empty.js",
      );
    } else {
      call_rev2_public_process_report(
        runtime,
        root,
        operation,
        "file:///rev2_public_process_fixture_positive_report.js",
      );
    }
    let after = rev2_v8_fixture_canaries();
    let expected_guard_calls =
      if rev2_process_fixture_is_active_resources(operation) {
        2
      } else {
        1
      };
    assert_eq!(
      after.public_wrapper_guard_calls,
      before.public_wrapper_guard_calls + expected_guard_calls,
      "{} ambient process control crossed an inexact number of guards",
      operation.operation_id
    );
    assert_eq!(
      Rev2V8FixtureCanaries {
        public_wrapper_guard_calls: before.public_wrapper_guard_calls,
        ..after
      },
      before,
      "{} ambient process control crossed unrelated native work",
      operation.operation_id
    );
    assert_rev2_public_process_guard_sequence(
      operation,
      before.public_wrapper_guard_calls,
      expected_guard_calls,
      "positive control",
    );
  }

  fn assert_rev2_public_process_event_guard_sequence(
    start: usize,
    expected: &[(&str, &str)],
    operation: &Rev2V8FixtureOperation,
    context: &str,
  ) {
    let expected = expected
      .iter()
      .map(|(target, api_name)| {
        (
          "runtime".to_string(),
          "inspect".to_string(),
          (*target).to_string(),
          (*api_name).to_string(),
        )
      })
      .collect::<Vec<_>>();
    let observed = {
      let calls = PUBLIC_V8_WRAPPER_GUARD_CALLS.lock().unwrap();
      calls[start..].to_vec()
    };
    assert_eq!(
      observed, expected,
      "{} used an inexact process event guard sequence during {context}",
      operation.operation_id
    );
  }

  fn rev2_public_process_event_prepare_guards(
    operation: &Rev2V8FixtureOperation,
  ) -> &'static [(&'static str, &'static str)] {
    match operation.operation_id {
      "process-events-replacement"
      | "process-add-listener-forwarder-runtime" => &[],
      "process-events-sensitive-table" => &[
        ("uncaughtException", "process.on"),
        ("newListener", "process.on"),
      ],
      "process-remove-listener-forwarder-runtime" => &[
        ("uncaughtException", "process.on"),
        ("newListener", "process.on"),
      ],
      _ => panic!(
        "unknown public process event fixture operation {}",
        operation.operation_id
      ),
    }
  }

  fn rev2_public_process_event_denied_guards(
    operation: &Rev2V8FixtureOperation,
    complete_sensitive_table: bool,
  ) -> Vec<(&'static str, &'static str)> {
    match operation.operation_id {
      "process-events-replacement" => {
        vec![("process-events", "process._events=set")]
      }
      "process-events-sensitive-table" => {
        let mut guards = vec![("uncaughtException", "process._events.get")];
        if complete_sensitive_table {
          guards.extend([
            ("uncaughtException", "process._events.set"),
            ("uncaughtException", "process._events.defineProperty"),
            ("uncaughtException", "process._events.deleteProperty"),
            ("uncaughtException", "process._events.has"),
            ("process-events", "process._events.ownKeys"),
            (
              "uncaughtException",
              "process._events.getOwnPropertyDescriptor",
            ),
            ("uncaughtException", "process._events.get"),
            ("uncaughtException", "process._events.set"),
            ("process-events", "process._events.getPrototypeOf"),
            ("process-events", "process._events.setPrototypeOf"),
            ("process-events", "process._events.isExtensible"),
            ("process-events", "process._events.preventExtensions"),
            ("process-events", "process._events.preventExtensions"),
            ("process-events", "process._events.preventExtensions"),
            ("removeListener", "process._events.defineProperty"),
            ("removeListener", "process.emit(removeListener)"),
            ("removeListener", "process._events.defineProperty"),
            ("removeListener", "process.emit(removeListener)"),
            ("uncaughtException", "EventEmitter.emit"),
            ("uncaughtException", "EventEmitter.removeListener"),
            ("newListener", "EventEmitter.removeListener"),
          ]);
        }
        guards
      }
      "process-add-listener-forwarder-runtime" => {
        vec![
          ("uncaughtException", "process.on"),
          ("newListener", "process.on"),
        ]
      }
      "process-remove-listener-forwarder-runtime" => {
        vec![
          ("uncaughtException", "process.off"),
          ("newListener", "process.off"),
        ]
      }
      _ => panic!(
        "unknown public process event fixture operation {}",
        operation.operation_id
      ),
    }
  }

  fn rev2_public_process_event_cleanup_guards(
    operation: &Rev2V8FixtureOperation,
  ) -> &'static [(&'static str, &'static str)] {
    match operation.operation_id {
      "process-events-replacement" => {
        &[("process-events", "process._events=set")]
      }
      "process-events-sensitive-table" => &[
        ("uncaughtException", "process.off"),
        ("newListener", "process.off"),
      ],
      "process-add-listener-forwarder-runtime" => &[
        ("uncaughtException", "process.on"),
        ("newListener", "process.on"),
        ("uncaughtException", "process.off"),
        ("newListener", "process.off"),
      ],
      "process-remove-listener-forwarder-runtime" => &[
        ("uncaughtException", "process.off"),
        ("newListener", "process.off"),
      ],
      _ => panic!(
        "unknown public process event fixture operation {}",
        operation.operation_id
      ),
    }
  }

  fn prepare_rev2_public_process_event_fixture_state(
    runtime: &mut JsRuntime,
    root: &Path,
    operation: &Rev2V8FixtureOperation,
  ) {
    set_actor(root, "main.ts");
    let operation_id_json =
      deno_core::serde_json::to_string(operation.operation_id).unwrap();
    execute(
      runtime,
      "file:///rev2_public_process_events_fixture_prepare.js",
      format!(
        r#"
        rev2ProcessEventsController.prepare({operation_id_json});
        "#
      ),
    );
  }

  fn deny_rev2_public_process_event_fixture_operation(
    runtime: &mut JsRuntime,
    root: &Path,
    operation: &Rev2V8FixtureOperation,
    complete_sensitive_table: bool,
  ) {
    set_actor(root, "node_modules/denied-native/index.cjs");
    let operation_id_json =
      deno_core::serde_json::to_string(operation.operation_id).unwrap();
    execute(
      runtime,
      "file:///rev2_public_process_events_fixture_denied.js",
      format!(
        r#"
        {{
          const operationId = {operation_id_json};
          let attempts;
          if (operationId === "process-events-replacement") {{
            attempts = [[
              "replaceEvents",
              "process-events",
              "process._events=set",
            ]];
          }} else if (operationId === "process-events-sensitive-table") {{
            attempts = [
              ["sensitiveGet", "uncaughtException", "process._events.get"],
              ["sensitiveSet", "uncaughtException", "process._events.set"],
              [
                "sensitiveDefineProperty",
                "uncaughtException",
                "process._events.defineProperty",
              ],
              [
                "sensitiveDeleteProperty",
                "uncaughtException",
                "process._events.deleteProperty",
              ],
              ["sensitiveHas", "uncaughtException", "process._events.has"],
              [
                "sensitiveOwnKeys",
                "process-events",
                "process._events.ownKeys",
              ],
              [
                "sensitiveDescriptor",
                "uncaughtException",
                "process._events.getOwnPropertyDescriptor",
              ],
              [
                "sensitiveAccessorGetterReceiver",
                "uncaughtException",
                "process._events.get",
              ],
              [
                "sensitiveAccessorSetterReceiver",
                "uncaughtException",
                "process._events.set",
              ],
              [
                "sensitiveGetPrototypeOf",
                "process-events",
                "process._events.getPrototypeOf",
              ],
              [
                "sensitiveSetPrototypeOf",
                "process-events",
                "process._events.setPrototypeOf",
              ],
              [
                "sensitiveIsExtensible",
                "process-events",
                "process._events.isExtensible",
              ],
              [
                "sensitivePreventExtensions",
                "process-events",
                "process._events.preventExtensions",
              ],
              [
                "sensitiveFreeze",
                "process-events",
                "process._events.preventExtensions",
              ],
              [
                "sensitiveSeal",
                "process-events",
                "process._events.preventExtensions",
              ],
              [
                "sensitiveTrustedTableReentrancy",
                "removeListener",
                "process._events.defineProperty",
              ],
              [
                "sensitiveTrustedEmissionReentrancy",
                "removeListener",
                "process.emit(removeListener)",
              ],
              [
                "sensitiveReturnedTableReentrancy",
                "removeListener",
                "process._events.defineProperty",
              ],
              [
                "sensitiveReturnedEmissionReentrancy",
                "removeListener",
                "process.emit(removeListener)",
              ],
              [
                "borrowedEmitException",
                "uncaughtException",
                "EventEmitter.emit",
              ],
              [
                "borrowedRemoveException",
                "uncaughtException",
                "EventEmitter.removeListener",
              ],
              [
                "borrowedRemoveMeta",
                "newListener",
                "EventEmitter.removeListener",
              ],
            ];
            if (!{complete_sensitive_table}) attempts = attempts.slice(0, 1);
          }} else if (
            operationId === "process-add-listener-forwarder-runtime"
          ) {{
            attempts = [
              [
                "addListenerForwarder",
                "uncaughtException",
                "process.on",
              ],
              ["addMetaListenerForwarder", "newListener", "process.on"],
            ];
          }} else if (
            operationId === "process-remove-listener-forwarder-runtime"
          ) {{
            attempts = [
              [
                "removeListenerForwarder",
                "uncaughtException",
                "process.off",
              ],
              ["removeMetaListenerForwarder", "newListener", "process.off"],
            ];
          }} else {{
            throw new Error(
              `unknown process event fixture operation ${{operationId}}`,
            );
          }}
          for (const [method, target, apiName] of attempts) {{
            let denied = false;
            try {{
              rev2ProcessEvents[method]();
            }} catch (error) {{
              const message = String(error);
              const expected =
                `principal set [denied-native] may not use deny-only runtime:inspect:${{target}}`;
              if (!message.includes(expected)) {{
                throw new Error(
                  `${{operationId}}/${{apiName}} used the wrong actor or boundary: ${{message}}`,
                );
              }}
              denied = true;
            }}
            if (!denied) {{
              throw new Error(
                `${{operationId}}/${{apiName}} reached process event work`,
              );
            }}
          }}
        }}
        "#
      ),
    );
  }

  fn assert_rev2_public_process_event_fixture_denied_state(
    runtime: &mut JsRuntime,
    root: &Path,
    operation: &Rev2V8FixtureOperation,
  ) {
    set_actor(root, "main.ts");
    let operation_id_json =
      deno_core::serde_json::to_string(operation.operation_id).unwrap();
    execute(
      runtime,
      "file:///rev2_public_process_events_fixture_denied_state.js",
      format!("rev2ProcessEventsController.assertDenied({operation_id_json});"),
    );
  }

  fn cleanup_rev2_public_process_event_fixture_state(
    runtime: &mut JsRuntime,
    root: &Path,
    operation: &Rev2V8FixtureOperation,
  ) {
    set_actor(root, "main.ts");
    let operation_id_json =
      deno_core::serde_json::to_string(operation.operation_id).unwrap();
    execute(
      runtime,
      "file:///rev2_public_process_events_fixture_cleanup.js",
      format!("rev2ProcessEventsController.cleanup({operation_id_json});"),
    );
  }

  fn assert_rev2_public_process_event_fixture_clean_state(
    runtime: &mut JsRuntime,
    root: &Path,
    operation: &Rev2V8FixtureOperation,
    post_cleanup_denied: bool,
  ) {
    set_actor(root, "main.ts");
    let operation_id_json =
      deno_core::serde_json::to_string(operation.operation_id).unwrap();
    let method = if post_cleanup_denied {
      "assertPostCleanupDenied"
    } else {
      "assertClean"
    };
    execute(
      runtime,
      "file:///rev2_public_process_events_fixture_clean_state.js",
      format!("rev2ProcessEventsController.{method}({operation_id_json});"),
    );
  }

  fn prepare_rev2_public_process_event_meta_only_own_keys(
    runtime: &mut JsRuntime,
    root: &Path,
    operation: &Rev2V8FixtureOperation,
  ) {
    assert_eq!(
      operation.operation_id, "process-events-sensitive-table",
      "meta-only ownKeys preparation requires the sensitive-table operation"
    );
    set_actor(root, "main.ts");
    let operation_id_json =
      deno_core::serde_json::to_string(operation.operation_id).unwrap();
    execute(
      runtime,
      "file:///rev2_public_process_events_fixture_meta_only_prepare.js",
      format!(
        "rev2ProcessEventsController.prepareMetaOnlyOwnKeys({operation_id_json});"
      ),
    );
  }

  fn deny_rev2_public_process_event_meta_only_own_keys(
    runtime: &mut JsRuntime,
    root: &Path,
  ) {
    set_actor(root, "node_modules/denied-native/index.cjs");
    execute(
      runtime,
      "file:///rev2_public_process_events_fixture_meta_only_denied.js",
      r#"
      {
        let denied = false;
        try {
          rev2ProcessEvents.sensitiveOwnKeys();
        } catch (error) {
          const message = String(error);
          const expected =
            "principal set [denied-native] may not use deny-only runtime:inspect:process-events";
          if (!message.includes(expected)) {
            throw new Error(
              `meta-only process._events.ownKeys used the wrong actor or boundary: ${message}`,
            );
          }
          denied = true;
        }
        if (!denied) {
          throw new Error(
            "meta-only process._events.ownKeys reached raw table inspection",
          );
        }
      }
      "#
      .to_string(),
    );
  }

  fn assert_rev2_public_process_event_meta_only_own_keys_denied_state(
    runtime: &mut JsRuntime,
    root: &Path,
    operation: &Rev2V8FixtureOperation,
  ) {
    set_actor(root, "main.ts");
    let operation_id_json =
      deno_core::serde_json::to_string(operation.operation_id).unwrap();
    execute(
      runtime,
      "file:///rev2_public_process_events_fixture_meta_only_denied_state.js",
      format!(
        "rev2ProcessEventsController.assertMetaOnlyOwnKeysDenied({operation_id_json});"
      ),
    );
  }

  fn cleanup_rev2_public_process_event_meta_only_own_keys(
    runtime: &mut JsRuntime,
    root: &Path,
    operation: &Rev2V8FixtureOperation,
  ) {
    set_actor(root, "main.ts");
    let operation_id_json =
      deno_core::serde_json::to_string(operation.operation_id).unwrap();
    execute(
      runtime,
      "file:///rev2_public_process_events_fixture_meta_only_cleanup.js",
      format!(
        "rev2ProcessEventsController.cleanupMetaOnlyOwnKeys({operation_id_json});"
      ),
    );
  }

  fn prepare_rev2_public_async_hooks_fixture_state(
    runtime: &mut JsRuntime,
    root: &Path,
    operation: &Rev2V8FixtureOperation,
  ) {
    set_actor(root, "main.ts");
    let operation_id_json =
      deno_core::serde_json::to_string(operation.operation_id).unwrap();
    execute(
      runtime,
      "file:///rev2_public_async_hooks_fixture_prepare.js",
      format!(
        r#"
        {{
          const operationId = {operation_id_json};
          const asyncHooks = rev2AsyncHooks;
          const state = {{
            __proto__: null,
            operationId,
            hook: undefined,
            resource: undefined,
            resourceAsyncId: undefined,
            postDisableResource: undefined,
            postDisableResourceAsyncId: undefined,
            deniedResult: undefined,
            constructorDeniedResults: [undefined, undefined, undefined, undefined],
            constructorCallbackGetterReads: [0, 0, 0, 0],
            receiverCanaryResult: undefined,
            receiverCanaryReads: 0,
            deniedScopeEntries: 0,
            deniedScopeCompletions: 0,
            deniedScopeResult: undefined,
            deniedScopeSequence: [],
            beforeCalls: 0,
            afterCalls: 0,
            destroyCalls: 0,
            destroyAsyncIds: [],
            functionCalls: 0,
            resourceObservations: 0,
            sequence: [],
          }};
          state.plainCallbacks = {{
            __proto__: null,
            before() {{
              state.beforeCalls++;
              state.sequence.push("before");
            }},
            after() {{
              state.afterCalls++;
              state.sequence.push("after");
            }},
            destroy(asyncId) {{
              state.destroyCalls++;
              state.destroyAsyncIds.push(asyncId);
              state.sequence.push("destroy");
            }},
          }};
          function makeGetterCallbacks(index) {{
            function descriptor(value) {{
              return {{
                __proto__: null,
                enumerable: true,
                get() {{
                  state.constructorCallbackGetterReads[index]++;
                  return value;
                }},
              }};
            }}
            return Object.create(null, {{
              init: descriptor(undefined),
              before: descriptor(state.plainCallbacks.before),
              after: descriptor(state.plainCallbacks.after),
              destroy: descriptor(state.plainCallbacks.destroy),
              promiseResolve: descriptor(undefined),
            }});
          }}
          state.constructorGetterCallbacks = [
            makeGetterCallbacks(0),
            makeGetterCallbacks(1),
            makeGetterCallbacks(2),
            makeGetterCallbacks(3),
          ];
          state.receiverCanary = new Proxy(Object.create(null), {{
            get() {{
              state.receiverCanaryReads++;
              throw new Error("receiver state was read before the guard");
            }},
            getPrototypeOf() {{
              state.receiverCanaryReads++;
              throw new Error(
                "receiver prototype was observed before the guard",
              );
            }},
            has() {{
              state.receiverCanaryReads++;
              throw new Error("receiver state was queried before the guard");
            }},
          }});
          globalThis.rev2AsyncHooksState = state;

          switch (operationId) {{
            case "async-hooks-create-hook":
            case "async-hooks-execution-async-resource":
            case "async-hook-enable":
              state.hook = asyncHooks.createHook(state.plainCallbacks);
              state.resource = new asyncHooks.AsyncResource(
                `rev2:${{operationId}}`,
              );
              state.resourceAsyncId = state.resource.asyncId();
              break;
            case "async-hook-disable":
              state.hook = asyncHooks.createHook(state.plainCallbacks);
              state.hook.enable();
              state.resource = new asyncHooks.AsyncResource(
                `rev2:${{operationId}}`,
              );
              state.resourceAsyncId = state.resource.asyncId();
              break;
            default:
              throw new Error(
                `unknown async_hooks fixture operation ${{operationId}}`,
              );
          }}
        }}
        "#
      ),
    );
  }

  fn deny_rev2_public_async_hooks_fixture_operation(
    runtime: &mut JsRuntime,
    operation: &Rev2V8FixtureOperation,
  ) {
    let denied_actions = match operation.operation_id {
      "async-hooks-create-hook" => {
        r#"
          expectDenied(() => {
            state.constructorDeniedResults[0] = asyncHooks.createHook(
              state.constructorGetterCallbacks[0],
            );
          }, "public createHook");
          const RecoveredAsyncHook = state.hook.constructor;
          expectDenied(() => {
            state.constructorDeniedResults[1] = new RecoveredAsyncHook(
              state.constructorGetterCallbacks[1],
            );
          }, "inherited constructor");
          const SubclassedAsyncHook = class extends RecoveredAsyncHook {};
          expectDenied(() => {
            state.constructorDeniedResults[2] = new SubclassedAsyncHook(
              state.constructorGetterCallbacks[2],
            );
          }, "subclass constructor");
          expectDenied(() => {
            state.constructorDeniedResults[3] = Reflect.construct(
              RecoveredAsyncHook,
              [state.constructorGetterCallbacks[3]],
            );
          }, "Reflect.construct");
        "#
      }
      "async-hooks-execution-async-resource" => {
        r#"
          state.deniedScopeResult = state.resource.runInAsyncScope(() => {
            state.deniedScopeEntries++;
            state.deniedScopeSequence.push("function");
            expectDenied(() => {
              state.deniedResult = asyncHooks.executionAsyncResource();
            }, "active root AsyncResource observation");
            state.deniedScopeCompletions++;
            state.deniedScopeSequence.push("complete");
            return "denied-scope-complete";
          }, null);
        "#
      }
      "async-hook-disable" => {
        r#"
          const disable = state.hook.disable;
          expectDenied(() => {
            state.deniedResult = Reflect.apply(disable, state.hook, []);
          }, "valid public hook");
          expectDenied(() => {
            state.receiverCanaryResult = Reflect.apply(
              disable,
              state.receiverCanary,
              [],
            );
          }, "receiver-state precedence canary");
        "#
      }
      "async-hook-enable" => {
        r#"
          const enable = state.hook.enable;
          expectDenied(() => {
            state.deniedResult = Reflect.apply(enable, state.hook, []);
          }, "valid public hook");
          expectDenied(() => {
            state.receiverCanaryResult = Reflect.apply(
              enable,
              state.receiverCanary,
              [],
            );
          }, "receiver-state precedence canary");
        "#
      }
      _ => panic!(
        "unknown public async_hooks fixture operation {}",
        operation.operation_id
      ),
    };
    execute(
      runtime,
      "file:///rev2_public_async_hooks_fixture_denied.js",
      format!(
        r#"
        {{
          const asyncHooks = rev2AsyncHooks;
          const state = rev2AsyncHooksState;
          const before = {{
            __proto__: null,
            hook: state.hook,
            resource: state.resource,
            resourceAsyncId: state.resourceAsyncId,
            postDisableResource: state.postDisableResource,
            postDisableResourceAsyncId: state.postDisableResourceAsyncId,
            constructorCallbackGetterReads: [
              state.constructorCallbackGetterReads[0],
              state.constructorCallbackGetterReads[1],
              state.constructorCallbackGetterReads[2],
              state.constructorCallbackGetterReads[3],
            ],
            receiverCanaryReads: state.receiverCanaryReads,
            deniedScopeEntries: state.deniedScopeEntries,
            deniedScopeCompletions: state.deniedScopeCompletions,
            deniedScopeSequenceLength: state.deniedScopeSequence.length,
            beforeCalls: state.beforeCalls,
            afterCalls: state.afterCalls,
            destroyCalls: state.destroyCalls,
            destroyAsyncIdsLength: state.destroyAsyncIds.length,
            functionCalls: state.functionCalls,
            resourceObservations: state.resourceObservations,
            sequenceLength: state.sequence.length,
          }};
          function expectDenied(action, route) {{
            let denied = false;
            try {{
              action();
            }} catch (error) {{
              const message = String(error);
              const expected =
                "principal set [denied-native] may not use deny-only runtime:inspect:{}";
              if (!message.includes(expected)) {{
                throw new Error(
                  `${{route}} used the wrong actor or boundary: ${{message}}`,
                );
              }}
              denied = true;
            }}
            if (!denied) {{
              throw new Error(
                `${{route}} reached post-guard async_hooks work`,
              );
            }}
          }}

          {denied_actions}

          const activeResourceAttempt =
            state.operationId ===
              "async-hooks-execution-async-resource";
          if (
            state.deniedResult !== undefined ||
            state.constructorDeniedResults[0] !== undefined ||
            state.constructorDeniedResults[1] !== undefined ||
            state.constructorDeniedResults[2] !== undefined ||
            state.constructorDeniedResults[3] !== undefined ||
            state.receiverCanaryResult !== undefined ||
            state.hook !== before.hook ||
            state.resource !== before.resource ||
            state.resourceAsyncId !== before.resourceAsyncId ||
            state.postDisableResource !== before.postDisableResource ||
            state.postDisableResourceAsyncId !==
              before.postDisableResourceAsyncId ||
            state.constructorCallbackGetterReads[0] !==
              before.constructorCallbackGetterReads[0] ||
            state.constructorCallbackGetterReads[1] !==
              before.constructorCallbackGetterReads[1] ||
            state.constructorCallbackGetterReads[2] !==
              before.constructorCallbackGetterReads[2] ||
            state.constructorCallbackGetterReads[3] !==
              before.constructorCallbackGetterReads[3] ||
            state.receiverCanaryReads !== before.receiverCanaryReads ||
            state.beforeCalls !== before.beforeCalls ||
            state.afterCalls !== before.afterCalls ||
            state.destroyCalls !== before.destroyCalls ||
            state.destroyAsyncIds.length !== before.destroyAsyncIdsLength ||
            state.functionCalls !== before.functionCalls ||
            state.resourceObservations !== before.resourceObservations ||
            state.sequence.length !== before.sequenceLength ||
            state.deniedScopeEntries !==
              before.deniedScopeEntries + (activeResourceAttempt ? 1 : 0) ||
            state.deniedScopeCompletions !==
              before.deniedScopeCompletions +
                (activeResourceAttempt ? 1 : 0) ||
            state.deniedScopeSequence.length !==
              before.deniedScopeSequenceLength +
                (activeResourceAttempt ? 2 : 0) ||
            (
              activeResourceAttempt &&
              (
                state.deniedScopeResult !== "denied-scope-complete" ||
                state.deniedScopeSequence[
                    before.deniedScopeSequenceLength
                  ] !== "function" ||
                state.deniedScopeSequence[
                    before.deniedScopeSequenceLength + 1
                  ] !== "complete"
              )
            ) ||
            (!activeResourceAttempt &&
              state.deniedScopeResult !== undefined)
          ) {{
            throw new Error(
              "denied async_hooks operation changed observable state",
            );
          }}
        }}
        "#,
        operation.denied_target,
        denied_actions = denied_actions,
      ),
    );
  }

  fn cleanup_rev2_public_async_hooks_fixture_state(
    runtime: &mut JsRuntime,
    root: &Path,
    operation: &Rev2V8FixtureOperation,
  ) {
    set_actor(root, "main.ts");
    let body = match operation.operation_id {
      "async-hooks-create-hook" => {
        r#"
        assert(
          state.constructorCallbackGetterReads[0] === 0 &&
            state.constructorCallbackGetterReads[1] === 0 &&
            state.constructorCallbackGetterReads[2] === 0 &&
            state.constructorCallbackGetterReads[3] === 0 &&
            state.constructorDeniedResults[0] === undefined &&
            state.constructorDeniedResults[1] === undefined &&
            state.constructorDeniedResults[2] === undefined &&
            state.constructorDeniedResults[3] === undefined,
          "denied createHook route read callbacks or returned a hook",
        );
        state.hook.enable();
        resetObservations();
        const result = state.resource.runInAsyncScope(() => {
          state.functionCalls++;
          state.sequence.push("function");
          const observed = asyncHooks.executionAsyncResource();
          if (observed !== state.resource) {
            throw new Error("root createHook control observed wrong resource");
          }
          state.resourceObservations++;
          return "root-result";
        }, null);
        assert(
          result === "root-result",
          "root createHook control returned wrongly",
        );
        assertExactActiveSequence();
        assertExactDestroy();
        state.hook.disable();
        assertExplicitDisable();
      "#
      }
      "async-hooks-execution-async-resource" => {
        r#"
        assert(
          (
            state.deniedScopeEntries === 0 &&
            state.deniedScopeCompletions === 0 &&
            state.deniedScopeResult === undefined &&
            state.deniedScopeSequence.length === 0
          ) ||
            (
              state.deniedScopeEntries === 1 &&
              state.deniedScopeCompletions === 1 &&
              state.deniedScopeResult === "denied-scope-complete" &&
              state.deniedScopeSequence.length === 2 &&
              state.deniedScopeSequence[0] === "function" &&
              state.deniedScopeSequence[1] === "complete" &&
              state.resourceObservations === 0
            ),
          "executionAsyncResource control retained an inexact denied root-resource scope",
        );
        state.hook.enable();
        resetObservations();
        const result = state.resource.runInAsyncScope(() => {
          state.functionCalls++;
          state.sequence.push("function");
          const observed = asyncHooks.executionAsyncResource();
          if (observed !== state.resource) {
            throw new Error(
              "root executionAsyncResource observed wrong resource",
            );
          }
          state.resourceObservations++;
          return "root-result";
        }, null);
        assert(
          result === "root-result",
          "root executionAsyncResource control returned wrongly",
        );
        assertExactActiveSequence();
        assertExactDestroy();
        state.hook.disable();
        assertExplicitDisable();
      "#
      }
      "async-hook-disable" => {
        r#"
        resetObservations();
        const result = state.resource.runInAsyncScope(() => {
          state.functionCalls++;
          state.sequence.push("function");
          return "root-result";
        }, null);
        assert(
          result === "root-result",
          "denied disable active-hook control returned wrongly",
        );
        assertExactActiveSequence();
        assertExactDestroy();
        state.hook.disable();
        assertExplicitDisable();
      "#
      }
      "async-hook-enable" => {
        r#"
        resetObservations();
        const disabledResult = state.resource.runInAsyncScope(() => {
          state.functionCalls++;
          state.sequence.push("function");
          return "disabled-result";
        }, null);
        assert(
          disabledResult === "disabled-result" &&
            state.beforeCalls === 0 &&
            state.afterCalls === 0 &&
            state.sequence.length === 1 &&
            state.sequence[0] === "function",
          "denied enable inserted the root-created hook",
        );
        state.hook.enable();
        resetObservations();
        const activeResult = state.resource.runInAsyncScope(() => {
          state.functionCalls++;
          state.sequence.push("function");
          return "root-result";
        }, null);
        assert(
          activeResult === "root-result",
          "root enable control returned wrongly",
        );
        assertExactActiveSequence();
        assertExactDestroy();
        state.hook.disable();
        assertExplicitDisable();
      "#
      }
      _ => panic!(
        "unknown public async_hooks fixture operation {}",
        operation.operation_id
      ),
    };
    execute(
      runtime,
      "file:///rev2_public_async_hooks_fixture_cleanup.js",
      format!(
        r#"
        {{
          const asyncHooks = rev2AsyncHooks;
          const state = rev2AsyncHooksState;
          function assert(value, message) {{
            if (!value) throw new Error(message);
          }}
          function resetObservations() {{
            state.beforeCalls = 0;
            state.afterCalls = 0;
            state.functionCalls = 0;
            state.resourceObservations = 0;
            state.sequence.length = 0;
          }}
          function assertExactActiveSequence() {{
            assert(
              state.beforeCalls === 1 &&
                state.afterCalls === 1 &&
                state.destroyCalls === 0 &&
                state.destroyAsyncIds.length === 0 &&
                state.functionCalls === 1 &&
                state.sequence.length === 3 &&
                state.sequence[0] === "before" &&
                state.sequence[1] === "function" &&
                state.sequence[2] === "after",
              "root AsyncResource did not preserve before/function/after",
            );
          }}
          function assertExactDestroy() {{
            const destroyedResource = state.resource;
            assert(
              destroyedResource.emitDestroy() === destroyedResource,
              "explicit AsyncResource teardown returned the wrong resource",
            );
            assert(
              state.beforeCalls === 1 &&
                state.afterCalls === 1 &&
                state.destroyCalls === 1 &&
                state.destroyAsyncIds.length === 1 &&
                state.destroyAsyncIds[0] === state.resourceAsyncId &&
                state.functionCalls === 1 &&
                state.sequence.length === 4 &&
                state.sequence[0] === "before" &&
                state.sequence[1] === "function" &&
                state.sequence[2] === "after" &&
                state.sequence[3] === "destroy",
              "active hook did not observe one exact synchronous destroy callback",
            );
          }}
          function assertExplicitDisable() {{
            state.postDisableResource = new asyncHooks.AsyncResource(
              `rev2:${{state.operationId}}:post-disable`,
            );
            state.postDisableResourceAsyncId =
              state.postDisableResource.asyncId();
            assert(
              state.postDisableResourceAsyncId !== state.resourceAsyncId,
              "post-disable control reused the destroyed AsyncResource id",
            );
            resetObservations();
            const result = state.postDisableResource.runInAsyncScope(() => {{
              state.functionCalls++;
              state.sequence.push("function");
              return "disabled-result";
            }}, null);
            assert(
              result === "disabled-result" &&
                state.beforeCalls === 0 &&
                state.afterCalls === 0 &&
                state.destroyCalls === 1 &&
                state.destroyAsyncIds.length === 1 &&
                state.destroyAsyncIds[0] === state.resourceAsyncId &&
                state.functionCalls === 1 &&
                state.sequence.length === 1 &&
                state.sequence[0] === "function",
              "explicit root disable left the async hook active",
            );
            const postDisableResource = state.postDisableResource;
            assert(
              postDisableResource.emitDestroy() === postDisableResource &&
                state.destroyCalls === 1 &&
                state.destroyAsyncIds.length === 1 &&
                state.destroyAsyncIds[0] === state.resourceAsyncId &&
                state.sequence.length === 1 &&
                state.sequence[0] === "function",
              "post-disable resource teardown emitted a second destroy callback",
            );
            state.postDisableResource = undefined;
            state.postDisableResourceAsyncId = undefined;
          }}
          {body}
          assert(
            state.deniedResult === undefined &&
              state.receiverCanaryResult === undefined &&
              state.receiverCanaryReads === 0 &&
              state.destroyCalls === 1 &&
              state.destroyAsyncIds.length === 1 &&
              state.destroyAsyncIds[0] === state.resourceAsyncId &&
              state.postDisableResource === undefined &&
              state.postDisableResourceAsyncId === undefined,
            "async_hooks cleanup left an inexact denial or destroy state",
          );
          state.hook = undefined;
          state.resource = undefined;
          state.resourceAsyncId = undefined;
          state.postDisableResource = undefined;
          state.postDisableResourceAsyncId = undefined;
          state.plainCallbacks = undefined;
          state.constructorGetterCallbacks = undefined;
          state.receiverCanary = undefined;
          delete globalThis.rev2AsyncHooksState;
        }}
        "#
      ),
    );
  }

  fn rev2_public_async_hooks_expected_positive_guard_calls(
    operation: &Rev2V8FixtureOperation,
  ) -> Vec<(String, String, String, String)> {
    let mut calls = Vec::new();
    let mut push = |target: &str, api_name: &str| {
      calls.push((
        "runtime".to_string(),
        "inspect".to_string(),
        target.to_string(),
        api_name.to_string(),
      ));
    };
    let create_hook = "node:async_hooks.createHook";
    let execution_async_resource = "node:async_hooks.executionAsyncResource";
    let enable = "node:async_hooks.AsyncHook.enable";
    let disable = "node:async_hooks.AsyncHook.disable";
    match operation.operation_id {
      "async-hooks-create-hook" => {
        push("async-hooks", create_hook);
        push("async-hooks", enable);
        push("async-resource", execution_async_resource);
        push("async-hooks", disable);
      }
      "async-hooks-execution-async-resource" => {
        push("async-hooks", create_hook);
        push("async-hooks", enable);
        push("async-resource", execution_async_resource);
        push("async-hooks", disable);
      }
      "async-hook-disable" => {
        push("async-hooks", create_hook);
        push("async-hooks", enable);
        push("async-hooks", disable);
      }
      "async-hook-enable" => {
        push("async-hooks", create_hook);
        push("async-hooks", enable);
        push("async-hooks", disable);
      }
      _ => panic!(
        "unknown public async_hooks fixture operation {}",
        operation.operation_id
      ),
    }
    calls
  }

  fn rev2_public_async_hooks_prepare_guard_count(
    operation: &Rev2V8FixtureOperation,
  ) -> usize {
    match operation.operation_id {
      "async-hook-disable" => 2,
      "async-hooks-create-hook"
      | "async-hooks-execution-async-resource"
      | "async-hook-enable" => 1,
      _ => panic!(
        "unknown public async_hooks fixture operation {}",
        operation.operation_id
      ),
    }
  }

  fn rev2_public_async_hooks_denied_guard_count(
    operation: &Rev2V8FixtureOperation,
  ) -> usize {
    match operation.operation_id {
      "async-hooks-create-hook" => 4,
      "async-hook-disable" | "async-hook-enable" => 2,
      "async-hooks-execution-async-resource" => 1,
      _ => panic!(
        "unknown public async_hooks fixture operation {}",
        operation.operation_id
      ),
    }
  }

  fn rev2_public_async_hooks_expected_denied_cycle_guard_calls(
    operation: &Rev2V8FixtureOperation,
  ) -> Vec<(String, String, String, String)> {
    let mut expected =
      rev2_public_async_hooks_expected_positive_guard_calls(operation);
    let prepare_count = rev2_public_async_hooks_prepare_guard_count(operation);
    let denied_call = (
      "runtime".to_string(),
      "inspect".to_string(),
      operation.denied_target.to_string(),
      rev2_public_wrapper_guard_api_name(operation).to_string(),
    );
    for offset in 0..rev2_public_async_hooks_denied_guard_count(operation) {
      expected.insert(prepare_count + offset, denied_call.clone());
    }
    expected
  }

  fn run_rev2_public_async_hooks_positive_control(
    runtime: &mut JsRuntime,
    root: &Path,
    operation: &Rev2V8FixtureOperation,
  ) {
    let before = rev2_v8_fixture_canaries();
    prepare_rev2_public_async_hooks_fixture_state(runtime, root, operation);
    cleanup_rev2_public_async_hooks_fixture_state(runtime, root, operation);
    let after = rev2_v8_fixture_canaries();
    let expected =
      rev2_public_async_hooks_expected_positive_guard_calls(operation);
    assert_eq!(
      after.public_wrapper_guard_calls,
      before.public_wrapper_guard_calls + expected.len(),
      "{} ambient async_hooks control crossed an inexact number of guards",
      operation.operation_id
    );
    let observed = {
      let calls = PUBLIC_V8_WRAPPER_GUARD_CALLS.lock().unwrap();
      calls[before.public_wrapper_guard_calls..].to_vec()
    };
    assert_eq!(
      observed, expected,
      "{} ambient async_hooks control used an inexact guard sequence",
      operation.operation_id
    );
    assert_eq!(
      Rev2V8FixtureCanaries {
        public_wrapper_guard_calls: before.public_wrapper_guard_calls,
        ..after
      },
      before,
      "{} ambient async_hooks control crossed unrelated native work",
      operation.operation_id
    );
    execute(
      runtime,
      "file:///rev2_public_async_hooks_fixture_positive_clean.js",
      r#"
      if ("rev2AsyncHooksState" in globalThis) {
        throw new Error("ambient async_hooks control retained fixture state");
      }
      "#
      .to_string(),
    );
  }

  fn prepare_rev2_public_diagnostics_fixture_state(
    runtime: &mut JsRuntime,
    root: &Path,
    operation: &Rev2V8FixtureOperation,
    target: &str,
  ) {
    set_actor(root, "main.ts");
    let operation_id_json =
      deno_core::serde_json::to_string(operation.operation_id).unwrap();
    let target_json = deno_core::serde_json::to_string(target).unwrap();
    execute(
      runtime,
      "file:///rev2_public_diagnostics_fixture_prepare.js",
      format!(
        r#"
        {{
          const operationId = {operation_id_json};
          const diagnostics = rev2Diagnostics;
          const state = {{
            __proto__: null,
            name: {target_json},
            channel: undefined,
            initialPrototype: undefined,
            primarySubscriberCalls: 0,
            deniedSubscriberCalls: 0,
            primaryTransformCalls: 0,
            deniedTransformCalls: 0,
            primaryStoreRuns: 0,
            deniedStoreRuns: 0,
            primaryCallbackCalls: 0,
            deniedCallbackCalls: 0,
            lastSubscriberData: undefined,
            lastSubscriberName: undefined,
            lastStoreContext: undefined,
            lastCallbackThis: undefined,
            lastCallbackArgs: undefined,
            callbackThis: {{ __proto__: null, marker: "root-this" }},
          }};
          if (typeof state.name !== "string") {{
            throw new Error(
              "diagnostics fixtures cover exact primitive string names only",
            );
          }}
          state.primarySubscriber = (data, name) => {{
            state.primarySubscriberCalls++;
            state.lastSubscriberData = data;
            state.lastSubscriberName = name;
          }};
          state.deniedSubscriber = () => {{
            state.deniedSubscriberCalls++;
          }};
          state.primaryTransform = (data) => {{
            state.primaryTransformCalls++;
            return `context:${{data}}`;
          }};
          state.deniedTransform = (data) => {{
            state.deniedTransformCalls++;
            return `denied-context:${{data}}`;
          }};
          state.primaryStore = {{
            __proto__: null,
            run(context, next) {{
              state.primaryStoreRuns++;
              state.lastStoreContext = context;
              return next();
            }},
          }};
          state.deniedStore = {{
            __proto__: null,
            run(_context, next) {{
              state.deniedStoreRuns++;
              return next();
            }},
          }};
          state.primaryCallback = function (...args) {{
            state.primaryCallbackCalls++;
            state.lastCallbackThis = this;
            state.lastCallbackArgs = args;
            return "root-result";
          }};
          state.deniedCallback = () => {{
            state.deniedCallbackCalls++;
            return "denied-result";
          }};
          globalThis.rev2DiagnosticsState = state;

          switch (operationId) {{
            case "diagnostics-active-channel-bind-store":
            case "diagnostics-active-channel-has-subscribers":
            case "diagnostics-active-channel-publish":
            case "diagnostics-active-channel-unsubscribe":
              state.channel = diagnostics.channel(state.name);
              state.channel.subscribe(state.primarySubscriber);
              break;
            case "diagnostics-active-channel-run-stores":
            case "diagnostics-active-channel-subscribe":
            case "diagnostics-active-channel-unbind-store":
              state.channel = diagnostics.channel(state.name);
              state.channel.bindStore(
                state.primaryStore,
                state.primaryTransform,
              );
              break;
            case "diagnostics-channel-bind-store":
            case "diagnostics-channel-has-subscribers":
            case "diagnostics-channel-publish":
            case "diagnostics-channel-run-stores":
            case "diagnostics-channel-subscribe":
              state.channel = diagnostics.channel(state.name);
              if (
                Object.getPrototypeOf(state.channel) !==
                  diagnostics.Channel.prototype
              ) {{
                throw new Error("root did not prepare an inactive channel");
              }}
              break;
            case "diagnostics-has-subscribers":
              state.channel = diagnostics.channel(state.name);
              state.channel.subscribe(state.primarySubscriber);
              break;
            case "diagnostics-channel-constructor":
            case "diagnostics-channel":
            case "diagnostics-tracing-channel":
              break;
            default:
              throw new Error(
                `unknown diagnostics fixture operation ${{operationId}}`,
              );
          }}
          if (state.channel !== undefined) {{
            state.initialPrototype = Object.getPrototypeOf(state.channel);
          }}
        }}
        "#
      ),
    );
  }

  fn deny_rev2_public_diagnostics_fixture_operation(
    runtime: &mut JsRuntime,
    operation: &Rev2V8FixtureOperation,
  ) {
    let body = match operation.operation_id {
      "diagnostics-active-channel-bind-store"
      | "diagnostics-channel-bind-store" => {
        "state.channel.bindStore(state.deniedStore, state.deniedTransform)"
      }
      "diagnostics-active-channel-has-subscribers"
      | "diagnostics-channel-has-subscribers" => "state.channel.hasSubscribers",
      "diagnostics-active-channel-publish" | "diagnostics-channel-publish" => {
        r#"state.channel.publish("denied-data")"#
      }
      "diagnostics-active-channel-run-stores"
      | "diagnostics-channel-run-stores" => {
        r#"state.channel.runStores(
        "denied-data",
        state.deniedCallback,
        state.callbackThis,
        "denied-arg",
      )"#
      }
      "diagnostics-active-channel-subscribe"
      | "diagnostics-channel-subscribe" => {
        "state.channel.subscribe(state.deniedSubscriber)"
      }
      "diagnostics-active-channel-unbind-store" => {
        "state.channel.unbindStore(state.primaryStore)"
      }
      "diagnostics-active-channel-unsubscribe" => {
        "state.channel.unsubscribe(state.primarySubscriber)"
      }
      "diagnostics-channel-constructor" => {
        "new diagnostics.Channel(state.name)"
      }
      "diagnostics-channel" => "diagnostics.channel(state.name)",
      "diagnostics-has-subscribers" => "diagnostics.hasSubscribers(state.name)",
      "diagnostics-tracing-channel" => "diagnostics.tracingChannel(state.name)",
      _ => panic!(
        "unknown public diagnostics fixture operation {}",
        operation.operation_id
      ),
    };
    execute(
      runtime,
      "file:///rev2_public_diagnostics_fixture_denied.js",
      format!(
        r#"
        {{
          const diagnostics = rev2Diagnostics;
          const state = rev2DiagnosticsState;
          let denied = false;
          try {{
            state.deniedResult = {body};
          }} catch (error) {{
            const message = String(error);
            const expected =
              "principal set [denied-native] may not use deny-only runtime:inspect:{}";
            if (!message.includes(expected)) {{
              throw new Error(
                `public diagnostics wrapper used the wrong actor or boundary: ${{message}}`,
              );
            }}
            denied = true;
          }}
          if (!denied) {{
            throw new Error(
              "public diagnostics wrapper reached post-guard work",
            );
          }}
          if (
            state.deniedResult !== undefined ||
            state.primarySubscriberCalls !== 0 ||
            state.deniedSubscriberCalls !== 0 ||
            state.primaryTransformCalls !== 0 ||
            state.deniedTransformCalls !== 0 ||
            state.primaryStoreRuns !== 0 ||
            state.deniedStoreRuns !== 0 ||
            state.primaryCallbackCalls !== 0 ||
            state.deniedCallbackCalls !== 0
          ) {{
            throw new Error(
              "denied diagnostics operation changed observable state",
            );
          }}
          if (
            state.channel !== undefined &&
            Object.getPrototypeOf(state.channel) !== state.initialPrototype
          ) {{
            throw new Error(
              "denied diagnostics operation changed the channel prototype",
            );
          }}
        }}
        "#,
        operation.denied_target,
      ),
    );
  }

  fn cleanup_rev2_public_diagnostics_fixture_state(
    runtime: &mut JsRuntime,
    root: &Path,
    operation: &Rev2V8FixtureOperation,
  ) {
    set_actor(root, "main.ts");
    let body = match operation.operation_id {
      "diagnostics-active-channel-bind-store" => {
        r#"
        let result = state.channel.runStores(
          "root-bind-probe",
          state.primaryCallback,
          state.callbackThis,
          "root-arg",
        );
        assert(result === "root-result", "root bind probe returned wrongly");
        assert(
          state.primaryStoreRuns === 0 &&
            state.primaryTransformCalls === 0,
          "denied active bind installed its store",
        );
        assert(
          state.primarySubscriberCalls === 1,
          "root bind probe did not publish through the seed subscriber",
        );
        state.channel.bindStore(
          state.primaryStore,
          state.primaryTransform,
        );
        result = state.channel.runStores(
          "root-bound-probe",
          state.primaryCallback,
          state.callbackThis,
          "root-bound-arg",
        );
        assert(
          result === "root-result" &&
            state.primaryStoreRuns === 1 &&
            state.primaryTransformCalls === 1 &&
            state.lastStoreContext === "context:root-bound-probe",
          "root active bind did not install and execute its exact store",
        );
        assert(
          state.channel.unbindStore(state.primaryStore) === true,
          "root could not remove its active-bind store",
        );
        assert(
          state.channel.unsubscribe(state.primarySubscriber) === true,
          "root could not remove the seed subscriber",
        );
      "#
      }
      "diagnostics-active-channel-has-subscribers" => {
        r#"
        assert(
          state.channel.hasSubscribers === true,
          "denied active getter changed subscriber state",
        );
        assert(
          state.channel.unsubscribe(state.primarySubscriber) === true,
          "root could not remove the active getter seed subscriber",
        );
      "#
      }
      "diagnostics-active-channel-publish" => {
        r#"
        state.channel.publish("root-publish");
        assert(
          state.primarySubscriberCalls === 1 &&
            state.lastSubscriberData === "root-publish" &&
            state.lastSubscriberName === state.name,
          "root publish did not deliver the exact payload and name once",
        );
        assert(
          state.channel.unsubscribe(state.primarySubscriber) === true,
          "root could not remove the publish seed subscriber",
        );
      "#
      }
      "diagnostics-active-channel-run-stores" => {
        r#"
        const result = state.channel.runStores(
          "root-run",
          state.primaryCallback,
          state.callbackThis,
          "root-arg",
        );
        assert(
          result === "root-result" &&
            state.primaryTransformCalls === 1 &&
            state.primaryStoreRuns === 1 &&
            state.lastStoreContext === "context:root-run" &&
            state.primaryCallbackCalls === 1 &&
            state.lastCallbackThis === state.callbackThis &&
            state.lastCallbackArgs.length === 1 &&
            state.lastCallbackArgs[0] === "root-arg",
          "root runStores did not execute transform/store/callback exactly",
        );
        assert(
          state.channel.unbindStore(state.primaryStore) === true,
          "root could not remove the prepared store",
        );
      "#
      }
      "diagnostics-active-channel-subscribe" => {
        r#"
        state.channel.publish("root-before-subscribe");
        assert(
          state.primarySubscriberCalls === 0 &&
            state.deniedSubscriberCalls === 0,
          "denied active subscribe installed a handler",
        );
        state.channel.subscribe(state.primarySubscriber);
        state.channel.publish("root-subscribe-probe");
        assert(
          state.primarySubscriberCalls === 1 &&
            state.deniedSubscriberCalls === 0,
          "denied active subscribe installed its handler",
        );
        assert(
          state.channel.unsubscribe(state.primarySubscriber) === true,
          "root could not remove its active-subscribe handler",
        );
        assert(
          state.channel.unbindStore(state.primaryStore) === true,
          "root could not remove the active-subscribe activation store",
        );
      "#
      }
      "diagnostics-active-channel-unbind-store" => {
        r#"
        const result = state.channel.runStores(
          "root-unbind-probe",
          state.primaryCallback,
          state.callbackThis,
          "root-arg",
        );
        assert(
          result === "root-result" &&
            state.primaryTransformCalls === 1 &&
            state.primaryStoreRuns === 1 &&
            state.primaryCallbackCalls === 1,
          "denied active unbind removed the prepared store",
        );
        assert(
          state.channel.unbindStore(state.primaryStore) === true,
          "root could not remove the retained store",
        );
      "#
      }
      "diagnostics-active-channel-unsubscribe" => {
        r#"
        state.channel.publish("root-unsubscribe-probe");
        assert(
          state.primarySubscriberCalls === 1,
          "denied active unsubscribe removed the seed handler",
        );
        assert(
          state.channel.unsubscribe(state.primarySubscriber) === true,
          "root could not remove the retained handler",
        );
      "#
      }
      "diagnostics-channel-bind-store" => {
        r#"
        let result = state.channel.runStores(
          "root-before-bind",
          state.primaryCallback,
          state.callbackThis,
          "first",
        );
        assert(
          result === "root-result" &&
            state.primaryCallbackCalls === 1 &&
            state.primaryStoreRuns === 0 &&
            state.primaryTransformCalls === 0,
          "denied inactive bind installed a store",
        );
        state.channel.bindStore(
          state.primaryStore,
          state.primaryTransform,
        );
        result = state.channel.runStores(
          "root-after-bind",
          state.primaryCallback,
          state.callbackThis,
          "second",
        );
        assert(
          result === "root-result" &&
            state.primaryCallbackCalls === 2 &&
            state.primaryStoreRuns === 1 &&
            state.primaryTransformCalls === 1 &&
            state.lastStoreContext === "context:root-after-bind",
          "root inactive bind did not activate the exact store",
        );
        assert(
          state.channel.unbindStore(state.primaryStore) === true,
          "root could not remove its inactive-bind store",
        );
      "#
      }
      "diagnostics-channel-constructor" => {
        r#"
        state.channel = diagnostics.channel(state.name);
        assert(
          Object.getPrototypeOf(state.channel) ===
              diagnostics.Channel.prototype &&
            state.channel instanceof diagnostics.Channel &&
            state.channel.name === state.name,
          "root constructor produced the wrong inactive channel",
        );
        assert(
          diagnostics.channel(state.name) === state.channel,
          "root constructor did not register exact channel identity",
        );
      "#
      }
      "diagnostics-channel-has-subscribers" => {
        r#"
        assert(
          state.channel.hasSubscribers === false,
          "denied inactive getter changed subscriber state",
        );
      "#
      }
      "diagnostics-channel-publish" => {
        r#"
        assert(
          state.channel.publish("root-inactive-publish") === undefined,
          "inactive publish did not retain its exact no-op behavior",
        );
      "#
      }
      "diagnostics-channel-run-stores" => {
        r#"
        const result = state.channel.runStores(
          "root-inactive-run",
          state.primaryCallback,
          state.callbackThis,
          "first",
          "second",
        );
        assert(
          result === "root-result" &&
            state.primaryCallbackCalls === 1 &&
            state.lastCallbackThis === state.callbackThis &&
            state.lastCallbackArgs.length === 2 &&
            state.lastCallbackArgs[0] === "first" &&
            state.lastCallbackArgs[1] === "second",
          "inactive runStores did not preserve exact callback semantics",
        );
      "#
      }
      "diagnostics-channel-subscribe" => {
        r#"
        state.channel.subscribe(state.primarySubscriber);
        assert(
          Object.getPrototypeOf(state.channel) !==
            diagnostics.Channel.prototype,
          "root inactive subscribe did not activate the channel",
        );
        state.channel.publish("root-inactive-subscribe");
        assert(
          state.primarySubscriberCalls === 1 &&
            state.deniedSubscriberCalls === 0,
          "root inactive subscribe installed the wrong handlers",
        );
        assert(
          state.channel.unsubscribe(state.primarySubscriber) === true,
          "root could not remove its inactive-subscribe handler",
        );
      "#
      }
      "diagnostics-channel" => {
        r#"
        state.channel = diagnostics.channel(state.name);
        assert(
          state.channel instanceof diagnostics.Channel &&
            state.channel.name === state.name &&
            diagnostics.channel(state.name) === state.channel,
          "root channel lookup did not preserve exact identity",
        );
      "#
      }
      "diagnostics-has-subscribers" => {
        r#"
        assert(
          diagnostics.hasSubscribers(state.name) === true,
          "denied top-level hasSubscribers changed active state",
        );
        assert(
          state.channel.unsubscribe(state.primarySubscriber) === true,
          "root could not remove the top-level getter seed handler",
        );
      "#
      }
      "diagnostics-tracing-channel" => {
        r#"
        const tracing = diagnostics.tracingChannel(state.name);
        const events = [
          "start",
          "end",
          "asyncStart",
          "asyncEnd",
          "error",
        ];
        const seen = new Set();
        for (const event of events) {
          const channel = tracing[event];
          assert(
            channel instanceof diagnostics.Channel &&
              channel.name === `tracing:${state.name}:${event}` &&
              !seen.has(channel),
            `root tracing channel produced a wrong ${event} member`,
          );
          seen.add(channel);
        }
        assert(seen.size === 5, "root tracing channel did not create five members");
      "#
      }
      _ => panic!(
        "unknown public diagnostics fixture operation {}",
        operation.operation_id
      ),
    };
    execute(
      runtime,
      "file:///rev2_public_diagnostics_fixture_cleanup.js",
      format!(
        r#"
        {{
          const diagnostics = rev2Diagnostics;
          const state = rev2DiagnosticsState;
          function assert(value, message) {{
            if (!value) throw new Error(message);
          }}
          {body}
          assert(
            state.deniedSubscriberCalls === 0 &&
              state.deniedTransformCalls === 0 &&
              state.deniedStoreRuns === 0 &&
              state.deniedCallbackCalls === 0,
            "denied diagnostics work appeared during cleanup",
          );
          if (state.channel !== undefined) {{
            assert(
              Object.getPrototypeOf(state.channel) ===
                diagnostics.Channel.prototype,
              "explicit diagnostics cleanup did not restore inactivity",
            );
          }}
          state.channel = undefined;
          state.primaryStore = undefined;
          state.deniedStore = undefined;
          state.primarySubscriber = undefined;
          state.deniedSubscriber = undefined;
          delete globalThis.rev2DiagnosticsState;
        }}
        "#
      ),
    );
  }

  fn rev2_public_diagnostics_expected_positive_guard_calls(
    operation: &Rev2V8FixtureOperation,
    target: &str,
  ) -> Vec<(String, String, String, String)> {
    let mut calls = Vec::new();
    let mut push = |call_target: &str, api_name: &str| {
      calls.push((
        "runtime".to_string(),
        "inspect".to_string(),
        call_target.to_string(),
        api_name.to_string(),
      ));
    };
    let channel = "node:diagnostics_channel.channel";
    let constructor = "node:diagnostics_channel.Channel";
    let subscribe = "node:diagnostics_channel.subscribe";
    let unsubscribe = "node:diagnostics_channel.unsubscribe";
    let bind_store = "node:diagnostics_channel.bindStore";
    let unbind_store = "node:diagnostics_channel.unbindStore";
    let has_subscribers = "node:diagnostics_channel.hasSubscribers";
    let publish = "node:diagnostics_channel.publish";
    let run_stores = "node:diagnostics_channel.runStores";

    match operation.operation_id {
      "diagnostics-active-channel-bind-store" => {
        for api in [
          channel,
          constructor,
          subscribe,
          subscribe,
          run_stores,
          bind_store,
          run_stores,
          unbind_store,
          unsubscribe,
        ] {
          push(target, api);
        }
      }
      "diagnostics-active-channel-has-subscribers" => {
        for api in [
          channel,
          constructor,
          subscribe,
          subscribe,
          has_subscribers,
          unsubscribe,
        ] {
          push(target, api);
        }
      }
      "diagnostics-active-channel-publish" => {
        for api in [
          channel,
          constructor,
          subscribe,
          subscribe,
          publish,
          unsubscribe,
        ] {
          push(target, api);
        }
      }
      "diagnostics-active-channel-run-stores"
      | "diagnostics-active-channel-unbind-store" => {
        for api in [
          channel,
          constructor,
          bind_store,
          bind_store,
          run_stores,
          unbind_store,
        ] {
          push(target, api);
        }
      }
      "diagnostics-active-channel-subscribe" => {
        for api in [
          channel,
          constructor,
          bind_store,
          bind_store,
          publish,
          subscribe,
          publish,
          unsubscribe,
          unbind_store,
        ] {
          push(target, api);
        }
      }
      "diagnostics-active-channel-unsubscribe" => {
        for api in [
          channel,
          constructor,
          subscribe,
          subscribe,
          publish,
          unsubscribe,
        ] {
          push(target, api);
        }
      }
      "diagnostics-channel-bind-store" => {
        for api in [
          channel,
          constructor,
          run_stores,
          bind_store,
          bind_store,
          run_stores,
          unbind_store,
        ] {
          push(target, api);
        }
      }
      "diagnostics-channel-constructor" => {
        push(target, channel);
        push(target, constructor);
        push(target, channel);
      }
      "diagnostics-channel-has-subscribers" => {
        for api in [channel, constructor, has_subscribers] {
          push(target, api);
        }
      }
      "diagnostics-channel-publish" => {
        for api in [channel, constructor, publish] {
          push(target, api);
        }
      }
      "diagnostics-channel-run-stores" => {
        for api in [channel, constructor, run_stores] {
          push(target, api);
        }
      }
      "diagnostics-channel-subscribe" => {
        for api in [
          channel,
          constructor,
          subscribe,
          subscribe,
          publish,
          unsubscribe,
        ] {
          push(target, api);
        }
      }
      "diagnostics-channel" => {
        for api in [channel, constructor, channel] {
          push(target, api);
        }
      }
      "diagnostics-has-subscribers" => {
        for api in [
          channel,
          constructor,
          subscribe,
          subscribe,
          has_subscribers,
          has_subscribers,
          unsubscribe,
        ] {
          push(target, api);
        }
      }
      "diagnostics-tracing-channel" => {
        push(target, "node:diagnostics_channel.tracingChannel");
        for event in ["start", "end", "asyncStart", "asyncEnd", "error"] {
          let member_target = format!("tracing:{target}:{event}");
          push(&member_target, channel);
          push(&member_target, constructor);
        }
      }
      _ => panic!(
        "unknown public diagnostics fixture operation {}",
        operation.operation_id
      ),
    }
    calls
  }

  fn run_rev2_public_diagnostics_positive_control(
    runtime: &mut JsRuntime,
    root: &Path,
    operation: &Rev2V8FixtureOperation,
    phase: &str,
  ) {
    let target = format!("{}:positive-{phase}", operation.denied_target);
    let before = rev2_v8_fixture_canaries();
    prepare_rev2_public_diagnostics_fixture_state(
      runtime, root, operation, &target,
    );
    cleanup_rev2_public_diagnostics_fixture_state(runtime, root, operation);
    let after = rev2_v8_fixture_canaries();
    let expected =
      rev2_public_diagnostics_expected_positive_guard_calls(operation, &target);
    assert_eq!(
      after.public_wrapper_guard_calls,
      before.public_wrapper_guard_calls + expected.len(),
      "{} ambient diagnostics control crossed an inexact number of guards",
      operation.operation_id
    );
    let observed = {
      let calls = PUBLIC_V8_WRAPPER_GUARD_CALLS.lock().unwrap();
      calls[before.public_wrapper_guard_calls..].to_vec()
    };
    assert_eq!(
      observed, expected,
      "{} ambient diagnostics control used an inexact guard sequence",
      operation.operation_id
    );
    assert_eq!(
      Rev2V8FixtureCanaries {
        public_wrapper_guard_calls: before.public_wrapper_guard_calls,
        ..after
      },
      before,
      "{} ambient diagnostics control crossed unrelated native work",
      operation.operation_id
    );
    execute(
      runtime,
      "file:///rev2_public_diagnostics_fixture_positive_clean.js",
      r#"
      if ("rev2DiagnosticsState" in globalThis) {
        throw new Error("ambient diagnostics control retained fixture state");
      }
      "#
      .to_string(),
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
    assert_exact_public_wrapper_guard_call(operation, operation_guard_index);
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

  fn run_rev2_public_process_event_meta_only_own_keys(
    runtime: &mut JsRuntime,
    root: &Path,
    operation: &Rev2V8FixtureOperation,
    case_kind: &str,
    mode: &str,
  ) {
    if operation.operation_id != "process-events-sensitive-table" {
      return;
    }

    let prepare_guards = [("newListener", "process.on")];
    let before_prepare = rev2_v8_fixture_canaries();
    prepare_rev2_public_process_event_meta_only_own_keys(
      runtime, root, operation,
    );
    let after_prepare = rev2_v8_fixture_canaries();
    assert_eq!(
      after_prepare.public_wrapper_guard_calls,
      before_prepare.public_wrapper_guard_calls + prepare_guards.len(),
      "{} crossed an inexact number of meta-only preparation guards in {case_kind}/{mode}",
      operation.operation_id
    );
    assert_rev2_public_process_event_guard_sequence(
      before_prepare.public_wrapper_guard_calls,
      &prepare_guards,
      operation,
      "meta-only root preparation",
    );
    assert_eq!(
      Rev2V8FixtureCanaries {
        public_wrapper_guard_calls: before_prepare.public_wrapper_guard_calls,
        ..after_prepare
      },
      before_prepare,
      "{} meta-only preparation crossed unrelated native work in {case_kind}/{mode}",
      operation.operation_id
    );

    let before_denial = rev2_v8_fixture_canaries();
    deny_rev2_public_process_event_meta_only_own_keys(runtime, root);
    let after_denial = rev2_v8_fixture_canaries();
    assert_eq!(
      after_denial.public_wrapper_guard_calls,
      before_denial.public_wrapper_guard_calls + 1,
      "{} crossed an inexact number of meta-only denial guards in {case_kind}/{mode}",
      operation.operation_id
    );
    assert_rev2_public_process_event_guard_sequence(
      before_denial.public_wrapper_guard_calls,
      &[("process-events", "process._events.ownKeys")],
      operation,
      "meta-only denied ownKeys",
    );
    assert_eq!(
      Rev2V8FixtureCanaries {
        public_wrapper_guard_calls: before_denial.public_wrapper_guard_calls,
        ..after_denial
      },
      before_denial,
      "{} meta-only denial changed process event state or unrelated native work in {case_kind}/{mode}",
      operation.operation_id
    );
    assert_rev2_public_process_event_meta_only_own_keys_denied_state(
      runtime, root, operation,
    );

    let cleanup_guards = [("newListener", "process.off")];
    let before_cleanup = rev2_v8_fixture_canaries();
    cleanup_rev2_public_process_event_meta_only_own_keys(
      runtime, root, operation,
    );
    let after_cleanup = rev2_v8_fixture_canaries();
    assert_eq!(
      after_cleanup.public_wrapper_guard_calls,
      before_cleanup.public_wrapper_guard_calls + cleanup_guards.len(),
      "{} crossed an inexact number of meta-only cleanup guards in {case_kind}/{mode}",
      operation.operation_id
    );
    assert_rev2_public_process_event_guard_sequence(
      before_cleanup.public_wrapper_guard_calls,
      &cleanup_guards,
      operation,
      "meta-only root cleanup",
    );
    assert_eq!(
      Rev2V8FixtureCanaries {
        public_wrapper_guard_calls: before_cleanup.public_wrapper_guard_calls,
        ..after_cleanup
      },
      before_cleanup,
      "{} meta-only cleanup crossed unrelated native work in {case_kind}/{mode}",
      operation.operation_id
    );
    assert_rev2_public_process_event_fixture_clean_state(
      runtime, root, operation, false,
    );
  }

  fn run_rev2_public_process_signal_contract(
    runtime: &mut JsRuntime,
    root: &Path,
    operation: &Rev2V8FixtureOperation,
  ) {
    assert_eq!(
      operation.operation_id, "process-events-sensitive-table",
      "process signal contract requires the sensitive-table operation"
    );
    set_actor(root, "main.ts");
    execute(
      runtime,
      "file:///rev2_public_process_signal_contract.js",
      "rev2ProcessEventsController.assertSignalContract();".to_string(),
    );
    assert_eq!(
      PROCESS_SIGNAL_BIND_COUNT.load(Ordering::SeqCst),
      1,
      "process signal duplicates, prepending, or borrowed additions rebound the native signal"
    );
    assert_eq!(
      PROCESS_SIGNAL_INTERNAL_BIND_COUNT.load(Ordering::SeqCst),
      0,
      "public process signal registration used the trusted bind path"
    );
    assert_eq!(
      PROCESS_SIGNAL_UNBIND_COUNT.load(Ordering::SeqCst),
      1,
      "process signal once/borrowed/remove-all cleanup did not unbind exactly once"
    );
    PROCESS_SIGNAL_FAIL_NEXT_UNBIND.store(true, Ordering::SeqCst);
    execute(
      runtime,
      "file:///rev2_public_process_signal_addition_preflight_contract.js",
      "rev2ProcessEventsController.assertSignalAdditionPreflightContract();"
        .to_string(),
    );
    assert!(
      PROCESS_SIGNAL_FAIL_NEXT_UNBIND.load(Ordering::SeqCst),
      "inextensible process signal addition bound before exact table preflight"
    );
    assert_eq!(
      PROCESS_SIGNAL_BIND_COUNT.load(Ordering::SeqCst),
      1,
      "refused process signal addition crossed native bind"
    );
    assert_eq!(
      PROCESS_SIGNAL_UNBIND_COUNT.load(Ordering::SeqCst),
      1,
      "refused process signal addition reached rollback unbind"
    );
    execute(
      runtime,
      "file:///rev2_public_process_signal_unbind_failure_contract.js",
      "rev2ProcessEventsController.assertSignalUnbindFailureContract();"
        .to_string(),
    );
    assert!(
      !PROCESS_SIGNAL_FAIL_NEXT_UNBIND.load(Ordering::SeqCst),
      "process signal removal did not reach the injected native unbind failure"
    );
    assert_eq!(
      PROCESS_SIGNAL_BIND_COUNT.load(Ordering::SeqCst),
      2,
      "process signal unbind retry rebound or skipped the exact native registration"
    );
    assert_eq!(
      PROCESS_SIGNAL_INTERNAL_BIND_COUNT.load(Ordering::SeqCst),
      0,
      "public process signal unbind retry crossed the trusted bind path"
    );
    assert_eq!(
      PROCESS_SIGNAL_UNBIND_COUNT.load(Ordering::SeqCst),
      3,
      "process signal unbind failure and retry did not make two exact attempts"
    );

    let guard_start = PUBLIC_V8_WRAPPER_GUARD_CALL_COUNT.load(Ordering::SeqCst);
    execute(
      runtime,
      "file:///rev2_public_process_mixed_own_keys_contract.js",
      "rev2ProcessEventsController.assertMixedOwnKeysContract();".to_string(),
    );
    let observed = {
      let calls = PUBLIC_V8_WRAPPER_GUARD_CALLS.lock().unwrap();
      calls[guard_start..].to_vec()
    };
    assert_eq!(
      observed,
      vec![
        (
          "runtime".to_string(),
          "inspect".to_string(),
          "process-events".to_string(),
          "process._events=set".to_string(),
        ),
        (
          "runtime".to_string(),
          "inspect".to_string(),
          "process-events".to_string(),
          "process._events.ownKeys".to_string(),
        ),
        (
          "runtime".to_string(),
          "inspect".to_string(),
          "uncaughtException".to_string(),
          "process._events.ownKeys".to_string(),
        ),
        (
          "runtime".to_string(),
          "inspect".to_string(),
          "unhandledRejection".to_string(),
          "process._events.ownKeys".to_string(),
        ),
        (
          "runtime".to_string(),
          "inspect".to_string(),
          "newListener".to_string(),
          "process._events.ownKeys".to_string(),
        ),
        (
          "runtime".to_string(),
          "inspect".to_string(),
          "removeListener".to_string(),
          "process._events.ownKeys".to_string(),
        ),
        (
          "process".to_string(),
          "signal".to_string(),
          "inspect:SIGUSR1".to_string(),
          "process._events.ownKeys".to_string(),
        ),
        (
          "process".to_string(),
          "signal".to_string(),
          "inspect:SIGUSR2".to_string(),
          "process._events.ownKeys".to_string(),
        ),
        (
          "runtime".to_string(),
          "inspect".to_string(),
          "process-events".to_string(),
          "process._events=set".to_string(),
        ),
      ],
      "mixed process ownKeys did not guard every exact returned protected key"
    );
  }

  fn run_rev2_public_process_unhandled_rejection_listener_count_poison_contract(
    root: &Path,
  ) {
    reset_rev2_v8_fixture_canaries();
    let tokio_runtime = tokio::runtime::Builder::new_current_thread()
      .enable_all()
      .build()
      .unwrap();
    let _tokio_guard = tokio_runtime.enter();
    let mut runtime = new_public_process_wrapper_runtime();
    set_actor(root, "main.ts");
    let target = compiled_rev2_v8_fixture_target().expect(
      "process unhandled-rejection fixtures require an exact supported host",
    );
    execute(
      &mut runtime,
      "file:///rev2_public_process_unhandled_rejection_listener_count_poison_contract.js",
      r#"
      {
        const core = Deno.core;
        if (core.build.target !== "unknown") {
          throw new Error(
            "process rejection fixture build info was already set",
          );
        }
        core.setBuildInfo("__REV2_PROCESS_REJECTION_TARGET__");
        globalThis.Deno = Object.freeze({
          __proto__: null,
          core,
          build: core.build,
          pid: 4242,
          ppid: 4241,
          env: Object.freeze({
            __proto__: null,
            get() {
              return undefined;
            },
          }),
          cwd() {
            return "/rev2-process-rejection-fixture";
          },
          hostname() {
            return "rev2-process-rejection-host";
          },
          networkInterfaces() {
            return [];
          },
          addSignalListener() {},
          removeSignalListener() {},
        });

        let mutableGlobalEventListenerCalls = 0;
        let leakedGlobalErrorListener;
        globalThis.addEventListener = function (type, listener) {
          mutableGlobalEventListenerCalls++;
          leakedGlobalErrorListener = [type, listener];
        };
        globalThis.removeEventListener = function (type, listener) {
          mutableGlobalEventListenerCalls++;
          leakedGlobalErrorListener = [type, listener];
        };
        const webEvent = core.loadExtScript("ext:deno_web/02_event.js");
        const publicErrorTarget = new webEvent.EventTarget();
        const authenticGlobalAddEventListener =
          publicErrorTarget.addEventListener;
        const authenticGlobalRemoveEventListener =
          publicErrorTarget.removeEventListener;
        let mutableGlobalDispatchCalls = 0;
        publicErrorTarget.dispatchEvent = function () {
          mutableGlobalDispatchCalls++;
          throw new Error(
            "mutable global dispatchEvent received exception authority",
          );
        };
        webEvent.saveGlobalThisReference(publicErrorTarget);

        const processObject =
          core.createLazyLoader("node:process")().default;
        const bridge =
          globalThis.__rev2ProcessUnhandledRejectionFixture;
        const bridgeKeys = Reflect.ownKeys(bridge);
        if (
          bridge === null ||
          typeof bridge !== "object" ||
          Object.getPrototypeOf(bridge) !== null ||
          !Object.isFrozen(bridge) ||
          bridgeKeys.length !== 3 ||
          bridgeKeys[0] !== "dispatchUnhandledRejection" ||
          bridgeKeys[1] !== "dispatchGlobalError" ||
          bridgeKeys[2] !== "installTrustedProcessEventTable" ||
          typeof bridge.dispatchUnhandledRejection !== "function" ||
          typeof bridge.dispatchGlobalError !== "function" ||
          typeof bridge.installTrustedProcessEventTable !== "function" ||
          "internals" in bridge ||
          "token" in bridge ||
          "__proto__" in bridge
        ) {
          throw new Error(
            "process rejection fixture bridge was not exact",
          );
        }

        function refusedDirectListener() {}
        let directSetRefused = false;
        let directDefineRefused = false;
        let directPrototypeRefused = false;
        try {
          processObject._events.uncaughtException =
            refusedDirectListener;
        } catch (error) {
          directSetRefused = error instanceof TypeError;
        }
        try {
          Reflect.defineProperty(
            processObject._events,
            "unhandledRejection",
            {
              __proto__: null,
              configurable: true,
              enumerable: true,
              value: refusedDirectListener,
              writable: true,
            },
          );
        } catch (error) {
          directDefineRefused = error instanceof TypeError;
        }
        try {
          Reflect.setPrototypeOf(
            processObject._events,
            Object.create(null),
          );
        } catch (error) {
          directPrototypeRefused = error instanceof TypeError;
        }

        let listenerCountPoisonCalls = 0;
        const monitorDeliveries = [];
        const uncaughtDeliveries = [];
        function monitorListener(reason, origin) {
          monitorDeliveries.push([reason, origin]);
        }
        function uncaughtListener(reason, origin) {
          uncaughtDeliveries.push([reason, origin]);
        }
        const ownListenerCountDescriptor =
          Reflect.getOwnPropertyDescriptor(
            processObject,
            "listenerCount",
          );
        const retainedRawListeners = processObject.rawListeners;
        const monitorOnlyReason = new Error(
          "rev2 monitor-only unhandled rejection",
        );
        const consumedReason = new Error(
          "rev2 consumed unhandled rejection",
        );
        const monitorOnlyError = new Error(
          "rev2 monitor-only global error",
        );
        const consumedError = new Error(
          "rev2 consumed global error",
        );
        const monitorOnlyPromise = Object.freeze({
          __proto__: null,
          fixture: "monitor-only",
        });
        const consumedPromise = Object.freeze({
          __proto__: null,
          fixture: "consumed",
        });

        processObject.on(
          "uncaughtExceptionMonitor",
          monitorListener,
        );
        let armedDirectDeleteRefused = false;
        try {
          Reflect.deleteProperty(
            processObject._events,
            "uncaughtExceptionMonitor",
          );
        } catch (error) {
          armedDirectDeleteRefused = error instanceof TypeError;
        }
        Object.defineProperty(processObject, "listenerCount", {
          __proto__: null,
          configurable: true,
          enumerable: true,
          value() {
            listenerCountPoisonCalls++;
            return 1;
          },
          writable: true,
        });
        try {
          const monitorOnlyErrorPreventions =
            bridge.dispatchGlobalError(monitorOnlyError);
          if (
            monitorOnlyErrorPreventions !== 0 ||
            monitorDeliveries.length !== 1 ||
            monitorDeliveries[0][0] !== monitorOnlyError ||
            monitorDeliveries[0][1] !== "uncaughtException" ||
            uncaughtDeliveries.length !== 0
          ) {
            throw new Error(
              "poisoned globals changed the monitor-only error branch",
            );
          }

          const monitorOnlyPreventions =
            bridge.dispatchUnhandledRejection(
              monitorOnlyReason,
              monitorOnlyPromise,
            );
          if (
            monitorOnlyPreventions !== 0 ||
            monitorDeliveries.length !== 2 ||
            monitorDeliveries[1][0] !== monitorOnlyReason ||
            monitorDeliveries[1][1] !== "unhandledRejection" ||
            uncaughtDeliveries.length !== 0
          ) {
            throw new Error(
              "listenerCount poisoning suppressed the monitor-only fatal branch",
            );
          }

          processObject.on("uncaughtException", uncaughtListener);
          let publicErrorListenerCalls = 0;
          function cancelAndPoisonPublicError(event) {
            publicErrorListenerCalls++;
            event.preventDefault();
            Object.defineProperty(event, "error", {
              __proto__: null,
              configurable: true,
              get() {
                throw new Error("public ErrorEvent.error poison ran");
              },
            });
          }
          Reflect.apply(
            authenticGlobalAddEventListener,
            publicErrorTarget,
            ["error", cancelAndPoisonPublicError],
          );
          try {
            webEvent.reportException(consumedError);
          } finally {
            Reflect.apply(
              authenticGlobalRemoveEventListener,
              publicErrorTarget,
              ["error", cancelAndPoisonPublicError],
            );
          }
          if (
            publicErrorListenerCalls !== 1 ||
            mutableGlobalDispatchCalls !== 0 ||
            monitorDeliveries.length !== 3 ||
            monitorDeliveries[2][0] !== consumedError ||
            monitorDeliveries[2][1] !== "uncaughtException" ||
            uncaughtDeliveries.length !== 1 ||
            uncaughtDeliveries[0][0] !== consumedError ||
            uncaughtDeliveries[0][1] !== "uncaughtException"
          ) {
            throw new Error(
              "poisoned globals changed the consumed error branch",
            );
          }

          const consumedPreventions =
            bridge.dispatchUnhandledRejection(
              consumedReason,
              consumedPromise,
            );
          if (
            consumedPreventions !== 1 ||
            monitorDeliveries.length !== 4 ||
            monitorDeliveries[3][0] !== consumedReason ||
            monitorDeliveries[3][1] !== "unhandledRejection" ||
            uncaughtDeliveries.length !== 2 ||
            uncaughtDeliveries[1][0] !== consumedReason ||
            uncaughtDeliveries[1][1] !== "unhandledRejection"
          ) {
            throw new Error(
              "listenerCount poisoning changed the consumed fatal branch",
            );
          }
        } finally {
          if (ownListenerCountDescriptor === undefined) {
            Reflect.deleteProperty(processObject, "listenerCount");
          } else {
            Reflect.defineProperty(
              processObject,
              "listenerCount",
              ownListenerCountDescriptor,
            );
          }
          processObject.off("uncaughtException", uncaughtListener);
          processObject.off(
            "uncaughtExceptionMonitor",
            monitorListener,
          );
        }

        const reentrantMonitorError = new Error(
          "rev2 reentrant monitor replacement refusal",
        );
        let reentrantMonitorDeliveries = 0;
        let reentrantMonitorReplacementRefused = false;
        function reentrantMonitor(reason, origin) {
          if (
            reason !== reentrantMonitorError ||
            origin !== "uncaughtException"
          ) {
            throw new Error(
              "reentrant monitor received an inexact exception",
            );
          }
          reentrantMonitorDeliveries++;
          try {
            processObject._events = Object.create(null);
          } catch (error) {
            reentrantMonitorReplacementRefused = error instanceof TypeError;
          }
        }
        processObject.on("uncaughtExceptionMonitor", reentrantMonitor);
        const reentrantMonitorPreventions =
          bridge.dispatchGlobalError(reentrantMonitorError);
        processObject.off("uncaughtExceptionMonitor", reentrantMonitor);

        const captureError = new Error(
          "rev2 capture callback replacement refusal",
        );
        let captureDeliveries = 0;
        function captureListener(error) {
          if (error !== captureError) {
            throw new Error(
              "capture callback received an inexact error",
            );
          }
          captureDeliveries++;
        }
        processObject.setUncaughtExceptionCaptureCallback(
          captureListener,
        );
        let captureReplacementRefused = false;
        try {
          processObject._events = Object.create(null);
        } catch (error) {
          captureReplacementRefused = error instanceof TypeError;
        }
        const capturePreventions = bridge.dispatchGlobalError(captureError);
        processObject.setUncaughtExceptionCaptureCallback(null);

        processObject.on("uncaughtException", uncaughtListener);
        processObject._events = Object.create(null);
        const replacementDirectFatalHandled = processObject._fatalException(
          new Error("direct fatal dispatch after public table replacement"),
          false,
        );
        let replacementClearedGlobalErrorListener = false;
        let replacementClearedUnhandledRejectionCallback = false;
        try {
          bridge.dispatchGlobalError(new Error("stale global error"));
        } catch (error) {
          replacementClearedGlobalErrorListener =
            error instanceof Error &&
            error.message === "node process global error listener was absent";
        }
        try {
          bridge.dispatchUnhandledRejection(
            new Error("stale unhandled rejection"),
            Object.freeze({ __proto__: null }),
          );
        } catch (error) {
          replacementClearedUnhandledRejectionCallback =
            error instanceof Error &&
            error.message ===
              "node process unhandled-rejection callback was absent";
        }
        let captureAfterReplacementRefused = false;
        try {
          processObject.setUncaughtExceptionCaptureCallback(
            captureListener,
          );
        } catch (error) {
          captureAfterReplacementRefused = error instanceof TypeError;
        }
        function ordinaryListener() {}
        processObject.on("rev2-requalification", ordinaryListener);
        processObject.off("rev2-requalification", ordinaryListener);
        const requalifiedCaptureError = new Error(
          "rev2 requalified capture callback",
        );
        let requalifiedCaptureDeliveries = 0;
        processObject.setUncaughtExceptionCaptureCallback((error) => {
          if (error !== requalifiedCaptureError) {
            throw new Error(
              "requalified capture callback received an inexact error",
            );
          }
          requalifiedCaptureDeliveries++;
        });
        const requalifiedCapturePreventions =
          bridge.dispatchGlobalError(requalifiedCaptureError);
        processObject.setUncaughtExceptionCaptureCallback(null);
        let requalifiedMonitorDeliveries = 0;
        function requalifiedMonitor(reason, origin) {
          if (
            reason.message !== "requalified unhandled rejection" ||
            origin !== "unhandledRejection"
          ) {
            throw new Error(
              "requalified exception routing changed reason or origin",
            );
          }
          requalifiedMonitorDeliveries++;
        }
        processObject.on(
          "uncaughtExceptionMonitor",
          requalifiedMonitor,
        );
        const requalifiedPreventions =
          bridge.dispatchUnhandledRejection(
            new Error("requalified unhandled rejection"),
            Object.freeze({ __proto__: null }),
          );
        processObject.off(
          "uncaughtExceptionMonitor",
          requalifiedMonitor,
        );
        if (
          !directSetRefused ||
          !directDefineRefused ||
          !directPrototypeRefused ||
          !armedDirectDeleteRefused ||
          listenerCountPoisonCalls !== 0 ||
          mutableGlobalEventListenerCalls !== 0 ||
          mutableGlobalDispatchCalls !== 0 ||
          leakedGlobalErrorListener !== undefined ||
          reentrantMonitorPreventions !== 0 ||
          reentrantMonitorDeliveries !== 1 ||
          !reentrantMonitorReplacementRefused ||
          !captureReplacementRefused ||
          capturePreventions !== 1 ||
          captureDeliveries !== 1 ||
          !captureAfterReplacementRefused ||
          replacementDirectFatalHandled !== false ||
          !replacementClearedGlobalErrorListener ||
          !replacementClearedUnhandledRejectionCallback ||
          requalifiedCapturePreventions !== 1 ||
          requalifiedCaptureDeliveries !== 1 ||
          requalifiedPreventions !== 0 ||
          requalifiedMonitorDeliveries !== 1 ||
          Reflect.apply(
              retainedRawListeners,
              processObject,
              ["uncaughtException"],
            ).length !== 0 ||
          Reflect.apply(
              retainedRawListeners,
              processObject,
              ["uncaughtExceptionMonitor"],
            ).length !== 0
        ) {
          throw new Error(
            "runtime rejection dispatch used mutable listenerCount or retained listeners",
          );
        }
      }
      "#
      .replace("__REV2_PROCESS_REJECTION_TARGET__", target),
    );
    let observed = PUBLIC_V8_WRAPPER_GUARD_CALLS.lock().unwrap().clone();
    assert!(
      observed
        .iter()
        .all(|(_, _, _, api_name)| api_name != "process.listenerCount"),
      "internal unhandled-rejection dispatch crossed the mutable public process.listenerCount guard"
    );
    drop(runtime);
  }

  fn run_rev2_public_process_event_fixture_mode(
    root: &Path,
    operation: &Rev2V8FixtureOperation,
    case_kind: &str,
    mode: &str,
  ) {
    if operation.operation_id == "process-events-sensitive-table"
      && case_kind == "deny-only-closed-or-absent"
      && mode == "permissive"
    {
      run_rev2_public_process_unhandled_rejection_listener_count_poison_contract(
        root,
      );
    }
    reset_rev2_v8_fixture_canaries();
    let tokio_runtime = tokio::runtime::Builder::new_current_thread()
      .enable_all()
      .build()
      .unwrap();
    let _tokio_guard = tokio_runtime.enter();
    let mut runtime = new_public_process_wrapper_runtime();
    load_public_process_events_wrapper(&mut runtime, root);
    assert_public_process_event_guard_precedes_wrapper_work(operation);
    assert_rev2_public_process_event_guard_sequence(
      0,
      &[("uncaughtException", "process.rawListeners")],
      operation,
      "isolated public-wrapper loading",
    );

    let prepare_start =
      PUBLIC_V8_WRAPPER_GUARD_CALL_COUNT.load(Ordering::SeqCst);
    prepare_rev2_public_process_event_fixture_state(
      &mut runtime,
      root,
      operation,
    );
    assert_rev2_public_process_event_guard_sequence(
      prepare_start,
      rev2_public_process_event_prepare_guards(operation),
      operation,
      "root preparation",
    );

    let before = rev2_v8_fixture_canaries();
    deny_rev2_public_process_event_fixture_operation(
      &mut runtime,
      root,
      operation,
      true,
    );
    let after = rev2_v8_fixture_canaries();
    let denied_guards =
      rev2_public_process_event_denied_guards(operation, true);
    assert_eq!(
      after.public_wrapper_guard_calls,
      before.public_wrapper_guard_calls + denied_guards.len(),
      "{} crossed an inexact number of process event denial guards in {case_kind}/{mode}",
      operation.operation_id
    );
    assert_rev2_public_process_event_guard_sequence(
      before.public_wrapper_guard_calls,
      &denied_guards,
      operation,
      "denied operation",
    );
    assert_eq!(
      Rev2V8FixtureCanaries {
        public_wrapper_guard_calls: before.public_wrapper_guard_calls,
        ..after
      },
      before,
      "{} changed process event state or unrelated native work before denial in {case_kind}/{mode}",
      operation.operation_id
    );
    assert_rev2_public_process_event_fixture_denied_state(
      &mut runtime,
      root,
      operation,
    );

    let before_cleanup = rev2_v8_fixture_canaries();
    cleanup_rev2_public_process_event_fixture_state(
      &mut runtime,
      root,
      operation,
    );
    let after_cleanup = rev2_v8_fixture_canaries();
    let cleanup_guards = rev2_public_process_event_cleanup_guards(operation);
    assert_eq!(
      after_cleanup.public_wrapper_guard_calls,
      before_cleanup.public_wrapper_guard_calls + cleanup_guards.len(),
      "{} crossed an inexact number of process event cleanup guards in {case_kind}/{mode}",
      operation.operation_id
    );
    assert_rev2_public_process_event_guard_sequence(
      before_cleanup.public_wrapper_guard_calls,
      cleanup_guards,
      operation,
      "explicit root cleanup",
    );
    assert_eq!(
      Rev2V8FixtureCanaries {
        public_wrapper_guard_calls: before_cleanup.public_wrapper_guard_calls,
        ..after_cleanup
      },
      before_cleanup,
      "{} cleanup crossed unrelated native work in {case_kind}/{mode}",
      operation.operation_id
    );
    assert_rev2_public_process_event_fixture_clean_state(
      &mut runtime,
      root,
      operation,
      false,
    );

    run_rev2_public_process_event_meta_only_own_keys(
      &mut runtime,
      root,
      operation,
      case_kind,
      mode,
    );

    if case_kind == "staged-barrier:cleanup" {
      let before_post_cleanup = rev2_v8_fixture_canaries();
      deny_rev2_public_process_event_fixture_operation(
        &mut runtime,
        root,
        operation,
        false,
      );
      let after_post_cleanup = rev2_v8_fixture_canaries();
      let post_cleanup_guards =
        rev2_public_process_event_denied_guards(operation, false);
      assert_eq!(
        after_post_cleanup.public_wrapper_guard_calls,
        before_post_cleanup.public_wrapper_guard_calls
          + post_cleanup_guards.len(),
        "{} crossed an inexact number of post-cleanup process event denial guards in {mode}",
        operation.operation_id
      );
      assert_rev2_public_process_event_guard_sequence(
        before_post_cleanup.public_wrapper_guard_calls,
        &post_cleanup_guards,
        operation,
        "post-cleanup denied operation",
      );
      assert_eq!(
        Rev2V8FixtureCanaries {
          public_wrapper_guard_calls: before_post_cleanup
            .public_wrapper_guard_calls,
          ..after_post_cleanup
        },
        before_post_cleanup,
        "{} post-cleanup denial changed process event state or unrelated native work in {mode}",
        operation.operation_id
      );
      assert_rev2_public_process_event_fixture_clean_state(
        &mut runtime,
        root,
        operation,
        true,
      );
    }

    if operation.operation_id == "process-events-sensitive-table"
      && case_kind == "deny-only-closed-or-absent"
      && mode == "permissive"
    {
      run_rev2_public_process_signal_contract(&mut runtime, root, operation);
    }

    assert_rev2_v8_fixture_terminal_clean(operation.operation_id, mode);
    drop(runtime);
    assert_eq!(
      GC_PROFILER_ACTIVE_STATE_COUNT.load(Ordering::SeqCst),
      0,
      "{} retained unrelated native profiler state after process event runtime disposal in {mode}",
      operation.operation_id
    );
  }

  fn run_rev2_public_process_fixture_mode(
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
    let mut runtime = new_public_process_wrapper_runtime();
    assert_public_process_guard_precedes_wrapper_work(operation);
    if rev2_process_fixture_is_active_resources(operation) {
      load_public_process_active_resources_wrapper(&mut runtime, root);
    } else {
      load_public_process_report_wrapper(&mut runtime, root);
    }

    if case_kind == "staged-barrier:cleanup" {
      run_rev2_public_process_positive_control(&mut runtime, root, operation);
    }

    let sequence_start =
      PUBLIC_V8_WRAPPER_GUARD_CALL_COUNT.load(Ordering::SeqCst);
    prepare_rev2_public_process_fixture_state(&mut runtime, root, operation);
    let before = rev2_v8_fixture_canaries();
    deny_rev2_public_process_fixture_operation(&mut runtime, root, operation);
    let after = rev2_v8_fixture_canaries();
    assert_eq!(
      after.public_wrapper_guard_calls,
      before.public_wrapper_guard_calls + 1,
      "{} did not cross exactly one process guard in {case_kind}/{mode}",
      operation.operation_id
    );
    assert_exact_public_wrapper_guard_call(
      operation,
      before.public_wrapper_guard_calls,
    );
    assert_eq!(
      Rev2V8FixtureCanaries {
        public_wrapper_guard_calls: before.public_wrapper_guard_calls,
        ..after
      },
      before,
      "{} changed process wrapper state or unrelated native work before denial in {case_kind}/{mode}",
      operation.operation_id
    );
    assert_rev2_public_process_fixture_state(
      &mut runtime,
      root,
      operation,
      rev2_process_fixture_is_active_resources(operation),
      "file:///rev2_public_process_fixture_denied_state.js",
    );

    let cleanup_guard_calls =
      cleanup_rev2_public_process_fixture_state(&mut runtime, root, operation);
    assert_rev2_public_process_fixture_state(
      &mut runtime,
      root,
      operation,
      false,
      "file:///rev2_public_process_fixture_clean_state.js",
    );

    let post_cleanup_denial = case_kind == "staged-barrier:cleanup";
    if post_cleanup_denial {
      let before_post_cleanup = rev2_v8_fixture_canaries();
      deny_rev2_public_process_fixture_operation(&mut runtime, root, operation);
      let after_post_cleanup = rev2_v8_fixture_canaries();
      assert_eq!(
        after_post_cleanup.public_wrapper_guard_calls,
        before_post_cleanup.public_wrapper_guard_calls + 1,
        "{} post-cleanup denial did not cross exactly one process guard in {mode}",
        operation.operation_id
      );
      assert_exact_public_wrapper_guard_call(
        operation,
        before_post_cleanup.public_wrapper_guard_calls,
      );
      assert_eq!(
        Rev2V8FixtureCanaries {
          public_wrapper_guard_calls: before_post_cleanup
            .public_wrapper_guard_calls,
          ..after_post_cleanup
        },
        before_post_cleanup,
        "{} post-cleanup denial reached process wrapper work or unrelated native work in {mode}",
        operation.operation_id
      );
      assert_rev2_public_process_fixture_state(
        &mut runtime,
        root,
        operation,
        false,
        "file:///rev2_public_process_fixture_post_cleanup_denied_state.js",
      );
    }

    assert_rev2_public_process_guard_sequence(
      operation,
      sequence_start,
      1 + cleanup_guard_calls + usize::from(post_cleanup_denial),
      "prepare/deny/behavioral-cleanup/post-cleanup denial",
    );

    if case_kind == "staged-barrier:cancellation" {
      run_rev2_public_process_positive_control(&mut runtime, root, operation);
    }
    assert_rev2_public_process_fixture_state(
      &mut runtime,
      root,
      operation,
      false,
      "file:///rev2_public_process_fixture_terminal_state.js",
    );
    assert_rev2_v8_fixture_terminal_clean(operation.operation_id, mode);
    drop(runtime);
    assert_eq!(
      GC_PROFILER_ACTIVE_STATE_COUNT.load(Ordering::SeqCst),
      0,
      "{} retained unrelated native profiler state after process wrapper runtime disposal in {mode}",
      operation.operation_id
    );
  }

  fn run_rev2_public_async_hooks_denied_cycle(
    runtime: &mut JsRuntime,
    root: &Path,
    operation: &Rev2V8FixtureOperation,
    case_kind: &str,
    mode: &str,
  ) {
    let sequence_start =
      PUBLIC_V8_WRAPPER_GUARD_CALL_COUNT.load(Ordering::SeqCst);
    prepare_rev2_public_async_hooks_fixture_state(runtime, root, operation);
    let expected_prepare_calls =
      rev2_public_async_hooks_prepare_guard_count(operation);
    assert_eq!(
      PUBLIC_V8_WRAPPER_GUARD_CALL_COUNT.load(Ordering::SeqCst),
      sequence_start + expected_prepare_calls,
      "{} preparation crossed an inexact async_hooks guard sequence",
      operation.operation_id
    );

    set_actor(root, "node_modules/denied-native/index.cjs");
    let before = rev2_v8_fixture_canaries();
    deny_rev2_public_async_hooks_fixture_operation(runtime, operation);
    let after = rev2_v8_fixture_canaries();
    let denied_guard_count =
      rev2_public_async_hooks_denied_guard_count(operation);
    assert_eq!(
      after.public_wrapper_guard_calls,
      before.public_wrapper_guard_calls + denied_guard_count,
      "{} crossed an inexact number of async_hooks denial guards in {case_kind}/{mode}",
      operation.operation_id
    );
    for call_index in
      before.public_wrapper_guard_calls..after.public_wrapper_guard_calls
    {
      assert_exact_public_wrapper_guard_call(operation, call_index);
    }
    assert_eq!(
      Rev2V8FixtureCanaries {
        public_wrapper_guard_calls: before.public_wrapper_guard_calls,
        ..after
      },
      before,
      "{} changed async hook state or unrelated native work before denial in {case_kind}/{mode}",
      operation.operation_id
    );

    cleanup_rev2_public_async_hooks_fixture_state(runtime, root, operation);
    let observed = {
      let calls = PUBLIC_V8_WRAPPER_GUARD_CALLS.lock().unwrap();
      calls[sequence_start..].to_vec()
    };
    assert_eq!(
      observed,
      rev2_public_async_hooks_expected_denied_cycle_guard_calls(operation),
      "{} prepare/deny/cleanup used an inexact async_hooks guard sequence",
      operation.operation_id
    );
    execute(
      runtime,
      "file:///rev2_public_async_hooks_fixture_denied_cycle_clean.js",
      r#"
      if ("rev2AsyncHooksState" in globalThis) {
        throw new Error("async_hooks denied cycle retained fixture state");
      }
      "#
      .to_string(),
    );
  }

  fn run_rev2_public_async_hooks_fixture_mode(
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
    assert_public_async_hooks_guard_precedes_wrapper_work(operation);
    load_public_async_hooks_wrapper(&mut runtime, root);

    if case_kind == "staged-barrier:cleanup" {
      run_rev2_public_async_hooks_positive_control(
        &mut runtime,
        root,
        operation,
      );
    }

    let denied_cycles_start =
      PUBLIC_V8_WRAPPER_GUARD_CALL_COUNT.load(Ordering::SeqCst);
    run_rev2_public_async_hooks_denied_cycle(
      &mut runtime,
      root,
      operation,
      case_kind,
      mode,
    );
    if case_kind == "staged-barrier:cleanup" {
      run_rev2_public_async_hooks_denied_cycle(
        &mut runtime,
        root,
        operation,
        case_kind,
        mode,
      );
    }
    let denied_cycles_end =
      PUBLIC_V8_WRAPPER_GUARD_CALL_COUNT.load(Ordering::SeqCst);
    let expected_cycle =
      rev2_public_async_hooks_expected_denied_cycle_guard_calls(operation);
    let mut expected = expected_cycle.clone();
    if case_kind == "staged-barrier:cleanup" {
      expected.extend(expected_cycle);
    }
    let observed = {
      let calls = PUBLIC_V8_WRAPPER_GUARD_CALLS.lock().unwrap();
      calls[denied_cycles_start..denied_cycles_end].to_vec()
    };
    assert_eq!(
      observed, expected,
      "{} did not append the exact fresh post-cleanup denied sequence",
      operation.operation_id
    );

    if case_kind == "staged-barrier:cancellation" {
      run_rev2_public_async_hooks_positive_control(
        &mut runtime,
        root,
        operation,
      );
    }
    assert_rev2_v8_fixture_terminal_clean(operation.operation_id, mode);
    drop(runtime);
    assert_eq!(
      GC_PROFILER_ACTIVE_STATE_COUNT.load(Ordering::SeqCst),
      0,
      "{} retained unrelated native profiler state after async_hooks runtime disposal in {mode}",
      operation.operation_id
    );
  }

  fn run_rev2_public_diagnostics_fixture_mode(
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
    assert_public_diagnostics_guard_precedes_wrapper_work(operation);
    load_public_diagnostics_wrapper(&mut runtime, root);

    if case_kind == "staged-barrier:cleanup" {
      run_rev2_public_diagnostics_positive_control(
        &mut runtime,
        root,
        operation,
        "before-cleanup-case",
      );
    }

    let base_guard_start =
      PUBLIC_V8_WRAPPER_GUARD_CALL_COUNT.load(Ordering::SeqCst);
    prepare_rev2_public_diagnostics_fixture_state(
      &mut runtime,
      root,
      operation,
      operation.denied_target,
    );
    set_actor(root, "node_modules/denied-native/index.cjs");
    let before = rev2_v8_fixture_canaries();
    deny_rev2_public_diagnostics_fixture_operation(&mut runtime, operation);
    let after = rev2_v8_fixture_canaries();
    assert_eq!(
      after.public_wrapper_guard_calls,
      before.public_wrapper_guard_calls + 1,
      "{} did not cross exactly one diagnostics guard in {case_kind}/{mode}",
      operation.operation_id
    );
    assert_exact_public_wrapper_guard_call(
      operation,
      before.public_wrapper_guard_calls,
    );
    assert_eq!(
      Rev2V8FixtureCanaries {
        public_wrapper_guard_calls: before.public_wrapper_guard_calls,
        ..after
      },
      before,
      "{} changed diagnostics state or unrelated native work before denial in {case_kind}/{mode}",
      operation.operation_id
    );

    cleanup_rev2_public_diagnostics_fixture_state(
      &mut runtime,
      root,
      operation,
    );
    let base_guard_end =
      PUBLIC_V8_WRAPPER_GUARD_CALL_COUNT.load(Ordering::SeqCst);
    let mut expected_base_calls =
      rev2_public_diagnostics_expected_positive_guard_calls(
        operation,
        operation.denied_target,
      );
    let prepare_call_count =
      before.public_wrapper_guard_calls - base_guard_start;
    expected_base_calls.insert(
      prepare_call_count,
      (
        "runtime".to_string(),
        "inspect".to_string(),
        operation.denied_target.to_string(),
        rev2_public_wrapper_guard_api_name(operation).to_string(),
      ),
    );
    let observed_base_calls = {
      let calls = PUBLIC_V8_WRAPPER_GUARD_CALLS.lock().unwrap();
      calls[base_guard_start..base_guard_end].to_vec()
    };
    assert_eq!(
      observed_base_calls, expected_base_calls,
      "{} used an inexact prepare/deny/same-target-cleanup guard sequence in {case_kind}/{mode}",
      operation.operation_id
    );
    if case_kind == "staged-barrier:cancellation" {
      run_rev2_public_diagnostics_positive_control(
        &mut runtime,
        root,
        operation,
        "after-cancellation",
      );
    }
    assert_rev2_v8_fixture_terminal_clean(operation.operation_id, mode);
    drop(runtime);
    assert_eq!(
      GC_PROFILER_ACTIVE_STATE_COUNT.load(Ordering::SeqCst),
      0,
      "{} retained unrelated native profiler state after diagnostics runtime disposal in {mode}",
      operation.operation_id
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
    assert_exact_public_wrapper_guard_call(
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
    if rev2_process_fixture_is_events(operation) {
      // @ref LLP 0019#runtime-and-memory-inspection [tests] -- Exercise the
      // actual public node:process event-table setter, guarded Proxy traps,
      // and addListener/removeListener forwarders. The frozen facade and
      // controller omit raw process/table/EventEmitter/token/internal handles;
      // closure-private canaries prove denial precedes observation, delivery,
      // or retained mutation. Deno.core remains installed as the trusted
      // fixture loader, so this narrows the authored harness surface and does
      // not establish guest confinement.
      // @ref LLP 0019#pre-promotion-conformance-candidate-execution
      // [constrained-by] -- This isolated development harness emits only the
      // existing process-local candidate report. It authenticates no
      // execution, changes no cell or backend status, advertises no profile,
      // and grants no production or release authority.
      run_rev2_public_process_event_fixture_mode(
        root, operation, case_kind, mode,
      );
      return rev2_v8_fixture_assertions(operation, case_kind);
    }
    if matches!(
      operation.operation_id,
      "process-get-active-handles"
        | "process-get-active-requests"
        | "process-get-active-resource-names"
        | "process-report-get-report"
        | "process-report-write-report"
    ) {
      // @ref LLP 0019#runtime-and-memory-inspection [tests] -- Execute the
      // actual internal process active-resource/report scripts behind their
      // frozen null-prototype public facades. Primitive exact inputs cross the
      // shared test guard; behavioral resource teardown and report work
      // canaries prove the guard precedes observation/construction.
      // @ref LLP 0019#pre-promotion-conformance-candidate-execution
      // [constrained-by] -- This emits process-local development output only.
      // It is explicitly non-evidence, authenticates no execution, promotes
      // no cell, advertises no profile, and supplies no production authority.
      run_rev2_public_process_fixture_mode(root, operation, case_kind, mode);
      return rev2_v8_fixture_assertions(operation, case_kind);
    }
    if matches!(
      operation.operation_id,
      "async-hooks-create-hook"
        | "async-hooks-execution-async-resource"
        | "async-hook-disable"
        | "async-hook-enable"
    ) {
      // @ref LLP 0019#runtime-and-memory-inspection [tests] -- Exercise only
      // the public async-hooks inspection surface.
      // @ref LLP 0019#pre-promotion-conformance-candidate-execution
      // [constrained-by] -- Load the actual ext:deno_node/async_hooks.ts
      // public facade. Public createHook creates every exercised hook, the
      // shared test guard records exact runtime:inspect tuples, and behavioral
      // canaries close the closure-private hook array without exposing its
      // separate no-guard internal hook class or factory. This is
      // development-only candidate output, not a receipt, evidence artifact,
      // external report, or promotion input.
      run_rev2_public_async_hooks_fixture_mode(
        root, operation, case_kind, mode,
      );
      return rev2_v8_fixture_assertions(operation, case_kind);
    }
    if operation.operation_id.starts_with("diagnostics-") {
      // @ref LLP 0019#runtime-and-memory-inspection [tests] -- Execute the
      // actual ext:deno_node/diagnostics_channel.js public facade. The
      // shared test guard records its exact deny-only runtime:inspect tuple;
      // closure-private state is observed only through public behavior and
      // exact root teardown. Internal channel facades remain unreachable.
      // These rows deliberately use primitive exact string names: they
      // establish guard precedence over authority-bearing state/work after
      // required target derivation, not malformed-name or user-coercion
      // behavior.
      // @ref LLP 0019#pre-promotion-conformance-candidate-execution
      // [constrained-by] -- Results remain development-only candidate output,
      // not a receipt, evidence artifact, external report, or promotion input.
      run_rev2_public_diagnostics_fixture_mode(
        root, operation, case_kind, mode,
      );
      return rev2_v8_fixture_assertions(operation, case_kind);
    }
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

  fn rev2_v8_fixture_child_completion_line(
    operation_id: &str,
    case_kind: &str,
    target: &str,
    mode: &str,
  ) -> String {
    let test_json =
      deno_core::serde_json::to_string(REV2_V8_FIXTURE_TEST).unwrap();
    let operation_json =
      deno_core::serde_json::to_string(operation_id).unwrap();
    let case_kind_json = deno_core::serde_json::to_string(case_kind).unwrap();
    let target_json = deno_core::serde_json::to_string(target).unwrap();
    let mode_json = deno_core::serde_json::to_string(mode).unwrap();
    format!(
      r#"{REV2_V8_FIXTURE_CHILD_COMPLETION_PREFIX}{{"schema":"oden/capsec-native-v8-inspection-fixture-child-completion/1","test":{test_json},"operationId":{operation_json},"caseKind":{case_kind_json},"target":{target_json},"mode":{mode_json}}}"#
    )
  }

  fn validate_and_strip_rev2_v8_fixture_child_completion(
    stdout: &str,
    stderr: &str,
    expected_line: &str,
  ) -> Result<String, &'static str> {
    if stdout.contains(REV2_V8_FIXTURE_CHILD_COMPLETION_PREFIX) {
      return Err("native fixture child completion appeared on stdout");
    }
    if stderr
      .matches(REV2_V8_FIXTURE_CHILD_COMPLETION_PREFIX)
      .count()
      != 1
    {
      return Err(
        "native fixture child stderr did not contain exactly one completion marker",
      );
    }
    if stderr.lines().filter(|line| *line == expected_line).count() != 1 {
      return Err(
        "native fixture child stderr lacked one exact completion line",
      );
    }
    let exact_line = format!("{expected_line}\n");
    if stderr.matches(&exact_line).count() != 1 {
      return Err("native fixture child completion was not newline bounded");
    }
    let stripped = stderr.replacen(&exact_line, "", 1);
    if stripped.contains(REV2_V8_FIXTURE_CHILD_COMPLETION_PREFIX) {
      return Err("native fixture child completion remained after stripping");
    }
    Ok(stripped)
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
    let completion = rev2_v8_fixture_child_completion_line(
      operation.operation_id,
      "deny-only-closed-or-absent",
      "aarch64-apple-darwin",
      "enforce",
    );
    assert_eq!(
      validate_and_strip_rev2_v8_fixture_child_completion(
        "running 1 test\n",
        &format!("before\n{completion}\nafter\n"),
        &completion,
      ),
      Ok("before\nafter\n".to_string())
    );
    assert!(
      validate_and_strip_rev2_v8_fixture_child_completion(
        &format!("{completion}\n"),
        "",
        &completion,
      )
      .is_err()
    );
    assert!(
      validate_and_strip_rev2_v8_fixture_child_completion(
        "",
        &format!("{completion} trailing\n"),
        &completion,
      )
      .is_err()
    );
    assert!(
      validate_and_strip_rev2_v8_fixture_child_completion(
        "",
        &format!("{completion}\n{completion}\n"),
        &completion,
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
      let completion = rev2_v8_fixture_child_completion_line(
        &operation_id,
        &case_kind,
        &target,
        &mode,
      ) + "\n";
      std::io::stderr().write_all(completion.as_bytes()).unwrap();
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
        let stderr_with_completion = String::from_utf8(output.stderr).unwrap();
        let expected_completion = rev2_v8_fixture_child_completion_line(
          &operation_id,
          &case_kind,
          &target,
          mode,
        );
        let stderr = validate_and_strip_rev2_v8_fixture_child_completion(
          &stdout,
          &stderr_with_completion,
          &expected_completion,
        )
        .unwrap_or_else(|reason| {
          panic!(
            "Rev2 V8 fixture child supplied inexact completion evidence for {target}/{operation_id}/{case_kind}/{mode}: {reason}\nstdout={}\nstderr={}",
            bounded_debug_output(&stdout),
            bounded_debug_output(&stderr_with_completion),
          )
        });
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
