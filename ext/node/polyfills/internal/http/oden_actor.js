// Copyright 2018-2026 the Deno authors. MIT license.

import { core, primordials } from "ext:core/mod.js";
import { op_oden_schedule_context } from "ext:core/ops";

const {
  SafeWeakMap,
  WeakMapPrototypeGet,
  WeakMapPrototypeSet,
} = primordials;

// The operation actor is deliberately held outside request/options objects so
// custom Agents and reflected user options cannot recover or replace it.
// @ref LLP 0019#operation-scoped-positive-authority-provenance [implements]
const requestActors = new SafeWeakMap();

export function captureOdenHttpRequestActor(request) {
  WeakMapPrototypeSet(requestActors, request, op_oden_schedule_context());
}

export function runWithOdenHttpRequestActor(request, callback) {
  const actor = WeakMapPrototypeGet(requestActors, request);
  if (actor === undefined) return callback();

  const prior = core.getAsyncContext();
  core.setAsyncContext(actor);
  try {
    return callback();
  } finally {
    core.setAsyncContext(prior);
  }
}
