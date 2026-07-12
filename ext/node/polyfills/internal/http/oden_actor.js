// Copyright 2018-2026 the Deno authors. MIT license.

import { core, primordials } from "ext:core/mod.js";
import { op_oden_schedule_context } from "ext:core/ops";

const {
  Error,
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

export function hasOdenHttpRequestActor(request) {
  return WeakMapPrototypeGet(requestActors, request) !== undefined;
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

export function runWithRequiredOdenHttpRequestActor(request, callback) {
  const actor = WeakMapPrototypeGet(requestActors, request);
  if (actor === undefined) {
    const error = new Error(
      "oden capsec: missing Node HTTP request actor",
    );
    error.code = "ERR_ACCESS_DENIED";
    throw error;
  }

  const prior = core.getAsyncContext();
  core.setAsyncContext(actor);
  try {
    return callback();
  } finally {
    core.setAsyncContext(prior);
  }
}
