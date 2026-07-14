// Copyright 2018-2026 the Deno authors. MIT license.
import { op_print } from "ext:core/ops";

export const sealedValue = typeof op_print === "function";
