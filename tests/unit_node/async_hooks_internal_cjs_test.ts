// Copyright 2018-2026 the Deno authors. MIT license.
import { createRequire } from "node:module";
import { assert, assertEquals } from "@std/assert";

Deno.test(function internalAsyncHooksIsNotAUserCjsBuiltin() {
  // @ref LLP 0019#runtime-and-memory-inspection [tests]
  const require = createRequire(
    new URL("./testdata/cjs-package-resolution-anchor.cjs", import.meta.url),
  );
  assert(
    require.resolve("async-hooks-internal-launder").replaceAll("\\", "/")
      .endsWith(
        "/testdata/node_modules/async-hooks-internal-launder/index.cjs",
      ),
  );
  const probe = require("async-hooks-internal-launder") as () => unknown;
  assertEquals(probe(), {
    packageScoped: true,
    packageIdentity: true,
    publicBuiltinControl: true,
    cases: [
      {
        specifier: "internal/async_hooks",
        refused: true,
        code: "MODULE_NOT_FOUND",
      },
      {
        specifier: "node:internal/async_hooks",
        refused: true,
        code: "ERR_UNKNOWN_BUILTIN_MODULE",
      },
    ],
  });
});
