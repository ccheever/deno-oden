# Golden cross-integration fixtures (TEST-ONLY)

Exact byte copies of the ENG-24019 CapSec Rev2 shadow-pilot parent-repo
artifacts, consumed by the golden tests in
`cli/lib/standalone/oden_target_policy_session.rs` so the fork-side
session family and the parent-side validator
(`scripts/capsec/rev2_target_policy.ts`) pin identical digest vectors over
identical bytes.

Provenance (paths are relative to the parent Oden repo root):

| file here | exact byte copy of |
| --- | --- |
| `filesystem-final-lto-target-policy.json` | `capsec/rev2/registry/filesystem-final-lto-target-policy.json` |
| `approval.json` | `capsec/rev2/fixtures/test-authority/approval.json` |
| `approval-signature.bin` | `capsec/rev2/fixtures/test-authority/approval-signature.bin` |
| `ed25519-public-key.bin` | `capsec/rev2/fixtures/test-authority/ed25519-public-key.bin` |
| `test-current-state.json` | `capsec/rev2/fixtures/test-authority/test-current-state.json` |

The signing key is the well-known, publicly derivable TEST-ONLY authority
(seed = `SHA-256("oden:capsec:test-authority:ed25519:v1")`, keyId under the
coherent `/2` public-key domain
`sha256-klO1cvvohAH-s3QgHuFalxHR4zv2KW1fnMURElsM58c`). The approval is the
current coherent `/2` contract (schema `.../registry-approval/2`,
`policyRevision: 1`, all `:2` domains) matching the `/2` registry. It grants
no production authority anywhere; production key resolution is external to
both repositories and deliberately unimplemented.

Regenerate in the parent repo with:

```
deno run -A scripts/capsec/rev2_target_policy.ts \
  --write-registry --write-test-authority \
  --test-authority capsec/rev2/fixtures/test-authority
```

then re-copy these five files byte-for-byte and update the golden digest
constants in BOTH pinning sites (`scripts/capsec/rev2_target_policy.ts` and
the test module of `oden_target_policy_session.rs`) in the same change.
