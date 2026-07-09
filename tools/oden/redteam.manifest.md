# Oden red-team soundness gate (generated)

Phase-2 exit gate. 18 attack classes CLOSED with a guarding spec test; 5 DOCUMENTED RESIDUALS. Zero undocumented open holes.

## Closed (guarded by a spec fixture)

| category | attack | guarding test(s) | note |
| --- | --- | --- | --- |
| attribution-laundering | script-identity forgery via //# sourceURL= / eval naming | oden_capsec_cjs_attribution, oden_capsec_compilefn_forgery | attribution keys on the unforgeable V8 script_id; a forged sourceURL quarantines |
| attribution-laundering | compileFunction/evalContext register code under another package's locator | oden_capsec_compilefn_forgery | the wrappers are sealed off the user-reachable core; only loader-resolved specifiers register |
| attribution-laundering | reachable self-grant / set-principal surface (Deno.core, __ globals) | oden_capsec_seal, oden_capsec_global_inventory | the powerful ambient surface is captured-then-sealed; the global inventory is drift-guarded |
| attribution-laundering | no-user frame collapses into root | oden_capsec_cped_async, oden_capsec_readiness | precedence row 4 is the no-user sentinel, never root; enforce fails closed on a missing prerequisite |
| attribution-laundering | detached deputies over deferral queues lose schedule-time principal | oden_capsec_cped_async, oden_capsec_deferral_channels | the CPED scheduling principal rides all 9 enumerated deferral channels (timers, microtask, promise reactions, nextTick, setImmediate, AsyncResource, dynamic-import continuation, op-completion continuation, FinalizationRegistry cleanup) |
| attribution-laundering | CPED token replay / forge / drop | oden_capsec_cped_token | the slot holds an opaque registry token; unknown/stale/forged -> no-user sentinel + audit; dropped -> sentinel |
| attribution-laundering | seal-bypass of the async-context primitives | oden_capsec_seal | the four seal conditions run as always-on conformance; a broken seal fails enforce closed |
| classification-confusion | data:/blob: minted code borrows a package's authority | oden_capsec_import_gating | data:/blob:/remote imports by a package are default-denied under enforce; classify() sends them to quarantine |
| runtime-escape-hatch | worker / child-runtime creation by a package | oden_capsec_worker_deny | package worker creation is default-denied under enforce (interim stance until inheritance is designed) |
| runtime-escape-hatch | node:vm fresh-context eval by a package | oden_capsec_compilefn_forgery | node:vm filename is caller-supplied and NOT trusted for attribution; vm code quarantines (userland ENG-23804 also denies it) |
| path-fs-semantics | relative-path / .. escape out of a granted fs scope | oden_capsec_policy_file | fs op targets and grant scopes are lexically normalized (absolute, .. folded); a .. escape lands outside its scope and denies |
| path-fs-semantics | op-body pre-check fast-path skip (query_read_all) bypasses the container | oden_capsec_layer2_independence | layer-2 decides independently of layer-1; the require/worker_threads pre-check skips are forced closed while armed |
| resource-ownership | cross-principal use of a guessed / handed rid | oden_capsec_resource_owner | owner metadata denies cross-principal rid use (fs-watcher wired end-to-end); other owner-checked families are named residuals in resource_families.manifest.md |
| config-env | ungated env value / policy widening under audit/enforce | oden_capsec_policy_file, oden_capsec_audit_log | one gated env path; policy parsed once per startup from the committed source; audit records every mediated op |
| generation | silent policy drift / expansion of authority | oden_capsec_policy_gen | the generated artifact is byte-reproducible; --check classes expansions (high-severity) apart from shrinkages and fails on drift |
| generation | deny-ceiling bypass through an op-body fast path (fast-skip-with-denies) | oden_capsec_ceiling | the layer-1-compiled ceiling denies hold under --allow-all through direct ops and the node: require path |
| lockdown | a dependency patches a shared intrinsic a check relies on | oden_capsec_lockdown | the freeze walk makes the primordials non-writable under ODEN_CAPSEC_LOCKDOWN; default-on-under-enforce is deferred (ENG-23781) pending ext/node lazy-write repairs |
| attribution-laundering | confused deputy: a granted package reads on an ungranted caller's behalf (synchronous) | oden_capsec_deputy_intersection | opt-in deputyClasses arm stack-intersection (row 3): the decision constrains every non-ambient principal on the live call chain, so an ungranted caller beneath a granted deputy denies ([deputy, evil]); self-scheduling collapses without false denials; unarmed classes decide exactly as rows 1/2/4 |

## Documented residuals (sound-but-open or deferred, with owner)

| category | attack | owner | why open | note |
| --- | --- | --- | --- | --- |
| classification-confusion | symlink / vendored-tree / global-cache path aliasing into root | ENG-23763 | integrity-bound locators (lockfile hashes) inherited from Deno's content-addressed lockfile; end-to-end red-team needs a lockfile-managed corpus | classify() attributes symlinked/workspace deps to their package (fork commit cb7cf6e); content-swap fails closed via Deno's lockfile before attribution |
| runtime-escape-hatch | node:inspector / self-inspection, WASI | ENG-23779 | default-denied for package principals under enforce; a designed story per hatch is the remaining escape-hatch-closure work | each is a deniable capability; default-deny holds, a per-hatch fixture is owed |
| runtime-escape-hatch | eval / new Function minting unattributed code bound to caller | ENG-23783 | eval-to-caller binding blocked on a rusty_v8 with SetModifyCodeGenerationFromStringsCallback (ENG-23791); until then eval quarantines (fail-closed) | eval'd code quarantines today (sound); attributing it to the caller needs the code-gen hook |
| resource-ownership | owner-check not yet wired for most families | ENG-23776 | per-family owner-check integration is sequenced; only fs:watch is wired, the rest are named residuals (audited, not silently accepted) | the mechanism + classification are landed; wiring each remaining owner-checked family closes its residual |
| attribution-laundering | async detached-deputy / schedule-before-first-op: scheduler present only in the CPED | ENG-23881 | the synchronous confused deputy is closed by stack-intersection (oden_capsec_deputy_intersection); the async case — scheduler carried only in the CPED with a granted deputy frame live, or a callback scheduled before its first op — needs a snapshot-scoped scheduling-boundary stamp to feed the intersection. Reading the op-dispatch slot for it was measured to be unsound (it pollutes later synchronous ops of unrelated packages with a false denial), so it stays a documented residual: sound today (fails closed to no-user, never launders) | NOT an open laundering hole — module-eval stamping was measured to launder and was rejected; the residual is the async-detached over-denial, whose sound closure is the call-boundary boundary stamp |

## Verdict

**GO** — every attack class in the inherited hole checklist is either closed with a guarding fixture or a documented residual with an owning ticket. No undocumented open holes. The residuals are sound-but-restrictive (schedule-before-first-op fails closed) or deferred by design (lockdown default-on, integrity-bound locators, eval-to-caller, per-family owner-checks).

