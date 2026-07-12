// Keep the fork evaluator byte-identical to the reviewed generated artifacts.
// The isolated harness owns only dependency resolution and test/oracle wiring;
// it does not become part of the default Deno workspace graph.
#[path = "../../oden_rev2_registry_generated.rs"]
mod rev2_registry_generated;

#[path = "../../oden_rev2_core_generated.rs"]
pub mod rev2;
