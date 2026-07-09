console.log("Deno.oden:", typeof Deno.oden);
try {
  const c = Deno[Deno.internal]?.core;
  console.log("mint-op:", typeof c?.ops?.op_oden_handle_mint);
} catch {
  console.log("mint-op: sealed");
}
