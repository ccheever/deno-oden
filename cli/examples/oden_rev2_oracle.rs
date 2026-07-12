// Copyright 2018-2026 the Deno authors. MIT license.

//! Diagnostic Rev2 oracle built from the production Deno CLI dependency graph.

fn main() {
  if let Err(error) = deno_runtime::deno_permissions::rev2::run_oracle_stdio() {
    eprintln!("{error}");
    std::process::exit(2);
  }
}
