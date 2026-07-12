fn main() {
  if let Err(error) = deno_permissions::rev2::run_oracle_stdio() {
    eprintln!("{error}");
    std::process::exit(2);
  }
}
