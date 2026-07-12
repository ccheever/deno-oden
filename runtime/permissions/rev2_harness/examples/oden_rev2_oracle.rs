fn main() {
  if let Err(error) = oden_rev2_fork_harness::rev2::run_oracle_stdio() {
    eprintln!("{error}");
    std::process::exit(2);
  }
}
