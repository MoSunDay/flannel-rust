//! `cargo test` wrapper: run the full closed-loop harness binary and
//! require a clean exit (skips inside the harness are tolerated and
//! reported, hard failures are not).

#[test]
fn full_e2e_harness() {
    let bin = env!("CARGO_BIN_EXE_flannel-e2e");
    let out = std::process::Command::new(bin)
        .output()
        .expect("spawning flannel-e2e");
    print!("{}", String::from_utf8_lossy(&out.stdout));
    eprint!("{}", String::from_utf8_lossy(&out.stderr));
    assert!(
        out.status.success(),
        "flannel-e2e harness failed (exit {:?})",
        out.status.code()
    );
}
