//! flanneld binary: flag parsing plus the tokio runtime wrapper around
//! [`flanneld::run`]. Go's `flag.NewFlagSet("flannel", flag.ExitOnError)`
//! behavior is reproduced here: parse errors print the error plus usage
//! to stderr and exit 2; `-h`/`--help` prints usage and exits 0.

use flannel_core::flags::{FlagError, FlagSet};
use flanneld::flags_defs::{build_flag_set, options_from_flag_set};
use tokio_util::sync::CancellationToken;
use tracing_subscriber::EnvFilter;

/// Go: `usage()` — `Usage: <argv0> [OPTION]...` plus `PrintDefaults`,
/// written to stderr.
fn print_usage(fs: &FlagSet) {
    let argv0 = std::env::args().next().unwrap_or_else(|| "flanneld".into());
    eprintln!("Usage: {argv0} [OPTION]...");
    eprint!("{}", fs.usage());
}

/// Parse CLI args into the flag set, mirroring Go ExitOnError handling.
/// Returns None when parsing succeeded, else the exit code to use.
fn parse_flags(fs: &mut FlagSet) -> Option<i32> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match fs.parse(&args) {
        Ok(()) => None,
        Err(FlagError::Help) => {
            print_usage(fs);
            Some(0)
        }
        Err(e) => {
            // Go ExitOnError prints the error then the usage, exit 2.
            eprintln!("{e}");
            print_usage(fs);
            Some(2)
        }
    }
}

#[tokio::main]
async fn main() {
    let mut fs = build_flag_set();
    if let Some(code) = parse_flags(&mut fs) {
        std::process::exit(code);
    }

    // klog-equivalent logging: env filter (RUST_LOG) with an info
    // default. Go sets logtostderr=true; tracing writes to stderr.
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .init();

    // Go: `flagutil.SetFlagsFromEnv(flannelFlags, "FLANNELD")` in main();
    // errors are logged and startup continues (Go coreos flagutil).
    for err in fs.set_flags_from_env("FLANNELD") {
        tracing::error!("Failed to set flag FLANNELD from env: {err}");
    }

    let opts = options_from_flag_set(&fs);
    let cancel = CancellationToken::new();

    let exit_code = match flanneld::run(opts, cancel).await {
        Ok(code) => code,
        Err(e) => {
            tracing::error!("flanneld failed: {e:#}");
            1
        }
    };
    std::process::exit(exit_code);
}
