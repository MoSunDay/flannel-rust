//! Table-driven tests for the Go `flag`-compatible parser (`super`).

use super::{FlagError, FlagSet};

fn flagset() -> FlagSet {
    let mut fs = FlagSet::new("flannel");
    fs.register_bool("v", false, "verbose");
    fs.register_int("x", 0, "some int");
    fs.register_string("s", "", "some string");
    fs.register_slice("r", "repeatable");
    fs
}

fn args(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| s.to_string()).collect()
}

#[test]
fn dash_and_double_dash_forms_are_equivalent() {
    let forms: &[&[&str]] = &[&["--x=5"], &["-x=5"], &["-x", "5"], &["--x", "5"]];
    for argv in forms {
        let mut fs = flagset();
        fs.parse(&args(argv)).unwrap();
        assert_eq!(fs.get_int("x"), 5, "form: {argv:?}");
    }
}

#[test]
fn bool_flag_never_consumes_next_arg() {
    let mut fs = flagset();
    fs.parse(&args(&["-v", "positional", "-x", "3"])).unwrap();
    assert!(fs.get_bool("v"));
    assert_eq!(fs.get_int("x"), 0); // parsing stopped at the positional
    assert_eq!(fs.remaining_args(), args(&["positional", "-x", "3"]));

    let mut fs = flagset();
    fs.parse(&args(&["-v=false", "next"])).unwrap();
    assert!(!fs.get_bool("v"));
    assert_eq!(fs.remaining_args(), args(&["next"]));
}

#[test]
fn bool_accepts_all_go_parsebool_forms() {
    let cases: [(&str, bool); 12] = [
        ("1", true),
        ("t", true),
        ("T", true),
        ("true", true),
        ("TRUE", true),
        ("True", true),
        ("0", false),
        ("f", false),
        ("F", false),
        ("false", false),
        ("FALSE", false),
        ("False", false),
    ];
    for (raw, want) in cases {
        let mut fs = flagset();
        let argv = vec![format!("-v={raw}")];
        fs.parse(&argv).unwrap();
        assert_eq!(fs.get_bool("v"), want, "raw={raw}");
    }
}

#[test]
fn bool_rejects_non_parsebool_values() {
    for raw in ["yes", "2", ""] {
        let mut fs = flagset();
        let argv = vec![format!("-v={raw}")];
        let err = fs.parse(&argv).unwrap_err();
        assert_eq!(
            err.to_string(),
            format!("invalid value \"{raw}\" for flag -v: strconv.ParseBool: parsing \"{raw}\": invalid syntax"),
            "raw={raw}"
        );
    }
}

#[test]
fn int_accepts_go_base_zero_forms() {
    for (raw, want) in [
        ("0x10", 16),
        ("0X10", 16),
        ("-0x10", -16),
        ("0o17", 15),
        ("0b101", 5),
        ("010", 8),
        ("+7", 7),
        ("0", 0),
        ("-0", 0),
    ] {
        let mut fs = flagset();
        fs.parse(&args(&["-x", raw])).unwrap();
        assert_eq!(fs.get_int("x"), want, "raw={raw}");
    }
}

#[test]
fn int_bad_value_errors_match_go() {
    let mut fs = flagset();
    let err = fs.parse(&args(&["-x", "0xzz"])).unwrap_err();
    assert_eq!(
        err.to_string(),
        "invalid value \"0xzz\" for flag -x: strconv.ParseInt: parsing \"0xzz\": invalid syntax"
    );
    let mut fs = flagset();
    let err = fs.parse(&args(&["-x=9223372036854775808"])).unwrap_err();
    assert_eq!(
        err.to_string(),
        "invalid value \"9223372036854775808\" for flag -x: \
         strconv.ParseInt: parsing \"9223372036854775808\": value out of range"
    );
}

#[test]
fn int_flag_consumes_negative_literal() {
    let mut fs = flagset();
    fs.parse(&args(&["-x", "-5"])).unwrap();
    assert_eq!(fs.get_int("x"), -5);
}

#[test]
fn stop_at_first_positional() {
    let mut fs = flagset();
    fs.parse(&args(&["-x", "1", "positional", "-v"])).unwrap();
    assert_eq!(fs.get_int("x"), 1);
    assert!(!fs.get_bool("v")); // after a positional nothing is parsed
    assert_eq!(fs.remaining_args(), args(&["positional", "-v"]));
}

#[test]
fn double_dash_terminates_flags() {
    let mut fs = flagset();
    fs.parse(&args(&["-x", "1", "--", "-v", "rest"])).unwrap();
    assert_eq!(fs.get_int("x"), 1);
    assert!(!fs.get_bool("v"));
    assert_eq!(fs.remaining_args(), args(&["-v", "rest"]));
}

#[test]
fn lone_dash_is_positional() {
    let mut fs = flagset();
    fs.parse(&args(&["-"])).unwrap();
    assert_eq!(fs.remaining_args(), args(&["-"]));
}

#[test]
fn unknown_flag_error_matches_go() {
    let mut fs = flagset();
    let err = fs.parse(&args(&["-q", "1"])).unwrap_err();
    assert!(matches!(err, FlagError::UnknownFlag(_)));
    assert_eq!(err.to_string(), "flag provided but not defined: -q");
}

#[test]
fn missing_value_error_matches_go() {
    let mut fs = flagset();
    let err = fs.parse(&args(&["-x"])).unwrap_err();
    assert!(matches!(err, FlagError::MissingValue(_)));
    assert_eq!(err.to_string(), "flag needs an argument: -x");
}

#[test]
fn bad_flag_syntax_matches_go() {
    let mut fs = flagset();
    let err = fs.parse(&args(&["---x"])).unwrap_err();
    assert_eq!(err.to_string(), "bad flag syntax: ---x");
    let mut fs = flagset();
    let err = fs.parse(&args(&["--=5"])).unwrap_err();
    assert_eq!(err.to_string(), "bad flag syntax: --=5");
}

#[test]
fn help_flags_yield_help_error_with_usage_available() {
    for argv in [["--help"], ["-help"], ["-h"]] {
        let mut fs = flagset();
        let err = fs.parse(&args(&argv)).unwrap_err();
        assert!(matches!(err, FlagError::Help), "{argv:?} -> {err}");
        assert_eq!(err.to_string(), "flag: help requested");
        assert!(fs.usage().starts_with("Usage of flannel:\n"));
    }
}

#[test]
fn registered_h_flag_is_not_special() {
    let mut fs = FlagSet::new("flannel");
    fs.register_bool("h", false, "custom h");
    fs.parse(&args(&["-h"])).unwrap();
    assert!(fs.get_bool("h"));
}

#[test]
fn slice_appends_over_repeated_flags() {
    let mut fs = flagset();
    fs.parse(&args(&["-r", "a", "-r=b", "--r", "c"])).unwrap();
    assert_eq!(fs.get_slice("r"), args(&["a", "b", "c"]));
    assert!(fs.is_set("r"));
    assert_eq!(fs.default_value("r").as_deref(), Some("[]")); // Go fmt.Sprint
}

#[test]
fn defaults_and_default_value_accessor() {
    let mut fs = FlagSet::new("flannel");
    fs.register_bool("b", true, "b");
    fs.register_int("i", 12, "i");
    fs.register_string("s", "def", "s");
    assert_eq!(fs.default_value("b").as_deref(), Some("true"));
    assert_eq!(fs.default_value("i").as_deref(), Some("12"));
    assert_eq!(fs.default_value("s").as_deref(), Some("def"));
    assert_eq!(fs.default_value("missing"), None);
    assert!(fs.get_bool("b"));
    assert_eq!(fs.get_int("i"), 12);
    assert_eq!(fs.get_string("s"), "def");
    assert!(!fs.is_set("b")); // default alone does not count as set
}

#[test]
fn usage_is_go_style_and_sorted() {
    let mut fs = FlagSet::new("flannel");
    fs.register_bool("verbose", true, "log verbosely");
    fs.register_int("mtu", 1400, "interface MTU");
    fs.register_int("zero", 0, "zero default");
    fs.register_string("subnet-file", "/etc/flannel", "subnet file");
    fs.register_string("empty", "", "empty default");
    fs.register_slice("opt", "backend options");
    fs.register_bool("v", false, "short bool");

    let u = fs.usage();
    assert!(u.starts_with("Usage of flannel:\n"), "{u}");
    let pos = |s: &str| u.find(s).unwrap_or_else(|| panic!("missing {s} in:\n{u}"));
    assert!(pos("  -mtu") < pos("  -opt"));
    assert!(pos("  -opt") < pos("  -subnet-file"));
    assert!(pos("  -subnet-file") < pos("  -v\t"));
    assert!(pos("  -v\t") < pos("  -verbose"));
    assert!(pos("  -verbose") < pos("  -zero"));
    // 1-char bool: usage on the same line (Go alignment rule, head <= 4).
    assert!(u.contains("  -v\tshort bool\n"));
    assert!(u.contains("  -mtu int\n    \tinterface MTU (default 1400)\n"));
    assert!(u.contains("  -subnet-file string\n    \tsubnet file (default \"/etc/flannel\")\n"));
    assert!(u.contains("  -verbose\n    \tlog verbosely (default true)\n"));
    // Go isZeroValue: zero-value defaults are omitted.
    assert!(!u.contains("(default 0)"));
    assert!(!u.contains("(default \"\")"));
    assert!(!u.contains("(default false)"));
    // Empty slice: type name "value" (Go UnquoteUsage fallback), no default.
    assert!(u.contains("  -opt value\n    \tbackend options\n"));
}

#[test]
fn env_overrides_cli_and_marks_set_by_env() {
    let prefix = "FLX_ENV_OVERRIDE";
    let key = format!("{prefix}_X");
    std::env::set_var(&key, "42");
    let mut fs = flagset();
    fs.parse(&args(&["-x", "1", "-s", "cli"])).unwrap();
    assert!(fs.is_set("x"));
    let errs = fs.set_flags_from_env(prefix);
    std::env::remove_var(&key);
    assert!(errs.is_empty());
    assert_eq!(fs.get_int("x"), 42); // env beats CLI
    assert!(fs.was_set_by_env("x"));
    assert!(fs.is_set("x"));
    assert_eq!(fs.get_string("s"), "cli");
    assert!(!fs.was_set_by_env("s"));
}

#[test]
fn env_name_mapping_dash_to_underscore_uppercase() {
    let prefix = "FLX_ENV_MAP";
    let mut fs = FlagSet::new("flannel");
    fs.register_string("etcd-endpoints", "http://127.0.0.1:2379", "endpoints");
    let key = format!("{prefix}_ETCD_ENDPOINTS");
    std::env::set_var(&key, "http://10.0.0.1:2379");
    let errs = fs.set_flags_from_env(prefix);
    std::env::remove_var(&key);
    assert!(errs.is_empty());
    assert_eq!(fs.get_string("etcd-endpoints"), "http://10.0.0.1:2379");
    assert!(fs.was_set_by_env("etcd-endpoints"));
}

#[test]
fn env_bad_value_is_collected_not_fatal() {
    let prefix = "FLX_ENV_BAD";
    let key_x = format!("{prefix}_X");
    let key_s = format!("{prefix}_S");
    std::env::set_var(&key_x, "nope");
    std::env::set_var(&key_s, "from-env");
    let mut fs = flagset();
    fs.parse(&args(&["-x", "7"])).unwrap();
    let errs = fs.set_flags_from_env(prefix);
    std::env::remove_var(&key_x);
    std::env::remove_var(&key_s);
    assert_eq!(errs.len(), 1);
    assert_eq!(errs[0].flag, "x");
    assert_eq!(errs[0].env_key, key_x);
    assert!(errs[0]
        .to_string()
        .starts_with(&format!("invalid value \"nope\" for env var {key_x}:")));
    assert_eq!(fs.get_int("x"), 7); // CLI value kept
    assert_eq!(fs.get_string("s"), "from-env"); // other flags still applied
    assert!(!fs.is_set("v"));
}

#[test]
fn env_empty_value_ignored() {
    let prefix = "FLX_ENV_EMPTY";
    let key = format!("{prefix}_X");
    std::env::set_var(&key, "");
    let mut fs = flagset();
    let errs = fs.set_flags_from_env(prefix);
    std::env::remove_var(&key);
    assert!(errs.is_empty());
    assert!(!fs.is_set("x"));
    assert_eq!(fs.get_int("x"), 0);
}

#[test]
fn tolerated_unknown_flags_are_skipped() {
    let mut fs = FlagSet::new("flannel");
    fs.register_string("etcd-endpoints", "", "endpoints");
    let mut fs = fs.with_tolerated_unknown(&["v", "logtostderr"]);
    fs.parse(&args(&[
        "-v=2",
        "--logtostderr",
        "--etcd-endpoints",
        "http://x",
    ]))
    .unwrap();
    assert_eq!(fs.get_string("etcd-endpoints"), "http://x");
    assert!(fs.remaining_args().is_empty());
}

#[test]
fn tolerated_unknown_space_form_value_is_skipped() {
    let mut fs = FlagSet::new("flannel");
    fs.register_int("x", 0, "x");
    let mut fs = fs.with_tolerated_unknown(&["v"]);
    fs.parse(&args(&["-v", "2", "-x", "7"])).unwrap();
    assert_eq!(fs.get_int("x"), 7);
    assert!(fs.remaining_args().is_empty());
}

#[test]
fn tolerated_unknown_bool_style_does_not_eat_next_flag() {
    let mut fs = FlagSet::new("flannel");
    fs.register_int("x", 0, "x");
    let mut fs = fs.with_tolerated_unknown(&["logtostderr"]);
    fs.parse(&args(&["--logtostderr", "-x", "9"])).unwrap();
    assert_eq!(fs.get_int("x"), 9);
}

#[test]
fn non_tolerated_unknown_still_errors() {
    let mut fs = flagset().with_tolerated_unknown(&["v"]);
    let err = fs.parse(&args(&["-q"])).unwrap_err();
    assert_eq!(err.to_string(), "flag provided but not defined: -q");
}
