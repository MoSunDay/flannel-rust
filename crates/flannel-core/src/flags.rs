//! Go `flag`-package-compatible parser (drop-in flanneld CLI compatibility).
//!
//! Ports Go's `flag` package as driven by flannel's `main.go`:
//! `flag.NewFlagSet("flannel", flag.ExitOnError)` + `Parse(os.Args[1:])` +
//! coreos `flagutil.SetFlagsFromEnv(fs, "FLANNELD")` — env applied AFTER the
//! CLI parse, overriding it; bad env values are collected, not fatal.
//!
//! Go semantics: `-name`/`--name` identical; bools never consume the next
//! arg (bare `-name` means true); stop at first non-flag arg; `--` terminates
//! flags; lone `-` is positional; Go error texts. No `1_000` separators.

use std::env;

/// Go-style parse error; `Display` mimics Go `flag` package messages.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FlagError {
    /// Go: `flag provided but not defined: -name`
    #[error("flag provided but not defined: -{0}")]
    UnknownFlag(String),
    /// Go: `invalid value "v" for flag -name: <reason>` (name, value, reason)
    #[error("invalid value \"{1}\" for flag -{0}: {2}")]
    BadValue(String, String, String),
    /// Go: `flag needs an argument: -name`
    #[error("flag needs an argument: -{0}")]
    MissingValue(String),
    /// Go: `bad flag syntax: <arg>` (e.g. `---x`, `--=x`)
    #[error("bad flag syntax: {0}")]
    BadSyntax(String),
    /// Unregistered `-h`/`-help`/`--help`; Go callers print usage, exit 0.
    #[error("flag: help requested")]
    Help,
}

/// One env-var application failure (coreos flagutil collects these;
/// flannel logs them and keeps going).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid value \"{value}\" for env var {env_key}: {reason}")]
pub struct EnvError {
    pub flag: String,
    pub env_key: String,
    pub value: String,
    pub reason: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Bool,
    Int,
    Str,
    Slice,
}

#[derive(Debug, Clone, PartialEq)]
enum Value {
    Bool(bool),
    Int(i64),
    Str(String),
    Slice(Vec<String>),
}

#[derive(Debug, Clone)]
struct Flag {
    name: String,
    kind: Kind,
    help: String,
    value: Value,
    default: Value,
    set_by_cli: bool,
    set_by_env: bool,
}

/// Go `flag.FlagSet` equivalent. Plain data plus inherent methods.
#[derive(Debug, Clone)]
pub struct FlagSet {
    name: String,
    flags: Vec<Flag>,
    remaining: Vec<String>,
    tolerated_unknown: Vec<String>,
}

/// `strconv.ParseBool`: 1,t,T,TRUE,true,True / 0,f,F,FALSE,false,False.
fn parse_bool(s: &str) -> Result<bool, String> {
    match s {
        "1" | "t" | "T" | "TRUE" | "true" | "True" => Ok(true),
        "0" | "f" | "F" | "FALSE" | "false" | "False" => Ok(false),
        _ => Err(format!(
            "strconv.ParseBool: parsing \"{s}\": invalid syntax"
        )),
    }
}

/// `strconv.ParseInt(s, 0, 64)`: sign + `0x`/`0o`/`0b` prefixes; a bare
/// leading `0` means octal. (Underscore separators unsupported.)
fn parse_int(s: &str) -> Result<i64, String> {
    let invalid = || format!("strconv.ParseInt: parsing \"{s}\": invalid syntax");
    let out_of_range = || format!("strconv.ParseInt: parsing \"{s}\": value out of range");
    let (sign, body) = match s.as_bytes().first() {
        Some(b'+') => ("+", &s[1..]),
        Some(b'-') => ("-", &s[1..]),
        _ => ("", s),
    };
    if body.is_empty() {
        return Err(invalid());
    }
    let prefix = body.get(..2).map(str::to_ascii_lowercase);
    let (digits, radix) = match prefix.as_deref() {
        Some("0x") => (&body[2..], 16),
        Some("0o") => (&body[2..], 8),
        Some("0b") => (&body[2..], 2),
        _ if body.len() > 1 && body.starts_with('0') => (&body[1..], 8), // octal
        _ => (body, 10),
    };
    if digits.is_empty() {
        return Err(invalid());
    }
    let signed = format!("{sign}{digits}");
    i64::from_str_radix(&signed, radix).map_err(|e| match e.kind() {
        std::num::IntErrorKind::PosOverflow | std::num::IntErrorKind::NegOverflow => out_of_range(),
        _ => invalid(),
    })
}

/// Apply one raw string to a flag (same validation for CLI and env).
fn set_flag_value(flag: &mut Flag, raw: &str) -> Result<(), String> {
    match flag.kind {
        Kind::Bool => flag.value = Value::Bool(parse_bool(raw)?),
        Kind::Int => flag.value = Value::Int(parse_int(raw)?),
        Kind::Str => flag.value = Value::Str(raw.to_string()),
        Kind::Slice => {
            if let Value::Slice(items) = &mut flag.value {
                items.push(raw.to_string());
            }
        }
    }
    Ok(())
}

/// Go `Flag.DefValue` rendering (bools "true"/"false", slices `fmt.Sprint`).
fn def_value_string(flag: &Flag) -> String {
    match &flag.default {
        Value::Bool(b) => b.to_string(),
        Value::Int(i) => i.to_string(),
        Value::Str(s) => s.clone(),
        Value::Slice(items) => format!("[{}]", items.join(" ")),
    }
}

/// Go `isZeroValue`: defaults are printed only when non-zero-valued.
fn shows_default(flag: &Flag) -> bool {
    match &flag.default {
        Value::Bool(b) => *b,
        Value::Int(i) => *i != 0,
        Value::Str(s) => !s.is_empty(),
        Value::Slice(items) => !items.is_empty(),
    }
}

impl FlagSet {
    /// Go `flag.NewFlagSet(name, flag.ExitOnError)`; errors are returned
    /// instead of exiting so callers choose exit behavior.
    pub fn new(name: &str) -> Self {
        FlagSet {
            name: name.to_string(),
            flags: Vec::new(),
            remaining: Vec::new(),
            tolerated_unknown: Vec::new(),
        }
    }

    fn register(&mut self, name: &str, kind: Kind, default: Value, help: &str) {
        assert!(self.find(name).is_none(), "flag {name:?} already defined");
        self.flags.push(Flag {
            name: name.to_string(),
            kind,
            help: help.to_string(),
            value: default.clone(),
            default,
            set_by_cli: false,
            set_by_env: false,
        });
    }

    pub fn register_bool(&mut self, name: &str, default: bool, help: &str) {
        self.register(name, Kind::Bool, Value::Bool(default), help);
    }

    pub fn register_int(&mut self, name: &str, default: i64, help: &str) {
        self.register(name, Kind::Int, Value::Int(default), help);
    }

    pub fn register_string(&mut self, name: &str, default: &str, help: &str) {
        self.register(name, Kind::Str, Value::Str(default.to_string()), help);
    }

    /// Repeatable append flag (flannel's `flagSlice`); default is empty.
    pub fn register_slice(&mut self, name: &str, help: &str) {
        self.register(name, Kind::Slice, Value::Slice(Vec::new()), help);
    }

    /// Unknown flags whose base name is listed are skipped with a
    /// `tracing::warn` instead of erroring (klog flags from supervisors).
    #[must_use]
    pub fn with_tolerated_unknown(mut self, names: &[&str]) -> Self {
        self.tolerated_unknown = names.iter().map(|n| (*n).to_string()).collect();
        self
    }

    fn find(&self, name: &str) -> Option<usize> {
        self.flags.iter().position(|f| f.name == name)
    }

    fn flag(&self, name: &str) -> &Flag {
        self.find(name)
            .map(|idx| &self.flags[idx])
            .unwrap_or_else(|| panic!("flag {name:?} is not registered"))
    }

    /// Go `FlagSet.Parse`. Stops at the first non-flag argument or `--`.
    pub fn parse(&mut self, args: &[String]) -> Result<(), FlagError> {
        let mut i = 0usize;
        while i < args.len() {
            let arg = &args[i];
            // Go: len(s) < 2 || s[0] != '-' => positional => stop.
            if arg.len() < 2 || !arg.starts_with('-') {
                break;
            }
            let mut minuses = 1;
            if arg.as_bytes()[1] == b'-' {
                minuses = 2;
                if arg.len() == 2 {
                    i += 1; // "--" terminates the flags
                    break;
                }
            }
            let body = &arg[minuses..];
            if body.is_empty() || body.starts_with('-') || body.starts_with('=') {
                return Err(FlagError::BadSyntax(arg.clone()));
            }
            let (name, inline, has_value) = match body.find('=') {
                Some(pos) => (&body[..pos], body[pos + 1..].to_string(), true),
                None => (body, String::new(), false),
            };
            i += 1;

            if let Some(idx) = self.find(name) {
                let kind = self.flags[idx].kind;
                let raw = if kind == Kind::Bool {
                    // Go: bool flags never consume the next argument.
                    if has_value {
                        inline
                    } else {
                        "true".to_string()
                    }
                } else if has_value {
                    inline
                } else if i < args.len() {
                    let next = args[i].clone();
                    i += 1;
                    next
                } else {
                    return Err(FlagError::MissingValue(name.to_string()));
                };
                if let Err(reason) = set_flag_value(&mut self.flags[idx], &raw) {
                    return Err(FlagError::BadValue(name.to_string(), raw, reason));
                }
                self.flags[idx].set_by_cli = true;
            } else if name == "help" || name == "h" {
                // Go: unregistered help/h => usage + ErrHelp (usage() works).
                self.remaining = args[i..].to_vec();
                return Err(FlagError::Help);
            } else if self.tolerated_unknown.iter().any(|t| t == name) {
                tracing::warn!(flag = name, "skipping tolerated unknown flag");
                if !has_value && i < args.len() && !args[i].starts_with('-') {
                    i += 1; // assume a value-taking flag: skip its value too
                }
            } else {
                return Err(FlagError::UnknownFlag(name.to_string()));
            }
        }
        self.remaining = args[i..].to_vec();
        Ok(())
    }

    /// coreos `flagutil.SetFlagsFromEnv`: env key `{PREFIX}_{NAME}`
    /// (uppercased, `-` -> `_`); non-empty values parse like CLI values and
    /// OVERRIDE them (call after [`parse`]). Bad values collected, not fatal.
    pub fn set_flags_from_env(&mut self, prefix: &str) -> Vec<EnvError> {
        let mut errors = Vec::new();
        let names: Vec<String> = self.flags.iter().map(|f| f.name.clone()).collect();
        for name in names {
            let env_key = format!("{prefix}_{}", name.replace('-', "_").to_uppercase());
            let raw = env::var(&env_key).unwrap_or_default();
            if raw.is_empty() {
                continue; // Go: empty env values are skipped
            }
            let idx = self.find(&name).expect("registered flag");
            match set_flag_value(&mut self.flags[idx], &raw) {
                Ok(()) => self.flags[idx].set_by_env = true,
                Err(reason) => errors.push(EnvError {
                    flag: name,
                    env_key,
                    value: raw,
                    reason,
                }),
            }
        }
        errors
    }

    pub fn get_bool(&self, name: &str) -> bool {
        match &self.flag(name).value {
            Value::Bool(b) => *b,
            other => panic!("flag {name:?} is {other:?}, not a bool"),
        }
    }

    pub fn get_int(&self, name: &str) -> i64 {
        match &self.flag(name).value {
            Value::Int(n) => *n,
            other => panic!("flag {name:?} is {other:?}, not an int"),
        }
    }

    pub fn get_string(&self, name: &str) -> String {
        match &self.flag(name).value {
            Value::Str(s) => s.clone(),
            other => panic!("flag {name:?} is {other:?}, not a string"),
        }
    }

    pub fn get_slice(&self, name: &str) -> Vec<String> {
        match &self.flag(name).value {
            Value::Slice(items) => items.clone(),
            other => panic!("flag {name:?} is {other:?}, not a slice"),
        }
    }

    /// True if the flag was set via CLI or env (Go "actual" map).
    pub fn is_set(&self, name: &str) -> bool {
        self.find(name)
            .is_some_and(|idx| self.flags[idx].set_by_cli || self.flags[idx].set_by_env)
    }

    pub fn was_set_by_env(&self, name: &str) -> bool {
        self.find(name)
            .is_some_and(|idx| self.flags[idx].set_by_env)
    }

    /// Args after the first positional (or after `--`).
    pub fn remaining_args(&self) -> Vec<String> {
        self.remaining.clone()
    }

    /// Go `Flag.DefValue` as a string; `None` for unregistered names.
    pub fn default_value(&self, name: &str) -> Option<String> {
        self.find(name)
            .map(|idx| def_value_string(&self.flags[idx]))
    }

    /// Go default `flag.Usage`: "Usage of <name>:" header + `PrintDefaults`
    /// — sorted by name, `  -name type\n    \tdesc (default x)`; bools omit
    /// the type; zero-value defaults omitted; heads <= 4 chars (e.g. `  -v`)
    /// get usage on the same line, matching Go's alignment rule.
    pub fn usage(&self) -> String {
        let mut out = format!("Usage of {}:\n", self.name);
        let mut flags: Vec<&Flag> = self.flags.iter().collect();
        flags.sort_by(|a, b| a.name.cmp(&b.name));
        for flag in flags {
            let mut head = format!("  -{}", flag.name);
            let type_name = match flag.kind {
                Kind::Bool => "",
                Kind::Int => "int",
                Kind::Str => "string",
                Kind::Slice => "value", // Go UnquoteUsage fallback for custom Value
            };
            if !type_name.is_empty() {
                head.push_str(&format!(" {type_name}"));
            }
            out.push_str(&head);
            out.push_str(if head.len() <= 4 { "\t" } else { "\n    \t" });
            out.push_str(&flag.help);
            if shows_default(flag) {
                let def = def_value_string(flag);
                let rendered = if flag.kind == Kind::Str {
                    format!("{def:?}")
                } else {
                    def
                };
                out.push_str(&format!(" (default {rendered})"));
            }
            out.push('\n');
        }
        out
    }
}

#[cfg(test)]
#[path = "flags/tests.rs"]
mod tests;
