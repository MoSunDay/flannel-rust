//! Port of the parts of `sigs.k8s.io/knftables` v0.0.18 that flannel
//! uses: a minimal `nft -f` script generator and runner. A [`Transaction`]
//! renders to one `nft` operation per line; [`Nft::run`] feeds the script
//! to `nft -f -` and [`Nft::check`] to `nft -c -f -` (validate without
//! applying), like knftables' `Run`/`Check`.
//!
//! Deviation from knftables: nftables before ~1.0.7 rejects
//! `add table ... comment` and ` ; `-separated base-chain attributes
//! (this image ships nft v1.0.2), so [`Nft::new`] probes the installed
//! `nft` once and transactions fall back to the legacy syntax when needed.

use crate::subnet::manager::Ctx;
use anyhow::{anyhow, Result};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

/// Go/knftables: `knftables.Family` ("ip" or "ip6").
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub enum Family {
    /// knftables: `IPv4Family`.
    #[default]
    Ip,
    /// knftables: `IPv6Family`.
    Ip6,
}

impl Family {
    /// knftables `Family` is itself the string ("ip"/"ip6").
    pub fn as_str(self) -> &'static str {
        match self {
            Family::Ip => "ip",
            Family::Ip6 => "ip6",
        }
    }
}

/// Go: `knftables.Concat` — joins tokens with single spaces.
pub fn concat(parts: &[&str]) -> String {
    parts.join(" ")
}

/// Go: `knftables` type/hook/priority constants used by flannel.
pub const NAT_TYPE: &str = "nat";
pub const FILTER_TYPE: &str = "filter";
pub const FORWARD_HOOK: &str = "forward";
pub const POSTROUTING_HOOK: &str = "postrouting";
pub const FILTER_PRIORITY: &str = "0";
pub const SNAT_PRIORITY: &str = "100";

/// Go: `knftables.Chain` (the fields flannel sets; all but name optional).
pub struct ChainDef {
    pub name: String,
    pub comment: Option<String>,
    pub typ: Option<&'static str>,
    pub hook: Option<&'static str>,
    pub priority: Option<&'static str>,
}

/// Go: `knftables.Transaction`: ordered operations rendered one per line.
#[derive(Default)]
pub struct Transaction {
    family: Family,
    table: String,
    /// False on nftables < ~1.0.7: render legacy syntax (module docs).
    modern: bool,
    lines: Vec<String>,
}

impl Transaction {
    /// knftables: `nft.NewTransaction()` (see [`Nft::new_transaction`]).
    pub fn new(family: Family, table: &str, modern: bool) -> Self {
        Self {
            family,
            table: table.to_string(),
            modern,
            lines: Vec::new(),
        }
    }

    /// Go: `tx.Add(&knftables.Table{Comment})`. Legacy `nft` has no
    /// table comments, so the comment is dropped there.
    pub fn add_table(&mut self, comment: Option<&str>) -> &mut Self {
        let mut line = format!("add table {} {}", self.family.as_str(), self.table);
        if let Some(c) = comment.filter(|_| self.modern) {
            line.push_str(&format!(" comment {c:?}"));
        }
        self.lines.push(line);
        self
    }

    /// Go: `tx.Add(&knftables.Chain{...})`. Attributes render in the
    /// order comment, type, hook, priority (only those set), each
    /// `key value`. Modern (knftables-exact) joins them with ` ; ` and
    /// ends the block with a trailing ` ; `; legacy keeps the base-chain
    /// spec positional: `type T hook H priority P`.
    pub fn add_chain(&mut self, def: &ChainDef) -> &mut Self {
        let mut attrs: Vec<String> = Vec::new();
        if let Some(c) = &def.comment {
            attrs.push(format!("comment {c:?}"));
        }
        if self.modern {
            if let Some(t) = def.typ {
                attrs.push(format!("type {t}"));
            }
            if let Some(h) = def.hook {
                attrs.push(format!("hook {h}"));
            }
            if let Some(p) = def.priority {
                attrs.push(format!("priority {p}"));
            }
        } else if def.typ.is_some() || def.hook.is_some() || def.priority.is_some() {
            let mut spec = String::new();
            if let Some(t) = def.typ {
                spec.push_str(&format!("type {t}"));
            }
            if let Some(h) = def.hook {
                spec.push_str(&format!(" hook {h}"));
            }
            if let Some(p) = def.priority {
                spec.push_str(&format!(" priority {p}"));
            }
            attrs.push(spec);
        }
        let f = self.family.as_str();
        let line = if attrs.is_empty() {
            format!("add chain {f} {} {}", self.table, def.name)
        } else {
            format!(
                "add chain {f} {} {} {{ {} ; }}",
                self.table,
                def.name,
                attrs.join(" ; ")
            )
        };
        self.lines.push(line);
        self
    }

    /// Go: `tx.Flush(&knftables.Chain{Name})`.
    pub fn flush_chain(&mut self, name: &str) -> &mut Self {
        self.lines.push(format!(
            "flush chain {} {} {name}",
            self.family.as_str(),
            self.table
        ));
        self
    }

    /// Go: `tx.Add(&knftables.Rule{Chain, Rule})`.
    pub fn add_rule(&mut self, chain: &str, rule: &str) -> &mut Self {
        self.lines.push(format!(
            "add rule {} {} {chain} {rule}",
            self.family.as_str(),
            self.table
        ));
        self
    }

    /// Go: `tx.Delete(&knftables.Table{})`.
    pub fn delete_table(&mut self) -> &mut Self {
        self.lines.push(format!(
            "delete table {} {}",
            self.family.as_str(),
            self.table
        ));
        self
    }

    /// Go: knftables renders one operation per line, newline-terminated.
    pub fn render(&self) -> String {
        if self.lines.is_empty() {
            return String::new();
        }
        self.lines.join("\n") + "\n"
    }
}

/// Go/knftables: the `nft` handle bound to one family + table
/// (`knftables.Interface`).
#[derive(Clone)]
pub struct Nft {
    family: Family,
    table: String,
    path: PathBuf,
    /// Knftables-style syntax supported (see module docs).
    modern: bool,
}

impl Nft {
    /// Go: `knftables.New(family, table)`: locate the `nft` binary, then
    /// probe whether the installed nftables accepts the knftables-style
    /// rendering (table comments, ` ; `-separated chain attributes).
    pub async fn new(family: Family, table: &str) -> Result<Self> {
        let path =
            look_path("nft").ok_or_else(|| anyhow!("no nftables support: nft binary not found"))?;
        let modern = probe_modern_syntax(&path, family).await;
        Ok(Self {
            family,
            table: table.to_string(),
            path,
            modern,
        })
    }

    pub fn family(&self) -> Family {
        self.family
    }

    pub fn is_modern(&self) -> bool {
        self.modern
    }

    /// Go: `nft.NewTransaction()`.
    pub fn new_transaction(&self) -> Transaction {
        Transaction::new(self.family, &self.table, self.modern)
    }

    /// Go: `nft.Run(ctx, tx)`: apply via `nft -f -`.
    pub async fn run(&self, ctx: Ctx<'_>, tx: &Transaction) -> Result<()> {
        exec_script(ctx, &self.path, false, &tx.render()).await
    }

    /// Go: `nft.Check(ctx, tx)`: validate via `nft -c -f -`.
    pub async fn check(&self, ctx: Ctx<'_>, tx: &Transaction) -> Result<()> {
        exec_script(ctx, &self.path, true, &tx.render()).await
    }
}

/// Go: `exec.LookPath("nft")` over $PATH (existence + an exec bit).
fn look_path(bin: &str) -> Option<PathBuf> {
    use std::os::unix::fs::PermissionsExt;
    let paths = std::env::var_os("PATH")?;
    std::env::split_paths(&paths).find_map(|dir| {
        let cand = dir.join(bin);
        let exec = cand.is_file()
            && cand
                .metadata()
                .map(|m| m.permissions().mode() & 0o111 != 0)
                .unwrap_or(false);
        exec.then_some(cand)
    })
}

/// `nft [-c] -f -` with `script` on stdin; on cancellation the child is
/// dropped, which kills it (`kill_on_drop`). knftables passes ctx to
/// `exec.CommandContext` for the same effect.
async fn exec_script(ctx: Ctx<'_>, path: &Path, check: bool, script: &str) -> Result<()> {
    let mut cmd = Command::new(path);
    if check {
        cmd.arg("-c");
    }
    cmd.arg("-f")
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let mut child = cmd.spawn().map_err(|e| anyhow!("nft spawn failed: {e}"))?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(script.as_bytes())
            .await
            .map_err(|e| anyhow!("nft stdin write failed: {e}"))?;
    }
    tokio::select! {
        () = ctx.cancelled() => Err(anyhow!("nft run cancelled")),
        res = child.wait_with_output() => {
            let out = res.map_err(|e| anyhow!("nft wait failed: {e}"))?;
            if out.status.success() {
                return Ok(());
            }
            let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
            let detail = if stderr.is_empty() {
                String::from_utf8_lossy(&out.stdout).trim().to_string()
            } else {
                stderr
            };
            Err(anyhow!("nft run failed: {detail}"))
        }
    }
}

/// Check-mode probe of the knftables-style syntax against a throwaway
/// table (nothing is applied); false selects the legacy rendering.
async fn probe_modern_syntax(path: &Path, family: Family) -> bool {
    let f = family.as_str();
    let script = format!(
        "add table {f} flannel-syntax-probe comment \"probe\"\n\
         add chain {f} flannel-syntax-probe probe {{ comment \"probe\" ; type filter ; hook forward ; priority 0 ; }}\n"
    );
    let token = tokio_util::sync::CancellationToken::new();
    exec_script(&token, path, true, &script).await.is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn forward_chain() -> ChainDef {
        ChainDef {
            name: "forward".to_string(),
            comment: Some("chain to accept flannel traffic".to_string()),
            typ: Some(FILTER_TYPE),
            hook: Some(FORWARD_HOOK),
            priority: Some(FILTER_PRIORITY),
        }
    }

    #[test]
    fn concat_joins_with_single_spaces() {
        assert_eq!(
            concat(&["ip saddr", "!=", "127.0.0.1", "masquerade fully-random"]),
            "ip saddr != 127.0.0.1 masquerade fully-random"
        );
    }

    /// Pins the knftables-exact rendering (modern syntax).
    #[test]
    fn render_knftables_shape_modern() {
        let mut tx = Transaction::new(Family::Ip, "flannel-ipv4", true);
        tx.add_table(Some("rules for flannel-ipv4"))
            .add_chain(&forward_chain())
            .flush_chain("forward")
            .add_rule("forward", &concat(&["ip saddr", "10.244.0.0/16", "accept"]))
            .delete_table();
        assert_eq!(
            tx.render(),
            [
                "add table ip flannel-ipv4 comment \"rules for flannel-ipv4\"",
                "add chain ip flannel-ipv4 forward { comment \"chain to accept flannel traffic\" ; type filter ; hook forward ; priority 0 ; }",
                "flush chain ip flannel-ipv4 forward",
                "add rule ip flannel-ipv4 forward ip saddr 10.244.0.0/16 accept",
                "delete table ip flannel-ipv4",
            ]
            .join("\n")
                + "\n"
        );
    }

    /// Pins the fallback rendering accepted by nftables < ~1.0.7.
    #[test]
    fn render_legacy_shape() {
        let mut tx = Transaction::new(Family::Ip6, "flannel-ipv6", false);
        tx.add_table(Some("rules for flannel-ipv6"))
            .add_chain(&ChainDef {
                name: "postrtg".to_string(),
                comment: Some("chain to manage traffic masquerading by flannel".to_string()),
                typ: Some(NAT_TYPE),
                hook: Some(POSTROUTING_HOOK),
                priority: Some(SNAT_PRIORITY),
            });
        assert_eq!(
            tx.render(),
            [
                "add table ip6 flannel-ipv6",
                "add chain ip6 flannel-ipv6 postrtg { comment \"chain to manage traffic masquerading by flannel\" ; type nat hook postrouting priority 100 ; }",
            ]
            .join("\n")
                + "\n"
        );
    }
}
