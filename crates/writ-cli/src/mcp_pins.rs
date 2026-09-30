//! `writ mcp pins|accept|reset`: review and trust changed MCP tool
//! definitions held by the proxy's tool pinning (see `writ_mcp::pins`).

use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Result};
use clap::Subcommand;
use serde_json::Value;
use writ_mcp::pins::{pin_path, Pin, ToolPins};

#[derive(Subcommand, Debug)]
pub enum McpCmd {
    /// List pinned MCP tools and held (changed) definitions, per server.
    Pins {
        /// Only this server; also prints each held tool's old and new
        /// definition.
        #[arg(long)]
        server: Option<String>,
    },
    /// Trust the changed definition of held tools (every held tool of the
    /// server when none is named).
    Accept { server: String, tools: Vec<String> },
    /// Forget every pin of a server; the next `tools/list` pins afresh.
    Reset { server: String },
}

/// Where the proxy keeps tool pins: next to the ledger (`.writ/` for a
/// Postgres ledger).
pub(crate) fn pins_dir(ledger: &Path) -> PathBuf {
    if crate::cmds::is_pg(ledger) {
        return PathBuf::from(".writ").join("mcp-pins");
    }
    match ledger.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.join("mcp-pins"),
        _ => PathBuf::from("mcp-pins"),
    }
}

pub fn run(ledger: &Path, cmd: &McpCmd) -> Result<()> {
    let dir = pins_dir(ledger);
    match cmd {
        McpCmd::Pins { server } => list(&dir, server.as_deref()),
        McpCmd::Accept { server, tools } => {
            let path = pin_path(&dir, server);
            if !path.exists() {
                bail!("no pins for server {server:?} in {}", dir.display());
            }
            let mut pins = ToolPins::load(&path, server).map_err(|e| anyhow!(e))?;
            let accepted = pins.accept(tools).map_err(|e| anyhow!(e))?;
            if accepted.is_empty() {
                println!("  {server}: nothing held");
            } else {
                println!(
                    "  {server}: now trusting the new definition of {}",
                    accepted.join(", ")
                );
            }
            Ok(())
        }
        McpCmd::Reset { server } => {
            let path = pin_path(&dir, server);
            let mut pins = ToolPins::load(&path, server).map_err(|e| anyhow!(e))?;
            pins.reset().map_err(|e| anyhow!(e))?;
            println!("  {server}: pins cleared; the next tools/list pins every tool again");
            Ok(())
        }
    }
}

fn list(dir: &Path, only: Option<&str>) -> Result<()> {
    let mut files: Vec<PathBuf> = match only {
        Some(s) => vec![pin_path(dir, s)],
        None => std::fs::read_dir(dir)
            .map(|rd| {
                rd.flatten()
                    .map(|e| e.path())
                    .filter(|p| p.extension().is_some_and(|x| x == "json"))
                    .collect()
            })
            .unwrap_or_default(),
    };
    files.sort();
    if files.is_empty() || (only.is_some() && !files[0].exists()) {
        println!(
            "  No pinned MCP tools yet ({}). `writ proxy --mcp` pins each server's tools on first use.",
            dir.display()
        );
        return Ok(());
    }
    for f in files {
        let name = f
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("?")
            .to_string();
        let pins = ToolPins::load(&f, &name).map_err(|e| anyhow!(e))?;
        let file = pins.file();
        println!(
            "  {}  {} pinned, {} held{}",
            file.server,
            file.tools.len(),
            file.pending.len(),
            if file.pending.is_empty() {
                String::new()
            } else {
                format!(
                    ": {}",
                    file.pending.keys().cloned().collect::<Vec<_>>().join(", ")
                )
            }
        );
        if only.is_some() {
            for (tool, new) in &file.pending {
                let old = file.tools.get(tool);
                println!();
                println!(
                    "  held: {tool}  (changed definition first seen {})",
                    new.seen_at
                );
                print_change(old, new);
                println!("  trust it: writ mcp accept {} {tool}", file.server);
            }
        }
    }
    Ok(())
}

fn field(p: &Pin, k: &str) -> Value {
    p.definition.get(k).cloned().unwrap_or(Value::Null)
}

fn print_change(old: Option<&Pin>, new: &Pin) {
    let Some(old) = old else {
        return;
    };
    let mut keys: Vec<String> = old
        .definition
        .as_object()
        .into_iter()
        .chain(new.definition.as_object())
        .flat_map(|m| m.keys().cloned())
        .collect();
    keys.sort();
    keys.dedup();
    for k in keys {
        let (a, b) = (field(old, &k), field(new, &k));
        if a == b {
            continue;
        }
        let show = |v: &Value| match v {
            Value::String(s) => s.clone(),
            Value::Null => "(absent)".into(),
            other => other.to_string(),
        };
        println!("    {k}:");
        println!("      was: {}", show(&a));
        println!("      now: {}", show(&b));
    }
}
