//! First contact: `provio init` (a policy plus hooks for every agent found),
//! `provio test` (one call through the policy, nothing run or recorded), and
//! the policy `provio scan` and `provio test` judge with when there is no
//! provio.yaml yet.

use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use provio_core::call::{CallerIdentity, InterceptMode, ServerIdentity, ToolCall};
use provio_core::verdict::Verdict;
use provio_core::Timestamp;
use provio_policy::NativePolicyEngine;
use serde_json::{json, Map, Value};

use crate::integrate::Target;

/// The packs a new policy starts from, and that `scan`/`test` judge with
/// when there is no policy file.
pub(crate) const STARTER_PACKS: &[&str] = &["floor", "secrets-guard"];

fn packs_policy(default: &str, packs: &[String]) -> String {
    format!(
        "version: 1\ndefault: {default}\npacks: [{}]\n",
        packs.join(", ")
    )
}

/// The engine `provio scan` / `provio test` judge with, and a label for it:
/// `--packs` if given (everything else allowed), else the policy file if
/// it exists, else the starter packs.
pub(crate) fn judging_policy(
    policy: &Path,
    packs: &[String],
) -> Result<(NativePolicyEngine, String)> {
    let from_packs = |packs: Vec<String>, why: &str| -> Result<(NativePolicyEngine, String)> {
        let src = packs_policy("allow", &packs);
        let engine = NativePolicyEngine::from_source(&src).map_err(|e| anyhow!(e.to_string()))?;
        Ok((engine, format!("packs {}{why}", packs.join(" + "))))
    };
    if packs.iter().any(|p| p == "all") {
        let all: Vec<String> = provio_policy::packs::BUNDLED
            .iter()
            .map(|(id, _)| id.to_string())
            // floor first: its deny/ask rules then decide before any other
            // pack's (packs keep the order they are listed in).
            .filter(|id| id != "floor")
            .fold(vec!["floor".to_string()], |mut v, id| {
                v.push(id);
                v
            });
        return from_packs(all, " (every bundled pack)");
    }
    if !packs.is_empty() {
        return from_packs(packs.to_vec(), "");
    }
    if policy.exists() {
        let engine = crate::cmds::load_engine(policy, false)?;
        return Ok((engine, policy.display().to_string()));
    }
    from_packs(
        STARTER_PACKS.iter().map(|s| s.to_string()).collect(),
        &format!(" (no {} here; `provio init` creates one)", policy.display()),
    )
}

// --- provio test ------------------------------------------------------------------

#[derive(clap::Args, Debug)]
pub struct TestArgs {
    /// A shell command, as an agent would run it.
    #[arg(conflicts_with_all = ["tool", "call"])]
    pub command: Vec<String>,
    /// Test another tool instead of a shell command: `fs.read`, `fs.write`,
    /// `http`, or an MCP tool name.
    #[arg(long)]
    pub tool: Option<String>,
    /// `path` argument (file tools).
    #[arg(long)]
    pub path: Option<String>,
    /// `url` argument (`http`).
    #[arg(long)]
    pub url: Option<String>,
    /// `query` argument (SQL tools).
    #[arg(long)]
    pub query: Option<String>,
    /// File contents being written (`fs.write`), checked like a script.
    #[arg(long)]
    pub content: Option<String>,
    /// MCP server the tool belongs to.
    #[arg(long)]
    pub server: Option<String>,
    /// A whole call as JSON: `{"tool": "...", "args": {...}, "server": "..."}`.
    #[arg(long)]
    pub call: Option<String>,
    /// Judge with these bundled packs instead of the policy file (`all`:
    /// every bundled pack).
    #[arg(long, value_delimiter = ',')]
    pub packs: Vec<String>,
    /// Print the verdict as JSON.
    #[arg(long)]
    pub json: bool,
}

/// `provio test`: exit 0 allow/redact, 2 deny, 3 ask (errors exit 1).
pub fn test(policy: &Path, args: &TestArgs) -> Result<i32> {
    let (engine, label) = judging_policy(policy, &args.packs)?;
    let call = test_call(args)?;
    let verdict = crate::inspect::evaluate(&engine, &call);
    let code = match &verdict {
        Verdict::Allow { .. } | Verdict::Redact { .. } => 0,
        Verdict::Deny { .. } => 2,
        Verdict::Ask { .. } => 3,
    };
    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "policy": label,
                "call": { "tool": call.tool, "args": call.args, "server": call.server.as_ref().map(|s| &s.name) },
                "verdict": verdict,
            }))?
        );
        return Ok(code);
    }
    let what = match call.args.get("command").and_then(Value::as_str) {
        Some(c) if call.tool == "bash" => c.to_string(),
        _ => format!("{} {}", call.tool, call.args),
    };
    println!("  {what}");
    match &verdict {
        Verdict::Allow { rule_id } => match rule_id.as_deref() {
            Some("default") | None => {
                println!("  ALLOW  no rule names this call; the policy default allows it")
            }
            Some(r) => println!("  ALLOW  by rule {r}"),
        },
        Verdict::Redact { rule_id, .. } => {
            println!(
                "  ALLOW  by rule {rule_id}; matching output is masked before the model sees it"
            )
        }
        Verdict::Deny {
            rule_id,
            reason,
            location,
        } => {
            println!("  DENY   {rule_id}{}", loc(location));
            println!("         {reason}");
        }
        Verdict::Ask {
            rule_id,
            diff,
            location,
            irreversible,
            ..
        } => {
            let tail = if *irreversible { " (irreversible)" } else { "" };
            println!("  ASK    {rule_id}{}{tail}", loc(location));
            println!("         {diff}");
        }
    }
    println!("  policy: {label}");
    Ok(code)
}

fn loc(location: &Option<String>) -> String {
    location
        .as_deref()
        .map(|l| format!("  ({l})"))
        .unwrap_or_default()
}

pub(crate) fn test_call(args: &TestArgs) -> Result<ToolCall> {
    let (tool, argmap, server) = if let Some(raw) = &args.call {
        let v: Value = serde_json::from_str(raw).context("--call is not valid JSON")?;
        let tool = v
            .get("tool")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("--call needs a \"tool\""))?
            .to_string();
        let a = match v.get("args") {
            None | Some(Value::Null) => Map::new(),
            Some(Value::Object(m)) => m.clone(),
            Some(_) => bail!("--call \"args\" must be an object"),
        };
        let server = v.get("server").and_then(Value::as_str).map(str::to_string);
        (tool, a, server)
    } else {
        let mut a = Map::new();
        let tool = match (&args.tool, args.command.is_empty()) {
            (Some(t), _) => t.clone(),
            (None, false) => {
                a.insert("command".into(), json!(args.command.join(" ")));
                "bash".into()
            }
            (None, true) => bail!("give a command (`provio test \"rm -rf ~\"`), --tool, or --call"),
        };
        for (k, v) in [
            ("path", &args.path),
            ("url", &args.url),
            ("query", &args.query),
            ("content", &args.content),
        ] {
            if let Some(v) = v {
                a.insert(k.into(), json!(v));
            }
        }
        (tool, a, args.server.clone())
    };
    Ok(ToolCall {
        call_id: "provio-test".into(),
        session_id: "provio-test".into(),
        caller: CallerIdentity {
            agent: "provio-test".into(),
            agent_version: None,
            user: None,
            non_human_id: None,
        },
        mode: InterceptMode::SdkHook,
        tool,
        args: Value::Object(argmap),
        server: server.map(|name| ServerIdentity {
            name,
            transport: "unknown".into(),
            version: None,
        }),
        trust: None,
        captured_at: Timestamp::now(),
    })
}

// --- provio init ------------------------------------------------------------------

#[derive(clap::Args, Debug)]
pub struct InitArgs {
    /// Wire these agents (default: every agent found on this machine).
    #[arg(long, value_enum, value_delimiter = ',')]
    pub agent: Vec<Target>,
    /// New policy asks before anything no rule names (default: allows it,
    /// with the disaster floor and secrets guard on).
    #[arg(long)]
    pub strict: bool,
    /// Wire your user-level agent configuration (every project), with the
    /// policy and ledger in ~/.provio/, instead of this project.
    #[arg(long)]
    pub global: bool,
    /// Show what would be done; write nothing.
    #[arg(long)]
    pub dry_run: bool,
}

fn home() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
}

fn on_path(names: &[&str]) -> bool {
    let Some(path) = std::env::var_os("PATH") else {
        return false;
    };
    let exts: &[&str] = if cfg!(windows) {
        &["", ".exe", ".cmd", ".bat", ".ps1"]
    } else {
        &[""]
    };
    std::env::split_paths(&path).any(|dir| {
        names
            .iter()
            .any(|n| exts.iter().any(|e| dir.join(format!("{n}{e}")).is_file()))
    })
}

/// Is `target` installed here (its CLI on PATH or its config directory)?
fn detected(target: Target) -> bool {
    let h = home();
    let dir = |rel: &[&str]| {
        h.as_ref()
            .is_some_and(|h| rel.iter().fold(h.clone(), |p, r| p.join(r)).is_dir())
    };
    match target {
        Target::ClaudeCode => on_path(&["claude"]) || dir(&[".claude"]),
        Target::Codex => on_path(&["codex"]) || dir(&[".codex"]),
        Target::Gemini => on_path(&["gemini"]) || dir(&[".gemini"]),
        Target::Cursor => on_path(&["cursor-agent", "cursor"]) || dir(&[".cursor"]),
        Target::Windsurf => on_path(&["windsurf"]) || dir(&[".codeium", "windsurf"]),
    }
}

fn target_name(t: Target) -> &'static str {
    match t {
        Target::ClaudeCode => "claude-code",
        Target::Codex => "codex",
        Target::Gemini => "gemini",
        Target::Cursor => "cursor",
        Target::Windsurf => "windsurf",
    }
}

const ALL_TARGETS: [Target; 5] = [
    Target::ClaudeCode,
    Target::Codex,
    Target::Gemini,
    Target::Cursor,
    Target::Windsurf,
];

pub(crate) fn starter_policy(strict: bool) -> String {
    let default = if strict { "ask" } else { "allow" };
    let default_note = if strict {
        "# default: what happens to a call no rule names. `ask`: you approve it\n\
         # (in the agent's own prompt where it has one). `allow` keeps agents fast."
    } else {
        "# default: what happens to a call no rule names. `allow` keeps agents fast;\n\
         # `ask` makes you approve everything the rules below do not decide."
    };
    format!(
        "# provio.yaml, written by `provio init`. Every tool call your agents make is\n\
         # checked against this file before it runs, and every decision is\n\
         # recorded in a tamper-evident ledger (`provio log`, `provio verify`).\n\
         #\n\
         {default_note}\n\
         version: 1\n\
         default: {default}\n\
         \n\
         # Bundled policy packs. `floor`: the disasters no agent should cause on its\n\
         # own (wiping ~ or /, force-pushing main, reading SSH/cloud keys, disabling\n\
         # its own hooks); `secrets-guard`: keys and tokens stay out of the model.\n\
         # More: aws-safety, gcp-azure-safety, github-safety, database-safety,\n\
         # k8s-prod, terraform-safety, package-publish-guard, pii-redaction.\n\
         packs: [{}]\n\
         \n\
         # Your own rules; first match wins, and the packs' deny/ask rules come\n\
         # first. Try one: provio test \"git push --force origin main\"\n\
         rules: []\n\
         \n\
         # Session guards (these are the defaults): ask before a session that read\n\
         # a credential file sends data out, and when an agent repeats the same call\n\
         # 5 times in a row. call_budget caps the tool calls of one session (0: none).\n\
         # session_guards:\n\
         #   secret_then_egress: ask   # ask | deny | off\n\
         #   repeated_call: ask        # ask | deny | off\n\
         #   repeated_call_limit: 5\n\
         #   call_budget: 0\n\
         #   over_budget: ask          # ask | deny\n",
        STARTER_PACKS.join(", ")
    )
}

pub fn init(policy: &Path, ledger: &Path, args: &InitArgs) -> Result<()> {
    let (root, policy, ledger) = if args.global {
        let h = home()
            .ok_or_else(|| anyhow!("cannot find your home directory (HOME / USERPROFILE)"))?;
        let dir = h.join(".provio");
        (h.clone(), dir.join("provio.yaml"), dir.join("ledger.jsonl"))
    } else {
        let cwd = std::env::current_dir()?;
        (cwd.clone(), std::path::absolute(policy)?, {
            if crate::cmds::is_pg(ledger) {
                ledger.to_path_buf()
            } else {
                std::path::absolute(ledger)?
            }
        })
    };
    let targets: Vec<Target> = if args.agent.is_empty() {
        ALL_TARGETS.into_iter().filter(|t| detected(*t)).collect()
    } else {
        args.agent.clone()
    };

    println!();
    println!(
        "  provio init  {}",
        if args.global {
            format!("user-level, every project (hooks in {})", root.display())
        } else {
            format!("this project ({})", root.display())
        }
    );
    println!();
    if policy.exists() {
        crate::cmds::load_engine(&policy, false).with_context(|| {
            format!(
                "{} exists but does not load; fix it first",
                policy.display()
            )
        })?;
        println!("  policy   {} (kept as it is)", policy.display());
    } else {
        let text = starter_policy(args.strict);
        NativePolicyEngine::from_source(&text).map_err(|e| anyhow!(e.to_string()))?;
        if !args.dry_run {
            if let Some(dir) = policy.parent() {
                std::fs::create_dir_all(dir)?;
            }
            std::fs::write(&policy, &text)
                .with_context(|| format!("write {}", policy.display()))?;
        }
        println!(
            "  policy   {} ({}: default {}, packs {})",
            policy.display(),
            if args.dry_run { "would create" } else { "new" },
            if args.strict { "ask" } else { "allow" },
            STARTER_PACKS.join(" + ")
        );
    }
    if !args.global && !args.dry_run {
        ignore_provio_dir(&root);
    }
    if targets.is_empty() {
        println!();
        println!("  No coding agent found (Claude Code, Codex, Gemini CLI, Cursor, Windsurf).");
        println!("  Name one: provio init --agent claude-code");
        return Ok(());
    }
    println!();
    let mut failed = Vec::new();
    for t in &targets {
        if args.global && *t == Target::Windsurf {
            println!("  - windsurf: user-level hooks are not supported yet; run `provio init --agent windsurf` in a project");
            continue;
        }
        if args.dry_run {
            println!("  would wire {}", target_name(*t));
            continue;
        }
        let res = if args.global {
            let back = std::env::current_dir()?;
            std::env::set_current_dir(&root)?;
            let r = crate::integrate::integrate(&policy, &ledger, *t, false);
            std::env::set_current_dir(back)?;
            r
        } else {
            crate::integrate::integrate(&policy, &ledger, *t, false)
        };
        if let Err(e) = res {
            println!("  x {}: {e:#}", target_name(*t));
            failed.push(target_name(*t));
        }
    }
    let missing: Vec<&str> = ALL_TARGETS
        .into_iter()
        .filter(|t| !targets.contains(t))
        .map(target_name)
        .collect();
    println!();
    if !missing.is_empty() && args.agent.is_empty() {
        println!(
            "  not found here: {} (add one with --agent)",
            missing.join(", ")
        );
    }
    println!("  Try it:        provio test \"rm -rf ~\"");
    println!("  Look back:     provio scan         (what your agents did in the last 30 days)");
    println!("  Watch live:    provio ui           (decisions, approvals, the policy editor)");
    println!();
    if !failed.is_empty() {
        bail!("could not wire: {}", failed.join(", "));
    }
    Ok(())
}

/// Keep the ledger out of commits: add `.provio/` to the project's
/// .gitignore when the project is a git repository and does not already.
fn ignore_provio_dir(root: &Path) {
    if !root.join(".git").exists() {
        return;
    }
    let gi = root.join(".gitignore");
    let existing = std::fs::read_to_string(&gi).unwrap_or_default();
    if existing
        .lines()
        .any(|l| matches!(l.trim(), ".provio" | ".provio/" | "/.provio" | "/.provio/"))
    {
        return;
    }
    let sep = if existing.is_empty() || existing.ends_with('\n') {
        ""
    } else {
        "\n"
    };
    if std::fs::write(
        &gi,
        format!("{existing}{sep}# provio ledger and state\n.provio/\n"),
    )
    .is_ok()
    {
        println!("  .gitignore  added .provio/ (the ledger stays local)");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn examples_starter_is_what_init_writes() {
        // examples/starter.yaml is the playground's first preset and the
        // docs' example; keep it byte-identical to `provio init`.
        let on_disk = include_str!("../../../examples/starter.yaml").replace(
            "
", "
",
        );
        assert_eq!(on_disk, starter_policy(false));
    }

    #[test]
    fn starter_policies_compile_and_hold_the_floor() {
        for strict in [false, true] {
            let e = NativePolicyEngine::from_source(&starter_policy(strict)).unwrap();
            let call = test_call(&TestArgs {
                command: vec!["rm".into(), "-rf".into(), "~".into()],
                tool: None,
                path: None,
                url: None,
                query: None,
                content: None,
                server: None,
                call: None,
                packs: vec![],
                json: false,
            })
            .unwrap();
            let v = crate::inspect::evaluate(&e, &call);
            assert!(matches!(v, Verdict::Deny { .. }), "{v:?}");
        }
    }
}
