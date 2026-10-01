//! provio: a safety floor your AI agents can't get under. One policy for
//! every agent, checked before every tool call, with a tamper-evident ledger.

use std::path::PathBuf;

use clap::{Parser, Subcommand};

mod cmds;
mod hook;
mod inspect;
mod integrate;
mod mcp_http;
mod mcp_pins;
mod onboard;
mod packs;
mod receipt;
mod report;
mod run;
mod scan;
mod session_guard;
mod ui;

#[derive(Parser)]
#[command(
    name = "provio",
    version,
    about = "A safety floor your AI agents can't get under: one policy for every agent, checked before every tool call, recorded in a tamper-evident ledger.",
    long_about = None
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Policy file (default: ./provio.yaml; a legacy ./writ.yaml is used
    /// when there is no provio.yaml).
    #[arg(long, global = true)]
    policy: Option<PathBuf>,

    /// Ledger path (default: ./.provio/ledger.jsonl). A SQLite ledger (`.db`,
    /// `.sqlite`, `.sqlite3`, or any file with a SQLite header) needs a
    /// build with `--features sqlite`; without it, such paths are refused.
    #[arg(long, global = true)]
    ledger: Option<PathBuf>,

    /// Flip the policy default from ask to allow. Dangerous; for demos only.
    #[arg(long, global = true)]
    yolo: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Protect this project: a starter policy (the disaster floor and the
    /// secrets guard) and hooks for every coding agent found here.
    Init(onboard::InitArgs),

    /// What would provio have done? Replays your agents' past sessions
    /// (Claude Code, Codex, Gemini CLI transcripts) through the policy.
    /// Reads only; installs and records nothing.
    Scan(scan::ScanArgs),

    /// Try one call against the policy: `provio test "rm -rf ~"`. Nothing
    /// runs and nothing is recorded. Exit 0 allow, 2 deny, 3 ask.
    Test(onboard::TestArgs),

    /// Wrap an agent, policy enforced: `provio run -- claude`
    Run {
        /// Sandbox backend (provio doctor lists what this machine supports).
        #[arg(long, default_value = "local-os")]
        backend: String,
        /// Network for the wrapped agent: `open` (it must reach its model
        /// API; reported as not enforced) or `none` (kernel-enforced).
        #[arg(long, value_enum, default_value_t = run::NetMode::Open)]
        net: run::NetMode,
        /// Extra writable path for the agent, beyond the workspace and its
        /// profile's state dirs. Repeatable.
        #[arg(long = "allow-write", value_name = "PATH")]
        allow_write: Vec<PathBuf>,
        /// Launch without the kernel boundary (launch supervision only).
        #[arg(long)]
        unconfined: bool,
        /// Run even if the kernel can only partly enforce the boundary;
        /// each gap is reported.
        #[arg(long)]
        best_effort: bool,
        /// Do not wire provio's per-tool-call hooks into agents that support
        /// them (e.g. Claude Code).
        #[arg(long)]
        no_hooks: bool,
        /// The agent command line, after `--`.
        #[arg(last = true, required = true)]
        cmd: Vec<String>,
    },

    /// Hook gateway for agent SDKs and agent hook systems (INTERFACES.md
    /// Contract 6): decide one tool call, or serve JSON lines with --stdio.
    Check {
        /// Serve newline-delimited JSON requests until stdin closes.
        #[arg(long)]
        stdio: bool,
        /// Wire format of stdin/stdout.
        #[arg(long, value_enum, default_value_t = hook::Format::Provio)]
        format: hook::Format,
        /// What an `ask` verdict does without a terminal: fail closed, or
        /// defer the human decision to the calling agent's own UI.
        #[arg(long, value_enum, default_value_t = hook::AskMode::Deny)]
        ask: hook::AskMode,
        /// When the policy file does not exist: `deny` every call (fail
        /// closed), or judge with the `starter` policy (the floor and
        /// secrets-guard packs) and record to ~/.provio/ledger.jsonl unless
        /// --ledger is given. Used by the Claude Code plugin, which runs in
        /// projects that have no provio.yaml.
        #[arg(long, value_enum, default_value_t = NoPolicy::Deny)]
        if_no_policy: NoPolicy,
    },

    /// Wire provio into an agent's configuration: `provio integrate claude-code`
    Integrate {
        #[arg(value_enum)]
        target: integrate::Target,
        /// Print the configuration instead of writing it.
        #[arg(long)]
        print: bool,
    },

    /// Sit in front of an MCP server: `provio proxy --mcp --server github -- npx server`
    Proxy {
        #[arg(long)]
        mcp: bool,
        /// Downstream server identity (used for policy + credentials).
        #[arg(long, required = true)]
        server: String,
        /// Streamable HTTP / SSE transport options (default transport: stdio).
        #[command(flatten)]
        http: mcp_http::HttpArgs,
        /// Do not pin tool definitions. By default the first definition of
        /// each tool is pinned, and a changed one is hidden from the agent
        /// and its calls refused until `provio mcp accept`.
        #[arg(long)]
        no_pin: bool,
        /// Downstream server command line, after `--` (stdio transport).
        #[arg(last = true)]
        cmd: Vec<String>,
    },

    /// Local web console: connect an agent, watch decisions live, approve
    /// asks, edit and test the policy, try the sandbox.
    Ui(ui::UiArgs),

    /// MCP tool pins: review and trust changed tool definitions.
    Mcp {
        #[command(subcommand)]
        sub: mcp_pins::McpCmd,
    },

    /// Signed receipts over the ledger, and anchoring them externally.
    Receipt {
        #[command(subcommand)]
        sub: receipt::ReceiptCmd,
    },

    /// What did my agent actually do?
    Log,

    /// One decision, in full.
    Show { call_id: String },

    /// Verify the local ledger hash chain and name the first broken record.
    Verify,

    /// Policy operations.
    Policy {
        #[command(subcommand)]
        sub: PolicyCmd,
    },

    /// Reproduce a trajectory / replay a candidate policy against it.
    Replay {
        /// Session id (see `provio log`).
        session: String,
        /// Candidate policy to evaluate against the recorded calls.
        #[arg(long)]
        candidate: Option<PathBuf>,
        /// Re-branch from this decision index; irreversible steps refuse
        /// unless --ack-irreversible is passed.
        #[arg(long)]
        branch_from: Option<u64>,
        /// Explicit acknowledgement for irreversible steps (spec §10).
        #[arg(long)]
        ack_irreversible: bool,
    },

    /// Coverage report: which call paths are governed and which are blind.
    Doctor,

    /// What your agents did: what provio stopped, what needed you, a timeline
    /// per session and the ledger's integrity, as one self-contained page
    /// (or Markdown, or JSON). `--sign <key>` embeds a verifiable receipt.
    Report(report::ReportArgs),
}

/// `provio check --if-no-policy`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
enum NoPolicy {
    Deny,
    Starter,
}

#[derive(Subcommand)]
enum PolicyCmd {
    /// Unit-test your rules against recorded fixtures.
    Test {
        /// Fixture directory (contains *.yaml test cases).
        #[arg(long)]
        fixtures: Option<PathBuf>,
    },
    /// Install a community policy pack from packs/.
    Add { pack: String },
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn".into()),
        )
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();
    let policy = cli
        .policy
        .clone()
        .unwrap_or_else(|| legacy_or("provio.yaml", "writ.yaml"));
    let ledger = cli
        .ledger
        .clone()
        .unwrap_or_else(|| legacy_or(".provio/ledger.jsonl", ".writ/ledger.jsonl"));
    match cli.command {
        Commands::Init(args) => onboard::init(&policy, &ledger, &args),
        Commands::Scan(args) => scan::scan(&policy, &args),
        Commands::Test(args) => {
            let code = onboard::test(&policy, &args)?;
            std::process::exit(code)
        }
        Commands::Run {
            backend,
            net,
            allow_write,
            unconfined,
            best_effort,
            no_hooks,
            cmd,
        } => run::run(&run::RunArgs {
            policy: policy.clone(),
            ledger: ledger.clone(),
            yolo: cli.yolo,
            backend,
            net,
            allow_write,
            unconfined,
            best_effort,
            no_hooks,
            cmd,
        }),
        Commands::Check {
            stdio,
            format,
            ask,
            if_no_policy,
        } => {
            let mut ledger = ledger;
            if if_no_policy == NoPolicy::Starter && !policy.exists() {
                cmds::use_starter_when_missing();
                if cli.ledger.is_none() {
                    if let Some(home) =
                        std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE"))
                    {
                        ledger = PathBuf::from(home).join(".provio").join("ledger.jsonl");
                    }
                }
            }
            hook::check(&policy, &ledger, cli.yolo, stdio, format, ask)
        }
        Commands::Integrate { target, print } => {
            integrate::integrate(&policy, &ledger, target, print)
        }
        Commands::Proxy {
            mcp,
            server,
            http,
            no_pin,
            cmd,
        } => {
            if http.is_http() {
                mcp_http::proxy_http(&policy, &ledger, cli.yolo, mcp, &server, &http, !no_pin)
            } else {
                if cmd.is_empty() {
                    anyhow::bail!("stdio transport needs the downstream server command after `--`");
                }
                cmds::proxy(&policy, &ledger, cli.yolo, mcp, &server, &cmd, !no_pin)
            }
        }
        Commands::Mcp { sub } => mcp_pins::run(&ledger, &sub),
        Commands::Ui(args) => ui::serve(&policy, &ledger, cli.yolo, &args),
        Commands::Receipt { sub } => receipt::run(&policy, &ledger, &sub),
        Commands::Log => cmds::log(&ledger),
        Commands::Show { call_id } => cmds::show(&ledger, &call_id),
        Commands::Verify => cmds::verify(&ledger),
        Commands::Policy { sub } => match sub {
            PolicyCmd::Test { fixtures } => cmds::policy_test(&policy, fixtures),
            PolicyCmd::Add { pack } => cmds::policy_add(&pack),
        },
        Commands::Doctor => cmds::doctor(&policy, &ledger),
        Commands::Replay {
            session,
            candidate,
            branch_from,
            ack_irreversible,
        } => cmds::replay(&ledger, &session, candidate, branch_from, ack_irreversible),
        Commands::Report(args) => report::report(&ledger, &args),
    }
}

/// `new` unless only the pre-rename `legacy` path exists (writ → provio),
/// in which case the legacy path is used with a one-line notice.
fn legacy_or(new: &str, legacy: &str) -> PathBuf {
    let (n, l) = (PathBuf::from(new), PathBuf::from(legacy));
    let top = |p: &PathBuf| p.components().next().map(|c| PathBuf::from(c.as_os_str()));
    let exists = |p: &PathBuf| top(p).is_some_and(|t| t.exists());
    if !exists(&n) && exists(&l) {
        eprintln!(
            "  provio · using {legacy} from before the rename (writ → provio); rename it to {new} when convenient"
        );
        return l;
    }
    n
}
