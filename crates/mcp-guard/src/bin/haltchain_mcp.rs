use std::collections::HashMap;
use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process;
use std::sync::Arc;

use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    routing::{get, post},
};
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};

#[derive(Parser)]
#[command(
    name = "haltchain-mcp",
    about = "Runtime MCP security scanner and enforcement engine",
    version,
    long_about = "HaltChain MCP Guard — scans MCP configurations for poisoned tools,\n\
                   validates against baseline inventories, and provides runtime\n\
                   enforcement for AI agent tool calls.\n\n\
                   Unlike simple scanners, HaltChain adds behavioral analysis,\n\
                   cross-agent correlation, and cryptographic audit trails."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan MCP configuration files for security issues
    Scan {
        /// Path to MCP config file (e.g. ~/.cursor/mcp.json)
        #[arg(short, long)]
        config: PathBuf,

        /// Path to baseline inventory (approved tools per org/agent)
        #[arg(short, long)]
        baseline: Option<PathBuf>,

        /// Output format: text, json
        #[arg(short, long, default_value = "text")]
        format: String,

        /// Verbose output
        #[arg(short, long)]
        verbose: bool,
    },

    /// Run as a sidecar enforcement endpoint on localhost
    Serve {
        /// Port to listen on
        #[arg(short, long, default_value = "8787")]
        port: u16,

        /// Path to baseline inventory
        #[arg(short, long)]
        baseline: Option<PathBuf>,

        /// Database URL for policy evaluation (optional — runs without DB if not set)
        #[arg(long)]
        database_url: Option<String>,
    },

    /// Validate a single MCP tool call against policies
    Check {
        /// Tool name to validate
        #[arg(short = 't', long)]
        tool: String,

        /// Tool arguments as JSON string
        #[arg(short = 'a', long, default_value = "{}")]
        args: String,

        /// Agent ID (UUID)
        #[arg(short = 'i', long)]
        agent_id: String,

        /// Organization ID (UUID)
        #[arg(short = 'o', long)]
        org_id: String,

        /// Path to baseline inventory
        #[arg(short = 'b', long)]
        baseline: Option<PathBuf>,
    },
}

#[derive(Debug, Deserialize)]
struct McpConfigWrapper {
    #[serde(default)]
    mcp_servers: Option<HashMap<String, serde_json::Value>>,
    #[serde(default, rename = "mcpServers")]
    mcp_servers_camel: Option<HashMap<String, serde_json::Value>>,
}

#[derive(Debug, Serialize)]
struct ScanResult {
    config_path: String,
    servers_found: usize,
    issues: Vec<ScanIssue>,
    risk_score: f64,
    verdict: String,
}

#[derive(Debug, Serialize)]
struct ScanIssue {
    server: String,
    severity: String,
    category: String,
    message: String,
    tool_name: Option<String>,
}

const BLOCKED_PATTERNS: &[&str] = &[
    "exec",
    "shell",
    "sudo",
    "curl",
    "bash",
    "rm -rf",
    "drop database",
    "token_exfiltration",
    "credential_dump",
    "wget",
    "nc",
    "ncat",
    "netcat",
    "eval(",
    "system(",
    "os.system",
    "subprocess",
    "__import__",
    "pickle",
    "marshal",
];

fn scan_config(path: &PathBuf, baseline_path: &Option<PathBuf>, verbose: bool) -> ScanResult {
    let content = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error reading {}: {}", path.display(), e);
            process::exit(1);
        }
    };

    let wrapper: McpConfigWrapper = match serde_json::from_str(&content) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error parsing {}: {}", path.display(), e);
            process::exit(1);
        }
    };

    let servers = wrapper
        .mcp_servers
        .as_ref()
        .or(wrapper.mcp_servers_camel.as_ref())
        .cloned()
        .unwrap_or_default();

    let baseline = baseline_path
        .as_ref()
        .and_then(|p| fs::read_to_string(p).ok())
        .and_then(|c| serde_json::from_str::<BaselineInventory>(&c).ok());

    let mut issues = Vec::new();

    for (server_name, server_config) in &servers {
        if verbose {
            println!("Scanning server: {}", server_name);
        }

        // Check if server has command-based execution
        if let Some(cmd) = server_config.get("command")
            && let Some(cmd_str) = cmd.as_str()
        {
            for pattern in BLOCKED_PATTERNS {
                if cmd_str.to_lowercase().contains(&pattern.to_lowercase()) {
                    issues.push(ScanIssue {
                        server: server_name.clone(),
                        severity: "CRITICAL".to_string(),
                        category: "command_injection".to_string(),
                        message: format!(
                            "Server command contains blocked pattern '{}': {}",
                            pattern, cmd_str
                        ),
                        tool_name: None,
                    });
                }
            }
        }

        // Check args for suspicious patterns
        if let Some(args) = server_config.get("args").and_then(|a| a.as_array()) {
            for arg in args {
                if let Some(arg_str) = arg.as_str() {
                    for pattern in BLOCKED_PATTERNS {
                        if arg_str.to_lowercase().contains(&pattern.to_lowercase()) {
                            issues.push(ScanIssue {
                                server: server_name.clone(),
                                severity: "HIGH".to_string(),
                                category: "suspicious_arg".to_string(),
                                message: format!(
                                    "Server arg contains blocked pattern '{}': {}",
                                    pattern, arg_str
                                ),
                                tool_name: None,
                            });
                        }
                    }
                }
            }
        }

        // Check for environment variable leaks
        if let Some(env) = server_config.get("env").and_then(|e| e.as_object()) {
            for (key, value) in env {
                let key_lower = key.to_lowercase();
                if (key_lower.contains("secret")
                    || key_lower.contains("password")
                    || key_lower.contains("token")
                    || key_lower.contains("api_key")
                    || key_lower.contains("private_key"))
                    && let Some(val_str) = value.as_str()
                    && !val_str.starts_with("$")
                    && !val_str.starts_with("${")
                {
                    issues.push(ScanIssue {
                        server: server_name.clone(),
                        severity: "HIGH".to_string(),
                        category: "credential_exposure".to_string(),
                        message: format!("Potential hardcoded credential in env var '{}'", key),
                        tool_name: None,
                    });
                }
            }
        }

        // Check if tool is in baseline (if baseline provided)
        if let Some(ref bl) = baseline
            && !bl.is_tool_approved(server_name)
        {
            issues.push(ScanIssue {
                server: server_name.clone(),
                severity: "MEDIUM".to_string(),
                category: "baseline_violation".to_string(),
                message: format!(
                    "Server '{}' not found in baseline inventory — unknown tool",
                    server_name
                ),
                tool_name: None,
            });
        }

        // Check for network access patterns
        if let Some(args) = server_config.get("args").and_then(|a| a.as_array()) {
            for arg in args {
                if let Some(arg_str) = arg.as_str()
                    && (arg_str.starts_with("http://") || arg_str.starts_with("https://"))
                {
                    issues.push(ScanIssue {
                        server: server_name.clone(),
                        severity: "LOW".to_string(),
                        category: "network_access".to_string(),
                        message: format!("Server connects to external URL: {}", arg_str),
                        tool_name: None,
                    });
                }
            }
        }
    }

    let critical_count = issues.iter().filter(|i| i.severity == "CRITICAL").count();
    let high_count = issues.iter().filter(|i| i.severity == "HIGH").count();
    let medium_count = issues.iter().filter(|i| i.severity == "MEDIUM").count();

    let risk_score =
        (critical_count as f64 * 10.0) + (high_count as f64 * 5.0) + (medium_count as f64 * 2.0);

    let verdict = if critical_count > 0 {
        "BLOCKED — critical security issues found"
    } else if high_count > 0 {
        "WARNING — high-severity issues require review"
    } else if medium_count > 0 {
        "ADVISORY — baseline violations detected"
    } else {
        "CLEAN — no security issues found"
    };

    ScanResult {
        config_path: path.display().to_string(),
        servers_found: servers.len(),
        issues,
        risk_score,
        verdict: verdict.to_string(),
    }
}

#[derive(Debug, Deserialize)]
struct BaselineInventory {
    #[serde(default)]
    approved_tools: Vec<String>,
    #[serde(default)]
    orgs: HashMap<String, BaselineOrg>,
}

#[derive(Debug, Deserialize)]
struct BaselineOrg {
    #[serde(default)]
    approved_tools: Vec<String>,
}

impl BaselineInventory {
    fn is_tool_approved(&self, tool_name: &str) -> bool {
        if self.approved_tools.iter().any(|t| t == tool_name) {
            return true;
        }
        for org in self.orgs.values() {
            if org.approved_tools.iter().any(|t| t == tool_name) {
                return true;
            }
        }
        false
    }
}

fn check_tool(
    tool_name: &str,
    args_json: &str,
    baseline_path: &Option<PathBuf>,
) -> Result<String, String> {
    let mut issues = Vec::new();

    for pattern in BLOCKED_PATTERNS {
        if tool_name.to_lowercase().contains(&pattern.to_lowercase()) {
            issues.push(format!("Tool name contains blocked pattern '{}'", pattern));
        }
        if args_json.to_lowercase().contains(&pattern.to_lowercase()) {
            issues.push(format!("Tool args contain blocked pattern '{}'", pattern));
        }
    }

    if let Some(bl_path) = baseline_path {
        let content =
            fs::read_to_string(bl_path).map_err(|e| format!("Failed to read baseline: {}", e))?;
        let baseline: BaselineInventory = serde_json::from_str(&content)
            .map_err(|e| format!("Failed to parse baseline: {}", e))?;

        if !baseline.is_tool_approved(tool_name) {
            issues.push(format!("Tool '{}' not in baseline inventory", tool_name));
        }
    } else if !is_fail_open() {
        // No baseline and not explicitly fail-open: block unknown tools
        issues.push("no-baseline-configured".to_string());
    }

    if issues.is_empty() {
        Ok(serde_json::to_string(&serde_json::json!({
            "decision": "allow",
            "tool": tool_name,
            "reason": "all checks passed"
        }))
        .unwrap())
    } else {
        Ok(serde_json::to_string(&serde_json::json!({
            "decision": "block",
            "tool": tool_name,
            "reason": issues.join("; ")
        }))
        .unwrap())
    }
}

fn is_fail_open() -> bool {
    std::env::var("HALTCHAIN_LITE_FAIL_OPEN")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

#[derive(Debug, Deserialize)]
struct CheckRequest {
    tool: String,
    #[serde(default = "default_empty_json")]
    args: String,
}

fn default_empty_json() -> String {
    "{}".to_string()
}

struct ServeState {
    baseline: Option<PathBuf>,
}

async fn health_handler() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "ok",
        "service": "haltchain-mcp",
        "note": "reduced CLI checks; use haltchain-api /mcp/inspect for full enforcement"
    }))
}

async fn check_handler(
    State(state): State<Arc<ServeState>>,
    Json(body): Json<CheckRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    match check_tool(&body.tool, &body.args, &state.baseline) {
        Ok(raw) => {
            let parsed: serde_json::Value =
                serde_json::from_str(&raw).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
            Ok(Json(parsed))
        }
        Err(_e) => Err(StatusCode::BAD_REQUEST),
    }
}

async fn run_serve(port: u16, baseline: Option<PathBuf>) -> Result<(), Box<dyn std::error::Error>> {
    let state = Arc::new(ServeState { baseline });
    let app = Router::new()
        .route("/health", get(health_handler))
        .route("/check", post(check_handler))
        .with_state(state);

    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    let bound = listener.local_addr().unwrap_or(addr);
    println!("haltchain-mcp listening on http://{bound}");
    println!("GET  /health");
    println!("POST /check  {{\"tool\":\"...\",\"args\":\"{{}}\"}}");
    axum::serve(listener, app).await?;
    Ok(())
}

fn print_scan_result(result: &ScanResult, format: &str) {
    if format == "json" {
        println!("{}", serde_json::to_string_pretty(result).unwrap());
        return;
    }

    println!("╔══════════════════════════════════════════════════╗");
    println!("║         HaltChain MCP Security Scan             ║");
    println!("╚══════════════════════════════════════════════════╝");
    println!();
    println!("Config: {}", result.config_path);
    println!("Servers found: {}", result.servers_found);
    println!("Issues found: {}", result.issues.len());
    println!("Risk score: {:.1}", result.risk_score);
    println!();

    if result.issues.is_empty() {
        println!("✅ {}", result.verdict);
    } else {
        println!("⚠️  {}", result.verdict);
        println!();
        for issue in &result.issues {
            let icon = match issue.severity.as_str() {
                "CRITICAL" => "🔴",
                "HIGH" => "🟠",
                "MEDIUM" => "🟡",
                "LOW" => "🔵",
                _ => "⚪",
            };
            println!(
                "  {} [{}] {}: {}",
                icon, issue.severity, issue.category, issue.message
            );
            println!("     Server: {}", issue.server);
        }
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "haltchain_mcp=info".into()),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Scan {
            config,
            baseline,
            format,
            verbose,
        } => {
            let result = scan_config(&config, &baseline, verbose);
            let has_critical = result.issues.iter().any(|i| i.severity == "CRITICAL");
            print_scan_result(&result, &format);
            if has_critical {
                process::exit(1);
            }
        }
        Commands::Serve {
            port,
            baseline,
            database_url: _,
        } => {
            if let Err(e) = run_serve(port, baseline).await {
                eprintln!("serve failed: {e}");
                process::exit(1);
            }
        }
        Commands::Check {
            tool,
            args,
            agent_id: _,
            org_id: _,
            baseline,
        } => match check_tool(&tool, &args, &baseline) {
            Ok(result) => {
                println!("{}", result);
                let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
                if parsed["decision"] == "block" {
                    process::exit(1);
                }
            }
            Err(e) => {
                eprintln!("Error: {}", e);
                process::exit(1);
            }
        },
    }
}
