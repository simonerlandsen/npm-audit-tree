use colored::Colorize;
use serde::Deserialize;
use std::collections::HashMap;
use std::env;
use std::process::{Command, exit};

#[derive(Deserialize)]
struct AuditReport {
    #[serde(default)]
    vulnerabilities: HashMap<String, Vulnerability>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum Via {
    Advisory {
        title: String,
        url: String,
    },
    #[allow(dead_code)]
    Package(String),
}

#[derive(Deserialize)]
struct Vulnerability {
    name: String,
    severity: String,
    #[serde(default)]
    via: Vec<Via>,
}

fn severity_order(severity: &str) -> u8 {
    match severity {
        "critical" => 0,
        "high" => 1,
        "moderate" => 2,
        "low" => 3,
        _ => 4,
    }
}

fn print_colored_header(name: &str, severity: &str) {
    let header = format!("=== {} ({}) ===", name, severity);
    let colored_header = match severity {
        "critical" => header.bright_red().bold(),
        "high" => header.red(),
        "moderate" => header.yellow(),
        "low" => header.cyan(),
        _ => header.white(),
    };
    println!("\n{}", colored_header);
}

fn print_advisory_info(via: &[Via]) {
    for v in via {
        if let Via::Advisory { title, url } = v {
            println!("{} - {}", title, url);
        }
    }
}

fn check_npm_installed() -> bool {
    Command::new("npm")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn run_npm_audit() -> Result<String, String> {
    let output = Command::new("npm")
        .args(["audit", "--json"])
        .output()
        .map_err(|e| format!("Failed to run npm audit: {}", e))?;

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    // If stdout is empty or not valid JSON, check stderr for error message
    if stdout.trim().is_empty() || !stdout.trim().starts_with('{') {
        if !stderr.trim().is_empty() {
            return Err(stderr.trim().to_string());
        }
        return Err("npm audit returned empty output".to_string());
    }

    Ok(stdout)
}

fn run_npm_ls(package: &str) -> String {
    Command::new("npm")
        .args(["ls", package])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default()
}

fn print_help() {
    println!("npm-audit-tree

Display npm audit vulnerabilities with their dependency trees.

USAGE:
    npm-audit-tree [OPTIONS] [SEVERITY]

ARGS:
    [SEVERITY]    Filter by severity: critical, high, moderate, low

OPTIONS:
    -h, --help       Print this help message
    -v, --version    Print version

EXAMPLES:
    npm-audit-tree              Show all vulnerabilities
    npm-audit-tree critical     Show only critical vulnerabilities
    npm-audit-tree high         Show only high severity");
}

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn main() {
    let args: Vec<String> = env::args().collect();

    // Check for help/version flags
    if let Some(arg) = args.get(1) {
        if arg == "-h" || arg == "--help" {
            print_help();
            return;
        }
        if arg == "-v" || arg == "--version" {
            println!("npm-audit-tree {}", VERSION);
            return;
        }
    }

    let filter = args.get(1).map(|s| s.to_lowercase());

    // Validate filter if provided
    if let Some(ref f) = filter {
        if !["critical", "high", "moderate", "low"].contains(&f.as_str()) {
            eprintln!("Invalid severity. Use: critical, high, moderate, or low");
            eprintln!("Try 'npm-audit-tree --help' for more information.");
            exit(1);
        }
    }

    // Check npm is installed
    if !check_npm_installed() {
        eprintln!("npm is not installed. Please install Node.js and npm first.");
        exit(1);
    }

    // Run npm audit
    let audit_json = match run_npm_audit() {
        Ok(json) => json,
        Err(e) => {
            eprintln!("{}", e);
            exit(1);
        }
    };

    // Parse audit output
    let report: AuditReport = match serde_json::from_str(&audit_json) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Failed to parse npm audit output: {}", e);
            exit(1);
        }
    };

    // Extract vulnerabilities
    let mut vulns: Vec<Vulnerability> = report.vulnerabilities.into_values().collect();

    // Filter by severity if specified
    if let Some(ref f) = filter {
        vulns.retain(|v| v.severity == *f);
    }

    // Check if no vulnerabilities
    if vulns.is_empty() {
        println!("{}", "No vulnerabilities found!".green());
        return;
    }

    // Sort by severity (critical first)
    vulns.sort_by(|a, b| severity_order(&a.severity).cmp(&severity_order(&b.severity)));

    // Print each vulnerability with its dependency tree
    for vuln in &vulns {
        print_colored_header(&vuln.name, &vuln.severity);
        print_advisory_info(&vuln.via);
        let tree = run_npm_ls(&vuln.name);
        if !tree.is_empty() {
            print!("{}", tree);
        }
    }
}
