use colored::Colorize;
use serde::Deserialize;
use std::collections::HashMap;
use std::env;
use std::process::{Command, exit};

#[derive(Deserialize, Debug, PartialEq)]
struct AuditReport {
    #[serde(default)]
    vulnerabilities: HashMap<String, Vulnerability>,
}

#[derive(Deserialize, Debug, PartialEq, Clone)]
#[serde(untagged)]
enum Via {
    Advisory {
        title: String,
        url: String,
    },
    #[allow(dead_code)]
    Package(String),
}

#[derive(Deserialize, Debug, PartialEq, Clone)]
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

fn parse_audit_report(json: &str) -> Result<AuditReport, String> {
    serde_json::from_str(json).map_err(|e| format!("Failed to parse npm audit output: {}", e))
}

fn filter_vulnerabilities(vulns: Vec<Vulnerability>, severity: Option<&str>) -> Vec<Vulnerability> {
    match severity {
        Some(f) => vulns.into_iter().filter(|v| v.severity == f).collect(),
        None => vulns,
    }
}

fn sort_vulnerabilities(mut vulns: Vec<Vulnerability>) -> Vec<Vulnerability> {
    vulns.sort_by(|a, b| severity_order(&a.severity).cmp(&severity_order(&b.severity)));
    vulns
}

fn validate_severity(severity: &str) -> bool {
    ["critical", "high", "moderate", "low"].contains(&severity)
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
        if !validate_severity(f) {
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
    let report = match parse_audit_report(&audit_json) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("{}", e);
            exit(1);
        }
    };

    // Extract, filter, and sort vulnerabilities
    let vulns: Vec<Vulnerability> = report.vulnerabilities.into_values().collect();
    let vulns = filter_vulnerabilities(vulns, filter.as_deref());
    let vulns = sort_vulnerabilities(vulns);

    // Check if no vulnerabilities
    if vulns.is_empty() {
        println!("{}", "No vulnerabilities found!".green());
        return;
    }

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

#[cfg(test)]
mod tests {
    use super::*;

    // ==================== severity_order tests ====================

    #[test]
    fn test_severity_order_critical() {
        assert_eq!(severity_order("critical"), 0);
    }

    #[test]
    fn test_severity_order_high() {
        assert_eq!(severity_order("high"), 1);
    }

    #[test]
    fn test_severity_order_moderate() {
        assert_eq!(severity_order("moderate"), 2);
    }

    #[test]
    fn test_severity_order_low() {
        assert_eq!(severity_order("low"), 3);
    }

    #[test]
    fn test_severity_order_unknown() {
        assert_eq!(severity_order("unknown"), 4);
        assert_eq!(severity_order(""), 4);
    }

    // ==================== validate_severity tests ====================

    #[test]
    fn test_validate_severity_valid() {
        assert!(validate_severity("critical"));
        assert!(validate_severity("high"));
        assert!(validate_severity("moderate"));
        assert!(validate_severity("low"));
    }

    #[test]
    fn test_validate_severity_invalid() {
        assert!(!validate_severity("medium"));
        assert!(!validate_severity("Critical"));
        assert!(!validate_severity(""));
        assert!(!validate_severity("info"));
    }

    // ==================== parse_audit_report tests ====================

    #[test]
    fn test_parse_empty_vulnerabilities() {
        let json = r#"{"vulnerabilities": {}}"#;
        let report = parse_audit_report(json).unwrap();
        assert!(report.vulnerabilities.is_empty());
    }

    #[test]
    fn test_parse_missing_vulnerabilities_field() {
        let json = r#"{}"#;
        let report = parse_audit_report(json).unwrap();
        assert!(report.vulnerabilities.is_empty());
    }

    #[test]
    fn test_parse_single_vulnerability() {
        let json = r#"{
            "vulnerabilities": {
                "lodash": {
                    "name": "lodash",
                    "severity": "high",
                    "via": [
                        {
                            "title": "Prototype Pollution",
                            "url": "https://npmjs.com/advisories/1234"
                        }
                    ]
                }
            }
        }"#;
        let report = parse_audit_report(json).unwrap();
        assert_eq!(report.vulnerabilities.len(), 1);
        let vuln = report.vulnerabilities.get("lodash").unwrap();
        assert_eq!(vuln.name, "lodash");
        assert_eq!(vuln.severity, "high");
    }

    #[test]
    fn test_parse_via_as_package_string() {
        let json = r#"{
            "vulnerabilities": {
                "foo": {
                    "name": "foo",
                    "severity": "moderate",
                    "via": ["bar"]
                }
            }
        }"#;
        let report = parse_audit_report(json).unwrap();
        let vuln = report.vulnerabilities.get("foo").unwrap();
        assert_eq!(vuln.via.len(), 1);
        assert!(matches!(&vuln.via[0], Via::Package(s) if s == "bar"));
    }

    #[test]
    fn test_parse_invalid_json() {
        let json = r#"not valid json"#;
        let result = parse_audit_report(json);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Failed to parse"));
    }

    // ==================== filter_vulnerabilities tests ====================

    fn create_test_vulns() -> Vec<Vulnerability> {
        vec![
            Vulnerability {
                name: "critical-pkg".to_string(),
                severity: "critical".to_string(),
                via: vec![],
            },
            Vulnerability {
                name: "high-pkg".to_string(),
                severity: "high".to_string(),
                via: vec![],
            },
            Vulnerability {
                name: "moderate-pkg".to_string(),
                severity: "moderate".to_string(),
                via: vec![],
            },
            Vulnerability {
                name: "low-pkg".to_string(),
                severity: "low".to_string(),
                via: vec![],
            },
        ]
    }

    #[test]
    fn test_filter_no_filter() {
        let vulns = create_test_vulns();
        let filtered = filter_vulnerabilities(vulns, None);
        assert_eq!(filtered.len(), 4);
    }

    #[test]
    fn test_filter_by_critical() {
        let vulns = create_test_vulns();
        let filtered = filter_vulnerabilities(vulns, Some("critical"));
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].name, "critical-pkg");
    }

    #[test]
    fn test_filter_by_high() {
        let vulns = create_test_vulns();
        let filtered = filter_vulnerabilities(vulns, Some("high"));
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].name, "high-pkg");
    }

    #[test]
    fn test_filter_no_matches() {
        let vulns = vec![Vulnerability {
            name: "pkg".to_string(),
            severity: "high".to_string(),
            via: vec![],
        }];
        let filtered = filter_vulnerabilities(vulns, Some("critical"));
        assert!(filtered.is_empty());
    }

    // ==================== sort_vulnerabilities tests ====================

    #[test]
    fn test_sort_by_severity() {
        let vulns = vec![
            Vulnerability {
                name: "low-pkg".to_string(),
                severity: "low".to_string(),
                via: vec![],
            },
            Vulnerability {
                name: "critical-pkg".to_string(),
                severity: "critical".to_string(),
                via: vec![],
            },
            Vulnerability {
                name: "high-pkg".to_string(),
                severity: "high".to_string(),
                via: vec![],
            },
        ];
        let sorted = sort_vulnerabilities(vulns);
        assert_eq!(sorted[0].severity, "critical");
        assert_eq!(sorted[1].severity, "high");
        assert_eq!(sorted[2].severity, "low");
    }

    #[test]
    fn test_sort_empty() {
        let vulns: Vec<Vulnerability> = vec![];
        let sorted = sort_vulnerabilities(vulns);
        assert!(sorted.is_empty());
    }

    #[test]
    fn test_sort_single_item() {
        let vulns = vec![Vulnerability {
            name: "pkg".to_string(),
            severity: "high".to_string(),
            via: vec![],
        }];
        let sorted = sort_vulnerabilities(vulns);
        assert_eq!(sorted.len(), 1);
    }

    // ==================== Integration tests ====================

    #[test]
    fn test_full_parsing_and_processing() {
        let json = r#"{
            "vulnerabilities": {
                "axios": {
                    "name": "axios",
                    "severity": "moderate",
                    "via": [
                        {
                            "title": "Server-Side Request Forgery",
                            "url": "https://github.com/advisories/GHSA-1234"
                        }
                    ]
                },
                "lodash": {
                    "name": "lodash",
                    "severity": "critical",
                    "via": [
                        {
                            "title": "Prototype Pollution",
                            "url": "https://github.com/advisories/GHSA-5678"
                        }
                    ]
                },
                "minimist": {
                    "name": "minimist",
                    "severity": "high",
                    "via": ["lodash"]
                }
            }
        }"#;

        let report = parse_audit_report(json).unwrap();
        let vulns: Vec<Vulnerability> = report.vulnerabilities.into_values().collect();
        let vulns = filter_vulnerabilities(vulns, None);
        let vulns = sort_vulnerabilities(vulns);

        assert_eq!(vulns.len(), 3);
        assert_eq!(vulns[0].severity, "critical");
        assert_eq!(vulns[1].severity, "high");
        assert_eq!(vulns[2].severity, "moderate");
    }

    #[test]
    fn test_real_npm_audit_format() {
        // This mirrors actual npm audit --json output structure
        let json = r#"{
            "auditReportVersion": 2,
            "vulnerabilities": {
                "glob-parent": {
                    "name": "glob-parent",
                    "severity": "high",
                    "isDirect": false,
                    "via": [
                        {
                            "source": 1751,
                            "name": "glob-parent",
                            "dependency": "glob-parent",
                            "title": "Regular expression denial of service",
                            "url": "https://github.com/advisories/GHSA-ww39-953v-wcq6",
                            "severity": "high",
                            "cwe": ["CWE-400"],
                            "cvss": {
                                "score": 7.5,
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
                            },
                            "range": "<5.1.2"
                        }
                    ],
                    "effects": [],
                    "range": "<5.1.2",
                    "nodes": ["node_modules/glob-parent"],
                    "fixAvailable": true
                }
            },
            "metadata": {
                "vulnerabilities": {
                    "info": 0,
                    "low": 0,
                    "moderate": 0,
                    "high": 1,
                    "critical": 0,
                    "total": 1
                }
            }
        }"#;

        let report = parse_audit_report(json).unwrap();
        assert_eq!(report.vulnerabilities.len(), 1);

        let vuln = report.vulnerabilities.get("glob-parent").unwrap();
        assert_eq!(vuln.name, "glob-parent");
        assert_eq!(vuln.severity, "high");
        assert_eq!(vuln.via.len(), 1);

        if let Via::Advisory { title, url } = &vuln.via[0] {
            assert_eq!(title, "Regular expression denial of service");
            assert!(url.contains("github.com/advisories"));
        } else {
            panic!("Expected Advisory variant");
        }
    }
}
