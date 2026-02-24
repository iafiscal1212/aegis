use serde::{Deserialize, Serialize};

/// Supported package ecosystems.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PackageEcosystem {
    Python,
    Node,
    Rust,
    System,
}

/// Where a package is being installed from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum InstallSource {
    /// Standard registry (PyPI, npm, crates.io)
    Registry,
    /// Git URL — higher risk
    Git(String),
    /// Direct URL — higher risk
    Url(String),
    /// Local path
    Path(String),
}

/// A parsed package install command.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedCommand {
    pub ecosystem: PackageEcosystem,
    pub packages: Vec<PackageSpec>,
    pub is_install: bool,
    pub is_dev: bool,
    pub force: bool,
    pub pre_release: bool,
    pub source: InstallSource,
    pub raw_command: String,
}

/// A single package specification with optional version constraint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageSpec {
    pub name: String,
    pub version: Option<String>,
}

impl PackageSpec {
    fn new(name: &str, version: Option<&str>) -> Self {
        Self {
            name: name.to_string(),
            version: version.map(|v| v.to_string()),
        }
    }
}

/// Parse a shell command string and extract package install information.
///
/// Returns `None` if the command is not a package install command.
pub fn parse_command(command: &str) -> Option<ParsedCommand> {
    let parts: Vec<&str> = shell_split(command);
    if parts.is_empty() {
        return None;
    }

    // Determine the base command (handles python -m pip, npx, etc.)
    let (ecosystem, cmd_offset) = detect_ecosystem(&parts)?;

    let remaining = &parts[cmd_offset..];
    if remaining.is_empty() {
        return None;
    }

    match ecosystem {
        PackageEcosystem::Python => parse_pip(remaining, command),
        PackageEcosystem::Node => parse_npm(remaining, command),
        PackageEcosystem::Rust => parse_cargo(remaining, command),
        PackageEcosystem::System => parse_apt(remaining, command),
    }
}

fn detect_ecosystem(parts: &[&str]) -> Option<(PackageEcosystem, usize)> {
    let base = strip_path(parts[0]);

    match base {
        "pip" | "pip3" => Some((PackageEcosystem::Python, 1)),
        "python" | "python3" => {
            // python -m pip install ...
            if parts.len() >= 3 && parts[1] == "-m" && (parts[2] == "pip" || parts[2] == "pip3") {
                Some((PackageEcosystem::Python, 3))
            } else {
                None
            }
        }
        "npm" | "npx" | "yarn" | "pnpm" | "bun" => Some((PackageEcosystem::Node, 1)),
        "cargo" => Some((PackageEcosystem::Rust, 1)),
        "apt" | "apt-get" => Some((PackageEcosystem::System, 1)),
        _ => None,
    }
}

fn strip_path(cmd: &str) -> &str {
    cmd.rsplit('/').next().unwrap_or(cmd)
}

fn parse_pip(parts: &[&str], raw: &str) -> Option<ParsedCommand> {
    if parts.is_empty() {
        return None;
    }

    let is_install = parts[0] == "install";
    if !is_install {
        return None;
    }

    let mut packages = Vec::new();
    let is_dev = false;
    let mut force = false;
    let mut pre_release = false;
    let mut source = InstallSource::Registry;
    let mut skip_next = false;

    for (i, part) in parts[1..].iter().enumerate() {
        if skip_next {
            skip_next = false;
            continue;
        }

        match *part {
            "--pre" => pre_release = true,
            "--force-reinstall" | "--force" => force = true,
            "-e" | "--editable" => {
                // Next arg is the path/url
                if let Some(next) = parts.get(i + 2) {
                    source = if next.starts_with("git+") || next.starts_with("git://") {
                        InstallSource::Git(next.to_string())
                    } else {
                        InstallSource::Path(next.to_string())
                    };
                    skip_next = true;
                }
            }
            "-r" | "--requirement" => {
                skip_next = true; // skip the requirements file arg
            }
            "-i" | "--index-url" | "--extra-index-url" | "-f" | "--find-links" | "--target"
            | "-t" | "--prefix" | "--root" | "--src" | "-c" | "--constraint" => {
                skip_next = true;
            }
            _ if part.starts_with('-') => {} // other flags
            _ => {
                // It's a package spec
                if part.starts_with("git+") || part.starts_with("https://") || part.starts_with("http://") {
                    source = if part.starts_with("git+") {
                        InstallSource::Git(part.to_string())
                    } else {
                        InstallSource::Url(part.to_string())
                    };
                } else if let Some((name, ver)) = parse_version_spec(part) {
                    packages.push(PackageSpec::new(name, Some(ver)));
                } else {
                    packages.push(PackageSpec::new(part, None));
                }
            }
        }
    }

    if packages.is_empty() && matches!(source, InstallSource::Registry) {
        return None;
    }

    Some(ParsedCommand {
        ecosystem: PackageEcosystem::Python,
        packages,
        is_install,
        is_dev,
        force,
        pre_release,
        source,
        raw_command: raw.to_string(),
    })
}

fn parse_npm(parts: &[&str], raw: &str) -> Option<ParsedCommand> {
    if parts.is_empty() {
        return None;
    }

    let is_install = matches!(parts[0], "install" | "i" | "add");
    if !is_install {
        return None;
    }

    let mut packages = Vec::new();
    let mut is_dev = false;
    let mut force = false;
    let mut source = InstallSource::Registry;

    for part in &parts[1..] {
        match *part {
            "-D" | "--save-dev" | "--dev" => is_dev = true,
            "-f" | "--force" => force = true,
            "-g" | "--global" | "--save" | "-S" | "--save-exact" | "-E" | "--save-optional"
            | "-O" | "--no-save" | "--legacy-peer-deps" => {}
            _ if part.starts_with('-') => {}
            _ => {
                if part.starts_with("git+") || part.starts_with("git://") {
                    source = InstallSource::Git(part.to_string());
                } else if part.starts_with("https://") || part.starts_with("http://") {
                    source = InstallSource::Url(part.to_string());
                } else if part.contains('/') && !part.contains('@') {
                    // Could be a github shorthand: user/repo
                    source = InstallSource::Git(part.to_string());
                } else if let Some(at_pos) = part.rfind('@') {
                    // package@version — but not @scope/package
                    if at_pos > 0 && !part.starts_with('@') {
                        let name = &part[..at_pos];
                        let ver = &part[at_pos + 1..];
                        packages.push(PackageSpec::new(name, Some(ver)));
                    } else if part.starts_with('@') {
                        // scoped package: @scope/name or @scope/name@version
                        if let Some(second_at) = part[1..].find('@') {
                            let name = &part[..second_at + 1];
                            let ver = &part[second_at + 2..];
                            packages.push(PackageSpec::new(name, Some(ver)));
                        } else {
                            packages.push(PackageSpec::new(part, None));
                        }
                    }
                } else {
                    packages.push(PackageSpec::new(part, None));
                }
            }
        }
    }

    if packages.is_empty() && matches!(source, InstallSource::Registry) {
        // `npm install` with no args installs from package.json — allow
        return None;
    }

    Some(ParsedCommand {
        ecosystem: PackageEcosystem::Node,
        packages,
        is_install,
        is_dev,
        force,
        pre_release: false,
        source,
        raw_command: raw.to_string(),
    })
}

fn parse_cargo(parts: &[&str], raw: &str) -> Option<ParsedCommand> {
    if parts.is_empty() {
        return None;
    }

    let is_install = matches!(parts[0], "add" | "install");
    if !is_install {
        return None;
    }

    let mut packages = Vec::new();
    let mut is_dev = false;
    let mut force = false;
    let mut source = InstallSource::Registry;
    let mut skip_next = false;

    for (i, part) in parts[1..].iter().enumerate() {
        if skip_next {
            skip_next = false;
            continue;
        }

        match *part {
            "--dev" | "-D" => is_dev = true,
            "--force" | "-f" => force = true,
            "--git" => {
                if let Some(url) = parts.get(i + 2) {
                    source = InstallSource::Git(url.to_string());
                    skip_next = true;
                }
            }
            "--path" => {
                if let Some(path) = parts.get(i + 2) {
                    source = InstallSource::Path(path.to_string());
                    skip_next = true;
                }
            }
            "--version" | "--vers" | "--branch" | "--tag" | "--rev" | "--registry"
            | "--features" | "--rename" => {
                skip_next = true;
            }
            _ if part.starts_with('-') => {}
            _ => {
                packages.push(PackageSpec::new(part, None));
            }
        }
    }

    if packages.is_empty() && matches!(source, InstallSource::Registry) {
        return None;
    }

    Some(ParsedCommand {
        ecosystem: PackageEcosystem::Rust,
        packages,
        is_install,
        is_dev,
        force,
        pre_release: false,
        source,
        raw_command: raw.to_string(),
    })
}

fn parse_apt(parts: &[&str], raw: &str) -> Option<ParsedCommand> {
    if parts.is_empty() {
        return None;
    }

    let is_install = parts[0] == "install";
    if !is_install {
        return None;
    }

    let mut packages = Vec::new();
    let mut force = false;

    for part in &parts[1..] {
        match *part {
            "-y" | "--yes" | "--assume-yes" | "-q" | "--quiet" => {}
            "--force-yes" => force = true,
            _ if part.starts_with('-') => {}
            _ => {
                if let Some((name, ver)) = part.split_once('=') {
                    packages.push(PackageSpec::new(name, Some(ver)));
                } else {
                    packages.push(PackageSpec::new(part, None));
                }
            }
        }
    }

    if packages.is_empty() {
        return None;
    }

    Some(ParsedCommand {
        ecosystem: PackageEcosystem::System,
        packages,
        is_install,
        is_dev: false,
        force,
        pre_release: false,
        source: InstallSource::Registry,
        raw_command: raw.to_string(),
    })
}

/// Simple shell-like splitting (handles quoting).
fn shell_split(input: &str) -> Vec<&str> {
    let input = input.trim();
    let mut parts = Vec::new();
    let mut start = None;
    let mut in_quote = None;
    let bytes = input.as_bytes();

    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i] as char;

        match (in_quote, c) {
            (None, '"') | (None, '\'') => {
                in_quote = Some(c);
                if start.is_none() {
                    start = Some(i + 1);
                }
            }
            (Some(q), c) if c == q => {
                if let Some(s) = start {
                    parts.push(&input[s..i]);
                    start = None;
                }
                in_quote = None;
            }
            (None, ' ') | (None, '\t') => {
                if let Some(s) = start {
                    parts.push(&input[s..i]);
                    start = None;
                }
            }
            _ => {
                if start.is_none() {
                    start = Some(i);
                }
            }
        }
        i += 1;
    }

    if let Some(s) = start {
        parts.push(&input[s..]);
    }

    parts
}

/// Parse version specifiers like `package>=1.0`, `package==2.3.1`, `package~=1.0`.
fn parse_version_spec(spec: &str) -> Option<(&str, &str)> {
    for op in &["===", "~=", "==", ">=", "<=", "!=", ">", "<"] {
        if let Some(pos) = spec.find(op) {
            let name = &spec[..pos];
            let version = &spec[pos..];
            if !name.is_empty() {
                return Some((name, version));
            }
        }
    }
    // Check for bracket extras: package[extra]>=1.0
    if let Some(bracket_pos) = spec.find('[') {
        let name = &spec[..bracket_pos];
        let rest = &spec[bracket_pos..];
        if !name.is_empty() && rest.contains(']') {
            return None; // Treat the whole thing including extras as the name for now
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pip_install_single() {
        let cmd = parse_command("pip install requests").unwrap();
        assert_eq!(cmd.ecosystem, PackageEcosystem::Python);
        assert!(cmd.is_install);
        assert_eq!(cmd.packages.len(), 1);
        assert_eq!(cmd.packages[0].name, "requests");
        assert_eq!(cmd.packages[0].version, None);
    }

    #[test]
    fn test_pip_install_multiple() {
        let cmd = parse_command("pip install flask django sqlalchemy").unwrap();
        assert_eq!(cmd.packages.len(), 3);
        assert_eq!(cmd.packages[0].name, "flask");
        assert_eq!(cmd.packages[1].name, "django");
        assert_eq!(cmd.packages[2].name, "sqlalchemy");
    }

    #[test]
    fn test_pip_install_with_version() {
        let cmd = parse_command("pip install requests>=2.28.0").unwrap();
        assert_eq!(cmd.packages[0].name, "requests");
        assert_eq!(cmd.packages[0].version, Some(">=2.28.0".to_string()));
    }

    #[test]
    fn test_pip_install_pre() {
        let cmd = parse_command("pip install --pre torch").unwrap();
        assert!(cmd.pre_release);
        assert_eq!(cmd.packages[0].name, "torch");
    }

    #[test]
    fn test_pip_install_git() {
        let cmd = parse_command("pip install git+https://github.com/user/repo.git").unwrap();
        assert!(matches!(cmd.source, InstallSource::Git(_)));
    }

    #[test]
    fn test_python_m_pip() {
        let cmd = parse_command("python -m pip install numpy").unwrap();
        assert_eq!(cmd.ecosystem, PackageEcosystem::Python);
        assert_eq!(cmd.packages[0].name, "numpy");
    }

    #[test]
    fn test_pip3_install() {
        let cmd = parse_command("pip3 install pandas").unwrap();
        assert_eq!(cmd.ecosystem, PackageEcosystem::Python);
        assert_eq!(cmd.packages[0].name, "pandas");
    }

    #[test]
    fn test_npm_install() {
        let cmd = parse_command("npm install express").unwrap();
        assert_eq!(cmd.ecosystem, PackageEcosystem::Node);
        assert_eq!(cmd.packages[0].name, "express");
    }

    #[test]
    fn test_npm_install_short() {
        let cmd = parse_command("npm i lodash").unwrap();
        assert_eq!(cmd.ecosystem, PackageEcosystem::Node);
        assert_eq!(cmd.packages[0].name, "lodash");
    }

    #[test]
    fn test_npm_install_dev() {
        let cmd = parse_command("npm install --save-dev jest").unwrap();
        assert!(cmd.is_dev);
        assert_eq!(cmd.packages[0].name, "jest");
    }

    #[test]
    fn test_npm_install_version() {
        let cmd = parse_command("npm install react@18.2.0").unwrap();
        assert_eq!(cmd.packages[0].name, "react");
        assert_eq!(cmd.packages[0].version, Some("18.2.0".to_string()));
    }

    #[test]
    fn test_npm_scoped_package() {
        let cmd = parse_command("npm install @types/node").unwrap();
        assert_eq!(cmd.packages[0].name, "@types/node");
    }

    #[test]
    fn test_cargo_add() {
        let cmd = parse_command("cargo add serde").unwrap();
        assert_eq!(cmd.ecosystem, PackageEcosystem::Rust);
        assert_eq!(cmd.packages[0].name, "serde");
    }

    #[test]
    fn test_cargo_add_dev() {
        let cmd = parse_command("cargo add --dev criterion").unwrap();
        assert!(cmd.is_dev);
        assert_eq!(cmd.packages[0].name, "criterion");
    }

    #[test]
    fn test_apt_install() {
        let cmd = parse_command("apt install -y curl wget").unwrap();
        assert_eq!(cmd.ecosystem, PackageEcosystem::System);
        assert_eq!(cmd.packages.len(), 2);
        assert_eq!(cmd.packages[0].name, "curl");
        assert_eq!(cmd.packages[1].name, "wget");
    }

    #[test]
    fn test_non_install_command() {
        assert!(parse_command("pip list").is_none());
        assert!(parse_command("npm run build").is_none());
        assert!(parse_command("cargo build").is_none());
        assert!(parse_command("ls -la").is_none());
        assert!(parse_command("echo hello").is_none());
    }

    #[test]
    fn test_npm_bare_install() {
        // `npm install` with no packages installs from package.json
        assert!(parse_command("npm install").is_none());
    }

    #[test]
    fn test_empty_command() {
        assert!(parse_command("").is_none());
    }

    #[test]
    fn test_yarn_add() {
        let cmd = parse_command("yarn add react-dom").unwrap();
        assert_eq!(cmd.ecosystem, PackageEcosystem::Node);
        assert_eq!(cmd.packages[0].name, "react-dom");
    }

    #[test]
    fn test_pip_force_reinstall() {
        let cmd = parse_command("pip install --force-reinstall numpy").unwrap();
        assert!(cmd.force);
    }
}
