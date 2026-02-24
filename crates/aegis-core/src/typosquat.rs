use serde::{Deserialize, Serialize};
use strsim::{jaro_winkler, normalized_levenshtein};

/// Result of a typosquatting check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TyposquatResult {
    /// The package name that was checked.
    pub query: String,
    /// Whether it looks like a typosquat.
    pub is_suspect: bool,
    /// The legitimate package it most closely resembles.
    pub closest_match: Option<String>,
    /// The distance to the closest match (0.0 = identical, 1.0 = completely different).
    pub distance: f64,
    /// Specific reason for flagging.
    pub reason: Option<String>,
}

/// Known combosquatting suffixes/prefixes.
const COMBO_PREFIXES: &[&str] = &[
    "python-", "py-", "pip-", "node-", "js-", "npm-", "go-",
];

const COMBO_SUFFIXES: &[&str] = &[
    "-python", "-py", "-pip", "-js", "-node", "-dev", "-utils",
    "-lib", "-tool", "-tools", "-helper", "-helpers", "-core",
    "-base", "-pro", "-plus", "-extra", "-ng", "-v2", "-next",
    "-official", "-sdk", "-api", "-cli", "-client",
];

/// Detector that checks package names against known popular packages.
pub struct TyposquatDetector {
    /// Popular package names by ecosystem.
    popular_python: Vec<String>,
    popular_node: Vec<String>,
    popular_rust: Vec<String>,
    /// Levenshtein distance threshold.
    threshold: usize,
}

impl TyposquatDetector {
    pub fn new(threshold: usize) -> Self {
        Self {
            popular_python: default_python_packages(),
            popular_node: default_node_packages(),
            popular_rust: default_rust_packages(),
            threshold,
        }
    }

    /// Add a custom list of popular packages for an ecosystem.
    pub fn set_popular_packages(&mut self, ecosystem: &str, packages: Vec<String>) {
        match ecosystem {
            "python" => self.popular_python = packages,
            "node" => self.popular_node = packages,
            "rust" => self.popular_rust = packages,
            _ => {}
        }
    }

    /// Check a package name for potential typosquatting.
    pub fn check(&self, name: &str, ecosystem: &str) -> TyposquatResult {
        let normalized = normalize_package_name(name);
        let popular = match ecosystem {
            "python" => &self.popular_python,
            "node" => &self.popular_node,
            "rust" => &self.popular_rust,
            _ => return TyposquatResult {
                query: name.to_string(),
                is_suspect: false,
                closest_match: None,
                distance: 1.0,
                reason: None,
            },
        };

        // Check exact match — it's a known package
        if popular.iter().any(|p| normalize_package_name(p) == normalized) {
            return TyposquatResult {
                query: name.to_string(),
                is_suspect: false,
                closest_match: Some(name.to_string()),
                distance: 0.0,
                reason: None,
            };
        }

        // Check combosquatting (prefix/suffix additions to known packages)
        if let Some(result) = self.check_combosquat(name, &normalized, popular) {
            return result;
        }

        // Check Levenshtein distance
        let mut best_match: Option<(String, f64)> = None;

        for pkg in popular {
            let pkg_normalized = normalize_package_name(pkg);

            // Skip if lengths are too different (optimization)
            let len_diff = (normalized.len() as isize - pkg_normalized.len() as isize).unsigned_abs();
            if len_diff > self.threshold {
                continue;
            }

            let lev_similarity = normalized_levenshtein(&normalized, &pkg_normalized);
            let jw_similarity = jaro_winkler(&normalized, &pkg_normalized);

            // Combined score — weight Jaro-Winkler higher for prefix similarity
            let score = lev_similarity * 0.4 + jw_similarity * 0.6;

            if let Some((_, best_score)) = &best_match {
                if score > *best_score {
                    best_match = Some((pkg.clone(), score));
                }
            } else {
                best_match = Some((pkg.clone(), score));
            }
        }

        if let Some((closest, score)) = best_match {
            let lev_dist = levenshtein_distance(&normalized, &normalize_package_name(&closest));
            let is_suspect = lev_dist > 0 && lev_dist <= self.threshold && score > 0.85;

            TyposquatResult {
                query: name.to_string(),
                is_suspect,
                closest_match: Some(closest),
                distance: 1.0 - score,
                reason: if is_suspect {
                    Some(format!(
                        "Levenshtein distance {} from popular package (threshold: {})",
                        lev_dist, self.threshold
                    ))
                } else {
                    None
                },
            }
        } else {
            TyposquatResult {
                query: name.to_string(),
                is_suspect: false,
                closest_match: None,
                distance: 1.0,
                reason: None,
            }
        }
    }

    fn check_combosquat(
        &self,
        name: &str,
        normalized: &str,
        popular: &[String],
    ) -> Option<TyposquatResult> {
        for prefix in COMBO_PREFIXES {
            if let Some(stripped) = normalized.strip_prefix(&normalize_package_name(prefix)) {
                if popular.iter().any(|p| normalize_package_name(p) == stripped) {
                    return Some(TyposquatResult {
                        query: name.to_string(),
                        is_suspect: true,
                        closest_match: Some(stripped.to_string()),
                        distance: 0.1,
                        reason: Some(format!("Combosquatting: prefix '{prefix}' added to known package")),
                    });
                }
            }
        }

        for suffix in COMBO_SUFFIXES {
            if let Some(stripped) = normalized.strip_suffix(&normalize_package_name(suffix)) {
                if popular.iter().any(|p| normalize_package_name(p) == stripped) {
                    return Some(TyposquatResult {
                        query: name.to_string(),
                        is_suspect: true,
                        closest_match: Some(stripped.to_string()),
                        distance: 0.1,
                        reason: Some(format!("Combosquatting: suffix '{suffix}' added to known package")),
                    });
                }
            }
        }

        None
    }
}

/// Normalize a package name: lowercase, replace hyphens with underscores.
pub fn normalize_package_name(name: &str) -> String {
    name.to_lowercase()
        .replace('-', "_")
        .replace('.', "_")
}

/// Simple Levenshtein distance (character-level).
fn levenshtein_distance(a: &str, b: &str) -> usize {
    let a_chars: Vec<char> = a.chars().collect();
    let b_chars: Vec<char> = b.chars().collect();
    let m = a_chars.len();
    let n = b_chars.len();

    let mut dp = vec![vec![0usize; n + 1]; m + 1];

    for i in 0..=m {
        dp[i][0] = i;
    }
    for j in 0..=n {
        dp[0][j] = j;
    }

    for i in 1..=m {
        for j in 1..=n {
            let cost = if a_chars[i - 1] == b_chars[j - 1] { 0 } else { 1 };
            dp[i][j] = (dp[i - 1][j] + 1)
                .min(dp[i][j - 1] + 1)
                .min(dp[i - 1][j - 1] + cost);
        }
    }

    dp[m][n]
}

/// Top Python packages (abbreviated — would be loaded from file in production).
fn default_python_packages() -> Vec<String> {
    [
        "requests", "numpy", "pandas", "flask", "django", "boto3", "urllib3",
        "setuptools", "wheel", "pip", "six", "python-dateutil", "pyyaml", "certifi",
        "idna", "charset-normalizer", "typing-extensions", "packaging", "cryptography",
        "pillow", "scipy", "matplotlib", "sqlalchemy", "click", "jinja2", "markupsafe",
        "werkzeug", "colorama", "attrs", "pluggy", "pytest", "coverage", "toml",
        "tomli", "importlib-metadata", "zipp", "platformdirs", "filelock", "virtualenv",
        "tqdm", "rich", "httpx", "pydantic", "fastapi", "uvicorn", "gunicorn",
        "celery", "redis", "psycopg2", "aiohttp", "beautifulsoup4", "lxml", "scrapy",
        "selenium", "paramiko", "fabric", "ansible", "black", "ruff", "mypy",
        "isort", "flake8", "pylint", "bandit", "pre-commit", "sphinx", "mkdocs",
        "docker", "kubernetes", "tensorflow", "torch", "scikit-learn", "transformers",
        "openai", "langchain", "streamlit", "gradio", "jupyter", "notebook", "ipython",
        "sympy", "networkx", "seaborn", "plotly", "dash", "bokeh", "arrow",
        "pendulum", "orjson", "ujson", "msgpack", "protobuf", "grpcio",
        "boto3", "google-cloud-storage", "azure-storage-blob", "moto",
        "sentry-sdk", "loguru", "structlog", "python-dotenv", "decouple",
        "alembic", "marshmallow", "pydantic-settings", "typer",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

/// Top Node packages.
fn default_node_packages() -> Vec<String> {
    [
        "express", "react", "react-dom", "next", "vue", "angular", "svelte",
        "typescript", "lodash", "axios", "moment", "dayjs", "date-fns",
        "webpack", "vite", "esbuild", "rollup", "parcel", "babel",
        "eslint", "prettier", "jest", "mocha", "chai", "vitest",
        "tailwindcss", "postcss", "autoprefixer", "sass", "less",
        "mongoose", "sequelize", "prisma", "typeorm", "knex",
        "socket.io", "ws", "graphql", "apollo-server",
        "commander", "yargs", "chalk", "inquirer", "ora",
        "dotenv", "cors", "helmet", "morgan", "compression",
        "jsonwebtoken", "bcrypt", "passport", "uuid", "nanoid",
        "zod", "joi", "yup", "ajv",
        "rxjs", "redux", "zustand", "mobx",
        "puppeteer", "playwright", "cheerio", "jsdom",
        "node-fetch", "got", "superagent", "undici",
        "sharp", "jimp", "canvas",
        "nodemailer", "bull", "ioredis",
        "winston", "pino", "bunyan",
        "glob", "minimatch", "chokidar", "fs-extra",
        "semver", "debug", "rimraf", "cross-env",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

/// Top Rust crates.
fn default_rust_packages() -> Vec<String> {
    [
        "serde", "serde_json", "tokio", "clap", "reqwest", "rand", "log",
        "regex", "chrono", "anyhow", "thiserror", "tracing", "hyper", "axum",
        "actix-web", "rocket", "diesel", "sqlx", "sea-orm",
        "rayon", "crossbeam", "parking_lot",
        "syn", "quote", "proc-macro2",
        "bytes", "futures", "async-trait",
        "uuid", "url", "base64", "sha2", "ring",
        "toml", "config", "dotenv",
        "tower", "tonic", "prost",
        "criterion", "proptest",
        "pyo3", "napi", "wasm-bindgen",
        "itertools", "once_cell", "lazy_static",
        "strsim", "similar", "difflib",
        "tempfile", "walkdir", "glob",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn detector() -> TyposquatDetector {
        TyposquatDetector::new(2)
    }

    #[test]
    fn test_exact_match_is_safe() {
        let d = detector();
        let result = d.check("requests", "python");
        assert!(!result.is_suspect);
        assert_eq!(result.distance, 0.0);
    }

    #[test]
    fn test_typo_detected() {
        let d = detector();
        let result = d.check("reqeusts", "python");
        assert!(result.is_suspect);
        assert_eq!(result.closest_match, Some("requests".to_string()));
    }

    #[test]
    fn test_colorama_typo() {
        let d = detector();
        let result = d.check("colourama", "python");
        assert!(result.is_suspect);
        assert_eq!(result.closest_match, Some("colorama".to_string()));
    }

    #[test]
    fn test_combosquat_prefix() {
        let d = detector();
        let result = d.check("python-requests", "python");
        assert!(result.is_suspect);
        assert!(result.reason.unwrap().contains("Combosquatting"));
    }

    #[test]
    fn test_combosquat_suffix() {
        let d = detector();
        let result = d.check("flask-dev", "python");
        assert!(result.is_suspect);
        assert!(result.reason.unwrap().contains("Combosquatting"));
    }

    #[test]
    fn test_completely_different_name_is_safe() {
        let d = detector();
        let result = d.check("my-unique-internal-tool-xyz", "python");
        assert!(!result.is_suspect);
    }

    #[test]
    fn test_normalize_package_name() {
        assert_eq!(normalize_package_name("My-Package"), "my_package");
        assert_eq!(normalize_package_name("some.pkg"), "some_pkg");
        assert_eq!(normalize_package_name("UPPER_CASE"), "upper_case");
    }

    #[test]
    fn test_node_typosquat() {
        let d = detector();
        let result = d.check("expresss", "node");
        assert!(result.is_suspect);
        assert_eq!(result.closest_match, Some("express".to_string()));
    }

    #[test]
    fn test_node_combosquat() {
        let d = detector();
        let result = d.check("react-dev", "node");
        assert!(result.is_suspect);
    }

    #[test]
    fn test_levenshtein_distance() {
        assert_eq!(levenshtein_distance("kitten", "sitting"), 3);
        assert_eq!(levenshtein_distance("same", "same"), 0);
        assert_eq!(levenshtein_distance("requests", "reqeusts"), 2);
    }

    #[test]
    fn test_hyphen_underscore_normalized() {
        let d = detector();
        // python-dateutil should match as exact
        let result = d.check("python_dateutil", "python");
        assert!(!result.is_suspect);
    }
}
