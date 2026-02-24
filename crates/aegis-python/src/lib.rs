use pyo3::prelude::*;
use pyo3::types::PyDict;

/// Parse a shell command and extract package install info.
/// Returns None if not a package install command.
#[pyfunction]
fn parse_command(py: Python<'_>, command: &str) -> PyResult<Option<PyObject>> {
    match ::aegis_core::command_parser::parse_command(command) {
        Some(parsed) => {
            let dict = PyDict::new_bound(py);
            dict.set_item(
                "ecosystem",
                match parsed.ecosystem {
                    ::aegis_core::command_parser::PackageEcosystem::Python => "python",
                    ::aegis_core::command_parser::PackageEcosystem::Node => "node",
                    ::aegis_core::command_parser::PackageEcosystem::Rust => "rust",
                    ::aegis_core::command_parser::PackageEcosystem::System => "system",
                },
            )?;

            let packages: Vec<PyObject> = parsed
                .packages
                .iter()
                .map(|p| {
                    let d = PyDict::new_bound(py);
                    d.set_item("name", &p.name).unwrap();
                    d.set_item("version", &p.version).unwrap();
                    d.unbind().into()
                })
                .collect();
            dict.set_item("packages", packages)?;

            dict.set_item("is_install", parsed.is_install)?;
            dict.set_item("is_dev", parsed.is_dev)?;
            dict.set_item("force", parsed.force)?;
            dict.set_item("pre_release", parsed.pre_release)?;
            dict.set_item("raw_command", &parsed.raw_command)?;

            let source = match &parsed.source {
                ::aegis_core::command_parser::InstallSource::Registry => "registry".to_string(),
                ::aegis_core::command_parser::InstallSource::Git(url) => format!("git:{url}"),
                ::aegis_core::command_parser::InstallSource::Url(url) => format!("url:{url}"),
                ::aegis_core::command_parser::InstallSource::Path(path) => format!("path:{path}"),
            };
            dict.set_item("source", source)?;

            Ok(Some(dict.unbind().into()))
        }
        None => Ok(None),
    }
}

/// Check a package name for typosquatting.
#[pyfunction]
#[pyo3(signature = (name, ecosystem, threshold=2))]
fn check_typosquat(py: Python<'_>, name: &str, ecosystem: &str, threshold: usize) -> PyResult<PyObject> {
    let detector = ::aegis_core::typosquat::TyposquatDetector::new(threshold);
    let result = detector.check(name, ecosystem);

    let dict = PyDict::new_bound(py);
    dict.set_item("query", &result.query)?;
    dict.set_item("is_suspect", result.is_suspect)?;
    dict.set_item("closest_match", &result.closest_match)?;
    dict.set_item("distance", result.distance)?;
    dict.set_item("reason", &result.reason)?;
    Ok(dict.unbind().into())
}

/// Analyze a Python setup.py content for suspicious patterns.
#[pyfunction]
fn analyze_python_setup(py: Python<'_>, content: &str, filename: &str) -> PyResult<PyObject> {
    let findings = ::aegis_core::package_analyzer::analyze_python_setup(content, filename);
    findings_to_python(py, &findings)
}

/// Analyze a package.json content for suspicious patterns.
#[pyfunction]
fn analyze_package_json(py: Python<'_>, content: &str, filename: &str) -> PyResult<PyObject> {
    let findings = ::aegis_core::package_analyzer::analyze_package_json(content, filename);
    findings_to_python(py, &findings)
}

/// Analyze a generic source file for suspicious patterns.
#[pyfunction]
fn analyze_source_file(py: Python<'_>, content: &str, filename: &str) -> PyResult<PyObject> {
    let findings = ::aegis_core::package_analyzer::analyze_source_file(content, filename);
    findings_to_python(py, &findings)
}

/// Calculate risk score from findings (0.0 = safe, 1.0 = extremely dangerous).
#[pyfunction]
fn calculate_risk_score(findings_count: Vec<(String, usize)>) -> PyResult<f64> {
    let mut score = 0.0f64;
    for (severity, count) in &findings_count {
        let weight = match severity.as_str() {
            "info" => 0.0,
            "low" => 0.05,
            "medium" => 0.15,
            "high" => 0.35,
            "critical" => 0.6,
            _ => 0.1,
        };
        score += weight * (*count as f64);
    }
    Ok(score.min(1.0))
}

/// Scan content against built-in pattern rules.
#[pyfunction]
#[pyo3(signature = (content, filename, custom_rules_yaml=None))]
fn match_patterns(
    py: Python<'_>,
    content: &str,
    filename: &str,
    custom_rules_yaml: Option<&str>,
) -> PyResult<PyObject> {
    let mut engine = ::aegis_core::pattern_engine::PatternEngine::default();

    if let Some(yaml) = custom_rules_yaml {
        engine
            .load_rules_yaml(yaml)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e))?;
    }

    let matches = engine.scan_content(content, filename);

    let result: Vec<PyObject> = matches
        .iter()
        .map(|m| {
            let dict = PyDict::new_bound(py);
            dict.set_item("rule_name", &m.rule_name).unwrap();
            dict.set_item("description", &m.description).unwrap();
            dict.set_item("severity", &m.severity).unwrap();
            dict.set_item("file", &m.file).unwrap();
            dict.set_item("line", m.line).unwrap();
            dict.set_item("matched_text", &m.matched_text).unwrap();
            dict.unbind().into()
        })
        .collect();
    Ok(result.to_object(py))
}

/// Normalize a package name (lowercase, hyphens/dots → underscores).
#[pyfunction]
fn normalize_package_name(name: &str) -> String {
    ::aegis_core::typosquat::normalize_package_name(name)
}

fn findings_to_python(py: Python<'_>, findings: &[::aegis_core::package_analyzer::Finding]) -> PyResult<PyObject> {
    let result: Vec<PyObject> = findings
        .iter()
        .map(|f| {
            let dict = PyDict::new_bound(py);
            dict.set_item(
                "severity",
                match f.severity {
                    ::aegis_core::package_analyzer::Severity::Info => "info",
                    ::aegis_core::package_analyzer::Severity::Low => "low",
                    ::aegis_core::package_analyzer::Severity::Medium => "medium",
                    ::aegis_core::package_analyzer::Severity::High => "high",
                    ::aegis_core::package_analyzer::Severity::Critical => "critical",
                },
            )
            .unwrap();
            dict.set_item("category", &f.category).unwrap();
            dict.set_item("description", &f.description).unwrap();
            dict.set_item("file", &f.file).unwrap();
            dict.set_item("line", f.line).unwrap();
            dict.set_item("snippet", &f.snippet).unwrap();
            dict.unbind().into()
        })
        .collect();
    Ok(result.to_object(py))
}

/// AEGIS Core — Rust-powered analysis engine.
#[pymodule]
fn aegis_core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(parse_command, m)?)?;
    m.add_function(wrap_pyfunction!(check_typosquat, m)?)?;
    m.add_function(wrap_pyfunction!(analyze_python_setup, m)?)?;
    m.add_function(wrap_pyfunction!(analyze_package_json, m)?)?;
    m.add_function(wrap_pyfunction!(analyze_source_file, m)?)?;
    m.add_function(wrap_pyfunction!(calculate_risk_score, m)?)?;
    m.add_function(wrap_pyfunction!(match_patterns, m)?)?;
    m.add_function(wrap_pyfunction!(normalize_package_name, m)?)?;
    Ok(())
}
