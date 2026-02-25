#include "daemon/typosquat.h"

#include <algorithm>
#include <cmath>

namespace aegis {

const std::vector<std::string> TyposquatDetector::COMBO_PREFIXES = {
    "python-", "py-", "pip-", "node-", "js-", "npm-", "go-"
};

const std::vector<std::string> TyposquatDetector::COMBO_SUFFIXES = {
    "-python", "-py", "-pip", "-js", "-node", "-dev", "-utils", "-lib",
    "-tool", "-tools", "-helper", "-helpers", "-core", "-base", "-pro",
    "-plus", "-extra", "-ng", "-v2", "-next", "-official", "-sdk",
    "-api", "-cli", "-client"
};

TyposquatDetector::TyposquatDetector(int threshold) : threshold_(threshold) {}

std::string TyposquatDetector::normalize(const std::string& name) {
    std::string result;
    result.reserve(name.size());
    for (char c : name) {
        char lower = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        if (lower == '-' || lower == '.') {
            result += '_';
        } else {
            result += lower;
        }
    }
    return result;
}

int TyposquatDetector::levenshtein(const std::string& a, const std::string& b) {
    const size_t m = a.size(), n = b.size();
    std::vector<int> prev(n + 1), curr(n + 1);

    for (size_t j = 0; j <= n; ++j) prev[j] = static_cast<int>(j);

    for (size_t i = 1; i <= m; ++i) {
        curr[0] = static_cast<int>(i);
        for (size_t j = 1; j <= n; ++j) {
            int cost = (a[i - 1] == b[j - 1]) ? 0 : 1;
            curr[j] = std::min({prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + cost});
        }
        std::swap(prev, curr);
    }
    return prev[n];
}

double TyposquatDetector::jaro_winkler(const std::string& s1, const std::string& s2) {
    if (s1 == s2) return 1.0;
    if (s1.empty() || s2.empty()) return 0.0;

    int len1 = static_cast<int>(s1.size());
    int len2 = static_cast<int>(s2.size());
    int match_distance = std::max(len1, len2) / 2 - 1;
    if (match_distance < 0) match_distance = 0;

    std::vector<bool> s1_matched(len1, false);
    std::vector<bool> s2_matched(len2, false);

    int matches = 0;
    int transpositions = 0;

    for (int i = 0; i < len1; ++i) {
        int start = std::max(0, i - match_distance);
        int end = std::min(i + match_distance + 1, len2);
        for (int j = start; j < end; ++j) {
            if (s2_matched[j] || s1[i] != s2[j]) continue;
            s1_matched[i] = true;
            s2_matched[j] = true;
            matches++;
            break;
        }
    }

    if (matches == 0) return 0.0;

    int k = 0;
    for (int i = 0; i < len1; ++i) {
        if (!s1_matched[i]) continue;
        while (!s2_matched[k]) k++;
        if (s1[i] != s2[k]) transpositions++;
        k++;
    }

    double jaro = (static_cast<double>(matches) / len1 +
                   static_cast<double>(matches) / len2 +
                   (matches - transpositions / 2.0) / matches) / 3.0;

    // Winkler modification
    int prefix = 0;
    for (int i = 0; i < std::min({len1, len2, 4}); ++i) {
        if (s1[i] == s2[i]) prefix++;
        else break;
    }

    return jaro + prefix * 0.1 * (1.0 - jaro);
}

double TyposquatDetector::combined_score(const std::string& a, const std::string& b) {
    int max_len = std::max(a.size(), b.size());
    if (max_len == 0) return 1.0;

    double lev_score = 1.0 - static_cast<double>(levenshtein(a, b)) / max_len;
    double jw_score = jaro_winkler(a, b);

    return 0.4 * lev_score + 0.6 * jw_score;
}

bool TyposquatDetector::is_combosquat(const std::string& name, const std::string& popular) {
    for (const auto& prefix : COMBO_PREFIXES) {
        if (name.size() > prefix.size() && name.substr(0, prefix.size()) == prefix) {
            if (name.substr(prefix.size()) == popular) return true;
        }
    }
    for (const auto& suffix : COMBO_SUFFIXES) {
        if (name.size() > suffix.size() &&
            name.substr(name.size() - suffix.size()) == suffix) {
            if (name.substr(0, name.size() - suffix.size()) == popular) return true;
        }
    }
    return false;
}

std::vector<TyposquatMatch> TyposquatDetector::check(
    const std::string& name, const std::string& ecosystem) const {
    std::string norm = normalize(name);
    std::vector<TyposquatMatch> results;

    const auto& packages = (ecosystem == "node") ? node_packages()
                         : (ecosystem == "rust") ? rust_packages()
                         : python_packages();

    for (const auto& popular : packages) {
        std::string norm_pop = normalize(popular);

        // Exact match = safe
        if (norm == norm_pop) return {};

        // Combosquatting check
        if (is_combosquat(norm, norm_pop)) {
            results.push_back({popular, 0.95, 0, true});
            continue;
        }

        // Distance check
        int dist = levenshtein(norm, norm_pop);
        if (dist > 0 && dist <= threshold_) {
            double score = combined_score(norm, norm_pop);
            if (score > 0.85) {
                results.push_back({popular, score, dist, false});
            }
        }
    }

    // Sort by score descending
    std::sort(results.begin(), results.end(),
              [](const auto& a, const auto& b) { return a.score > b.score; });

    return results;
}

const std::vector<std::string>& TyposquatDetector::python_packages() {
    static const std::vector<std::string> pkgs = {
        "requests", "numpy", "pandas", "flask", "django", "boto3", "urllib3",
        "setuptools", "wheel", "pip", "six", "python-dateutil", "pyyaml",
        "certifi", "idna", "charset-normalizer", "typing-extensions", "packaging",
        "cryptography", "pillow", "scipy", "matplotlib", "sqlalchemy", "click",
        "jinja2", "markupsafe", "werkzeug", "colorama", "attrs", "pluggy",
        "pytest", "coverage", "toml", "tomli", "importlib-metadata", "zipp",
        "platformdirs", "filelock", "virtualenv", "tqdm", "rich", "httpx",
        "pydantic", "fastapi", "uvicorn", "gunicorn", "celery", "redis",
        "psycopg2", "aiohttp", "beautifulsoup4", "lxml", "scrapy", "selenium",
        "paramiko", "fabric", "ansible", "black", "ruff", "mypy", "isort",
        "flake8", "pylint", "bandit", "pre-commit", "sphinx", "mkdocs",
        "docker", "kubernetes", "tensorflow", "torch", "scikit-learn",
        "transformers", "openai", "langchain", "streamlit", "gradio",
        "jupyter", "notebook", "ipython", "sympy", "networkx", "seaborn",
        "plotly", "dash", "bokeh", "arrow", "pendulum", "orjson", "ujson",
        "msgpack", "protobuf", "grpcio", "google-cloud-storage",
        "azure-storage-blob", "moto", "sentry-sdk", "loguru", "structlog",
        "python-dotenv", "decouple", "alembic", "marshmallow",
        "pydantic-settings", "typer"
    };
    return pkgs;
}

const std::vector<std::string>& TyposquatDetector::node_packages() {
    static const std::vector<std::string> pkgs = {
        "express", "react", "react-dom", "next", "vue", "angular", "svelte",
        "typescript", "lodash", "axios", "moment", "dayjs", "date-fns",
        "webpack", "vite", "esbuild", "rollup", "parcel", "babel", "eslint",
        "prettier", "jest", "mocha", "chai", "vitest", "tailwindcss",
        "postcss", "autoprefixer", "sass", "less", "mongoose", "sequelize",
        "prisma", "typeorm", "knex", "socket.io", "ws", "graphql",
        "apollo-server", "commander", "yargs", "chalk", "inquirer", "ora",
        "dotenv", "cors", "helmet", "morgan", "compression", "jsonwebtoken",
        "bcrypt", "passport", "uuid", "nanoid", "zod", "joi", "yup", "ajv",
        "rxjs", "redux", "zustand", "mobx", "puppeteer", "playwright",
        "cheerio", "jsdom", "node-fetch", "got", "superagent", "undici",
        "sharp", "jimp", "canvas", "nodemailer", "bull", "ioredis",
        "winston", "pino", "bunyan", "glob", "minimatch", "chokidar",
        "fs-extra", "semver", "debug", "rimraf", "cross-env"
    };
    return pkgs;
}

const std::vector<std::string>& TyposquatDetector::rust_packages() {
    static const std::vector<std::string> pkgs = {
        "serde", "serde_json", "tokio", "clap", "reqwest", "rand", "log",
        "regex", "chrono", "anyhow", "thiserror", "tracing", "hyper", "axum",
        "actix-web", "rocket", "diesel", "sqlx", "sea-orm", "rayon",
        "crossbeam", "parking_lot", "syn", "quote", "proc-macro2", "bytes",
        "futures", "async-trait", "uuid", "url", "base64", "sha2", "ring",
        "toml", "config", "dotenv", "tower", "tonic", "prost", "criterion",
        "proptest", "pyo3", "napi", "wasm-bindgen", "itertools", "once_cell",
        "lazy_static", "strsim", "similar", "difflib", "tempfile", "walkdir",
        "glob"
    };
    return pkgs;
}

}  // namespace aegis
