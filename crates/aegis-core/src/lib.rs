pub mod command_parser;
pub mod hash_check;
pub mod package_analyzer;
pub mod pattern_engine;
pub mod typosquat;

pub use command_parser::{ParsedCommand, PackageEcosystem, InstallSource};
pub use typosquat::{TyposquatResult, TyposquatDetector};
pub use package_analyzer::{AnalysisResult, Finding, Severity};
pub use pattern_engine::{PatternMatch, PatternEngine};
