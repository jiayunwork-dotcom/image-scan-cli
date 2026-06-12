use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum PackageManager {
    Apt,
    Rpm,
    Apk,
    Pip,
    Npm,
    Go,
    Cargo,
    Maven,
}

impl std::fmt::Display for PackageManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PackageManager::Apt => write!(f, "apt"),
            PackageManager::Rpm => write!(f, "rpm"),
            PackageManager::Apk => write!(f, "apk"),
            PackageManager::Pip => write!(f, "pip"),
            PackageManager::Npm => write!(f, "npm"),
            PackageManager::Go => write!(f, "go"),
            PackageManager::Cargo => write!(f, "cargo"),
            PackageManager::Maven => write!(f, "maven"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Package {
    pub name: String,
    pub version: String,
    pub package_manager: PackageManager,
    pub install_path: String,
    pub license: Option<String>,
    pub purl: Option<String>,
    pub dependencies: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Unknown,
}

impl Severity {
    pub fn from_cvss(score: f64) -> Self {
        if score >= 9.0 {
            Severity::Critical
        } else if score >= 7.0 {
            Severity::High
        } else if score >= 4.0 {
            Severity::Medium
        } else if score > 0.0 {
            Severity::Low
        } else {
            Severity::Unknown
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Critical => "Critical",
            Severity::High => "High",
            Severity::Medium => "Medium",
            Severity::Low => "Low",
            Severity::Unknown => "Unknown",
        }
    }

    pub fn order(&self) -> u8 {
        match self {
            Severity::Critical => 4,
            Severity::High => 3,
            Severity::Medium => 2,
            Severity::Low => 1,
            Severity::Unknown => 0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vulnerability {
    pub cve_id: String,
    pub cvss_v3_score: Option<f64>,
    pub cvss_v2_score: Option<f64>,
    pub severity: Severity,
    pub description: String,
    pub fix_version: Option<String>,
    pub package_name: String,
    pub package_version: String,
    pub package_manager: PackageManager,
    pub references: Vec<String>,
}

impl Vulnerability {
    pub fn effective_score(&self) -> f64 {
        self.cvss_v3_score.or(self.cvss_v2_score).unwrap_or(0.0)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageInfo {
    pub reference: String,
    pub name: String,
    pub tag: String,
    pub digest: Option<String>,
    pub architecture: String,
    pub os: String,
    pub layers: Vec<LayerInfo>,
    pub created: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LayerInfo {
    pub digest: String,
    pub size: u64,
    pub media_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub image: ImageInfo,
    pub packages: Vec<Package>,
    pub vulnerabilities: Vec<Vulnerability>,
    pub scan_time: DateTime<Utc>,
    pub scan_id: Uuid,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSummary {
    pub total_packages: usize,
    pub total_vulnerabilities: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub unknown_count: usize,
    pub fixable_count: usize,
    pub unfixable_count: usize,
    pub top_affected_packages: Vec<(String, usize)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineDiff {
    pub added: Vec<Vulnerability>,
    pub removed: Vec<Vulnerability>,
    pub unchanged: Vec<Vulnerability>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyConfig {
    pub ignore_cves: Vec<String>,
    pub ignore_packages: Vec<String>,
    pub severity_threshold: Option<Severity>,
    pub license_blacklist: Vec<String>,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        PolicyConfig {
            ignore_cves: Vec::new(),
            ignore_packages: Vec::new(),
            severity_threshold: None,
            license_blacklist: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Table,
    Json,
    Sarif,
    Html,
    CycloneDX,
    SPDX,
}

impl OutputFormat {
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "json" => OutputFormat::Json,
            "sarif" => OutputFormat::Sarif,
            "html" => OutputFormat::Html,
            "cyclonedx" => OutputFormat::CycloneDX,
            "spdx" => OutputFormat::SPDX,
            _ => OutputFormat::Table,
        }
    }
}

impl std::fmt::Display for OutputFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OutputFormat::Table => write!(f, "table"),
            OutputFormat::Json => write!(f, "json"),
            OutputFormat::Sarif => write!(f, "sarif"),
            OutputFormat::Html => write!(f, "html"),
            OutputFormat::CycloneDX => write!(f, "cyclonedx"),
            OutputFormat::SPDX => write!(f, "spdx"),
        }
    }
}

#[derive(Debug, Clone)]
pub enum ImageSource {
    Registry { image: String, auth: Option<RegistryAuth> },
    Tar { path: std::path::PathBuf },
    Oci { path: std::path::PathBuf },
}

#[derive(Debug, Clone)]
pub struct RegistryAuth {
    pub username: String,
    pub password: String,
}

pub type Result<T> = anyhow::Result<T>;
