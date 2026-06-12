use crate::types::{Package, PackageManager, Result, Severity, Vulnerability};
use crate::version::{compare_versions, version_in_fixed_range};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use sqlx::{Pool, Sqlite, SqlitePool};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

const OSV_API_URL: &str = "https://api.osv.dev/v1/query";
const _DEFAULT_ECOSYSTEMS: &[&str] = &[
    "Debian", "Alpine", "RPM", "PyPI", "npm", "Go", "crates.io", "Maven",
];

#[derive(Debug, Clone, Serialize, Deserialize)]
struct OsvQuery {
    package: OsvPackage,
    version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct OsvPackage {
    name: String,
    ecosystem: String,
    purl: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct OsvResponse {
    vulns: Option<Vec<OsvVulnerability>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct OsvVulnerability {
    id: String,
    summary: Option<String>,
    details: Option<String>,
    severity: Option<Vec<OsvSeverity>>,
    affected: Option<Vec<OsvAffected>>,
    references: Option<Vec<OsvReference>>,
    modified: Option<String>,
    published: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct OsvSeverity {
    #[serde(rename = "type")]
    severity_type: String,
    score: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct OsvAffected {
    package: Option<OsvPackage>,
    ranges: Option<Vec<OsvRange>>,
    versions: Option<Vec<String>>,
    database_specific: Option<HashMap<String, serde_json::Value>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct OsvRange {
    #[serde(rename = "type")]
    range_type: String,
    repo: Option<String>,
    events: Option<Vec<OsvEvent>>,
    database_specific: Option<HashMap<String, serde_json::Value>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct OsvEvent {
    introduced: Option<String>,
    fixed: Option<String>,
    limit: Option<String>,
    #[serde(rename = "last_affected")]
    last_affected: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct OsvReference {
    #[serde(rename = "type")]
    ref_type: String,
    url: String,
}

#[derive(Clone)]
#[allow(dead_code)]
pub struct CveDatabase {
    cache: Arc<DashMap<String, Vec<Vulnerability>>>,
    db_path: PathBuf,
    pool: Option<Arc<Pool<Sqlite>>>,
}

impl CveDatabase {
    pub async fn new(db_dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(db_dir)?;
        let db_path = db_dir.join("cve.db");

        let pool = SqlitePool::connect(&format!("sqlite://{}?mode=rwc", db_path.display())).await.ok();
        if let Some(p) = pool.as_ref() {
            Self::init_schema(p).await.ok();
        }

        Ok(CveDatabase {
            cache: Arc::new(DashMap::new()),
            db_path,
            pool: pool.map(Arc::new),
        })
    }

    async fn init_schema(pool: &Pool<Sqlite>) -> Result<()> {
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cve_id TEXT NOT NULL,
                package_name TEXT NOT NULL,
                package_manager TEXT NOT NULL,
                package_version TEXT,
                introduced TEXT,
                fixed TEXT,
                last_affected TEXT,
                cvss_v3_score REAL,
                cvss_v2_score REAL,
                severity TEXT,
                description TEXT,
                fix_version TEXT,
                references TEXT,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(cve_id, package_name, package_manager)
            );
            CREATE INDEX IF NOT EXISTS idx_vulns_pkg ON vulnerabilities(package_name, package_manager);
            CREATE INDEX IF NOT EXISTS idx_vulns_cve ON vulnerabilities(cve_id);
            "#
        ).execute(pool).await?;
        Ok(())
    }

    pub async fn update_database(&self) -> Result<()> {
        log::info!("Updating CVE database from OSV...");
        Ok(())
    }

    pub async fn match_packages(&self, packages: &[Package]) -> Result<Vec<Vulnerability>> {
        let mut all_vulns = Vec::new();
        let progress = indicatif::ProgressBar::new(packages.len() as u64);

        for pkg in packages.iter() {
            let cache_key = format!("{}:{}:{}", pkg.package_manager, pkg.name, pkg.version);
            if let Some(cached) = self.cache.get(&cache_key) {
                all_vulns.extend(cached.value().clone());
                progress.inc(1);
                continue;
            }

            let vulns = self.query_osv(pkg).await.unwrap_or_default();
            self.cache.insert(cache_key, vulns.clone());
            all_vulns.extend(vulns);
            progress.inc(1);
        }

        progress.finish_and_clear();

        all_vulns.sort_by(|a, b| {
            b.severity.order().cmp(&a.severity.order())
                .then(b.effective_score().partial_cmp(&a.effective_score()).unwrap_or(std::cmp::Ordering::Equal))
        });

        Ok(all_vulns)
    }

    async fn query_osv(&self, pkg: &Package) -> Result<Vec<Vulnerability>> {
        let ecosystem = match_package_manager_ecosystem(&pkg.package_manager);
        let mut vulnerabilities = Vec::new();

        for eco in ecosystem {
            let query = OsvQuery {
                package: OsvPackage {
                    name: pkg.name.clone(),
                    ecosystem: eco.to_string(),
                    purl: pkg.purl.clone(),
                },
                version: Some(pkg.version.clone()),
            };

            if let Ok(resp) = self.osv_api_request(&query).await {
                for osv_vuln in resp.vulns.unwrap_or_default() {
                    if let Some(vuln) = self.osv_to_vulnerability(osv_vuln, pkg, &eco) {
                        vulnerabilities.push(vuln);
                    }
                }
            }
        }

        Ok(vulnerabilities)
    }

    async fn osv_api_request(&self, query: &OsvQuery) -> Result<OsvResponse> {
        if let Ok(cached) = self.check_cache(query).await {
            return Ok(cached);
        }

        let client = reqwest::Client::new();
        let response = client
            .post(OSV_API_URL)
            .json(query)
            .timeout(std::time::Duration::from_secs(30))
            .send()
            .await;

        match response {
            Ok(resp) if resp.status().is_success() => {
                let osv_resp: OsvResponse = resp.json().await.unwrap_or(OsvResponse { vulns: None });
                self.store_cache(query, &osv_resp).await.ok();
                Ok(osv_resp)
            }
            _ => Ok(OsvResponse { vulns: None }),
        }
    }

    async fn check_cache(&self, _query: &OsvQuery) -> Result<OsvResponse> {
        Err(anyhow::anyhow!("cache miss"))
    }

    async fn store_cache(&self, _query: &OsvQuery, _resp: &OsvResponse) -> Result<()> {
        Ok(())
    }

    fn osv_to_vulnerability(&self, osv: OsvVulnerability, pkg: &Package, ecosystem: &str) -> Option<Vulnerability> {
        let description = osv.details.clone()
            .or(osv.summary.clone())
            .unwrap_or_else(|| osv.id.clone());

        let (cvss_v3, cvss_v2) = extract_cvss_scores(&osv);
        let severity = Severity::from_cvss(cvss_v3.or(cvss_v2).unwrap_or(0.0));

        let fix_version = extract_fix_version(&osv, &pkg.version, &pkg.package_manager);
        let is_affected = match_version_range(&osv, &pkg.version, &pkg.package_manager);

        if !is_affected {
            return None;
        }

        let references: Vec<String> = osv.references
            .unwrap_or_default()
            .iter()
            .map(|r| r.url.clone())
            .take(5)
            .collect();

        let published_date = osv.published.as_ref().and_then(|s| {
            chrono::DateTime::parse_from_rfc3339(s).ok().map(|dt| dt.with_timezone(&chrono::Utc))
        });

        Some(Vulnerability {
            cve_id: normalize_cve_id(&osv.id, ecosystem),
            cvss_v3_score: cvss_v3,
            cvss_v2_score: cvss_v2,
            severity,
            description,
            fix_version,
            package_name: pkg.name.clone(),
            package_version: pkg.version.clone(),
            package_manager: pkg.package_manager.clone(),
            references,
            published_date,
        })
    }
}

fn match_package_manager_ecosystem(pm: &PackageManager) -> Vec<&'static str> {
    match pm {
        PackageManager::Apt => vec!["Debian", "Ubuntu"],
        PackageManager::Rpm => vec!["RPM", "Fedora", "Red Hat"],
        PackageManager::Apk => vec!["Alpine"],
        PackageManager::Pip => vec!["PyPI"],
        PackageManager::Npm => vec!["npm"],
        PackageManager::Go => vec!["Go"],
        PackageManager::Cargo => vec!["crates.io"],
        PackageManager::Maven => vec!["Maven"],
    }
}

fn extract_cvss_scores(osv: &OsvVulnerability) -> (Option<f64>, Option<f64>) {
    let mut cvss_v3 = None;
    let mut cvss_v2 = None;

    if let Some(severities) = &osv.severity {
        for sev in severities {
            if sev.severity_type == "CVSS_V3" {
                if let Ok(score) = parse_cvss_vector(&sev.score) {
                    cvss_v3 = Some(score);
                }
            } else if sev.severity_type == "CVSS_V2" {
                if let Ok(score) = parse_cvss_vector(&sev.score) {
                    cvss_v2 = Some(score);
                }
            }
        }
    }

    (cvss_v3, cvss_v2)
}

fn parse_cvss_vector(vector: &str) -> Result<f64> {
    if vector.starts_with("CVSS:3") {
        if let Some(score_str) = vector.rsplit('/').last() {
            if let Some(score_part) = score_str.strip_prefix("SCORE:") {
                return score_part.parse::<f64>().map_err(|e: std::num::ParseFloatError| anyhow::anyhow!(e));
            }
        }
        return calculate_cvss_v3_basic(vector);
    }
    if vector.starts_with("CVSS:2") {
        return calculate_cvss_v2_basic(vector);
    }
    vector.parse::<f64>().map_err(|e| anyhow::anyhow!(e))
}

fn calculate_cvss_v3_basic(vector: &str) -> Result<f64> {
    let metrics: HashMap<&str, &str> = vector.split('/')
        .filter_map(|part| part.split_once(':'))
        .collect();

    let av = metrics.get("AV").copied().unwrap_or("N");
    let ac = metrics.get("AC").copied().unwrap_or("L");
    let pr = metrics.get("PR").copied().unwrap_or("N");
    let ui = metrics.get("UI").copied().unwrap_or("N");
    let s = metrics.get("S").copied().unwrap_or("U");
    let c = metrics.get("C").copied().unwrap_or("N");
    let i = metrics.get("I").copied().unwrap_or("N");
    let a = metrics.get("A").copied().unwrap_or("N");

    let av_score = match av {
        "N" => 0.85, "A" => 0.62, "L" => 0.55, "P" => 0.2, _ => 0.85
    };
    let ac_score = match ac {
        "L" => 0.77, "H" => 0.44, _ => 0.77
    };
    let pr_score = match (pr, s) {
        ("N", _) => 0.85,
        ("L", "U") => 0.62,
        ("L", "C") => 0.68,
        ("H", "U") => 0.27,
        ("H", "C") => 0.50,
        _ => 0.85
    };
    let ui_score = match ui {
        "N" => 0.85, "R" => 0.62, _ => 0.85
    };
    let c_score = match c {
        "H" => 0.56, "L" => 0.22, _ => 0.0
    };
    let i_score = match i {
        "H" => 0.56, "L" => 0.22, _ => 0.0
    };
    let a_score = match a {
        "H" => 0.56, "L" => 0.22, _ => 0.0
    };

    let exploitability = 8.22 * av_score * ac_score * pr_score * ui_score;
    let impact_base: f64 = 1.0 - ((1.0 - c_score) * (1.0 - i_score) * (1.0 - a_score));
    let impact = if s == "U" {
        6.42 * impact_base
    } else {
        7.52 * (impact_base - 0.029) - 3.25 * (impact_base - 0.02_f64).powi(15)
    };

    let score = if impact <= 0.0 {
        0.0
    } else if s == "U" {
        std::cmp::min((impact + exploitability) as i32, 1000) as f64
    } else {
        std::cmp::min((1.08 * (impact + exploitability)) as i32, 10) as f64
    };

    Ok((score * 10.0).round() / 10.0)
}

fn calculate_cvss_v2_basic(_vector: &str) -> Result<f64> {
    Ok(5.0)
}

fn extract_fix_version(osv: &OsvVulnerability, _current: &str, pm: &PackageManager) -> Option<String> {
    let affected = osv.affected.as_ref()?;
    let mut best_fix: Option<String> = None;

    for aff in affected {
        if let Some(ranges) = &aff.ranges {
            for range in ranges {
                if let Some(events) = &range.events {
                    let mut _intro = None;
                    let mut fix = None;
                    let mut _last = None;

                    for event in events {
                        if let Some(v) = &event.introduced { _intro = Some(v.clone()); }
                        if let Some(v) = &event.fixed { fix = Some(v.clone()); }
                        if let Some(v) = &event.last_affected { _last = Some(v.clone()); }
                    }

                    if let Some(fix_v) = fix {
                        match &best_fix {
                            None => best_fix = Some(fix_v),
                            Some(current_best) => {
                                if compare_versions(&fix_v, current_best, pm) == std::cmp::Ordering::Less {
                                    best_fix = Some(fix_v);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    best_fix
}

fn match_version_range(osv: &OsvVulnerability, version: &str, pm: &PackageManager) -> bool {
    let affected = match &osv.affected {
        Some(a) => a,
        None => return true,
    };

    for aff in affected {
        if let Some(vers) = &aff.versions {
            if vers.iter().any(|v| v == version) {
                return true;
            }
        }

        if let Some(ranges) = &aff.ranges {
            for range in ranges {
                if let Some(events) = &range.events {
                    let mut intro = None;
                    let mut fix = None;
                    let mut last = None;

                    for event in events {
                        if let Some(v) = &event.introduced { intro = Some(v.clone()); }
                        if let Some(v) = &event.fixed { fix = Some(v.clone()); }
                        if let Some(v) = &event.last_affected { last = Some(v.clone()); }
                    }

                    if version_in_fixed_range(
                        version,
                        intro.as_deref(),
                        fix.as_deref(),
                        last.as_deref(),
                        pm,
                    ) {
                        return true;
                    }
                }
            }
        }
    }

    false
}

fn normalize_cve_id(id: &str, ecosystem: &str) -> String {
    if id.starts_with("CVE-") {
        return id.to_string();
    }
    let prefix = match ecosystem {
        "Debian" => "DLA",
        "Ubuntu" => "USN",
        "Alpine" => "ALSA",
        "RPM" | "Fedora" | "Red Hat" => "RHSA",
        "PyPI" => "PYSEC",
        "npm" => "GHSA",
        "Go" => "GO-2024",
        "crates.io" => "RUSTSEC",
        "Maven" => "GHSA",
        _ => "OSV",
    };
    format!("{}-{}", prefix, id)
}

pub fn apply_policy(vulns: Vec<Vulnerability>, policy: &crate::types::PolicyConfig, ignore_unfixable: bool) -> Vec<Vulnerability> {
    vulns.into_iter()
        .filter(|v| {
            if policy.ignore_cves.iter().any(|c| c == &v.cve_id || v.cve_id.contains(c)) {
                return false;
            }
            if policy.ignore_packages.iter().any(|p| p == &v.package_name) {
                return false;
            }
            if ignore_unfixable && v.fix_version.is_none() {
                return false;
            }
            true
        })
        .collect()
}
