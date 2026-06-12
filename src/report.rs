use crate::sbom::FixSuggestion;
use crate::types::{
    BaselineDiff, ImageInfo, Package, PolicyConfig, ScanResult, ScanSummary, Severity, Vulnerability,
};
use colored::Colorize;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::{HashMap, HashSet};
use std::path::Path;

pub fn compute_summary(result: &ScanResult) -> ScanSummary {
    let mut critical = 0;
    let mut high = 0;
    let mut medium = 0;
    let mut low = 0;
    let mut unknown = 0;
    let mut fixable = 0;
    let mut unfixable = 0;

    for v in &result.vulnerabilities {
        match v.severity {
            Severity::Critical => critical += 1,
            Severity::High => high += 1,
            Severity::Medium => medium += 1,
            Severity::Low => low += 1,
            Severity::Unknown => unknown += 1,
        }
        if v.fix_version.is_some() {
            fixable += 1;
        } else {
            unfixable += 1;
        }
    }

    let mut pkg_counts: HashMap<String, usize> = HashMap::new();
    for v in &result.vulnerabilities {
        *pkg_counts.entry(v.package_name.clone()).or_insert(0) += 1;
    }

    let mut top_packages: Vec<(String, usize)> = pkg_counts.into_iter().collect();
    top_packages.sort_by(|a, b| b.1.cmp(&a.1));
    top_packages.truncate(10);

    ScanSummary {
        total_packages: result.packages.len(),
        total_vulnerabilities: result.vulnerabilities.len(),
        critical_count: critical,
        high_count: high,
        medium_count: medium,
        low_count: low,
        unknown_count: unknown,
        fixable_count: fixable,
        unfixable_count: unfixable,
        top_affected_packages: top_packages,
    }
}

pub fn print_console_report(
    result: &ScanResult,
    summary: &ScanSummary,
    suggestions: &[FixSuggestion],
    diff: Option<&BaselineDiff>,
    quiet: bool,
) {
    if quiet {
        println!(
            "PACKAGES={} VULNS={} CRITICAL={} HIGH={} MEDIUM={} LOW={} FIXABLE={}",
            summary.total_packages,
            summary.total_vulnerabilities,
            summary.critical_count,
            summary.high_count,
            summary.medium_count,
            summary.low_count,
            summary.fixable_count
        );
        return;
    }

    print_header("Image Scan Report");
    print_image_info(&result.image);
    print_summary(summary);

    if let Some(d) = diff {
        print_baseline_diff(d);
    }

    if !result.vulnerabilities.is_empty() {
        print_vulnerability_table(&result.vulnerabilities);
    }

    if !suggestions.is_empty() {
        print_fix_suggestions(suggestions);
    }

    if !summary.top_affected_packages.is_empty() {
        print_top_packages(&summary.top_affected_packages);
    }
}

fn print_header(title: &str) {
    let line = "═".repeat(80);
    let padded = format!("{:^80}", title);
    println!("\n{}", line.cyan().bold());
    println!("{}", padded.cyan().bold());
    println!("{}", line.cyan().bold());
}

fn print_image_info(image: &ImageInfo) {
    println!("\n{}", "📦 Image Information:".bold());
    println!("  {:<18} {}", "Name:".dimmed(), image.name.white());
    println!("  {:<18} {}", "Tag:".dimmed(), image.tag.white());
    println!("  {:<18} {}", "Architecture:".dimmed(), format!("{}/{}", image.os, image.architecture).white());
    if let Some(d) = &image.digest {
        println!("  {:<18} {}", "Digest:".dimmed(), d.dimmed());
    }
    println!("  {:<18} {}", "Layers:".dimmed(), image.layers.len().to_string().white());
}

fn print_summary(summary: &ScanSummary) {
    println!("\n{}", "📊 Scan Summary:".bold());
    println!("  {} packages detected", summary.total_packages.to_string().cyan());

    let total = summary.total_vulnerabilities;
    println!("  {} vulnerabilities found:", total.to_string().yellow().bold());

    let items = vec![
        ("Critical", summary.critical_count, Severity::Critical),
        ("High", summary.high_count, Severity::High),
        ("Medium", summary.medium_count, Severity::Medium),
        ("Low", summary.low_count, Severity::Low),
        ("Unknown", summary.unknown_count, Severity::Unknown),
    ];

    for (label, count, sev) in items {
        if count > 0 {
            let colored = format!("{} {}", count, label);
            println!("    {}", severity_color(&colored, &sev).bold());
        }
    }

    let total = summary.fixable_count + summary.unfixable_count;
    if total > 0 {
        let fixable_pct = (summary.fixable_count as f64 / total as f64) * 100.0;
        println!(
            "\n  {} Fixable ({:.1}%) / {} Unfixable",
            summary.fixable_count.to_string().green(),
            fixable_pct,
            summary.unfixable_count.to_string().red()
        );
    }
}

fn print_vulnerability_table(vulns: &[Vulnerability]) {
    println!("\n{}", "🔍 Vulnerabilities (sorted by severity):".bold());
    println!(
        "\n  {:<10} {:<8} {:<25} {:<18} {:<12} {}",
        "Severity".bold(),
        "Score".bold(),
        "CVE ID".bold(),
        "Package".bold(),
        "Version".bold(),
        "Fix Version".bold()
    );
    println!("  {}", "─".repeat(100));

    for v in vulns.iter().take(200) {
        let score = format!("{:.1}", v.effective_score());
        let fix = v.fix_version.clone().unwrap_or_else(|| "-".to_string());
        let desc = if v.description.len() > 100 {
            format!("{}...", &v.description[..100])
        } else {
            v.description.clone()
        };

        let sev_str = format!("{:<10}", v.severity.as_str());
        println!(
            "  {} {:<8} {:<25} {:<18} {:<12} {}",
            severity_color(&sev_str, &v.severity).bold(),
            score.white(),
            v.cve_id.yellow(),
            v.package_name.white(),
            v.package_version.dimmed(),
            if v.fix_version.is_some() { fix.green() } else { fix.dimmed() }
        );
        println!("      {}", desc.dimmed());
    }

    if vulns.len() > 200 {
        println!(
            "\n  ... and {} more vulnerabilities (use --format json for full list)",
            vulns.len() - 200
        );
    }
}

fn print_fix_suggestions(suggestions: &[FixSuggestion]) {
    println!("\n{}", "💡 Fix Suggestions:".bold());
    println!(
        "\n  {:<10} {:<30} {:<15} → {:<15} CVEs Fixed",
        "Severity".bold(),
        "Package".bold(),
        "Current".bold(),
        "Upgrade To".bold()
    );
    println!("  {}", "─".repeat(100));

    for s in suggestions.iter().take(25) {
        let sev_str = format!("{:<10}", s.max_severity.as_str());
        let pkg_str = if s.package_name.len() > 28 {
            format!("{}...", &s.package_name[..28])
        } else {
            s.package_name.clone()
        };
        println!(
            "  {} {:<30} {:<15} → {:<15} {}",
            severity_color(&sev_str, &s.max_severity).bold(),
            pkg_str.white(),
            s.current_version.dimmed(),
            s.suggested_version.green(),
            format!("{} CVEs", s.fixed_cves.len()).cyan()
        );
    }
}

fn print_top_packages(top: &[(String, usize)]) {
    println!("\n{}", "🔥 Top 10 Most Affected Packages:".bold());
    println!("\n  {:<5} {:<40} {}", "Rank".bold(), "Package".bold(), "Vulns".bold());
    println!("  {}", "─".repeat(60));

    for (idx, (pkg, count)) in top.iter().enumerate() {
        let pkg_str = if pkg.len() > 38 {
            format!("{}...", &pkg[..38])
        } else {
            pkg.clone()
        };
        let count_color = match *count {
            c if c >= 20 => count.to_string().red().bold(),
            c if c >= 10 => count.to_string().yellow().bold(),
            _ => count.to_string().white(),
        };
        println!(
            "  {:<5} {:<40} {}",
            format!("#{}", idx + 1).cyan(),
            pkg_str.white(),
            count_color
        );
    }
}

fn print_baseline_diff(diff: &BaselineDiff) {
    println!("\n{}", "📈 Baseline Comparison:".bold());

    if !diff.added.is_empty() {
        println!(
            "\n  {} {} {}:",
            "+".red().bold(),
            diff.added.len().to_string().red().bold(),
            "New vulnerabilities added".red()
        );
        for v in diff.added.iter().take(10) {
            println!(
                "    {}  {} {} ({})",
                "+".red().bold(),
                v.cve_id.red(),
                v.package_name.white(),
                v.package_version.dimmed()
            );
        }
    }

    if !diff.removed.is_empty() {
        println!(
            "\n  {} {} {}:",
            "-".green().bold(),
            diff.removed.len().to_string().green().bold(),
            "Vulnerabilities fixed".green()
        );
        for v in diff.removed.iter().take(10) {
            println!(
                "    {}  {} {} ({})",
                "-".green().bold(),
                v.cve_id.green(),
                v.package_name.white(),
                v.package_version.dimmed()
            );
        }
    }

    if !diff.unchanged.is_empty() {
        println!(
            "\n  {} {} {}",
            "=".white().bold(),
            diff.unchanged.len().to_string().white(),
            "Still present vulnerabilities (unresolved)".white()
        );
    }
}

fn severity_color(s: &str, sev: &Severity) -> colored::ColoredString {
    match sev {
        Severity::Critical => s.red(),
        Severity::High => s.truecolor(255, 165, 0),
        Severity::Medium => s.yellow(),
        Severity::Low => s.white(),
        Severity::Unknown => s.dimmed(),
    }
}

pub fn format_json(result: &ScanResult, summary: &ScanSummary) -> Result<String, serde_json::Error> {
    let output = json!({
        "scan_id": result.scan_id,
        "scan_time": result.scan_time,
        "image": result.image,
        "summary": summary,
        "packages": result.packages,
        "vulnerabilities": result.vulnerabilities,
    });
    serde_json::to_string_pretty(&output)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SarifReport {
    #[serde(rename = "$schema")]
    schema: String,
    version: String,
    runs: Vec<SarifRun>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SarifRun {
    tool: SarifTool,
    results: Vec<SarifResult>,
    invocations: Vec<SarifInvocation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SarifTool {
    driver: SarifDriver,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SarifDriver {
    name: String,
    version: String,
    informationUri: String,
    rules: Vec<SarifRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SarifRule {
    id: String,
    name: String,
    shortDescription: SarifMessage,
    fullDescription: SarifMessage,
    defaultConfiguration: SarifRuleConfig,
    helpUri: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SarifRuleConfig {
    level: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SarifMessage {
    text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SarifResult {
    ruleId: String,
    ruleIndex: usize,
    level: String,
    message: SarifMessage,
    locations: Vec<SarifLocation>,
    properties: SarifProperties,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SarifLocation {
    physicalLocation: SarifPhysicalLocation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SarifPhysicalLocation {
    artifactLocation: SarifArtifactLocation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SarifArtifactLocation {
    uri: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SarifProperties {
    issueSeverity: String,
    cvssScore: Option<f64>,
    packageName: String,
    packageVersion: String,
    fixVersion: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SarifInvocation {
    executionSuccessful: bool,
}

pub fn format_sarif(
    result: &ScanResult,
) -> Result<String, serde_json::Error> {
    let mut rules = Vec::new();
    let mut rule_map: HashMap<String, usize> = HashMap::new();
    let mut sarif_results = Vec::new();

    for (_idx, v) in result.vulnerabilities.iter().enumerate() {
        let rule_id = v.cve_id.clone();
        if !rule_map.contains_key(&rule_id) {
            rule_map.insert(rule_id.clone(), rules.len());
            rules.push(SarifRule {
                id: rule_id.clone(),
                name: rule_id.clone(),
                shortDescription: SarifMessage {
                    text: format!("{} vulnerability in {}", v.severity.as_str(), v.package_name),
                },
                fullDescription: SarifMessage {
                    text: v.description.clone(),
                },
                defaultConfiguration: SarifRuleConfig {
                    level: sarif_level(&v.severity),
                },
                helpUri: v.references.first().cloned(),
            });
        }

        let level = sarif_level(&v.severity);
        let artifact_path = format!(
            "{}@{} (installed via {})",
            v.package_name, v.package_version, v.package_manager
        );

        sarif_results.push(SarifResult {
            ruleId: rule_id.clone(),
            ruleIndex: *rule_map.get(&rule_id).unwrap_or(&0),
            level,
            message: SarifMessage {
                text: format!(
                    "{}: {} {} is vulnerable ({}). {}{}",
                    v.cve_id,
                    v.package_name,
                    v.package_version,
                    v.severity.as_str(),
                    v.description,
                    if let Some(fix) = &v.fix_version {
                        format!(" Upgrade to {} to fix.", fix)
                    } else {
                        String::new()
                    }
                ),
            },
            locations: vec![SarifLocation {
                physicalLocation: SarifPhysicalLocation {
                    artifactLocation: SarifArtifactLocation {
                        uri: artifact_path,
                    },
                },
            }],
            properties: SarifProperties {
                issueSeverity: v.severity.as_str().to_lowercase(),
                cvssScore: Some(v.effective_score()),
                packageName: v.package_name.clone(),
                packageVersion: v.package_version.clone(),
                fixVersion: v.fix_version.clone(),
            },
        });
    }

    let report = SarifReport {
        schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json".to_string(),
        version: "2.1.0".to_string(),
        runs: vec![SarifRun {
            tool: SarifTool {
                driver: SarifDriver {
                    name: "image-scan".to_string(),
                    version: env!("CARGO_PKG_VERSION").to_string(),
                    informationUri: "https://github.com/image-scan/cli".to_string(),
                    rules,
                },
            },
            results: sarif_results,
            invocations: vec![SarifInvocation {
                executionSuccessful: true,
            }],
        }],
    };

    serde_json::to_string_pretty(&report)
}

fn sarif_level(sev: &Severity) -> String {
    match sev {
        Severity::Critical | Severity::High => "error".to_string(),
        Severity::Medium => "warning".to_string(),
        Severity::Low | Severity::Unknown => "note".to_string(),
    }
}

pub fn format_html(
    result: &ScanResult,
    summary: &ScanSummary,
    suggestions: &[FixSuggestion],
) -> String {
    let vulns_json = serde_json::to_string(&result.vulnerabilities).unwrap_or_default();
    let packages_json = serde_json::to_string(&result.packages).unwrap_or_default();
    let _summary_json = serde_json::to_string(summary).unwrap_or_default();
    let suggestions_json = serde_json::to_string(suggestions).unwrap_or_default();

    let total_vulns = summary.total_vulnerabilities;
    let cr = summary.critical_count;
    let hi = summary.high_count;
    let me = summary.medium_count;
    let lo = summary.low_count;

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Image Scan Report - {name}:{tag}</title>
<style>
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f7fa; color: #333; }}
  .container {{ max-width: 1400px; margin: 0 auto; padding: 20px; }}
  header {{ background: linear-gradient(135deg, #1a365d 0%, #2c5282 100%); color: white; padding: 30px; border-radius: 12px; margin-bottom: 24px; }}
  h1 {{ font-size: 28px; margin-bottom: 8px; }}
  .subtitle {{ opacity: 0.8; font-size: 14px; }}
  .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin-bottom: 24px; }}
  .card {{ background: white; border-radius: 10px; padding: 20px; box-shadow: 0 2px 8px rgba(0,0,0,0.06); }}
  .card h3 {{ font-size: 13px; text-transform: uppercase; color: #718096; margin-bottom: 8px; }}
  .card .value {{ font-size: 32px; font-weight: 700; }}
  .critical {{ color: #e53e3e; }}
  .high {{ color: #dd6b20; }}
  .medium {{ color: #d69e2e; }}
  .low {{ color: #4a5568; }}
  .info {{ color: #2b6cb0; }}
  .success {{ color: #38a169; }}
  .table-card {{ background: white; border-radius: 10px; padding: 20px; box-shadow: 0 2px 8px rgba(0,0,0,0.06); margin-bottom: 24px; }}
  .section-title {{ font-size: 18px; font-weight: 600; margin-bottom: 16px; padding-bottom: 10px; border-bottom: 2px solid #e2e8f0; }}
  input[type="search"] {{ width: 100%; padding: 10px 14px; border: 1px solid #e2e8f0; border-radius: 8px; font-size: 14px; margin-bottom: 16px; }}
  .filter-row {{ display: flex; gap: 8px; margin-bottom: 16px; flex-wrap: wrap; }}
  .filter-btn {{ padding: 6px 14px; border: 1px solid #e2e8f0; background: white; border-radius: 6px; cursor: pointer; font-size: 13px; transition: all 0.2s; }}
  .filter-btn:hover {{ background: #f0f4f8; }}
  .filter-btn.active {{ background: #2b6cb0; color: white; border-color: #2b6cb0; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
  th, td {{ padding: 10px 12px; text-align: left; border-bottom: 1px solid #e2e8f0; }}
  th {{ background: #f7fafc; font-weight: 600; color: #4a5568; position: sticky; top: 0; }}
  tr:hover {{ background: #f7fafc; }}
  .badge {{ display: inline-block; padding: 2px 10px; border-radius: 12px; font-size: 11px; font-weight: 600; }}
  .badge-critical {{ background: #fed7d7; color: #c53030; }}
  .badge-high {{ background: #feebc8; color: #c05621; }}
  .badge-medium {{ background: #fefcbf; color: #975a16; }}
  .badge-low {{ background: #e2e8f0; color: #4a5568; }}
  .info-grid {{ display: grid; grid-template-columns: 140px 1fr; gap: 8px; font-size: 14px; }}
  .info-label {{ color: #718096; }}
  .progress-bar {{ height: 24px; background: #edf2f7; border-radius: 6px; overflow: hidden; }}
  .progress-fill {{ height: 100%; display: flex; align-items: center; justify-content: center; color: white; font-size: 11px; font-weight: 600; }}
  details {{ margin-bottom: 12px; }}
  summary {{ cursor: pointer; padding: 10px; background: #f7fafc; border-radius: 6px; font-weight: 500; }}
  summary:hover {{ background: #edf2f7; }}
  .hidden {{ display: none !important; }}
</style>
</head>
<body>
<div class="container">
  <header>
    <h1>🔒 Container Image Security Scan Report</h1>
    <div class="subtitle">Image: <strong>{name}:{tag}</strong> | Scanned: {time} | Platform: {arch}</div>
  </header>

  <div class="grid">
    <div class="card"><h3>Total Packages</h3><div class="value info">{packages}</div></div>
    <div class="card"><h3>Total Vulnerabilities</h3><div class="value {vuln_class}">{total}</div></div>
    <div class="card"><h3>Critical</h3><div class="value critical">{cr}</div></div>
    <div class="card"><h3>High</h3><div class="value high">{hi}</div></div>
    <div class="card"><h3>Medium</h3><div class="value medium">{me}</div></div>
    <div class="card"><h3>Low</h3><div class="value low">{lo}</div></div>
    <div class="card"><h3>Fixable</h3><div class="value success">{fixable}</div></div>
    <div class="card"><h3>Scan ID</h3><div class="value info" style="font-size:12px">{scan_id}</div></div>
  </div>

  <div class="table-card">
    <div class="section-title">📋 Image Details</div>
    <div class="info-grid">
      <div class="info-label">Image Name</div><div>{name}</div>
      <div class="info-label">Tag</div><div>{tag}</div>
      <div class="info-label">Digest</div><div>{digest}</div>
      <div class="info-label">Platform</div><div>{os}/{arch}</div>
      <div class="info-label">Layers</div><div>{layers}</div>
      <div class="info-label">Scan Time</div><div>{time}</div>
    </div>
  </div>

  <div class="table-card">
    <div class="section-title">💡 Fix Suggestions</div>
    <div id="suggestions"></div>
  </div>

  <div class="table-card">
    <div class="section-title">🔍 Vulnerabilities ({total})</div>
    <input type="search" id="searchInput" placeholder="Search CVE ID, package name, description..." />
    <div class="filter-row" id="filterRow">
      <button class="filter-btn active" data-sev="all">All</button>
      <button class="filter-btn" data-sev="Critical">Critical ({cr})</button>
      <button class="filter-btn" data-sev="High">High ({hi})</button>
      <button class="filter-btn" data-sev="Medium">Medium ({me})</button>
      <button class="filter-btn" data-sev="Low">Low ({lo})</button>
      <button class="filter-btn" data-sev="fixable">Fixable Only</button>
    </div>
    <div style="overflow-x: auto; max-height: 600px; overflow-y: auto;">
      <table id="vulnTable">
        <thead>
          <tr>
            <th>Severity</th>
            <th>Score</th>
            <th>CVE ID</th>
            <th>Package</th>
            <th>Version</th>
            <th>Fix Version</th>
            <th>Description</th>
          </tr>
        </thead>
        <tbody id="vulnBody"></tbody>
      </table>
    </div>
  </div>

  <div class="table-card">
    <div class="section-title">📦 Packages ({packages})</div>
    <input type="search" id="pkgSearch" placeholder="Search package name, type, version..." />
    <div style="overflow-x: auto; max-height: 400px; overflow-y: auto;">
      <table>
        <thead>
          <tr><th>Name</th><th>Version</th><th>Type</th><th>License</th><th>PURL</th></tr>
        </thead>
        <tbody id="pkgBody"></tbody>
      </table>
    </div>
  </div>
</div>

<script>
const vulns = {vulns_json};
const packages = {packages_json};
const suggestions = {suggestions_json};

let currentFilter = 'all';

function sevBadge(sev) {{
  const classes = {{'Critical':'badge-critical','High':'badge-high','Medium':'badge-medium','Low':'badge-low','Unknown':'badge-low'}};
  return `<span class="badge ${{classes[sev] || 'badge-low'}}">${{sev}}</span>`;
}}

function renderVulns(filtered) {{
  const body = document.getElementById('vulnBody');
  body.innerHTML = filtered.map(v => `
    <tr data-sev="${{v.severity}}" data-fixable="${{v.fix_version ? 'yes' : 'no'}}">
      <td>${{sevBadge(v.severity)}}</td>
      <td>${{(v.cvss_v3_score || v.cvss_v2_score || 0).toFixed(1)}}</td>
      <td><strong>${{v.cve_id}}</strong></td>
      <td>${{v.package_name}}</td>
      <td>${{v.package_version}}</td>
      <td>${{v.fix_version ? `<span style="color:#38a169;font-weight:600">${{v.fix_version}}</span>` : '-'}}</td>
      <td title="${{v.description}}">${{v.description.length > 80 ? v.description.substring(0,80)+'...' : v.description}}</td>
    </tr>
  `).join('') || '<tr><td colspan="7" style="text-align:center;padding:30px;color:#718096">No vulnerabilities match your filters</td></tr>';
}}

function applyFilters() {{
  const q = document.getElementById('searchInput').value.toLowerCase();
  let filtered = vulns;
  if (currentFilter === 'fixable') filtered = filtered.filter(v => v.fix_version);
  else if (currentFilter !== 'all') filtered = filtered.filter(v => v.severity === currentFilter);
  if (q) filtered = filtered.filter(v =>
    v.cve_id.toLowerCase().includes(q) ||
    v.package_name.toLowerCase().includes(q) ||
    v.description.toLowerCase().includes(q)
  );
  renderVulns(filtered);
}}

document.getElementById('searchInput').addEventListener('input', applyFilters);
document.getElementById('filterRow').addEventListener('click', e => {{
  if (e.target.classList.contains('filter-btn')) {{
    document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
    e.target.classList.add('active');
    currentFilter = e.target.dataset.sev;
    applyFilters();
  }}
}});

function renderPkgs(filtered) {{
  document.getElementById('pkgBody').innerHTML = filtered.map(p => `
    <tr>
      <td><strong>${{p.name}}</strong></td>
      <td>${{p.version}}</td>
      <td><span class="badge badge-low">${{p.package_manager}}</span></td>
      <td>${{p.license || '-'}}</td>
      <td style="font-size:11px;color:#718096"><code>${{p.purl || '-'}}</code></td>
    </tr>
  `).join('');
}}

document.getElementById('pkgSearch').addEventListener('input', e => {{
  const q = e.target.value.toLowerCase();
  renderPkgs(packages.filter(p =>
    p.name.toLowerCase().includes(q) ||
    p.version.toLowerCase().includes(q) ||
    p.package_manager.toLowerCase().includes(q)
  ));
}});

document.getElementById('suggestions').innerHTML = suggestions.length === 0 ? '<p style="color:#718096">No fix suggestions available</p>' :
  `<table><thead><tr><th>Severity</th><th>Package</th><th>Current</th><th>Upgrade To</th><th>CVEs Fixed</th><th>Impact</th></tr></thead><tbody>${{
    suggestions.map(s => `
      <tr>
        <td>${{sevBadge(s.max_severity)}}</td>
        <td><strong>${{s.package_name}}</strong></td>
        <td>${{s.current_version}}</td>
        <td><strong style="color:#38a169">${{s.suggested_version}}</strong></td>
        <td>${{s.fixed_cves.length}} (${{s.fixed_cves.slice(0,3).join(', ')}}${{s.fixed_cves.length > 3 ? '...' : ''}})</td>
        <td>${{s.total_cvss.toFixed(1)}} total CVSS</td>
      </tr>
    `).join('')
  }}</tbody></table>`;

applyFilters();
renderPkgs(packages);
</script>
</body>
</html>"#,
        name = result.image.name,
        tag = result.image.tag,
        time = result.scan_time.format("%Y-%m-%d %H:%M:%S UTC"),
        arch = result.image.architecture,
        os = result.image.os,
        digest = result.image.digest.clone().unwrap_or_default(),
        layers = result.image.layers.len(),
        packages = summary.total_packages,
        total = total_vulns,
        vuln_class = if total_vulns > 0 { if cr > 0 || hi > 0 {"critical"} else {"medium"} } else {"success"},
        cr = cr,
        hi = hi,
        me = me,
        lo = lo,
        fixable = summary.fixable_count,
        scan_id = result.scan_id,
    )
}

pub fn baseline_compare(current: &[Vulnerability], baseline: &ScanResult) -> BaselineDiff {
    let baseline_keys: HashSet<String> = baseline
        .vulnerabilities
        .iter()
        .map(|v| format!("{}:{}:{}", v.cve_id, v.package_name, v.package_version))
        .collect();

    let current_keys: HashSet<String> = current
        .iter()
        .map(|v| format!("{}:{}:{}", v.cve_id, v.package_name, v.package_version))
        .collect();

    let mut added = Vec::new();
    let mut unchanged = Vec::new();
    let mut removed = Vec::new();

    let current_map: HashMap<String, Vulnerability> = current
        .iter()
        .map(|v| {
            (
                format!("{}:{}:{}", v.cve_id, v.package_name, v.package_version),
                v.clone(),
            )
        })
        .collect();

    let baseline_map: HashMap<String, Vulnerability> = baseline
        .vulnerabilities
        .iter()
        .map(|v| {
            (
                format!("{}:{}:{}", v.cve_id, v.package_name, v.package_version),
                v.clone(),
            )
        })
        .collect();

    for key in &current_keys {
        if baseline_keys.contains(key) {
            if let Some(v) = current_map.get(key) {
                unchanged.push(v.clone());
            }
        } else {
            if let Some(v) = current_map.get(key) {
                added.push(v.clone());
            }
        }
    }

    for key in &baseline_keys {
        if !current_keys.contains(key) {
            if let Some(v) = baseline_map.get(key) {
                removed.push(v.clone());
            }
        }
    }

    added.sort_by(|a, b| b.severity.order().cmp(&a.severity.order()));
    removed.sort_by(|a, b| b.severity.order().cmp(&a.severity.order()));
    unchanged.sort_by(|a, b| b.severity.order().cmp(&a.severity.order()));

    BaselineDiff {
        added,
        removed,
        unchanged,
    }
}

pub fn load_policy(path: Option<&Path>) -> Result<PolicyConfig, anyhow::Error> {
    let Some(p) = path else {
        return Ok(PolicyConfig::default());
    };

    let content = std::fs::read_to_string(p)?;
    let yaml: serde_yaml::Value = serde_yaml::from_str(&content)?;

    let ignore_cves = yaml
        .get("ignore")
        .and_then(|i| i.get("cves"))
        .and_then(|v| v.as_sequence())
        .map(|seq| {
            seq.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();

    let ignore_packages = yaml
        .get("ignore")
        .and_then(|i| i.get("packages"))
        .and_then(|v| v.as_sequence())
        .map(|seq| {
            seq.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();

    let severity_threshold = yaml
        .get("severity-threshold")
        .and_then(|v| v.as_str())
        .map(|s| match s.to_lowercase().as_str() {
            "critical" => Severity::Critical,
            "high" => Severity::High,
            "medium" => Severity::Medium,
            "low" => Severity::Low,
            _ => Severity::Unknown,
        });

    let license_blacklist = yaml
        .get("license-blacklist")
        .and_then(|v| v.as_sequence())
        .map(|seq| {
            seq.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();

    Ok(PolicyConfig {
        ignore_cves,
        ignore_packages,
        severity_threshold,
        license_blacklist,
    })
}

pub fn check_severity_threshold(
    vulns: &[Vulnerability],
    threshold: Option<&Severity>,
) -> bool {
    let Some(t) = threshold else {
        return false;
    };

    vulns.iter().any(|v| v.severity.order() >= t.order())
}

pub fn check_license_blacklist(
    packages: &[Package],
    blacklist: &[String],
) -> Vec<String> {
    let mut violations = Vec::new();
    for pkg in packages {
        if let Some(lic) = &pkg.license {
            for bl in blacklist {
                if lic.to_lowercase().contains(&bl.to_lowercase()) {
                    violations.push(format!(
                        "Package {}@{} has blacklisted license: {}",
                        pkg.name, pkg.version, lic
                    ));
                }
            }
        }
    }
    violations
}

pub fn emit_github_annotations(vulns: &[Vulnerability], quiet: bool) {
    if std::env::var("GITHUB_ACTIONS").is_err() {
        return;
    }

    if quiet {
        let count = vulns.len();
        if count > 0 {
            println!("::notice::Image scan found {} vulnerabilities", count);
        }
        return;
    }

    for v in vulns.iter().take(50) {
        let level = match v.severity {
            Severity::Critical | Severity::High => "error",
            Severity::Medium => "warning",
            _ => "notice",
        };
        let title = format!("[{}] {}: {}", v.severity.as_str(), v.cve_id, v.package_name);
        let msg = format!(
            "Package {}@{} ({}). Score: {:.1}. {}",
            v.package_name,
            v.package_version,
            v.package_manager,
            v.effective_score(),
            if v.description.len() > 150 {
                format!("{}...", &v.description[..150])
            } else {
                v.description.clone()
            }
        );
        println!(
            "::{} title={}::{}",
            level,
            title.replace(':', "%3A").replace(',', "%2C"),
            msg.replace('%', "%25").replace('\n', "%0A").replace('\r', "%0D")
        );
    }
}

pub fn load_baseline(path: &Path) -> Result<ScanResult, anyhow::Error> {
    let content = std::fs::read_to_string(path)?;
    let result: ScanResult = serde_json::from_str(&content)?;
    Ok(result)
}
