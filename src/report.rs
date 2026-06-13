use crate::policy::{OverallPolicyResult, PolicyEvaluationResult, RuleSeverity, RuleStatus};
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
    policy_eval: Option<&PolicyEvaluationResult>,
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
        if let Some(pe) = policy_eval {
            println!("POLICY={}", pe.result.as_str());
        }
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

    if let Some(pe) = policy_eval {
        print_policy_evaluation(pe);
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

fn print_policy_evaluation(eval: &PolicyEvaluationResult) {
    print_header("Policy Evaluation");

    println!("\n  {:<18} {}", "Policy:".dimmed(), eval.policy_name.white());
    println!(
        "  {:<18} {}",
        "Version:".dimmed(),
        eval.policy_version.white()
    );

    let result_colored = match eval.result {
        OverallPolicyResult::Approved => eval.result.as_str().green().bold(),
        OverallPolicyResult::Rejected => eval.result.as_str().red().bold(),
        OverallPolicyResult::PassedWithWarnings => eval.result.as_str().yellow().bold(),
    };
    println!("  {:<18} {}", "Result:".dimmed(), result_colored);

    println!("\n  {}", "Rule Evaluation:".bold());
    println!("  {}", "─".repeat(76));

    for rule in &eval.rules {
        let status_icon = if rule.status == RuleStatus::Pass {
            "✅ PASS".green()
        } else {
            "❌ FAIL".red()
        };

        let sev_tag = format!("[{}]", rule.severity.as_str());
        let sev_colored = match rule.severity {
            RuleSeverity::Error => sev_tag.red(),
            RuleSeverity::Warning => sev_tag.yellow(),
            RuleSeverity::Info => sev_tag.blue(),
        };

        println!(
            "  {} {} {} - {}",
            status_icon,
            sev_colored,
            rule.id.cyan(),
            rule.name.white()
        );

        for v in &rule.violations {
            println!("     {}", format!("→ {}", v).dimmed());
        }
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

pub fn format_json(result: &ScanResult, summary: &ScanSummary, policy_eval: Option<&PolicyEvaluationResult>) -> Result<String, serde_json::Error> {
    let mut output = json!({
        "scan_id": result.scan_id,
        "scan_time": result.scan_time,
        "image": result.image,
        "summary": summary,
        "packages": result.packages,
        "vulnerabilities": result.vulnerabilities,
    });

    if let Some(pe) = policy_eval {
        output.as_object_mut().unwrap().insert(
            "policy_evaluation".to_string(),
            json!({
                "result": pe.result.as_str(),
                "policy_name": pe.policy_name,
                "policy_version": pe.policy_version,
                "rules": pe.rules.iter().map(|r| json!({
                    "id": r.id,
                    "name": r.name,
                    "status": match r.status {
                        RuleStatus::Pass => "pass",
                        RuleStatus::Fail => "fail",
                    },
                    "violations": r.violations,
                })).collect::<Vec<_>>(),
            }),
        );
    }

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
#[serde(rename_all = "camelCase")]
struct SarifDriver {
    name: String,
    version: String,
    information_uri: String,
    rules: Vec<SarifRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SarifRule {
    id: String,
    name: String,
    short_description: SarifMessage,
    full_description: SarifMessage,
    default_configuration: SarifRuleConfig,
    help_uri: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SarifRuleConfig {
    level: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SarifMessage {
    text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SarifResult {
    rule_id: String,
    rule_index: usize,
    level: String,
    message: SarifMessage,
    locations: Vec<SarifLocation>,
    properties: SarifProperties,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SarifLocation {
    physical_location: SarifPhysicalLocation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SarifPhysicalLocation {
    artifact_location: SarifArtifactLocation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SarifArtifactLocation {
    uri: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SarifProperties {
    issue_severity: String,
    cvss_score: Option<f64>,
    package_name: String,
    package_version: String,
    fix_version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SarifInvocation {
    execution_successful: bool,
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
                short_description: SarifMessage {
                    text: format!("{} vulnerability in {}", v.severity.as_str(), v.package_name),
                },
                full_description: SarifMessage {
                    text: v.description.clone(),
                },
                default_configuration: SarifRuleConfig {
                    level: sarif_level(&v.severity),
                },
                help_uri: v.references.first().cloned(),
            });
        }

        let level = sarif_level(&v.severity);
        let artifact_path = format!(
            "{}@{} (installed via {})",
            v.package_name, v.package_version, v.package_manager
        );

        sarif_results.push(SarifResult {
            rule_id: rule_id.clone(),
            rule_index: *rule_map.get(&rule_id).unwrap_or(&0),
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
                physical_location: SarifPhysicalLocation {
                    artifact_location: SarifArtifactLocation {
                        uri: artifact_path,
                    },
                },
            }],
            properties: SarifProperties {
                issue_severity: v.severity.as_str().to_lowercase(),
                cvss_score: Some(v.effective_score()),
                package_name: v.package_name.clone(),
                package_version: v.package_version.clone(),
                fix_version: v.fix_version.clone(),
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
                    information_uri: "https://github.com/image-scan/cli".to_string(),
                    rules,
                },
            },
            results: sarif_results,
            invocations: vec![SarifInvocation {
                execution_successful: true,
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
    policy_eval: Option<&PolicyEvaluationResult>,
) -> String {
    let vulns_json = sanitize_json_for_script(serde_json::to_string(&result.vulnerabilities).unwrap_or_default());
    let packages_json = sanitize_json_for_script(serde_json::to_string(&result.packages).unwrap_or_default());
    let suggestions_json = sanitize_json_for_script(serde_json::to_string(suggestions).unwrap_or_default());

    let cr = summary.critical_count;
    let hi = summary.high_count;
    let me = summary.medium_count;
    let lo = summary.low_count;
    let total_vulns = summary.total_vulnerabilities;

    let policy_card_html = match policy_eval {
        Some(pe) => {
            let css_class = match pe.result {
                OverallPolicyResult::Approved => "approved",
                OverallPolicyResult::Rejected => "rejected",
                OverallPolicyResult::PassedWithWarnings => "warned",
            };
            let result_text = pe.result.as_str();
            let mut rules_html = String::new();
            for rule in &pe.rules {
                let status_class = if rule.status == RuleStatus::Pass { "pass" } else { "fail" };
                let status_text = if rule.status == RuleStatus::Pass { "✅ PASS" } else { "❌ FAIL" };
                let escaped_name = html_escape(&rule.name);
                let escaped_id = html_escape(&rule.id);
                rules_html.push_str(&format!(
                    r#"<div class="policy-rule"><div class="rule-header"><span class="{status_class}">{status_text}</span><span>{escaped_name}</span><span class="rule-id">[{escaped_id}]</span></div>"#
                ));
                for v in &rule.violations {
                    let escaped_v = html_escape(v);
                    rules_html.push_str(&format!(
                        r#"<div class="violation">→ {escaped_v}</div>"#
                    ));
                }
                rules_html.push_str("</div>");
            }
            let policy_name_esc = html_escape(&pe.policy_name);
            let policy_version_esc = html_escape(&pe.policy_version);
            format!(
                r#"<div class="policy-card {css_class}"><h2>🛡️ Policy Compliance</h2><div class="policy-meta">{policy_name_esc} (v{policy_version_esc})</div><div class="policy-result {css_class}">{result_text}</div>{rules_html}</div>"#
            )
        }
        None => String::new(),
    };

    format!(
        r##"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Image Scan Report - {name}:{tag}</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#0f172a;color:#e2e8f0;min-height:100vh}}
.container{{max-width:1400px;margin:0 auto;padding:24px}}
.summary-card{{background:linear-gradient(135deg,#1e293b 0%,#334155 100%);border-radius:16px;padding:28px 32px;margin-bottom:28px;border:1px solid #475569}}
.summary-card h1{{font-size:24px;font-weight:700;margin-bottom:4px}}
.summary-card .meta{{font-size:13px;color:#94a3b8;margin-bottom:20px}}
.summary-stats{{display:flex;flex-wrap:wrap;gap:20px;align-items:center}}
.stat-item{{display:flex;align-items:center;gap:8px;font-size:15px}}
.stat-item .label{{color:#94a3b8;font-size:13px}}
.stat-item .value{{font-weight:700;font-size:20px}}
.dot{{width:12px;height:12px;border-radius:50%;display:inline-block;flex-shrink:0}}
.dot-critical{{background:#ef4444;box-shadow:0 0 8px rgba(239,68,68,0.5)}}
.dot-high{{background:#f97316;box-shadow:0 0 8px rgba(249,115,22,0.5)}}
.dot-medium{{background:#eab308;box-shadow:0 0 8px rgba(234,179,8,0.5)}}
.dot-low{{background:#6b7280;box-shadow:0 0 8px rgba(107,114,128,0.5)}}
.tabs{{display:flex;gap:0;margin-bottom:0}}
.tab-btn{{padding:12px 28px;background:#1e293b;color:#94a3b8;border:1px solid #334155;border-bottom:none;cursor:pointer;font-size:14px;font-weight:500;transition:all .2s}}
.tab-btn:first-child{{border-radius:10px 0 0 0}}
.tab-btn:last-child{{border-radius:0 10px 0 0}}
.tab-btn.active{{background:#1e293b;color:#e2e8f0;border-color:#3b82f6;box-shadow:inset 0 2px 0 #3b82f6}}
.tab-content{{display:none;background:#1e293b;border:1px solid #334155;border-radius:0 0 12px 12px;padding:20px}}
.tab-content.active{{display:block}}
.toolbar{{display:flex;flex-wrap:wrap;gap:12px;align-items:center;margin-bottom:16px}}
.search-box{{flex:1;min-width:200px;padding:10px 14px;background:#0f172a;border:1px solid #334155;border-radius:8px;color:#e2e8f0;font-size:14px;outline:none}}
.search-box:focus{{border-color:#3b82f6}}
.search-box::placeholder{{color:#64748b}}
.sev-filters{{display:flex;gap:6px;flex-wrap:wrap}}
.sev-btn{{padding:6px 14px;border-radius:6px;border:1px solid #334155;background:#0f172a;color:#94a3b8;cursor:pointer;font-size:12px;font-weight:600;transition:all .2s;user-select:none}}
.sev-btn:hover{{border-color:#64748b}}
.sev-btn.sel-critical{{background:#7f1d1d;border-color:#ef4444;color:#fca5a5}}
.sev-btn.sel-high{{background:#7c2d12;border-color:#f97316;color:#fdba74}}
.sev-btn.sel-medium{{background:#713f12;border-color:#eab308;color:#fde047}}
.sev-btn.sel-low{{background:#374151;border-color:#6b7280;color:#d1d5db}}
table{{width:100%;border-collapse:collapse;font-size:13px}}
thead th{{position:sticky;top:0;background:#0f172a;color:#94a3b8;font-weight:600;text-align:left;padding:10px 12px;border-bottom:1px solid #334155;cursor:pointer;user-select:none;white-space:nowrap}}
thead th:hover{{color:#e2e8f0}}
thead th .sort-arrow{{margin-left:4px;font-size:10px;opacity:.4}}
thead th.sorted .sort-arrow{{opacity:1;color:#3b82f6}}
tbody td{{padding:10px 12px;border-bottom:1px solid #1e293b;vertical-align:middle}}
tbody tr:hover{{background:#1e293b80}}
.table-wrap{{overflow:auto;max-height:520px;border-radius:8px}}
.badge{{display:inline-block;padding:3px 10px;border-radius:4px;font-size:11px;font-weight:700;letter-spacing:.3px}}
.badge-critical{{background:#991b1b;color:#fecaca}}
.badge-high{{background:#9a3412;color:#fed7aa}}
.badge-medium{{background:#854d0e;color:#fef08a}}
.badge-low{{background:#374151;color:#d1d5db}}
.badge-unknown{{background:#1f2937;color:#9ca3af}}
.fix-ver{{color:#4ade80;font-weight:600}}
.no-fix{{color:#64748b}}
.truncate{{max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;cursor:help}}
.section{{background:#1e293b;border:1px solid #334155;border-radius:12px;margin-bottom:28px;overflow:hidden}}
.section-header{{padding:20px 24px;border-bottom:1px solid #334155}}
.section-header h2{{font-size:18px;font-weight:600}}
.fix-section{{background:#1e293b;border:1px solid #334155;border-radius:12px;padding:24px;margin-bottom:28px}}
.fix-section h2{{font-size:18px;font-weight:600;margin-bottom:16px}}
.fix-group{{margin-bottom:16px;padding:12px 16px;background:#0f172a;border-radius:8px;border-left:3px solid #3b82f6}}
.fix-group .pkg-name{{font-weight:700;font-size:15px;margin-bottom:6px}}
.fix-group .upgrade{{color:#4ade80;margin-bottom:4px}}
.fix-group .cve-list{{color:#94a3b8;font-size:12px}}
.no-results{{text-align:center;padding:40px;color:#64748b}}
.pkg-search{{width:100%;padding:10px 14px;background:#0f172a;border:1px solid #334155;border-radius:8px;color:#e2e8f0;font-size:14px;outline:none;margin-bottom:16px}}
.pkg-search:focus{{border-color:#3b82f6}}
.pkg-search::placeholder{{color:#64748b}}
.policy-card{{border-radius:12px;padding:24px;margin-bottom:28px;border:2px solid}}
.policy-card.approved{{background:linear-gradient(135deg,#052e16 0%,#14532d 100%);border-color:#22c55e}}
.policy-card.rejected{{background:linear-gradient(135deg,#450a0a 0%,#7f1d1d 100%);border-color:#ef4444}}
.policy-card.warned{{background:linear-gradient(135deg,#422006 0%,#713f12 100%);border-color:#eab308}}
.policy-card h2{{font-size:18px;font-weight:700;margin-bottom:4px}}
.policy-card .policy-meta{{font-size:13px;color:#94a3b8;margin-bottom:16px}}
.policy-result{{font-size:28px;font-weight:800;letter-spacing:1px;margin-bottom:16px}}
.policy-result.approved{{color:#4ade80}}
.policy-result.rejected{{color:#f87171}}
.policy-result.warned{{color:#fbbf24}}
.policy-rule{{padding:10px 14px;background:rgba(0,0,0,.25);border-radius:8px;margin-bottom:8px}}
.policy-rule .rule-header{{display:flex;align-items:center;gap:8px;font-size:14px;font-weight:600}}
.policy-rule .rule-header .pass{{color:#4ade80}}
.policy-rule .rule-header .fail{{color:#f87171}}
.policy-rule .rule-id{{color:#94a3b8;font-size:12px}}
.policy-rule .violation{{color:#fca5a5;font-size:12px;margin-top:4px;padding-left:24px}}
footer{{text-align:center;padding:20px;color:#475569;font-size:12px}}
</style>
</head>
<body>
<div class="container">
  <div class="summary-card">
    <h1>🔒 {name}:{tag}</h1>
    <div class="meta">Platform: {os}/{arch} &nbsp;|&nbsp; Layers: {layers} &nbsp;|&nbsp; Packages: {packages} &nbsp;|&nbsp; Scanned: {time}</div>
    <div class="summary-stats">
      <div class="stat-item"><span class="dot dot-critical"></span><span class="label">Critical</span><span class="value" style="color:#ef4444">{cr}</span></div>
      <div class="stat-item"><span class="dot dot-high"></span><span class="label">High</span><span class="value" style="color:#f97316">{hi}</span></div>
      <div class="stat-item"><span class="dot dot-medium"></span><span class="label">Medium</span><span class="value" style="color:#eab308">{me}</span></div>
      <div class="stat-item"><span class="dot dot-low"></span><span class="label">Low</span><span class="value" style="color:#6b7280">{lo}</span></div>
      <div class="stat-item" style="margin-left:auto"><span class="label">Total Vulns</span><span class="value" style="color:#e2e8f0">{total}</span></div>
    </div>
  </div>

  <div class="section">
    <div class="tabs">
      <button class="tab-btn active" onclick="switchTab('vulns')">🔍 Vulnerability List</button>
      <button class="tab-btn" onclick="switchTab('pkgs')">📦 Package Manifest</button>
    </div>
    <div id="tab-vulns" class="tab-content active">
      <div class="toolbar">
        <input type="text" class="search-box" id="vulnSearch" placeholder="Search CVE ID or package name...">
        <div class="sev-filters" id="sevFilters">
          <button class="sev-btn sel-critical" data-sev="Critical" onclick="toggleSev(this)">Critical</button>
          <button class="sev-btn sel-high" data-sev="High" onclick="toggleSev(this)">High</button>
          <button class="sev-btn sel-medium" data-sev="Medium" onclick="toggleSev(this)">Medium</button>
          <button class="sev-btn sel-low" data-sev="Low" onclick="toggleSev(this)">Low</button>
        </div>
      </div>
      <div class="table-wrap">
        <table id="vulnTable">
          <thead>
            <tr>
              <th data-col="cve_id" onclick="sortVulns('cve_id')">CVE ID <span class="sort-arrow">▲</span></th>
              <th data-col="severity" onclick="sortVulns('severity')">Severity <span class="sort-arrow">▲</span></th>
              <th data-col="package_name" onclick="sortVulns('package_name')">Package <span class="sort-arrow">▲</span></th>
              <th data-col="package_version" onclick="sortVulns('package_version')">Version <span class="sort-arrow">▲</span></th>
              <th data-col="score" onclick="sortVulns('score')">CVSS <span class="sort-arrow">▼</span></th>
              <th data-col="fix_version" onclick="sortVulns('fix_version')">Fix Version <span class="sort-arrow">▲</span></th>
              <th>Description</th>
            </tr>
          </thead>
          <tbody id="vulnBody"></tbody>
        </table>
      </div>
    </div>
    <div id="tab-pkgs" class="tab-content">
      <input type="text" class="pkg-search" id="pkgSearch" placeholder="Search package name, version, type, license...">
      <div class="table-wrap" style="max-height:520px">
        <table id="pkgTable">
          <thead>
            <tr><th>Name</th><th>Version</th><th>Type</th><th>Install Path</th><th>License</th></tr>
          </thead>
          <tbody id="pkgBody"></tbody>
        </table>
      </div>
    </div>
  </div>

  <div class="fix-section" id="fixSection">
    <h2>💡 Fix Suggestions</h2>
    <div id="fixContent"></div>
  </div>

  {policy_card_html}

  <footer>Generated by image-scan at {time}</footer>
</div>

<script>
(function(){{
const vulns={vulns_json};
const packages={packages_json};
const suggestions={suggestions_json};

let activeSevs=new Set(['Critical','High','Medium','Low']);
let sortCol='score';
let sortDir=-1;

function sevOrder(s){{const m={{Critical:4,High:3,Medium:2,Low:1,Unknown:0}};return m[s]||0}}
function sevBadge(s){{
  const cls={{Critical:'badge-critical',High:'badge-high',Medium:'badge-medium',Low:'badge-low',Unknown:'badge-unknown'}};
  return '<span class="badge '+(cls[s]||'badge-unknown')+'">'+s+'</span>';
}}

function renderVulns(){{
  const q=document.getElementById('vulnSearch').value.toLowerCase();
  let filtered=vulns.filter(v=>activeSevs.has(v.severity));
  if(q)filtered=filtered.filter(v=>
    v.cve_id.toLowerCase().includes(q)||v.package_name.toLowerCase().includes(q)
  );
  filtered.sort((a,b)=>{{
    let va,vb;
    switch(sortCol){{
      case'cve_id':va=a.cve_id;vb=b.cve_id;return sortDir*va.localeCompare(vb);
      case'severity':va=sevOrder(a.severity);vb=sevOrder(b.severity);break;
      case'package_name':va=a.package_name;vb=b.package_name;return sortDir*va.localeCompare(vb);
      case'package_version':va=a.package_version;vb=b.package_version;return sortDir*va.localeCompare(vb);
      case'score':va=a.cvss_v3_score||a.cvss_v2_score||0;vb=b.cvss_v3_score||b.cvss_v2_score||0;break;
      case'fix_version':va=a.fix_version||'';vb=b.fix_version||'';return sortDir*va.localeCompare(vb);
      default:return 0;
    }}
    return sortDir*(va>vb?1:va<vb?-1:0);
  }});
  const body=document.getElementById('vulnBody');
  if(!filtered.length){{body.innerHTML='<tr><td colspan="7" class="no-results">No vulnerabilities match your filters</td></tr>';return}}
  body.innerHTML=filtered.map(v=>{{
    const score=(v.cvss_v3_score||v.cvss_v2_score||0).toFixed(1);
    const fixHtml=v.fix_version?'<span class="fix-ver">'+v.fix_version+'</span>':'<span class="no-fix">-</span>';
    const desc=v.description||'';
    const trunc=desc.length>80?desc.substring(0,80)+'...':desc;
    return '<tr><td><strong>'+v.cve_id+'</strong></td><td>'+sevBadge(v.severity)+'</td><td>'+v.package_name+'</td><td>'+v.package_version+'</td><td>'+score+'</td><td>'+fixHtml+'</td><td><div class="truncate" title="'+desc.replace(/"/g,'&quot;').replace(/</g,'&lt;')+'">'+trunc+'</div></td></tr>';
  }}).join('');
  document.querySelectorAll('#vulnTable thead th').forEach(th=>{{
    const col=th.dataset.col;
    th.classList.toggle('sorted',col===sortCol);
    const arrow=th.querySelector('.sort-arrow');
    if(arrow)arrow.textContent=col===sortCol?(sortDir===1?'▲':'▼'):'▲';
  }});
}}

window.sortVulns=function(col){{
  if(sortCol===col)sortDir*=-1;else{{sortCol=col;sortDir=col==='score'?-1:1}}
  renderVulns();
}};

window.toggleSev=function(btn){{
  const sev=btn.dataset.sev;
  if(activeSevs.has(sev))activeSevs.delete(sev);else activeSevs.add(sev);
  btn.classList.toggle('sel-'+sev.toLowerCase(),activeSevs.has(sev));
  renderVulns();
}};

window.switchTab=function(tab){{
  document.querySelectorAll('.tab-btn').forEach((b,i)=>b.classList.toggle('active',i===(tab==='vulns'?0:1)));
  document.querySelectorAll('.tab-content').forEach(c=>c.classList.remove('active'));
  document.getElementById('tab-'+tab).classList.add('active');
}};

document.getElementById('vulnSearch').addEventListener('input',renderVulns);

function renderPkgs(){{
  const q=document.getElementById('pkgSearch').value.toLowerCase();
  let filtered=packages;
  if(q)filtered=filtered.filter(p=>
    p.name.toLowerCase().includes(q)||
    p.version.toLowerCase().includes(q)||
    p.package_manager.toLowerCase().includes(q)||
    (p.license||'').toLowerCase().includes(q)||
    (p.install_path||'').toLowerCase().includes(q)
  );
  document.getElementById('pkgBody').innerHTML=filtered.map(p=>{{
    return '<tr><td><strong>'+p.name+'</strong></td><td>'+p.version+'</td><td>'+p.package_manager+'</td><td style="font-size:11px;color:#94a3b8">'+(p.install_path||'-')+'</td><td>'+(p.license||'-')+'</td></tr>';
  }}).join('');
}}
document.getElementById('pkgSearch').addEventListener('input',renderPkgs);

const fixContent=document.getElementById('fixContent');
if(!suggestions.length){{
  fixContent.innerHTML='<p style="color:#64748b">No fix suggestions available</p>';
}}else{{
  const grouped={{}};
  suggestions.forEach(s=>{{
    const key=s.package_name+'@'+s.current_version;
    if(!grouped[key])grouped[key]={{pkg:s.package_name,cur:s.current_version,ver:s.suggested_version,cves:[],sev:s.max_severity}};
    grouped[key].cves.push(...s.fixed_cves);
    if(sevOrder(s.max_severity)>sevOrder(grouped[key].sev))grouped[key].sev=s.max_severity;
  }});
  fixContent.innerHTML=Object.values(grouped).map(g=>{{
    return '<div class="fix-group"><div class="pkg-name">'+g.pkg+'</div><div class="upgrade">'+g.cur+' → '+g.ver+'</div><div class="cve-list">Fixes: '+g.cves.join(', ')+'</div></div>';
  }}).join('');
}}

renderVulns();
renderPkgs();
}})();
</script>
</body>
</html>"##,
        name = result.image.name,
        tag = result.image.tag,
        time = result.scan_time.format("%Y-%m-%d %H:%M:%S UTC"),
        arch = result.image.architecture,
        os = result.image.os,
        layers = result.image.layers.len(),
        packages = summary.total_packages,
        total = total_vulns,
        cr = cr,
        hi = hi,
        me = me,
        lo = lo,
        policy_card_html = policy_card_html,
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

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn sanitize_json_for_script(json: String) -> String {
    json.replace("</", "<\\/")
}
