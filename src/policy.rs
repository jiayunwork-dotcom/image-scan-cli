use crate::types::{LayerInfo, Package, PackageManager, Severity, Vulnerability};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdmissionPolicy {
    pub policy_name: String,
    pub version: String,
    #[serde(default)]
    pub description: String,
    #[serde(default = "default_fail_action")]
    pub fail_action: FailAction,
    pub rules: Vec<Rule>,
}

fn default_fail_action() -> FailAction {
    FailAction::Block
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum FailAction {
    Block,
    Warn,
}

impl std::fmt::Display for FailAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FailAction::Block => write!(f, "block"),
            FailAction::Warn => write!(f, "warn"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub id: String,
    pub name: String,
    pub severity: RuleSeverity,
    pub condition: RuleCondition,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum RuleSeverity {
    Error,
    Warning,
    Info,
}

impl RuleSeverity {
    pub fn as_str(&self) -> &'static str {
        match self {
            RuleSeverity::Error => "error",
            RuleSeverity::Warning => "warning",
            RuleSeverity::Info => "info",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleCondition {
    #[serde(rename = "type")]
    pub condition_type: String,
    pub max_critical: Option<u32>,
    pub max_high: Option<u32>,
    pub max_medium: Option<u32>,
    pub max_days_since_publish: Option<u64>,
    pub packages: Option<Vec<String>>,
    pub pins: Option<Vec<VersionPin>>,
    pub allowed_licenses: Option<Vec<String>>,
    pub limit: Option<usize>,
    pub max_layers: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionPin {
    pub name: String,
    pub allowed_versions: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum OverallPolicyResult {
    Approved,
    Rejected,
    PassedWithWarnings,
}

impl OverallPolicyResult {
    pub fn as_str(&self) -> &'static str {
        match self {
            OverallPolicyResult::Approved => "APPROVED",
            OverallPolicyResult::Rejected => "REJECTED",
            OverallPolicyResult::PassedWithWarnings => "PASSED WITH WARNINGS",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyEvaluationResult {
    pub policy_name: String,
    pub policy_version: String,
    pub result: OverallPolicyResult,
    pub rules: Vec<RuleEvaluationResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleEvaluationResult {
    pub id: String,
    pub name: String,
    pub severity: RuleSeverity,
    pub status: RuleStatus,
    pub violations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum RuleStatus {
    Pass,
    Fail,
}

pub fn try_load_admission_policy(path: &Path) -> anyhow::Result<Option<AdmissionPolicy>> {
    let content = std::fs::read_to_string(path)?;
    let yaml: serde_yaml::Value = serde_yaml::from_str(&content)?;

    if yaml.get("rules").is_none() {
        return Ok(None);
    }

    let policy: AdmissionPolicy = serde_yaml::from_str(&content)?;
    validate_admission_policy(&policy)?;
    Ok(Some(policy))
}

fn validate_admission_policy(policy: &AdmissionPolicy) -> anyhow::Result<()> {
    if policy.policy_name.is_empty() {
        anyhow::bail!("policy_name is required and cannot be empty");
    }
    if policy.version.is_empty() {
        anyhow::bail!("version is required and cannot be empty");
    }

    let mut ids: HashSet<String> = HashSet::new();
    for rule in &policy.rules {
        if rule.id.is_empty() {
            anyhow::bail!(
                "rule id is required and cannot be empty (rule: {})",
                rule.name
            );
        }
        if ids.contains(&rule.id) {
            anyhow::bail!("duplicate rule id: {}", rule.id);
        }
        ids.insert(rule.id.clone());

        validate_condition(&rule.condition, &rule.id)?;
    }

    Ok(())
}

fn validate_condition(cond: &RuleCondition, rule_id: &str) -> anyhow::Result<()> {
    match cond.condition_type.as_str() {
        "vuln_severity_threshold" => {
            if cond.max_critical.is_none()
                && cond.max_high.is_none()
                && cond.max_medium.is_none()
            {
                anyhow::bail!(
                    "rule '{}': vuln_severity_threshold requires at least one of max_critical, max_high, max_medium",
                    rule_id
                );
            }
        }
        "vuln_age_limit" => {
            if cond.max_days_since_publish.is_none() {
                anyhow::bail!(
                    "rule '{}': vuln_age_limit requires max_days_since_publish",
                    rule_id
                );
            }
        }
        "package_blacklist" => {
            if cond.packages.as_ref().map_or(true, |p| p.is_empty()) {
                anyhow::bail!(
                    "rule '{}': package_blacklist requires non-empty packages list",
                    rule_id
                );
            }
        }
        "package_version_pin" => {
            if cond.pins.as_ref().map_or(true, |p| p.is_empty()) {
                anyhow::bail!(
                    "rule '{}': package_version_pin requires non-empty pins list",
                    rule_id
                );
            }
        }
        "license_whitelist" => {
            if cond
                .allowed_licenses
                .as_ref()
                .map_or(true, |l| l.is_empty())
            {
                anyhow::bail!(
                    "rule '{}': license_whitelist requires non-empty allowed_licenses list",
                    rule_id
                );
            }
        }
        "max_total_vulns" => {
            if cond.limit.is_none() {
                anyhow::bail!("rule '{}': max_total_vulns requires limit", rule_id);
            }
        }
        "required_packages" => {
            if cond.packages.as_ref().map_or(true, |p| p.is_empty()) {
                anyhow::bail!(
                    "rule '{}': required_packages requires non-empty packages list",
                    rule_id
                );
            }
        }
        "layer_count_limit" => {
            if cond.max_layers.is_none() {
                anyhow::bail!(
                    "rule '{}': layer_count_limit requires max_layers",
                    rule_id
                );
            }
        }
        other => {
            anyhow::bail!("rule '{}': unknown condition type: {}", rule_id, other);
        }
    }
    Ok(())
}

pub fn evaluate_policy(
    policy: &AdmissionPolicy,
    vulnerabilities: &[Vulnerability],
    packages: &[Package],
    layers: &[LayerInfo],
) -> PolicyEvaluationResult {
    let mut rule_results = Vec::new();

    for rule in &policy.rules {
        let result = evaluate_rule(rule, vulnerabilities, packages, layers);
        rule_results.push(result);
    }

    let result = determine_overall_result(&rule_results, &policy.fail_action);

    PolicyEvaluationResult {
        policy_name: policy.policy_name.clone(),
        policy_version: policy.version.clone(),
        result,
        rules: rule_results,
    }
}

fn evaluate_rule(
    rule: &Rule,
    vulns: &[Vulnerability],
    packages: &[Package],
    layers: &[LayerInfo],
) -> RuleEvaluationResult {
    let violations = match rule.condition.condition_type.as_str() {
        "vuln_severity_threshold" => eval_vuln_severity_threshold(&rule.condition, vulns),
        "vuln_age_limit" => eval_vuln_age_limit(&rule.condition, vulns),
        "package_blacklist" => eval_package_blacklist(&rule.condition, packages),
        "package_version_pin" => eval_package_version_pin(&rule.condition, packages),
        "license_whitelist" => eval_license_whitelist(&rule.condition, packages),
        "max_total_vulns" => eval_max_total_vulns(&rule.condition, vulns),
        "required_packages" => eval_required_packages(&rule.condition, packages),
        "layer_count_limit" => eval_layer_count_limit(&rule.condition, layers),
        other => vec![format!("Unknown condition type: {}", other)],
    };

    let status = if violations.is_empty() {
        RuleStatus::Pass
    } else {
        RuleStatus::Fail
    };

    RuleEvaluationResult {
        id: rule.id.clone(),
        name: rule.name.clone(),
        severity: rule.severity.clone(),
        status,
        violations,
    }
}

fn determine_overall_result(rule_results: &[RuleEvaluationResult], fail_action: &FailAction) -> OverallPolicyResult {
    let has_error_fail = rule_results
        .iter()
        .any(|r| r.status == RuleStatus::Fail && r.severity == RuleSeverity::Error);

    if has_error_fail && fail_action == &FailAction::Block {
        return OverallPolicyResult::Rejected;
    }

    let has_fail = rule_results
        .iter()
        .any(|r| r.status == RuleStatus::Fail);

    if has_fail {
        return OverallPolicyResult::PassedWithWarnings;
    }

    OverallPolicyResult::Approved
}

fn eval_vuln_severity_threshold(
    cond: &RuleCondition,
    vulns: &[Vulnerability],
) -> Vec<String> {
    let mut violations = Vec::new();

    let critical_count = vulns
        .iter()
        .filter(|v| v.severity == Severity::Critical)
        .count() as u32;
    let high_count = vulns
        .iter()
        .filter(|v| v.severity == Severity::High)
        .count() as u32;
    let medium_count = vulns
        .iter()
        .filter(|v| v.severity == Severity::Medium)
        .count() as u32;

    if let Some(max) = cond.max_critical {
        if critical_count > max {
            let offending: Vec<String> = vulns
                .iter()
                .filter(|v| v.severity == Severity::Critical)
                .map(|v| format!("{} ({}@{}) - {}", v.cve_id, v.package_name, v.package_version, v.description))
                .collect();
            violations.push(format!(
                "Critical vulnerabilities: {} (max allowed: {}): {}",
                critical_count,
                max,
                offending.join(", ")
            ));
        }
    }

    if let Some(max) = cond.max_high {
        if high_count > max {
            let offending: Vec<String> = vulns
                .iter()
                .filter(|v| v.severity == Severity::High)
                .map(|v| format!("{} ({}@{}) - {}", v.cve_id, v.package_name, v.package_version, v.description))
                .collect();
            violations.push(format!(
                "High vulnerabilities: {} (max allowed: {}): {}",
                high_count,
                max,
                offending.join(", ")
            ));
        }
    }

    if let Some(max) = cond.max_medium {
        if medium_count > max {
            let offending: Vec<String> = vulns
                .iter()
                .filter(|v| v.severity == Severity::Medium)
                .map(|v| format!("{} ({}@{}) - {}", v.cve_id, v.package_name, v.package_version, v.description))
                .collect();
            violations.push(format!(
                "Medium vulnerabilities: {} (max allowed: {}): {}",
                medium_count,
                max,
                offending.join(", ")
            ));
        }
    }

    violations
}

fn eval_vuln_age_limit(cond: &RuleCondition, vulns: &[Vulnerability]) -> Vec<String> {
    let max_days = cond.max_days_since_publish.unwrap_or(0);
    let now = Utc::now();

    let mut violations = Vec::new();

    for v in vulns {
        if v.fix_version.is_some() {
            continue;
        }
        if let Some(pub_date) = v.published_date {
            let days = (now - pub_date).num_days();
            if days > max_days as i64 {
                violations.push(format!(
                    "{} ({}@{}) published {} days ago without fix (max: {}): {}",
                    v.cve_id, v.package_name, v.package_version, days, max_days, v.description
                ));
            }
        }
    }

    violations
}

fn eval_package_blacklist(cond: &RuleCondition, packages: &[Package]) -> Vec<String> {
    let patterns = match &cond.packages {
        Some(p) => p,
        None => return Vec::new(),
    };

    let mut violations = Vec::new();

    for pkg in packages {
        for pattern in patterns {
            if glob_match(pattern, &pkg.name) {
                violations.push(format!(
                    "{}@{} matches blacklisted pattern '{}'",
                    pkg.name, pkg.version, pattern
                ));
            }
        }
    }

    violations
}

fn eval_package_version_pin(cond: &RuleCondition, packages: &[Package]) -> Vec<String> {
    let pins = match &cond.pins {
        Some(p) => p,
        None => return Vec::new(),
    };

    let mut violations = Vec::new();

    for pin in pins {
        for pkg in packages {
            if pkg.name == pin.name {
                if !version_matches_range(&pkg.version, &pin.allowed_versions, &pkg.package_manager) {
                    violations.push(format!(
                        "{}@{} does not match allowed versions '{}'",
                        pkg.name, pkg.version, pin.allowed_versions
                    ));
                }
            }
        }
    }

    violations
}

fn eval_license_whitelist(cond: &RuleCondition, packages: &[Package]) -> Vec<String> {
    let allowed = match &cond.allowed_licenses {
        Some(l) => l,
        None => return Vec::new(),
    };

    let allowed_lower: Vec<String> = allowed.iter().map(|l| normalize_license_token(l)).collect();

    let mut violations = Vec::new();

    for pkg in packages {
        if let Some(lic) = &pkg.license {
            if lic.is_empty() {
                continue;
            }
            let tokens = split_license_tokens(lic);
            let is_allowed = tokens.iter().any(|token| {
                let norm = normalize_license_token(token);
                allowed_lower.iter().any(|a| a == &norm)
            });
            if !is_allowed {
                violations.push(format!(
                    "{}@{} has non-whitelisted license: {}",
                    pkg.name, pkg.version, lic
                ));
            }
        }
    }

    violations
}

fn split_license_tokens(license: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();

    let chars: Vec<char> = license.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];

        if c.is_whitespace() {
            if !current.is_empty() {
                tokens.push(std::mem::take(&mut current));
            }
            i += 1;
            continue;
        }

        if c == '/' || c == ',' || c == ';' || c == '(' || c == ')' {
            if !current.is_empty() {
                tokens.push(std::mem::take(&mut current));
            }
            i += 1;
            continue;
        }

        let remaining: String = chars[i..].iter().collect();
        let lower_remaining = remaining.to_lowercase();
        if lower_remaining.starts_with("or ") || lower_remaining == "or" {
            if !current.is_empty() {
                tokens.push(std::mem::take(&mut current));
            }
            i += 2;
            continue;
        }
        if lower_remaining.starts_with("and ") || lower_remaining == "and" {
            if !current.is_empty() {
                tokens.push(std::mem::take(&mut current));
            }
            i += 3;
            continue;
        }
        if lower_remaining.starts_with("with ") || lower_remaining == "with" {
            if !current.is_empty() {
                tokens.push(std::mem::take(&mut current));
            }
            i += 4;
            continue;
        }

        current.push(c);
        i += 1;
    }

    if !current.is_empty() {
        tokens.push(current);
    }

    tokens.retain(|t| !t.is_empty());
    tokens
}

fn normalize_license_token(token: &str) -> String {
    let mut s = token.to_lowercase();
    s = s.trim_end_matches('-').to_string();
    s = s.trim_end_matches('+').to_string();
    let suffixes = ["license", "licence", "public"];
    for suffix in &suffixes {
        if s.ends_with(suffix) {
            s = s[..s.len() - suffix.len()].to_string();
            s = s.trim_end_matches(['-', '_', ' ']).to_string();
        }
    }
    s.trim().to_string()
}

fn eval_max_total_vulns(cond: &RuleCondition, vulns: &[Vulnerability]) -> Vec<String> {
    let limit = cond.limit.unwrap_or(0);
    let total = vulns.len();

    if total > limit {
        vec![format!(
            "Total vulnerabilities: {} (limit: {})",
            total, limit
        )]
    } else {
        Vec::new()
    }
}

fn eval_required_packages(cond: &RuleCondition, packages: &[Package]) -> Vec<String> {
    let required = match &cond.packages {
        Some(p) => p,
        None => return Vec::new(),
    };

    let installed: HashSet<&str> = packages.iter().map(|p| p.name.as_str()).collect();

    let mut violations = Vec::new();

    for req in required {
        if !installed.contains(req.as_str()) {
            violations.push(format!("Required package '{}' is not installed", req));
        }
    }

    violations
}

fn eval_layer_count_limit(cond: &RuleCondition, layers: &[LayerInfo]) -> Vec<String> {
    let max = cond.max_layers.unwrap_or(0);
    let count = layers.len();

    if count > max {
        vec![format!("Layer count: {} (max: {})", count, max)]
    } else {
        Vec::new()
    }
}

fn glob_match(pattern: &str, name: &str) -> bool {
    if !pattern.contains('*') && !pattern.contains('?') {
        return pattern == name;
    }

    let regex_str = glob_to_regex(pattern);
    if let Ok(re) = regex::Regex::new(&regex_str) {
        re.is_match(name)
    } else {
        pattern == name
    }
}

fn glob_to_regex(pattern: &str) -> String {
    let mut result = String::from("^");
    for c in pattern.chars() {
        match c {
            '*' => result.push_str(".*"),
            '?' => result.push('.'),
            '.'
            | '('
            | ')'
            | '['
            | ']'
            | '{'
            | '}'
            | '+'
            | '^'
            | '$'
            | '|'
            | '\\' => {
                result.push('\\');
                result.push(c);
            }
            _ => result.push(c),
        }
    }
    result.push('$');
    result
}

fn version_matches_range(version: &str, range_expr: &str, pm: &PackageManager) -> bool {
    let constraints = match parse_version_range(range_expr) {
        Some(c) => c,
        None => return false,
    };

    let is_semver_eco = matches!(pm, PackageManager::Npm | PackageManager::Cargo | PackageManager::Go | PackageManager::Pip);

    if is_semver_eco {
        if let Ok(v) = semver::Version::parse(&normalize_version_for_semver(version)) {
            let req_str = range_expr.replace(' ', "");
            if let Ok(req) = semver::VersionReq::parse(&req_str) {
                return req.matches(&v);
            }
        }
    }

    for constraint in constraints {
        match constraint {
            RangeConstraint::Exact(ver) => {
                if crate::version::compare_versions(version, &ver, pm) != std::cmp::Ordering::Equal {
                    return false;
                }
            }
            RangeConstraint::Gte(ver) => {
                if crate::version::compare_versions(version, &ver, pm) == std::cmp::Ordering::Less {
                    return false;
                }
            }
            RangeConstraint::Gt(ver) => {
                if crate::version::compare_versions(version, &ver, pm) != std::cmp::Ordering::Greater {
                    return false;
                }
            }
            RangeConstraint::Lte(ver) => {
                if crate::version::compare_versions(version, &ver, pm) == std::cmp::Ordering::Greater {
                    return false;
                }
            }
            RangeConstraint::Lt(ver) => {
                if crate::version::compare_versions(version, &ver, pm) != std::cmp::Ordering::Less {
                    return false;
                }
            }
        }
    }

    true
}

#[derive(Debug, Clone, PartialEq)]
enum RangeConstraint {
    Exact(String),
    Gte(String),
    Gt(String),
    Lte(String),
    Lt(String),
}

fn parse_version_range(range_expr: &str) -> Option<Vec<RangeConstraint>> {
    let mut constraints = Vec::new();
    let parts: Vec<&str> = range_expr.split(',').collect();

    for part in parts {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }

        if part.starts_with(">=") {
            let ver = part[2..].trim().to_string();
            if ver.is_empty() { return None; }
            constraints.push(RangeConstraint::Gte(ver));
        } else if part.starts_with("<=") {
            let ver = part[2..].trim().to_string();
            if ver.is_empty() { return None; }
            constraints.push(RangeConstraint::Lte(ver));
        } else if part.starts_with(">") {
            let ver = part[1..].trim().to_string();
            if ver.is_empty() { return None; }
            constraints.push(RangeConstraint::Gt(ver));
        } else if part.starts_with("<") {
            let ver = part[1..].trim().to_string();
            if ver.is_empty() { return None; }
            constraints.push(RangeConstraint::Lt(ver));
        } else if part.starts_with("=") {
            let ver = part[1..].trim().to_string();
            if ver.is_empty() { return None; }
            constraints.push(RangeConstraint::Exact(ver));
        } else {
            constraints.push(RangeConstraint::Exact(part.to_string()));
        }
    }

    if constraints.is_empty() {
        None
    } else {
        Some(constraints)
    }
}

fn normalize_version_for_semver(v: &str) -> String {
    let v = v.trim_start_matches('v');
    let parts: Vec<&str> = v.split(|c| c == '.' || c == '-').collect();
    if parts.len() >= 3 {
        v.to_string()
    } else {
        let mut padded = v.to_string();
        for _ in parts.len()..3 {
            padded.push_str(".0");
        }
        padded
    }
}
