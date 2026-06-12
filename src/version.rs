use crate::types::PackageManager;
use std::cmp::Ordering;

pub fn compare_versions(a: &str, b: &str, pm: &PackageManager) -> Ordering {
    match pm {
        PackageManager::Apt => compare_deb_versions(a, b),
        PackageManager::Rpm => compare_rpm_versions(a, b),
        PackageManager::Npm | PackageManager::Cargo | PackageManager::Go => compare_semver(a, b),
        PackageManager::Pip => compare_python_versions(a, b),
        _ => compare_alphanumeric(a, b),
    }
}

fn compare_deb_versions(a: &str, b: &str) -> Ordering {
    let a_parts = parse_deb_version(a);
    let b_parts = parse_deb_version(b);

    match a_parts.0.cmp(&b_parts.0) {
        Ordering::Equal => {}
        ord => return ord,
    }

    match compare_alphanumeric(&a_parts.1, &b_parts.1) {
        Ordering::Equal => {}
        ord => return ord,
    }

    compare_alphanumeric(&a_parts.2, &b_parts.2)
}

fn parse_deb_version(v: &str) -> (u64, String, String) {
    let mut epoch = 0;
    let rest;
    if let Some(idx) = v.find(':') {
        epoch = v[..idx].parse().unwrap_or(0);
        rest = &v[idx + 1..];
    } else {
        rest = v;
    }

    let (upstream, revision) = if let Some(idx) = rest.rfind('-') {
        (rest[..idx].to_string(), rest[idx + 1..].to_string())
    } else {
        (rest.to_string(), String::new())
    };

    (epoch, upstream, revision)
}

fn compare_rpm_versions(a: &str, b: &str) -> Ordering {
    compare_alphanumeric(a, b)
}

fn compare_semver(a: &str, b: &str) -> Ordering {
    if let (Ok(va), Ok(vb)) = (
        semver::Version::parse(&normalize_semver(a)),
        semver::Version::parse(&normalize_semver(b)),
    ) {
        va.cmp(&vb)
    } else {
        compare_alphanumeric(a, b)
    }
}

fn normalize_semver(v: &str) -> String {
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

fn compare_python_versions(a: &str, b: &str) -> Ordering {
    compare_semver(a, b)
}

fn compare_alphanumeric(a: &str, b: &str) -> Ordering {
    let a_parts = split_version_parts(a);
    let b_parts = split_version_parts(b);

    for (ap, bp) in a_parts.iter().zip(b_parts.iter()) {
        match (ap.parse::<u64>(), bp.parse::<u64>()) {
            (Ok(an), Ok(bn)) => match an.cmp(&bn) {
                Ordering::Equal => continue,
                ord => return ord,
            },
            _ => match ap.cmp(bp) {
                Ordering::Equal => continue,
                ord => return ord,
            },
        }
    }

    a_parts.len().cmp(&b_parts.len())
}

fn split_version_parts(v: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut prev_is_digit = false;

    for c in v.chars() {
        let is_digit = c.is_ascii_digit();
        if !current.is_empty() && is_digit != prev_is_digit {
            parts.push(std::mem::take(&mut current));
        }
        if c.is_alphanumeric() {
            current.push(c);
            prev_is_digit = is_digit;
        } else if !current.is_empty() {
            parts.push(std::mem::take(&mut current));
            prev_is_digit = false;
        }
    }
    if !current.is_empty() {
        parts.push(current);
    }
    parts
}

pub fn version_in_range(version: &str, min_inclusive: Option<&str>, max_exclusive: Option<&str>, pm: &PackageManager) -> bool {
    if let Some(min) = min_inclusive {
        if compare_versions(version, min, pm) == Ordering::Less {
            return false;
        }
    }
    if let Some(max) = max_exclusive {
        if compare_versions(version, max, pm) != Ordering::Less {
            return false;
        }
    }
    true
}

pub fn version_in_fixed_range(version: &str, introduced: Option<&str>, fixed: Option<&str>, last_affected: Option<&str>, pm: &PackageManager) -> bool {
    if let Some(intro) = introduced {
        if compare_versions(version, intro, pm) == Ordering::Less {
            return false;
        }
    }

    if let Some(fix_v) = fixed {
        if compare_versions(version, fix_v, pm) != Ordering::Less {
            return false;
        }
    }

    if let Some(last) = last_affected {
        if compare_versions(version, last, pm) == Ordering::Greater {
            return false;
        }
    }

    true
}
