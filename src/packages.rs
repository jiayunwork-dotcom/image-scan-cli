use crate::purl::generate_purl;
use crate::types::{Package, PackageManager, Result};
use rayon::prelude::*;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

pub struct PackageDetector;

impl PackageDetector {
    pub fn detect_all(root: &Path) -> Result<Vec<Package>> {
        let mut packages = Vec::new();

        let os_packages = rayon::join(
            || Self::detect_apt(root).ok(),
            || Self::detect_rpm(root).ok(),
        );

        if let Some(mut apt_pkgs) = os_packages.0 {
            packages.append(&mut apt_pkgs);
        }
        if let Some(mut rpm_pkgs) = os_packages.1 {
            packages.append(&mut rpm_pkgs);
        }
        if let Some(mut apk_pkgs) = Self::detect_apk(root).ok() {
            packages.append(&mut apk_pkgs);
        }

        let ((pip_res, npm_res), (go_res, cargo_res)) = rayon::join(
            || rayon::join(|| Self::detect_pip(root), || Self::detect_npm(root)),
            || rayon::join(|| Self::detect_go(root), || Self::detect_cargo(root)),
        );
        let maven_res = Self::detect_maven(root);

        if let Ok(mut pip_pkgs) = pip_res { packages.append(&mut pip_pkgs); }
        if let Ok(mut npm_pkgs) = npm_res { packages.append(&mut npm_pkgs); }
        if let Ok(mut go_pkgs) = go_res { packages.append(&mut go_pkgs); }
        if let Ok(mut cargo_pkgs) = cargo_res { packages.append(&mut cargo_pkgs); }
        if let Ok(mut maven_pkgs) = maven_res { packages.append(&mut maven_pkgs); }

        packages.par_iter_mut().for_each(|pkg| {
            pkg.purl = Some(generate_purl(pkg));
        });

        Ok(packages)
    }

    pub fn detect_apt(root: &Path) -> Result<Vec<Package>> {
        let status_path = root.join("var/lib/dpkg/status");
        if !status_path.exists() {
            return Ok(Vec::new());
        }

        let content = std::fs::read_to_string(&status_path)?;
        let mut packages = Vec::new();

        let blocks: Vec<&str> = content.split("\n\n").collect();
        packages.par_extend(blocks.par_iter().filter_map(|block| {
            parse_dpkg_block(block, &status_path)
        }));

        Ok(packages)
    }

    pub fn detect_rpm(root: &Path) -> Result<Vec<Package>> {
        let rpm_base = root.join("var/lib/rpm");
        if !rpm_base.exists() {
            return Ok(Vec::new());
        }

        let mut packages = Vec::new();

        let sqlite_path = rpm_base.join("rpmdb.sqlite");
        if sqlite_path.exists() {
            return Self::detect_rpm_sqlite(&sqlite_path, root);
        }

        let packages_path = rpm_base.join("Packages");
        if packages_path.exists() {
            packages = Self::detect_rpm_bdb_fallback(&rpm_base, root)?;
        }

        Ok(packages)
    }

    fn detect_rpm_sqlite(db_path: &Path, _root: &Path) -> Result<Vec<Package>> {
        use std::process::Command;

        let output = Command::new("rpm")
            .arg("--dbpath")
            .arg(db_path.parent().unwrap())
            .args(["-qa", "--queryformat", "%{NAME}|%{VERSION}-%{RELEASE}|%{LICENSE}|%{INSTALLPREFIX}\n"])
            .output();

        let output = match output {
            Ok(out) if out.status.success() => String::from_utf8_lossy(&out.stdout).to_string(),
            _ => return Ok(Vec::new()),
        };

        let mut packages = Vec::new();
        for line in output.lines() {
            let parts: Vec<&str> = line.split('|').collect();
            if parts.len() >= 2 && !parts[0].is_empty() {
                packages.push(Package {
                    name: parts[0].to_string(),
                    version: parts[1].to_string(),
                    package_manager: PackageManager::Rpm,
                    install_path: parts.get(3).map(|s| s.to_string()).unwrap_or_default(),
                    license: parts.get(2).map(|s| s.to_string()).filter(|s| !s.is_empty() && s != "(none)"),
                    purl: None,
                    dependencies: Vec::new(),
                });
            }
        }

        Ok(packages)
    }

    fn detect_rpm_bdb_fallback(rpm_dir: &Path, _root: &Path) -> Result<Vec<Package>> {
        use std::process::Command;

        let output = Command::new("rpm")
            .arg("--dbpath")
            .arg(rpm_dir)
            .args(["-qa", "--queryformat", "%{NAME}|%{VERSION}-%{RELEASE}|%{LICENSE}|%{INSTALLPREFIX}\n"])
            .output();

        let output = match output {
            Ok(out) if out.status.success() => String::from_utf8_lossy(&out.stdout).to_string(),
            _ => return Ok(Vec::new()),
        };

        let mut packages = Vec::new();
        for line in output.lines() {
            let parts: Vec<&str> = line.split('|').collect();
            if parts.len() >= 2 && !parts[0].is_empty() {
                packages.push(Package {
                    name: parts[0].to_string(),
                    version: parts[1].to_string(),
                    package_manager: PackageManager::Rpm,
                    install_path: parts.get(3).map(|s| s.to_string()).unwrap_or_default(),
                    license: parts.get(2).map(|s| s.to_string()).filter(|s| !s.is_empty() && s != "(none)"),
                    purl: None,
                    dependencies: Vec::new(),
                });
            }
        }

        Ok(packages)
    }

    pub fn detect_apk(root: &Path) -> Result<Vec<Package>> {
        let installed_path = root.join("lib/apk/db/installed");
        if !installed_path.exists() {
            return Ok(Vec::new());
        }

        let content = std::fs::read_to_string(&installed_path)?;
        let mut packages = Vec::new();

        let blocks: Vec<&str> = content.split("\n\n").collect();
        packages.par_extend(blocks.par_iter().filter_map(|block| {
            parse_apk_block(block, &installed_path)
        }));

        Ok(packages)
    }

    pub fn detect_pip(root: &Path) -> Result<Vec<Package>> {
        let mut packages = Vec::new();
        let mut found: HashMap<String, ()> = HashMap::new();

        let site_packages: Vec<PathBuf> = WalkDir::new(root)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_dir())
            .filter(|e| e.file_name().to_string_lossy() == "site-packages")
            .map(|e| e.path().to_path_buf())
            .collect();

        for sp in &site_packages {
            let dist_infos: Vec<PathBuf> = WalkDir::new(sp)
                .max_depth(2)
                .into_iter()
                .filter_map(|e| e.ok())
                .filter(|e| {
                    let name = e.file_name().to_string_lossy();
                    e.file_type().is_dir() && (name.ends_with(".dist-info") || name.ends_with(".egg-info"))
                })
                .map(|e| e.path().to_path_buf())
                .collect();

            for info_dir in &dist_infos {
                let metadata_path = if info_dir.to_string_lossy().ends_with(".dist-info") {
                    info_dir.join("METADATA")
                } else {
                    info_dir.join("PKG-INFO")
                };

                if let Ok(content) = std::fs::read_to_string(&metadata_path) {
                    if let Some(pkg) = parse_python_metadata(&content, info_dir) {
                        let key = format!("{}:{}", pkg.name, pkg.version);
                        if found.insert(key, ()).is_none() {
                            packages.push(pkg);
                        }
                    }
                }
            }
        }

        Ok(packages)
    }

    pub fn detect_npm(root: &Path) -> Result<Vec<Package>> {
        let mut packages = Vec::new();
        let mut found: HashMap<String, ()> = HashMap::new();

        let package_jsons: Vec<PathBuf> = WalkDir::new(root)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| {
                let name = e.file_name().to_string_lossy();
                e.file_type().is_file() && name == "package.json"
            })
            .map(|e| e.path().to_path_buf())
            .collect();

        let deps_collected: Vec<(String, String, PathBuf)> = package_jsons.par_iter()
            .filter_map(|pj| parse_package_json_deps(pj).ok())
            .flatten()
            .collect();

        for (name, version, path) in deps_collected {
            let key = format!("{}:{}", name, version);
            if found.insert(key, ()).is_none() {
                packages.push(Package {
                    name,
                    version,
                    package_manager: PackageManager::Npm,
                    install_path: path.parent().map(|p| p.to_string_lossy().to_string()).unwrap_or_default(),
                    license: None,
                    purl: None,
                    dependencies: Vec::new(),
                });
            }
        }

        Ok(packages)
    }

    pub fn detect_go(root: &Path) -> Result<Vec<Package>> {
        let mut packages = Vec::new();
        let mut found: HashMap<String, ()> = HashMap::new();

        let go_sums: Vec<PathBuf> = WalkDir::new(root)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| {
                let name = e.file_name().to_string_lossy();
                e.file_type().is_file() && (name == "go.sum" || name == "modules.txt")
            })
            .map(|e| e.path().to_path_buf())
            .collect();

        for gs in &go_sums {
            let is_modules = gs.file_name().map(|f| f == "modules.txt").unwrap_or(false);
            if let Ok(content) = std::fs::read_to_string(gs) {
                let pkgs = if is_modules {
                    parse_go_vendor_modules(&content, gs)
                } else {
                    parse_go_sum(&content, gs)
                };
                for pkg in pkgs {
                    let key = format!("{}:{}", pkg.name, pkg.version);
                    if found.insert(key, ()).is_none() {
                        packages.push(pkg);
                    }
                }
            }
        }

        Ok(packages)
    }

    pub fn detect_cargo(root: &Path) -> Result<Vec<Package>> {
        let mut packages = Vec::new();
        let mut found: HashMap<String, ()> = HashMap::new();

        let cargo_locks: Vec<PathBuf> = WalkDir::new(root)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| {
                let name = e.file_name().to_string_lossy();
                e.file_type().is_file() && name == "Cargo.lock"
            })
            .map(|e| e.path().to_path_buf())
            .collect();

        for cl in &cargo_locks {
            if let Ok(content) = std::fs::read_to_string(cl) {
                if let Ok(lock) = toml::from_str::<toml::Value>(&content) {
                    if let Some(packages_arr) = lock.get("package").and_then(|p| p.as_array()) {
                        for pkg_val in packages_arr {
                            if let (Some(name), Some(version)) = (
                                pkg_val.get("name").and_then(|n| n.as_str()),
                                pkg_val.get("version").and_then(|v| v.as_str()),
                            ) {
                                let key = format!("{}:{}", name, version);
                                if found.insert(key.clone(), ()).is_none() {
                                    let mut deps = Vec::new();
                                    if let Some(dep_arr) = pkg_val.get("dependencies").and_then(|d| d.as_array()) {
                                        for dep in dep_arr {
                                            if let Some(dep_str) = dep.as_str() {
                                                let dep_name = dep_str.split(' ').next().unwrap_or(dep_str);
                                                deps.push(dep_name.to_string());
                                            } else if let Some(dep_name) = dep.get("name").and_then(|n| n.as_str()) {
                                                deps.push(dep_name.to_string());
                                            }
                                        }
                                    }
                                    packages.push(Package {
                                        name: name.to_string(),
                                        version: version.to_string(),
                                        package_manager: PackageManager::Cargo,
                                        install_path: cl.parent().map(|p| p.to_string_lossy().to_string()).unwrap_or_default(),
                                        license: pkg_val.get("source").and_then(|s| s.as_str()).map(|s| s.to_string()),
                                        purl: None,
                                        dependencies: deps,
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(packages)
    }

    pub fn detect_maven(root: &Path) -> Result<Vec<Package>> {
        let mut packages = Vec::new();
        let mut found: HashMap<String, ()> = HashMap::new();

        let maven_files: Vec<PathBuf> = WalkDir::new(root)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| {
                let name = e.file_name().to_string_lossy();
                e.file_type().is_file() && (name == "pom.xml" || name == "pom.properties")
            })
            .map(|e| e.path().to_path_buf())
            .collect();

        for mf in &maven_files {
            let is_props = mf.file_name().map(|f| f == "pom.properties").unwrap_or(false);
            let parsed = if is_props {
                parse_maven_properties(mf)
            } else {
                parse_maven_pom(mf)
            };

            if let Ok(pkgs) = parsed {
                for pkg in pkgs {
                    let key = format!("{}:{}", pkg.name, pkg.version);
                    if found.insert(key, ()).is_none() {
                        packages.push(pkg);
                    }
                }
            }
        }

        Ok(packages)
    }
}

fn parse_dpkg_block(block: &str, _source: &Path) -> Option<Package> {
    if block.trim().is_empty() {
        return None;
    }

    let mut name = None;
    let mut version = None;
    let mut license = None;
    let mut depends: Vec<String> = Vec::new();

    for line in block.lines() {
        if let Some((key, value)) = line.split_once(':') {
            let value = value.trim();
            match key {
                "Package" => name = Some(value.to_string()),
                "Version" => version = Some(value.to_string()),
                "License" => license = Some(value.to_string()),
                "Depends" | "Pre-Depends" => {
                    for dep in value.split(',') {
                        let dep_name = dep.trim().split(|c| c == ' ' || c == '(' || c == '[').next().unwrap_or("").trim();
                        if !dep_name.is_empty() {
                            depends.push(dep_name.to_string());
                        }
                    }
                }
                _ => {}
            }
        }
    }

    match (name, version) {
        (Some(n), Some(v)) if !n.is_empty() && !v.is_empty() => Some(Package {
            name: n,
            version: v,
            package_manager: PackageManager::Apt,
            install_path: "/".to_string(),
            license,
            purl: None,
            dependencies: depends,
        }),
        _ => None,
    }
}

fn parse_apk_block(block: &str, _source: &Path) -> Option<Package> {
    if block.trim().is_empty() {
        return None;
    }

    let mut name = None;
    let mut version = None;
    let mut license = None;
    let mut depends: Vec<String> = Vec::new();

    for line in block.lines() {
        if line.len() < 2 {
            continue;
        }
        let prefix = &line[0..2];
        let value = line[2..].trim();
        match prefix {
            "P:" => name = Some(value.to_string()),
            "V:" => version = Some(value.to_string()),
            "L:" => license = Some(value.to_string()),
            "D:" => {
                for dep in value.split(' ') {
                    let dep_name = dep.split(|c: char| c.is_ascii_punctuation() && c != '-' && c != '.' && c != '_').next().unwrap_or("").trim();
                    if !dep_name.is_empty() && dep_name.len() > 1 {
                        depends.push(dep_name.to_string());
                    }
                }
            }
            _ => {}
        }
    }

    match (name, version) {
        (Some(n), Some(v)) if !n.is_empty() && !v.is_empty() => Some(Package {
            name: n,
            version: v,
            package_manager: PackageManager::Apk,
            install_path: "/".to_string(),
            license,
            purl: None,
            dependencies: depends,
        }),
        _ => None,
    }
}

fn parse_python_metadata(content: &str, info_dir: &Path) -> Option<Package> {
    let mut name = None;
    let mut version = None;
    let mut license = None;
    let mut requires_dist: Vec<String> = Vec::new();

    for line in content.lines() {
        if let Some((key, value)) = line.split_once(':') {
            let key = key.trim();
            let value = value.trim();
            match key {
                "Name" => name = Some(value.to_string()),
                "Version" => version = Some(value.to_string()),
                "License" => license = Some(value.to_string()).filter(|s| !s.is_empty()),
                "Classifier" if value.contains("License ::") => {
                    if license.is_none() {
                        if let Some(last) = value.split(" :: ").last() {
                            license = Some(last.to_string());
                        }
                    }
                }
                "Requires-Dist" => {
                    let dep_name = value.split(|c: char| c.is_ascii_punctuation() && c != '-' && c != '.' && c != '_').next().unwrap_or("").trim();
                    if !dep_name.is_empty() {
                        requires_dist.push(dep_name.to_string());
                    }
                }
                _ => {}
            }
        }
    }

    match (name, version) {
        (Some(n), Some(v)) if !n.is_empty() && !v.is_empty() => Some(Package {
            name: n,
            version: v,
            package_manager: PackageManager::Pip,
            install_path: info_dir.to_string_lossy().to_string(),
            license,
            purl: None,
            dependencies: requires_dist,
        }),
        _ => None,
    }
}

fn parse_package_json_deps(pj_path: &Path) -> Result<Vec<(String, String, PathBuf)>> {
    let content = std::fs::read_to_string(pj_path)?;
    let json: serde_json::Value = serde_json::from_str(&content)?;

    let mut deps = Vec::new();

    for dep_type in &["dependencies", "devDependencies", "peerDependencies", "optionalDependencies"] {
        if let Some(dep_obj) = json.get(dep_type).and_then(|d| d.as_object()) {
            for (name, version_val) in dep_obj {
                if let Some(version) = version_val.as_str() {
                    let clean_version = version.trim_start_matches('^').trim_start_matches('~').trim_start_matches('=').trim_start_matches('>').trim_start_matches('<').trim_start_matches('*');
                    let clean_version = clean_version.split('|').next().unwrap_or("0.0.0").trim();
                    if !clean_version.is_empty() && clean_version != "*" {
                        deps.push((name.clone(), clean_version.to_string(), pj_path.to_path_buf()));
                    }
                }
            }
        }
    }

    if let Some(name) = json.get("name").and_then(|n| n.as_str()) {
        if let Some(version) = json.get("version").and_then(|v| v.as_str()) {
            deps.push((name.to_string(), version.to_string(), pj_path.to_path_buf()));
        }
    }

    Ok(deps)
}

fn parse_go_sum(content: &str, source: &Path) -> Vec<Package> {
    let mut packages = Vec::new();
    let mut seen: HashMap<String, ()> = HashMap::new();

    for line in content.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 {
            let name = parts[0];
            let version = parts[1].trim_end_matches("/go.mod");
            let key = format!("{}:{}", name, version);
            if seen.insert(key, ()).is_none() {
                packages.push(Package {
                    name: name.to_string(),
                    version: version.trim_start_matches('v').to_string(),
                    package_manager: PackageManager::Go,
                    install_path: source.parent().map(|p| p.to_string_lossy().to_string()).unwrap_or_default(),
                    license: None,
                    purl: None,
                    dependencies: Vec::new(),
                });
            }
        }
    }

    packages
}

fn parse_go_vendor_modules(content: &str, source: &Path) -> Vec<Package> {
    let mut packages = Vec::new();

    for line in content.lines() {
        if line.starts_with("# ") {
            let parts: Vec<&str> = line[2..].split_whitespace().collect();
            if parts.len() >= 2 {
                packages.push(Package {
                    name: parts[0].to_string(),
                    version: parts[1].trim_start_matches('v').to_string(),
                    package_manager: PackageManager::Go,
                    install_path: source.parent().map(|p| p.to_string_lossy().to_string()).unwrap_or_default(),
                    license: None,
                    purl: None,
                    dependencies: Vec::new(),
                });
            }
        }
    }

    packages
}

fn parse_maven_pom(pom_path: &Path) -> Result<Vec<Package>> {
    let content = std::fs::read_to_string(pom_path)?;
    let mut packages = Vec::new();

    let _re_project = regex::Regex::new(r"<project>[\s\S]*?</project>").ok();
    let re_group = regex::Regex::new(r"<groupId>([^<]+)</groupId>").ok();
    let re_artifact = regex::Regex::new(r"<artifactId>([^<]+)</artifactId>").ok();
    let re_version = regex::Regex::new(r"<version>([^<]+)</version>").ok();
    let re_dep = regex::Regex::new(r"<dependency>[\s\S]*?</dependency>").ok();

    let (_, parent_group, parent_version) = if let (Some(rg), Some(ra), Some(rv)) = (re_group.as_ref(), re_artifact.as_ref(), re_version.as_ref()) {
        let root_content = if let Some(rd) = re_dep.as_ref() {
            rd.replace_all(&content, "").to_string()
        } else {
            content.clone()
        };
        let group = rg.captures(&root_content).and_then(|c| c.get(1)).map(|m| m.as_str().to_string());
        let artifact = ra.captures(&root_content).and_then(|c| c.get(1)).map(|m| m.as_str().to_string());
        let version = rv.captures(&root_content).and_then(|c| c.get(1)).map(|m| m.as_str().to_string());
        (artifact, group, version)
    } else {
        (None, None, None)
    };

    if let (Some(rg), Some(ra), Some(rv), Some(rd)) = (re_group, re_artifact, re_version, re_dep) {
        for dep_match in rd.find_iter(&content) {
            let dep_str = dep_match.as_str();
            let group = rg.captures(dep_str).and_then(|c| c.get(1)).map(|m| m.as_str().to_string()).or(parent_group.clone());
            let artifact = ra.captures(dep_str).and_then(|c| c.get(1)).map(|m| m.as_str().to_string());
            let version = rv.captures(dep_str).and_then(|c| c.get(1)).map(|m| m.as_str().to_string()).or(parent_version.clone());

            if let (Some(a), Some(v)) = (artifact, version) {
                packages.push(Package {
                    name: if let Some(g) = group.as_ref() { format!("{}:{}", g, a) } else { a.clone() },
                    version: v,
                    package_manager: PackageManager::Maven,
                    install_path: pom_path.parent().map(|p| p.to_string_lossy().to_string()).unwrap_or_default(),
                    license: None,
                    purl: None,
                    dependencies: Vec::new(),
                });
            }
        }
    }

    Ok(packages)
}

fn parse_maven_properties(props_path: &Path) -> Result<Vec<Package>> {
    let content = std::fs::read_to_string(props_path)?;
    let mut group_id = None;
    let mut artifact_id = None;
    let mut version = None;

    for line in content.lines() {
        if let Some((key, value)) = line.split_once('=') {
            match key.trim() {
                "groupId" => group_id = Some(value.trim().to_string()),
                "artifactId" => artifact_id = Some(value.trim().to_string()),
                "version" => version = Some(value.trim().to_string()),
                _ => {}
            }
        }
    }

    match (group_id, artifact_id, version) {
        (Some(_g), Some(a), Some(v)) => Ok(vec![Package {
            name: a,
            version: v,
            package_manager: PackageManager::Maven,
            install_path: props_path.parent().map(|p| p.to_string_lossy().to_string()).unwrap_or_default(),
            license: None,
            purl: None,
            dependencies: Vec::new(),
        }]),
        _ => Ok(Vec::new()),
    }
}
