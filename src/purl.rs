use crate::types::{Package, PackageManager};
use urlencoding::encode;

pub fn generate_purl(pkg: &Package) -> String {
    let package_type = match pkg.package_manager {
        PackageManager::Apt => "deb",
        PackageManager::Rpm => "rpm",
        PackageManager::Apk => "apk",
        PackageManager::Pip => "pypi",
        PackageManager::Npm => "npm",
        PackageManager::Go => "golang",
        PackageManager::Cargo => "cargo",
        PackageManager::Maven => "maven",
    };

    let namespace = match pkg.package_manager {
        PackageManager::Apt => Some("debian"),
        PackageManager::Apk => Some("alpine"),
        _ => None,
    };

    let encoded_name = encode(&pkg.name);
    let encoded_version = encode(&pkg.version);

    match namespace {
        Some(ns) => format!("pkg:{}%2F{}/{}@{}", package_type, ns, encoded_name, encoded_version),
        None => format!("pkg:{}/{}@{}", package_type, encoded_name, encoded_version),
    }
}

pub fn purl_for_manager(name: &str, version: &str, pm: &PackageManager) -> String {
    let pkg = Package {
        name: name.to_string(),
        version: version.to_string(),
        package_manager: pm.clone(),
        install_path: String::new(),
        license: None,
        purl: None,
        dependencies: Vec::new(),
    };
    generate_purl(&pkg)
}
