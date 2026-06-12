use crate::types::{ImageInfo, Package, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

const BOM_FORMAT: &str = "CycloneDX";
const SPEC_VERSION: &str = "1.5";
const SPDX_VERSION: &str = "SPDX-2.3";
const DATA_LICENSE: &str = "CC0-1.0";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CycloneDxBom {
    bom_format: String,
    spec_version: String,
    serial_number: Option<String>,
    version: u32,
    metadata: CycloneDxMetadata,
    components: Vec<CycloneDxComponent>,
    dependencies: Vec<CycloneDxDependency>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CycloneDxMetadata {
    timestamp: String,
    tools: Vec<CycloneDxTool>,
    component: Option<CycloneDxComponent>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CycloneDxTool {
    vendor: String,
    name: String,
    version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CycloneDxComponent {
    #[serde(rename = "type")]
    component_type: String,
    name: String,
    version: Option<String>,
    purl: Option<String>,
    licenses: Option<Vec<CycloneDxLicenseWrapper>>,
    hashes: Option<Vec<CycloneDxHash>>,
    scope: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CycloneDxLicenseWrapper {
    license: CycloneDxLicense,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CycloneDxLicense {
    id: Option<String>,
    name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CycloneDxHash {
    alg: String,
    content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CycloneDxDependency {
    #[serde(rename = "ref")]
    ref_field: String,
    depends_on: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SpdxDocument {
    spdx_version: String,
    data_license: String,
    #[serde(rename = "SPDXID")]
    spdxid: String,
    name: String,
    document_namespace: String,
    creation_info: SpdxCreationInfo,
    packages: Vec<SpdxPackage>,
    relationships: Vec<SpdxRelationship>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SpdxCreationInfo {
    created: String,
    creators: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SpdxPackage {
    #[serde(rename = "SPDXID")]
    spdxid: String,
    name: String,
    version_info: Option<String>,
    download_location: String,
    license_concluded: String,
    license_declared: String,
    supplier: String,
    package_verification_code: Option<SpdxPkgVerification>,
    external_refs: Option<Vec<SpdxExternalRef>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SpdxPkgVerification {
    package_verification_code_value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SpdxExternalRef {
    reference_category: String,
    reference_type: String,
    reference_locator: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SpdxRelationship {
    spdx_element_id: String,
    relationship_type: String,
    related_spdx_element: String,
}

pub fn generate_cyclonedx(
    image: &ImageInfo,
    packages: &[Package],
    scan_time: DateTime<Utc>,
) -> Result<serde_json::Value> {
    let serial_number = format!("urn:uuid:{}", uuid::Uuid::new_v4());

    let image_component = CycloneDxComponent {
        component_type: "container".to_string(),
        name: image.name.clone(),
        version: Some(image.tag.clone()),
        purl: Some(format!(
            "pkg:oci/{}@{}?arch={}&os={}",
            image.name,
            image.digest.as_deref().unwrap_or(&image.tag),
            image.architecture,
            image.os
        )),
        licenses: None,
        hashes: None,
        scope: Some("required".to_string()),
    };

    let metadata = CycloneDxMetadata {
        timestamp: scan_time.to_rfc3339(),
        tools: vec![CycloneDxTool {
            vendor: "ImageScanCLI".to_string(),
            name: "image-scan".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        }],
        component: Some(image_component),
    };

    let mut components = Vec::new();
    let mut dependencies = Vec::new();
    let mut package_refs: HashMap<String, String> = HashMap::new();

    for (idx, pkg) in packages.iter().enumerate() {
        let purl = pkg.purl.clone().unwrap_or_else(|| {
            format!("pkg:generic/{}@{}", pkg.name, pkg.version)
        });
        let component_ref = format!("pkg-{}-{}", idx, purl_to_id(&purl));
        package_refs.insert(format!("{}:{}", pkg.name, pkg.version), component_ref.clone());

        let licenses = pkg.license.clone().map(|lic| {
            vec![CycloneDxLicenseWrapper {
                license: CycloneDxLicense {
                    id: if is_spdx_license_id(&lic) { Some(lic.clone()) } else { None },
                    name: if !is_spdx_license_id(&lic) { Some(lic.clone()) } else { None },
                },
            }]
        });

        let hashes = Some(vec![
            CycloneDxHash {
                alg: "SHA-256".to_string(),
                content: compute_sha256(&format!("{}:{}", pkg.name, pkg.version)),
            }
        ]);

        components.push(CycloneDxComponent {
            component_type: "library".to_string(),
            name: pkg.name.clone(),
            version: Some(pkg.version.clone()),
            purl: Some(purl),
            licenses,
            hashes,
            scope: Some("required".to_string()),
        });

        if !pkg.dependencies.is_empty() {
            let mut depends_on = Vec::new();
            for dep_name in &pkg.dependencies {
                if let Some(dep_ref) = find_package_ref(dep_name, packages, &package_refs) {
                    depends_on.push(dep_ref);
                }
            }
            if !depends_on.is_empty() {
                dependencies.push(CycloneDxDependency {
                    ref_field: component_ref,
                    depends_on,
                });
            }
        }
    }

    let bom = CycloneDxBom {
        bom_format: BOM_FORMAT.to_string(),
        spec_version: SPEC_VERSION.to_string(),
        serial_number: Some(serial_number),
        version: 1,
        metadata,
        components,
        dependencies,
    };

    Ok(serde_json::to_value(&bom)?)
}

pub fn generate_spdx(
    image: &ImageInfo,
    packages: &[Package],
    scan_time: DateTime<Utc>,
) -> Result<serde_json::Value> {
    let doc_namespace = format!(
        "https://imagescan.example.org/spdx/{}-{}",
        image.name,
        uuid::Uuid::new_v4()
    );

    let creation_info = SpdxCreationInfo {
        created: scan_time.to_rfc3339(),
        creators: vec![
            format!("Tool: image-scan-{}", env!("CARGO_PKG_VERSION")),
            "Organization: ImageScanCLI".to_string(),
        ],
    };

    let mut spdx_packages = Vec::new();
    let mut relationships = Vec::new();
    let mut package_ids: HashMap<String, String> = HashMap::new();

    let image_spdx_id = "SPDXRef-Image".to_string();
    spdx_packages.push(SpdxPackage {
        spdxid: image_spdx_id.clone(),
        name: format!("{}:{}", image.name, image.tag),
        version_info: Some(image.tag.clone()),
        download_location: if let Some(d) = &image.digest {
            format!("sha256:{}", d.trim_start_matches("sha256:"))
        } else {
            "NOASSERTION".to_string()
        },
        license_concluded: "NOASSERTION".to_string(),
        license_declared: "NOASSERTION".to_string(),
        supplier: "NOASSERTION".to_string(),
        package_verification_code: None,
        external_refs: Some(vec![
            SpdxExternalRef {
                reference_category: "PACKAGE-MANAGER".to_string(),
                reference_type: "purl".to_string(),
                reference_locator: format!(
                    "pkg:oci/{}@{}?arch={}&os={}",
                    image.name,
                    image.digest.as_deref().unwrap_or(&image.tag),
                    image.architecture,
                    image.os
                ),
            }
        ]),
    });

    for (idx, pkg) in packages.iter().enumerate() {
        let spdx_id = format!("SPDXRef-Package-{}", idx + 1);
        let pkg_key = format!("{}:{}", pkg.name, pkg.version);
        package_ids.insert(pkg_key, spdx_id.clone());

        let license = pkg.license.clone().unwrap_or_else(|| "NOASSERTION".to_string());

        let purl = pkg.purl.clone().unwrap_or_else(|| {
            format!("pkg:generic/{}@{}", pkg.name, pkg.version)
        });

        let verification = SpdxPkgVerification {
            package_verification_code_value: compute_sha256(&format!(
                "{}:{}:{}",
                pkg.name, pkg.version, pkg.package_manager
            )),
        };

        spdx_packages.push(SpdxPackage {
            spdxid: spdx_id.clone(),
            name: pkg.name.clone(),
            version_info: Some(pkg.version.clone()),
            download_location: "NOASSERTION".to_string(),
            license_concluded: license.clone(),
            license_declared: license,
            supplier: "NOASSERTION".to_string(),
            package_verification_code: Some(verification),
            external_refs: Some(vec![
                SpdxExternalRef {
                    reference_category: "PACKAGE-MANAGER".to_string(),
                    reference_type: "purl".to_string(),
                    reference_locator: purl,
                }
            ]),
        });

        relationships.push(SpdxRelationship {
            spdx_element_id: image_spdx_id.clone(),
            relationship_type: "CONTAINS".to_string(),
            related_spdx_element: spdx_id.clone(),
        });

        for dep_name in &pkg.dependencies {
            if let Some(dep_id) = find_spdx_package_id(dep_name, packages, &package_ids) {
                relationships.push(SpdxRelationship {
                    spdx_element_id: spdx_id.clone(),
                    relationship_type: "DEPENDS_ON".to_string(),
                    related_spdx_element: dep_id,
                });
            }
        }
    }

    let doc = SpdxDocument {
        spdx_version: SPDX_VERSION.to_string(),
        data_license: DATA_LICENSE.to_string(),
        spdxid: "SPDXRef-DOCUMENT".to_string(),
        name: format!("{}:{}", image.name, image.tag),
        document_namespace: doc_namespace,
        creation_info: creation_info,
        packages: spdx_packages,
        relationships,
    };

    Ok(serde_json::to_value(&doc)?)
}

fn purl_to_id(purl: &str) -> String {
    let hash = compute_sha256(purl);
    hash[0..12].to_string()
}

fn compute_sha256(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let result = hasher.finalize();
    hex::encode(result)
}

fn is_spdx_license_id(lic: &str) -> bool {
    matches!(
        lic.to_uppercase().as_str(),
        "MIT" | "Apache-2.0" | "GPL-2.0" | "GPL-3.0" | "LGPL-2.1" | "LGPL-3.0"
        | "BSD-2-CLAUSE" | "BSD-3-CLAUSE" | "MPL-2.0" | "ISC" | "UNLICENSE"
        | "ZLIB" | "ARTISTIC-2.0" | "CC0-1.0" | "CC-BY-4.0" | "EPL-2.0"
    )
}

fn find_package_ref(
    dep_name: &str,
    packages: &[Package],
    refs: &HashMap<String, String>,
) -> Option<String> {
    let dep_name_lower = dep_name.to_lowercase();
    for pkg in packages {
        if pkg.name.to_lowercase() == dep_name_lower {
            let key = format!("{}:{}", pkg.name, pkg.version);
            return refs.get(&key).cloned();
        }
    }
    None
}

fn find_spdx_package_id(
    dep_name: &str,
    packages: &[Package],
    ids: &HashMap<String, String>,
) -> Option<String> {
    let dep_name_lower = dep_name.to_lowercase();
    for pkg in packages {
        if pkg.name.to_lowercase() == dep_name_lower {
            let key = format!("{}:{}", pkg.name, pkg.version);
            return ids.get(&key).cloned();
        }
    }
    None
}

pub fn generate_fix_suggestions(
    vulns: &[crate::types::Vulnerability],
) -> Vec<FixSuggestion> {
    let mut grouped: HashMap<String, FixSuggestion> = HashMap::new();

    for vuln in vulns {
        if let Some(fix) = &vuln.fix_version {
            let key = format!("{}:{}", vuln.package_manager, vuln.package_name);
            let suggestion = grouped.entry(key).or_insert_with(|| FixSuggestion {
                package_name: vuln.package_name.clone(),
                package_manager: vuln.package_manager.clone(),
                current_version: vuln.package_version.clone(),
                suggested_version: fix.clone(),
                fixed_cves: Vec::new(),
                total_cvss: 0.0,
                max_severity: crate::types::Severity::Unknown,
            });

            suggestion.fixed_cves.push(vuln.cve_id.clone());
            suggestion.total_cvss += vuln.effective_score();
            if vuln.severity.order() > suggestion.max_severity.order() {
                suggestion.max_severity = vuln.severity.clone();
            }

            if crate::version::compare_versions(fix, &suggestion.suggested_version, &vuln.package_manager)
                == std::cmp::Ordering::Less
            {
                suggestion.suggested_version = fix.clone();
            }
        }
    }

    let mut result: Vec<FixSuggestion> = grouped.into_values().collect();
    result.sort_by(|a, b| {
        b.max_severity.order().cmp(&a.max_severity.order())
            .then(b.total_cvss.partial_cmp(&a.total_cvss).unwrap_or(std::cmp::Ordering::Equal))
    });
    result
}

#[derive(Debug, Clone, Serialize)]
pub struct FixSuggestion {
    pub package_name: String,
    pub package_manager: crate::types::PackageManager,
    pub current_version: String,
    pub suggested_version: String,
    pub fixed_cves: Vec<String>,
    pub total_cvss: f64,
    pub max_severity: crate::types::Severity,
}
