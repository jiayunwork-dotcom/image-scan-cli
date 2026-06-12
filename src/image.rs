use crate::types::{ImageInfo, ImageSource, LayerInfo, RegistryAuth, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use tokio::fs;
use tokio::io::AsyncWriteExt;
use indicatif::{ProgressBar, ProgressStyle};

#[derive(Debug, Serialize, Deserialize)]
struct OciManifest {
    schemaVersion: u32,
    mediaType: Option<String>,
    #[serde(rename = "manifests")]
    manifests: Option<Vec<OciManifestRef>>,
    config: Option<OciDescriptor>,
    layers: Option<Vec<OciDescriptor>>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct OciManifestRef {
    mediaType: String,
    digest: String,
    size: u64,
    platform: Option<OciPlatform>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct OciPlatform {
    architecture: String,
    os: String,
    #[serde(rename = "os.version")]
    os_version: Option<String>,
    variant: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct OciDescriptor {
    mediaType: String,
    digest: String,
    size: u64,
}

#[derive(Debug, Serialize, Deserialize)]
struct OciImageConfig {
    architecture: String,
    os: String,
    created: Option<String>,
    config: Option<OciRuntimeConfig>,
    rootfs: OciRootfs,
    history: Option<Vec<OciHistory>>,
}

#[derive(Debug, Serialize, Deserialize)]
struct OciRuntimeConfig {
    Env: Option<Vec<String>>,
    Cmd: Option<Vec<String>>,
    Labels: Option<HashMap<String, String>>,
}

#[derive(Debug, Serialize, Deserialize)]
struct OciRootfs {
    #[serde(rename = "type")]
    fs_type: String,
    diff_ids: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct OciHistory {
    created: Option<String>,
    created_by: Option<String>,
    comment: Option<String>,
    empty_layer: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize)]
struct DockerManifestEntry {
    Config: String,
    RepoTags: Vec<String>,
    Layers: Vec<String>,
}

pub struct ImageExtractor {
    cache_dir: PathBuf,
}

impl ImageExtractor {
    pub fn new(cache_dir: PathBuf) -> Self {
        ImageExtractor { cache_dir }
    }

    pub async fn extract(&self, source: &ImageSource) -> Result<(ImageInfo, PathBuf)> {
        fs::create_dir_all(&self.cache_dir).await?;
        let temp = tempfile::tempdir()?;
        let work_dir = temp.path().to_path_buf();
        std::mem::forget(temp);

        let image_info = match source {
            ImageSource::Registry { image, auth } => {
                self.extract_from_registry(image, auth.clone(), &work_dir).await?
            }
            ImageSource::Tar { path } => {
                self.extract_from_tar(path, &work_dir).await?
            }
            ImageSource::Oci { path } => {
                self.extract_from_oci(path, &work_dir).await?
            }
        };

        Ok((image_info, work_dir))
    }

    async fn extract_from_registry(
        &self,
        image_ref: &str,
        auth: Option<RegistryAuth>,
        work_dir: &Path,
    ) -> Result<ImageInfo> {
        let (registry, repo, tag) = parse_image_reference(image_ref);

        let token = get_registry_token(&registry, &repo, auth.clone()).await?;

        let manifest_url = format!("https://{}/v2/{}/manifests/{}", registry, repo, tag);
        let manifest = fetch_manifest(&manifest_url, &token).await?;

        let (manifest_digest, actual_manifest) = match manifest.manifests {
            Some(manifest_list) => {
                let selected = select_platform_manifest(&manifest_list, "linux", "amd64")
                    .ok_or_else(|| anyhow::anyhow!("No linux/amd64 manifest found"))?;

                let digest = selected.digest.clone();
                let sub_manifest_url = format!(
                    "https://{}/v2/{}/manifests/{}",
                    registry, repo, digest
                );
                let sub_manifest = fetch_manifest(&sub_manifest_url, &token).await?;
                (Some(digest), sub_manifest)
            }
            None => (None, manifest),
        };

        let layers = actual_manifest.layers.clone().unwrap_or_default();
        let config = actual_manifest.config.clone()
            .ok_or_else(|| anyhow::anyhow!("No config in manifest"))?;

        let layers_dir = work_dir.join("layers");
        fs::create_dir_all(&layers_dir).await?;

        let total_size: u64 = layers.iter().map(|l| l.size).sum();
        let pb = if total_size > 2 * 1024 * 1024 * 1024 {
            let pb = ProgressBar::new(total_size);
            pb.set_style(ProgressStyle::with_template(
                "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta})"
            ).unwrap().progress_chars("#>-"));
            Some(pb)
        } else {
            None
        };

        let mut layer_infos = Vec::new();
        for (idx, layer) in layers.iter().enumerate() {
            let layer_path = self.cache_dir.join(layer.digest.replace(":", "_"));
            if !layer_path.exists() {
                let blob_url = format!(
                    "https://{}/v2/{}/blobs/{}",
                    registry, repo, layer.digest
                );
                download_blob(&blob_url, &token, &layer_path, pb.as_ref()).await?;
            } else if let Some(pb) = &pb {
                pb.inc(layer.size);
            }

            let extract_dir = layers_dir.join(format!("layer_{:03}", idx));
            fs::create_dir_all(&extract_dir).await?;
            extract_layer_archive(&layer_path, &extract_dir)?;

            layer_infos.push(LayerInfo {
                digest: layer.digest.clone(),
                size: layer.size,
                media_type: layer.mediaType.clone(),
            });
        }

        if let Some(pb) = pb {
            pb.finish_with_message("Layers downloaded");
        }

        let config_url = format!(
            "https://{}/v2/{}/blobs/{}",
            registry, repo, config.digest
        );
        let config_data = fetch_blob_data(&config_url, &token).await?;
        let image_config: OciImageConfig = serde_json::from_slice(&config_data)?;

        Ok(ImageInfo {
            reference: image_ref.to_string(),
            name: repo.split('/').last().unwrap_or(&repo).to_string(),
            tag: if tag.contains("sha256:") { "latest".to_string() } else { tag.clone() },
            digest: manifest_digest,
            architecture: image_config.architecture,
            os: image_config.os,
            layers: layer_infos,
            created: image_config.created.and_then(|c| chrono::DateTime::parse_from_rfc3339(&c).ok().map(|d| d.with_timezone(&chrono::Utc))),
        })
    }

    async fn extract_from_tar(&self, tar_path: &Path, work_dir: &Path) -> Result<ImageInfo> {
        let file = std::fs::File::open(tar_path)?;
        let mut archive = tar::Archive::new(file);

        let _manifest_json_path = work_dir.join("manifest.json");
        let layers_dir = work_dir.join("layers");
        fs::create_dir_all(&layers_dir).await?;

        let entries: Vec<tar::Entry<_>> = archive.entries()?.filter_map(|e| e.ok()).collect();

        let mut manifest_content: Option<String> = None;
        let mut layer_data: HashMap<String, Vec<u8>> = HashMap::new();

        for entry in entries {
            let path = entry.path()?.to_path_buf();
            let data = entry.bytes().filter_map(|b| b.ok()).collect::<Vec<u8>>();

            if path.ends_with("manifest.json") {
                manifest_content = Some(String::from_utf8_lossy(&data).to_string());
            } else {
                let path_str = path.to_string_lossy().to_string();
                if path_str.ends_with(".tar") || path_str.ends_with(".tar.gz") || path_str.ends_with("layer.tar") {
                    layer_data.insert(path_str, data);
                }
            }
        }

        let manifest_content = manifest_content
            .ok_or_else(|| anyhow::anyhow!("manifest.json not found in tar"))?;
        let docker_manifests: Vec<DockerManifestEntry> = serde_json::from_str(&manifest_content)?;
        let docker_manifest = docker_manifests.first()
            .ok_or_else(|| anyhow::anyhow!("No manifest entries found"))?;

        let repo_tag = docker_manifest.RepoTags.first()
            .map(|t| t.clone())
            .unwrap_or_else(|| "unknown:latest".to_string());
        let (name, tag) = parse_repo_tag(&repo_tag);

        let mut layer_infos = Vec::new();
        for (idx, layer_path_str) in docker_manifest.Layers.iter().enumerate() {
            let extract_dir = layers_dir.join(format!("layer_{:03}", idx));
            fs::create_dir_all(&extract_dir).await?;

            if let Some(data) = layer_data.get(layer_path_str) {
                let temp_path = work_dir.join(format!("temp_layer_{:03}.tar", idx));
                fs::write(&temp_path, data).await?;
                extract_layer_archive(&temp_path, &extract_dir)?;
                let _ = fs::remove_file(&temp_path).await;

                layer_infos.push(LayerInfo {
                    digest: format!("sha256:{}", sha256_hash(data)),
                    size: data.len() as u64,
                    media_type: "application/vnd.docker.image.rootfs.diff.tar".to_string(),
                });
            }
        }

        Ok(ImageInfo {
            reference: tar_path.to_string_lossy().to_string(),
            name,
            tag,
            digest: None,
            architecture: "amd64".to_string(),
            os: "linux".to_string(),
            layers: layer_infos,
            created: None,
        })
    }

    async fn extract_from_oci(&self, oci_path: &Path, work_dir: &Path) -> Result<ImageInfo> {
        let index_path = oci_path.join("index.json");
        let index_content = fs::read_to_string(&index_path).await?;
        let index: OciManifest = serde_json::from_str(&index_content)?;

        let manifest_ref = match index.manifests {
            Some(refs) => {
                select_platform_manifest(&refs, "linux", "amd64")
                    .ok_or_else(|| anyhow::anyhow!("No linux/amd64 manifest in OCI index"))?
                    .clone()
            }
            None => {
                return Err(anyhow::anyhow!("OCI index.json has no manifests"));
            }
        };

        let manifest_path = oci_path.join("blobs").join(blob_digest_to_path(&manifest_ref.digest));
        let manifest_content = fs::read_to_string(&manifest_path).await?;
        let manifest: OciManifest = serde_json::from_str(&manifest_content)?;

        let layers = manifest.layers.ok_or_else(|| anyhow::anyhow!("No layers in manifest"))?;
        let layers_dir = work_dir.join("layers");
        fs::create_dir_all(&layers_dir).await?;

        let mut layer_infos = Vec::new();
        for (idx, layer) in layers.iter().enumerate() {
            let blob_path = oci_path.join("blobs").join(blob_digest_to_path(&layer.digest));
            let extract_dir = layers_dir.join(format!("layer_{:03}", idx));
            fs::create_dir_all(&extract_dir).await?;
            extract_layer_archive(&blob_path, &extract_dir)?;

            layer_infos.push(LayerInfo {
                digest: layer.digest.clone(),
                size: layer.size,
                media_type: layer.mediaType.clone(),
            });
        }

        let config = manifest.config.ok_or_else(|| anyhow::anyhow!("No config in manifest"))?;
        let config_path = oci_path.join("blobs").join(blob_digest_to_path(&config.digest));
        let config_content = fs::read_to_string(&config_path).await?;
        let image_config: OciImageConfig = serde_json::from_str(&config_content)?;

        Ok(ImageInfo {
            reference: oci_path.to_string_lossy().to_string(),
            name: oci_path.file_name()
                .map(|f| f.to_string_lossy().to_string())
                .unwrap_or_else(|| "unknown".to_string()),
            tag: "latest".to_string(),
            digest: Some(manifest_ref.digest),
            architecture: image_config.architecture,
            os: image_config.os,
            layers: layer_infos,
            created: image_config.created.and_then(|c| chrono::DateTime::parse_from_rfc3339(&c).ok().map(|d| d.with_timezone(&chrono::Utc))),
        })
    }
}

fn parse_image_reference(image: &str) -> (String, String, String) {
    let parts: Vec<&str> = image.splitn(2, '/').collect();
    let (registry, rest) = if parts.len() == 2 && (parts[0].contains('.') || parts[0].contains(':')) {
        (parts[0].to_string(), parts[1])
    } else {
        ("registry-1.docker.io".to_string(), image)
    };

    let rest_parts: Vec<&str> = rest.rsplitn(2, ':').collect();
    let (repo, tag) = if rest_parts.len() == 2 && !rest_parts[0].contains('/') {
        (rest_parts[1].to_string(), rest_parts[0].to_string())
    } else {
        (rest.to_string(), "latest".to_string())
    };

    (registry, repo, tag)
}

fn parse_repo_tag(repo_tag: &str) -> (String, String) {
    let parts: Vec<&str> = repo_tag.rsplitn(2, ':').collect();
    if parts.len() == 2 && !parts[0].contains('/') {
        (parts[1].to_string(), parts[0].to_string())
    } else {
        (repo_tag.to_string(), "latest".to_string())
    }
}

fn blob_digest_to_path(digest: &str) -> PathBuf {
    let digest = digest.trim_start_matches("sha256:");
    PathBuf::from("sha256").join(digest)
}

async fn get_registry_token(registry: &str, repo: &str, auth: Option<RegistryAuth>) -> Result<String> {
    let auth_url = if registry == "registry-1.docker.io" {
        format!(
            "https://auth.docker.io/token?service=registry.docker.io&scope=repository:{}:pull",
            repo
        )
    } else {
        format!(
            "https://{}/token?service={}&scope=repository:{}:pull",
            registry, registry, repo
        )
    };

    let client = reqwest::Client::new();
    let mut request = client.get(&auth_url);

    if let Some(auth) = auth {
        let credentials = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            format!("{}:{}", auth.username, auth.password),
        );
        request = request.header("Authorization", format!("Basic {}", credentials));
    }

    let response = request.send().await?;
    let json: serde_json::Value = response.json().await?;

    json["token"]
        .as_str()
        .or_else(|| json["access_token"].as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| anyhow::anyhow!("No token in auth response"))
}

async fn fetch_manifest(url: &str, token: &str) -> Result<OciManifest> {
    let client = reqwest::Client::new();
    let response = client
        .get(url)
        .header("Authorization", format!("Bearer {}", token))
        .header(
            "Accept",
            "application/vnd.oci.image.index.v1+json,\
             application/vnd.oci.image.manifest.v1+json,\
             application/vnd.docker.distribution.manifest.list.v2+json,\
             application/vnd.docker.distribution.manifest.v2+json",
        )
        .send()
        .await?;

    if !response.status().is_success() {
        return Err(anyhow::anyhow!(
            "Failed to fetch manifest: {} {}",
            response.status(),
            url
        ));
    }

    let manifest: OciManifest = response.json().await?;
    Ok(manifest)
}

fn select_platform_manifest(
    manifests: &[OciManifestRef],
    target_os: &str,
    target_arch: &str,
) -> Option<OciManifestRef> {
    for m in manifests {
        if let Some(platform) = &m.platform {
            if platform.os == target_os && platform.architecture == target_arch {
                return Some(m.clone());
            }
        }
    }
    manifests.first().cloned()
}

async fn fetch_blob_data(url: &str, token: &str) -> Result<Vec<u8>> {
    let client = reqwest::Client::new();
    let response = client
        .get(url)
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .await?;

    if !response.status().is_success() {
        return Err(anyhow::anyhow!("Failed to fetch blob: {}", response.status()));
    }

    Ok(response.bytes().await?.to_vec())
}

async fn download_blob(
    url: &str,
    token: &str,
    dest: &Path,
    pb: Option<&ProgressBar>,
) -> Result<()> {
    let client = reqwest::Client::new();
    let response = client
        .get(url)
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .await?;

    if !response.status().is_success() {
        return Err(anyhow::anyhow!("Failed to download blob: {}", response.status()));
    }

    let mut file = fs::File::create(dest).await?;
    let mut stream = response.bytes_stream();

    use futures::StreamExt;
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        file.write_all(&chunk).await?;
        if let Some(pb) = pb {
            pb.inc(chunk.len() as u64);
        }
    }
    file.flush().await?;

    Ok(())
}

fn extract_layer_archive(archive_path: &Path, dest: &Path) -> Result<()> {
    use std::fs::File;
    use std::io::BufReader;

    let file = File::open(archive_path)?;
    let path_str = archive_path.to_string_lossy();

    if path_str.ends_with(".gz") || path_str.ends_with(".tgz") {
        let decoder = flate2::read::GzDecoder::new(BufReader::new(file));
        let mut archive = tar::Archive::new(decoder);
        archive.unpack(dest)?;
    } else if path_str.ends_with(".zst") || path_str.ends_with(".zstd") {
        let decoder = zstd::Decoder::new(BufReader::new(file))?;
        let mut archive = tar::Archive::new(decoder);
        archive.unpack(dest)?;
    } else {
        let mut archive = tar::Archive::new(BufReader::new(file));
        archive.unpack(dest)?;
    }

    Ok(())
}

fn sha256_hash(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

pub fn merge_layers(layers_dir: &Path, merged_dir: &Path) -> Result<()> {
    use std::collections::HashSet;
    use walkdir::WalkDir;

    std::fs::create_dir_all(merged_dir)?;

    let mut whiteouts: HashSet<String> = HashSet::new();

    let mut layer_dirs: Vec<_> = WalkDir::new(layers_dir)
        .max_depth(1)
        .min_depth(1)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_dir())
        .map(|e| e.path().to_path_buf())
        .collect();
    layer_dirs.sort();

    for layer_dir in &layer_dirs {
        let entries: Vec<_> = WalkDir::new(layer_dir)
            .into_iter()
            .filter_map(|e| e.ok())
            .collect();

        for entry in &entries {
            let path = entry.path();
            if let Some(file_name) = path.file_name() {
                let name = file_name.to_string_lossy();
                if name.starts_with(".wh.") {
                    let stripped = name.trim_start_matches(".wh.");
                    let parent = path.parent().unwrap_or(layer_dir);
                    let relative = parent.strip_prefix(layer_dir)
                        .unwrap_or(std::path::Path::new(""));
                    let whiteout_path = relative.join(stripped);
                    whiteouts.insert(whiteout_path.to_string_lossy().to_string());
                    continue;
                }
            }

            let relative = path.strip_prefix(layer_dir)
                .unwrap_or(std::path::Path::new(""));

            if !relative.as_os_str().is_empty() {
                let relative_str = relative.to_string_lossy().to_string();
                if whiteouts.iter().any(|w| relative_str.starts_with(w)) {
                    continue;
                }
            }

            let dest_path = merged_dir.join(relative);

            if entry.file_type().is_dir() {
                std::fs::create_dir_all(&dest_path).ok();
            } else if entry.file_type().is_file() {
                if let Some(parent) = dest_path.parent() {
                    std::fs::create_dir_all(parent).ok();
                }
                std::fs::copy(path, &dest_path).ok();
            } else if entry.file_type().is_symlink() {
                if let Some(parent) = dest_path.parent() {
                    std::fs::create_dir_all(parent).ok();
                }
                if let Ok(target) = std::fs::read_link(path) {
                    std::os::unix::fs::symlink(target, &dest_path).ok();
                }
            }
        }

        let parent_dirs: Vec<_> = WalkDir::new(merged_dir)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_dir())
            .map(|e| e.path().to_path_buf())
            .collect();

        for parent in &parent_dirs {
            let relative = match parent.strip_prefix(merged_dir) {
                Ok(r) => r.to_string_lossy().to_string(),
                Err(_) => continue,
            };
            if relative.is_empty() {
                continue;
            }

            let mut to_remove = Vec::new();
            for whiteout in &whiteouts {
                if let Some(stripped) = whiteout.strip_prefix(&format!("{}/", relative)) {
                    if !stripped.contains('/') {
                        to_remove.push(parent.join(stripped));
                    }
                } else if whiteout == &relative {
                    to_remove.push(parent.clone());
                }
            }

            for removal in to_remove {
                if removal.exists() {
                    if removal.is_dir() {
                        std::fs::remove_dir_all(&removal).ok();
                    } else {
                        std::fs::remove_file(&removal).ok();
                    }
                }
            }
        }
    }

    Ok(())
}
