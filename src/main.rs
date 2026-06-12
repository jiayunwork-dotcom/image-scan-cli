use clap::{Parser, Subcommand};
use image_scan_cli::*;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "image-scan",
    version,
    about = "Container image security vulnerability scanner and SBOM generator",
    long_about = None,
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    #[arg(short, long, global = true, help = "Enable verbose logging")]
    verbose: bool,

    #[arg(short, long, global = true, help = "Quiet mode - only output summary")]
    quiet: bool,

    #[arg(long, global = true, help = "Cache directory for layers and CVE database")]
    cache_dir: Option<PathBuf>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    #[command(about = "Scan a container image for vulnerabilities")]
    Scan(ScanArgs),

    #[command(about = "Generate SBOM from a container image")]
    Sbom(SbomArgs),

    #[command(about = "Update CVE database")]
    UpdateDb,

    #[command(about = "Show version information")]
    Version,
}

#[derive(Parser, Debug, Clone)]
struct ScanArgs {
    #[arg(
        short,
        long,
        help = "Image reference (e.g., nginx:latest, docker.io/library/nginx:latest)"
    )]
    image: Option<String>,

    #[arg(long, help = "Path to local tar archive (docker save format)")]
    tar: Option<PathBuf>,

    #[arg(long, help = "Path to OCI layout directory")]
    oci: Option<PathBuf>,

    #[arg(long, help = "Registry username")]
    username: Option<String>,

    #[arg(long, help = "Registry password or token")]
    password: Option<String>,

    #[arg(
        short,
        long,
        default_value = "table",
        help = "Output format: table|json|sarif|html|cyclonedx|spdx"
    )]
    format: String,

    #[arg(short, long, help = "Output file path (default: stdout)")]
    output: Option<PathBuf>,

    #[arg(long, help = "Policy YAML file path")]
    policy: Option<PathBuf>,

    #[arg(long, help = "Baseline scan JSON file for comparison")]
    baseline: Option<PathBuf>,

    #[arg(long, help = "Ignore unfixable vulnerabilities (no fix version available)")]
    ignore_unfixable: bool,

    #[arg(
        long,
        help = "Severity threshold for non-zero exit: critical|high|medium|low"
    )]
    severity_threshold: Option<String>,

    #[arg(long, help = "Output GitHub Actions annotations")]
    github_annotations: bool,

    #[arg(long, help = "Output directory for HTML report and JSON scan data")]
    output_dir: Option<PathBuf>,
}

#[derive(Parser, Debug, Clone)]
struct SbomArgs {
    #[arg(
        short,
        long,
        help = "Image reference (e.g., nginx:latest, docker.io/library/nginx:latest)"
    )]
    image: Option<String>,

    #[arg(long, help = "Path to local tar archive (docker save format)")]
    tar: Option<PathBuf>,

    #[arg(long, help = "Path to OCI layout directory")]
    oci: Option<PathBuf>,

    #[arg(long, help = "Registry username")]
    username: Option<String>,

    #[arg(long, help = "Registry password or token")]
    password: Option<String>,

    #[arg(
        short,
        long,
        default_value = "cyclonedx",
        help = "SBOM format: cyclonedx|spdx|json"
    )]
    format: String,

    #[arg(short, long, help = "Output file path (default: stdout)")]
    output: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    dotenvy::dotenv().ok();
    let log_level = if cli.verbose { "debug" } else { "info" };
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(log_level)).init();

    let cache_dir = cli
        .cache_dir
        .clone()
        .unwrap_or_else(|| {
            dirs::home_dir()
                .map(|h| h.join(".image-scan").join("cache"))
                .unwrap_or_else(|| PathBuf::from("/tmp/image-scan-cache"))
        });

    match cli.command {
        Commands::Scan(args) => {
            let exit_code = run_scan(args, cache_dir, cli.quiet).await?;
            std::process::exit(exit_code);
        }
        Commands::Sbom(args) => {
            run_sbom(args, cache_dir).await?;
        }
        Commands::UpdateDb => {
            run_update_db(cache_dir).await?;
        }
        Commands::Version => {
            println!("image-scan {}", env!("CARGO_PKG_VERSION"));
            println!("Container image security vulnerability scanner and SBOM generator");
        }
    }

    Ok(())
}

fn determine_image_source(
    image: &Option<String>,
    tar: &Option<PathBuf>,
    oci: &Option<PathBuf>,
    username: &Option<String>,
    password: &Option<String>,
) -> anyhow::Result<ImageSource> {
    let auth = match (username, password) {
        (Some(u), Some(p)) => Some(RegistryAuth {
            username: u.clone(),
            password: p.clone(),
        }),
        _ => None,
    };

    if let Some(tar_path) = tar {
        if !tar_path.exists() {
            return Err(anyhow::anyhow!("Tar file not found: {:?}", tar_path));
        }
        return Ok(ImageSource::Tar {
            path: tar_path.clone(),
        });
    }

    if let Some(oci_path) = oci {
        if !oci_path.exists() {
            return Err(anyhow::anyhow!("OCI directory not found: {:?}", oci_path));
        }
        return Ok(ImageSource::Oci {
            path: oci_path.clone(),
        });
    }

    if let Some(img) = image {
        return Ok(ImageSource::Registry {
            image: img.clone(),
            auth,
        });
    }

    Err(anyhow::anyhow!(
        "Must specify one of: --image, --tar, or --oci"
    ))
}

async fn run_scan(args: ScanArgs, cache_dir: PathBuf, quiet: bool) -> anyhow::Result<i32> {
    let source = determine_image_source(
        &args.image,
        &args.tar,
        &args.oci,
        &args.username,
        &args.password,
    )?;

    let policy = report::load_policy(args.policy.as_deref())?;

    if !quiet {
        eprintln!("{}", "🔍 Extracting image layers...".cyan());
    }
    let extractor = image::ImageExtractor::new(cache_dir.join("layers"));
    let (image_info, work_dir) = extractor.extract(&source).await?;

    if !quiet {
        eprintln!(
            "{}",
            format!("   Extracted {} layers to workspace", image_info.layers.len()).dimmed()
        );
    }

    let merged_dir = work_dir.join("merged");
    let layers_dir = work_dir.join("layers");
    image::merge_layers(&layers_dir, &merged_dir)?;

    if !quiet {
        eprintln!("{}", "📦 Detecting installed packages...".cyan());
    }
    let packages = {
        let merged_clone = merged_dir.clone();
        tokio::task::spawn_blocking(move || packages::PackageDetector::detect_all(&merged_clone))
            .await??
    };

    if !quiet {
        eprintln!(
            "{}",
            format!("   Found {} packages", packages.len()).dimmed()
        );
    }

    if !quiet {
        eprintln!("{}", "🔐 Matching known vulnerabilities...".cyan());
    }
    let cve_db = cve::CveDatabase::new(&cache_dir.join("cve")).await?;
    let mut vulnerabilities = cve_db.match_packages(&packages).await?;

    let threshold_from_policy = policy.severity_threshold.clone();
    let effective_threshold = args
        .severity_threshold
        .as_deref()
        .map(|s| match s.to_lowercase().as_str() {
            "critical" => Severity::Critical,
            "high" => Severity::High,
            "medium" => Severity::Medium,
            "low" => Severity::Low,
            _ => Severity::Unknown,
        })
        .or(threshold_from_policy);

    vulnerabilities = cve::apply_policy(vulnerabilities, &policy, args.ignore_unfixable);

    let scan_time = chrono::Utc::now();
    let scan_result = ScanResult {
        image: image_info.clone(),
        packages: packages.clone(),
        vulnerabilities: vulnerabilities.clone(),
        scan_time,
        scan_id: uuid::Uuid::new_v4(),
    };

    let summary = report::compute_summary(&scan_result);
    let suggestions = sbom::generate_fix_suggestions(&vulnerabilities);

    let baseline_diff = if let Some(baseline_path) = &args.baseline {
        match report::load_baseline(baseline_path) {
            Ok(baseline) => Some(report::baseline_compare(&vulnerabilities, &baseline)),
            Err(e) => {
                eprintln!("⚠️  Warning: Could not load baseline: {}", e);
                None
            }
        }
    } else {
        None
    };

    let license_warnings = report::check_license_blacklist(&packages, &policy.license_blacklist);
    for warning in &license_warnings {
        eprintln!("⚠️  License Warning: {}", warning);
    }

    let output_format = OutputFormat::from_str(&args.format);

    match output_format {
        OutputFormat::Table => {
            report::print_console_report(
                &scan_result,
                &summary,
                &suggestions,
                baseline_diff.as_ref(),
                quiet,
            );
        }
        OutputFormat::Json => {
            let json = report::format_json(&scan_result, &summary)?;
            write_output(&json, args.output.as_deref())?;
        }
        OutputFormat::Sarif => {
            let sarif = report::format_sarif(&scan_result)?;
            write_output(&sarif, args.output.as_deref())?;
        }
        OutputFormat::Html => {
            let html = report::format_html(&scan_result, &summary, &suggestions);
            write_output(&html, args.output.as_deref())?;
        }
        OutputFormat::CycloneDX => {
            let cyclone = sbom::generate_cyclonedx(&image_info, &packages, scan_time)?;
            let json = serde_json::to_string_pretty(&cyclone)?;
            write_output(&json, args.output.as_deref())?;
        }
        OutputFormat::SPDX => {
            let spdx = sbom::generate_spdx(&image_info, &packages, scan_time)?;
            let json = serde_json::to_string_pretty(&spdx)?;
            write_output(&json, args.output.as_deref())?;
        }
    }

    if args.github_annotations {
        report::emit_github_annotations(&vulnerabilities, quiet);
    }

    if let Some(ref output_dir) = args.output_dir {
        std::fs::create_dir_all(output_dir)?;
        let image_slug = image_info.name.replace(['/', ':', '@'], "_");
        let timestamp = scan_time.format("%Y%m%d_%H%M%S");
        let json_filename = format!("{}_{}.json", image_slug, timestamp);
        let json_path = output_dir.join(&json_filename);
        let json_data = report::format_json(&scan_result, &summary)?;
        std::fs::write(&json_path, &json_data)?;
        eprintln!(
            "{}",
            format!("   JSON scan data written to: {:?}", json_path).dimmed()
        );
        let html_filename = format!("{}_{}.html", image_slug, timestamp);
        let html_path = output_dir.join(&html_filename);
        let html = report::format_html(&scan_result, &summary, &suggestions);
        std::fs::write(&html_path, &html)?;
        eprintln!(
            "{}",
            format!("   HTML report written to: {:?}", html_path).dimmed()
        );
    }

    let should_fail = report::check_severity_threshold(&vulnerabilities, effective_threshold.as_ref());

    if !quiet {
        if should_fail {
            eprintln!(
                "\n{}",
                "❌ SCAN FAILED: Vulnerabilities exceed severity threshold"
                    .red()
                    .bold()
            );
        } else {
            eprintln!(
                "\n{}",
                "✅ Scan completed successfully".green().bold()
            );
        }
    }

    let _ = std::fs::remove_dir_all(&work_dir);

    Ok(if should_fail { 1 } else { 0 })
}

async fn run_sbom(args: SbomArgs, cache_dir: PathBuf) -> anyhow::Result<()> {
    let source = determine_image_source(
        &args.image,
        &args.tar,
        &args.oci,
        &args.username,
        &args.password,
    )?;

    eprintln!("{}", "🔍 Extracting image layers...".cyan());
    let extractor = image::ImageExtractor::new(cache_dir.join("layers"));
    let (image_info, work_dir) = extractor.extract(&source).await?;

    let merged_dir = work_dir.join("merged");
    let layers_dir = work_dir.join("layers");
    image::merge_layers(&layers_dir, &merged_dir)?;

    eprintln!("{}", "📦 Detecting installed packages...".cyan());
    let packages = {
        let merged_clone = merged_dir.clone();
        tokio::task::spawn_blocking(move || packages::PackageDetector::detect_all(&merged_clone))
            .await??
    };

    let scan_time = chrono::Utc::now();
    let sbom_format = args.format.to_lowercase();

    let output = match sbom_format.as_str() {
        "spdx" => {
            let spdx = sbom::generate_spdx(&image_info, &packages, scan_time)?;
            serde_json::to_string_pretty(&spdx)?
        }
        "json" => {
            serde_json::to_string_pretty(&serde_json::json!({
                "image": image_info,
                "packages": packages,
                "generated_at": scan_time,
            }))?
        }
        _ => {
            let cyclone = sbom::generate_cyclonedx(&image_info, &packages, scan_time)?;
            serde_json::to_string_pretty(&cyclone)?
        }
    };

    write_output(&output, args.output.as_deref())?;

    eprintln!(
        "{}",
        format!("✅ SBOM generated: {} packages", packages.len())
            .green()
            .bold()
    );

    let _ = std::fs::remove_dir_all(&work_dir);
    Ok(())
}

async fn run_update_db(cache_dir: PathBuf) -> anyhow::Result<()> {
    eprintln!("{}", "📥 Updating CVE vulnerability database...".cyan());
    let cve_db = cve::CveDatabase::new(&cache_dir.join("cve")).await?;
    cve_db.update_database().await?;
    eprintln!("{}", "✅ CVE database updated successfully".green().bold());
    Ok(())
}

fn write_output(content: &str, output: Option<&std::path::Path>) -> anyhow::Result<()> {
    match output {
        Some(path) => {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(path, content)?;
            eprintln!(
                "{}",
                format!("   Output written to: {:?}", path).dimmed()
            );
        }
        None => {
            println!("{}", content);
        }
    }
    Ok(())
}

use colored::Colorize;
