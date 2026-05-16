mod agent_export;
mod aws_scan;
mod compare;
mod db;
mod model;
mod terraform_state;
mod ui;
mod writer;

use std::path::PathBuf;

use anyhow::{Error, Result};
use clap::{Parser, ValueEnum};
use tracing_subscriber::FmtSubscriber;

use crate::agent_export::export_agent_bundle;
use crate::aws_scan::{ScanOptions, scan_account};
use crate::compare::compare_infra;
use crate::terraform_state::{export_terraform_state, import_terraform_state_file};
use crate::ui::serve_ui;
use crate::writer::write_infra;

#[derive(Debug, Parser)]
#[command(name = "cloudmapper")]
#[command(about = "Export AWS account infrastructure as agent-readable JSON")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, clap::Subcommand)]
enum Command {
    /// Scan an AWS account and write an infra/ JSON bundle.
    Scan(ScanArgs),
    /// Compare AWS reality with imported Terraform state and emit findings.
    Compare(CompareArgs),
    /// Export cloudmapper data into portable formats.
    Export {
        #[command(subcommand)]
        command: ExportCommand,
    },
    /// Import or export Terraform state data in map.db.
    Terraform {
        #[command(subcommand)]
        command: TerraformCommand,
    },
    /// Serve a local Cytoscape infrastructure graph UI.
    Ui(UiArgs),
}

#[derive(Debug, Parser)]
struct ScanArgs {
    /// AWS profile name. Falls back to AWS_PROFILE or the default credential chain.
    #[arg(long)]
    profile: Option<String>,

    /// Regions to scan: "all" or a comma-separated list such as "us-east-1,eu-west-1".
    #[arg(long, default_value = "all")]
    regions: String,

    /// Region used for global APIs and region discovery.
    #[arg(long, default_value = "us-east-1")]
    home_region: String,

    /// Directory for the generated infrastructure bundle.
    #[arg(long, default_value = "infra")]
    out: PathBuf,

    /// Service set to scan.
    #[arg(long, value_enum, default_value_t = ServiceSet::Core)]
    services: ServiceSet,

    /// Include normalized raw detail blocks where the scanner supports them.
    #[arg(long)]
    include_raw: bool,

    /// Allow writing cloudmapper files into a non-empty directory that was not created by cloudmapper.
    #[arg(long)]
    allow_non_empty_out: bool,
}

#[derive(Debug, Parser)]
struct CompareArgs {
    /// Map database path.
    #[arg(long, default_value = "infra/map.db")]
    db: PathBuf,

    /// AWS scan id. Defaults to the latest scan in the database.
    #[arg(long)]
    scan_id: Option<String>,

    /// Terraform state id. Defaults to the latest imported Terraform state.
    #[arg(long)]
    terraform_state_id: Option<String>,

    /// Output file. If omitted, JSON is printed to stdout.
    #[arg(long)]
    out: Option<PathBuf>,
}

#[derive(Debug, clap::Subcommand)]
enum ExportCommand {
    /// Export one agent-ready JSON file with resources, graph, Terraform mapping, and findings.
    Agent(AgentExportArgs),
}

#[derive(Debug, Parser)]
struct AgentExportArgs {
    /// Map database path.
    #[arg(long, default_value = "infra/map.db")]
    db: PathBuf,

    /// AWS scan id. Defaults to the latest scan in the database.
    #[arg(long)]
    scan_id: Option<String>,

    /// Terraform state id. Defaults to the latest imported Terraform state when present.
    #[arg(long)]
    terraform_state_id: Option<String>,

    /// Compare run id. Defaults to the latest compare findings run when present.
    #[arg(long)]
    compare_run_id: Option<String>,

    /// Output file. Use "-" to print JSON to stdout.
    #[arg(long, default_value = "infra.agent.json")]
    out: PathBuf,
}

#[derive(Debug, clap::Subcommand)]
enum TerraformCommand {
    /// Import a Terraform state file into map.db.
    Import(TerraformImportArgs),
    /// Export imported Terraform state from map.db as normalized JSON.
    Export(TerraformExportArgs),
}

#[derive(Debug, Parser)]
struct TerraformImportArgs {
    /// Terraform state JSON file to import.
    #[arg(long)]
    state: PathBuf,

    /// Map database path.
    #[arg(long, default_value = "infra/map.db")]
    db: PathBuf,

    /// Optional stable state id. Defaults to lineage/serial when available.
    #[arg(long)]
    state_id: Option<String>,
}

#[derive(Debug, Parser)]
struct TerraformExportArgs {
    /// Map database path.
    #[arg(long, default_value = "infra/map.db")]
    db: PathBuf,

    /// State id to export. Defaults to the latest imported Terraform state.
    #[arg(long)]
    state_id: Option<String>,

    /// Output file. If omitted, JSON is printed to stdout.
    #[arg(long)]
    out: Option<PathBuf>,
}

#[derive(Debug, Parser)]
struct UiArgs {
    /// Map database path.
    #[arg(long, default_value = "infra/map.db")]
    db: PathBuf,

    /// Local address to bind.
    #[arg(long, default_value = "127.0.0.1:8765")]
    bind: String,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum ServiceSet {
    /// Account identity, regions, EC2/VPC, S3, IAM, Lambda, and tagged-resource discovery.
    Core,
}

#[tokio::main]
async fn main() {
    init_logging();

    if let Err(error) = run().await {
        eprintln!("{}", format_cli_error(&error));
        std::process::exit(1);
    }
}

fn init_logging() {
    let subscriber = FmtSubscriber::builder()
        .with_target(false)
        .with_max_level(tracing::Level::ERROR)
        .without_time()
        .finish();
    let _ = tracing::subscriber::set_global_default(subscriber);
}

async fn run() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Scan(args) => {
            let options = ScanOptions {
                profile: args.profile,
                regions: args.regions,
                home_region: args.home_region,
                include_raw: args.include_raw,
            };
            let inventory = scan_account(options).await?;
            write_infra(&args.out, &inventory, args.allow_non_empty_out)?;
            println!(
                "wrote {} resources, {} relationships, and {} scan errors to {}",
                inventory.resources.len(),
                inventory.relationships.len(),
                inventory.errors.len(),
                args.out.display()
            );
        }
        Command::Compare(args) => {
            let report = compare_infra(
                &args.db,
                args.scan_id.as_deref(),
                args.terraform_state_id.as_deref(),
            )?;
            let json = serde_json::to_string_pretty(&report)?;
            if let Some(out) = args.out {
                std::fs::write(&out, format!("{json}\n"))?;
                println!(
                    "wrote {} compare findings from {} to {}",
                    report.findings.len(),
                    args.db.display(),
                    out.display()
                );
            } else {
                println!("{json}");
            }
        }
        Command::Export { command } => match command {
            ExportCommand::Agent(args) => {
                let export = export_agent_bundle(
                    &args.db,
                    args.scan_id.as_deref(),
                    args.terraform_state_id.as_deref(),
                    args.compare_run_id.as_deref(),
                )?;
                let json = serde_json::to_string_pretty(&export)?;
                if args.out.as_os_str() == "-" {
                    println!("{json}");
                } else {
                    std::fs::write(&args.out, format!("{json}\n"))?;
                    println!(
                        "wrote agent export with {} resources, {} relationships, and {} findings from {} to {}",
                        export.counts.resources,
                        export.counts.relationships,
                        export.counts.findings,
                        args.db.display(),
                        args.out.display()
                    );
                }
            }
        },
        Command::Terraform { command } => match command {
            TerraformCommand::Import(args) => {
                let summary = import_terraform_state_file(&args.db, &args.state, args.state_id)?;
                println!(
                    "imported {} Terraform resource instances into {} as {}",
                    summary.resource_instances,
                    args.db.display(),
                    summary.state_id
                );
            }
            TerraformCommand::Export(args) => {
                let export = export_terraform_state(&args.db, args.state_id.as_deref())?;
                let json = serde_json::to_string_pretty(&export)?;
                if let Some(out) = args.out {
                    std::fs::write(&out, format!("{json}\n"))?;
                    println!(
                        "exported {} Terraform resource instances from {} to {}",
                        export.resource_instances.len(),
                        args.db.display(),
                        out.display()
                    );
                } else {
                    println!("{json}");
                }
            }
        },
        Command::Ui(args) => {
            serve_ui(&args.db, &args.bind)?;
        }
    }

    Ok(())
}

fn format_cli_error(error: &Error) -> String {
    let chain = error
        .chain()
        .map(|cause| cause.to_string())
        .collect::<Vec<_>>();
    let text = chain.join("\n").to_lowercase();
    let context = operation_context(&chain);
    let classification = classify_error(&text);

    let mut lines = Vec::new();
    lines.push(format!("cloudmapper error: {}", classification.summary));
    if let Some(context) = context.as_ref() {
        lines.push(format!("context: {context}"));
    }
    lines.push(format!("hint: {}", classification.hint));

    let details = dedup_details(&chain)
        .into_iter()
        .filter(|detail| Some(detail) != context.as_ref())
        .collect::<Vec<_>>();
    if !details.is_empty() {
        lines.push("details:".to_string());
        for detail in details.into_iter().take(4) {
            lines.push(format!("  - {detail}"));
        }
    }

    lines.join("\n")
}

struct ErrorClassification {
    summary: &'static str,
    hint: &'static str,
}

fn classify_error(text: &str) -> ErrorClassification {
    if text.contains("refresh token has expired")
        || text.contains("session has expired")
        || text.contains("failed to refresh cached login token")
    {
        return ErrorClassification {
            summary: "AWS credentials are expired",
            hint: "refresh AWS credentials and retry; for AWS SSO run `aws sso login`, or pass `--profile <name>` for a valid profile",
        };
    }

    if text.contains("no credentials") || text.contains("failed to load credentials") {
        return ErrorClassification {
            summary: "AWS credentials are not available",
            hint: "configure AWS credentials, set AWS_PROFILE, or pass `--profile <name>`",
        };
    }

    if text.contains("accessdenied") || text.contains("access denied") {
        return ErrorClassification {
            summary: "AWS API access was denied",
            hint: "check the selected AWS profile and IAM permissions for the requested scan",
        };
    }

    ErrorClassification {
        summary: "command failed",
        hint: "rerun with a valid input path, database, or AWS profile depending on the command context",
    }
}

fn operation_context(chain: &[String]) -> Option<String> {
    chain
        .iter()
        .find(|cause| {
            cause.starts_with("calling ")
                || cause.starts_with("opening ")
                || cause.starts_with("reading ")
                || cause.starts_with("parsing ")
                || cause.starts_with("binding ")
                || cause.starts_with("loading ")
        })
        .cloned()
}

fn dedup_details(chain: &[String]) -> Vec<String> {
    let mut details = Vec::new();
    for cause in chain {
        if is_low_signal_detail(cause) || details.contains(cause) {
            continue;
        }
        details.push(cause.clone());
    }
    details
}

fn is_low_signal_detail(cause: &str) -> bool {
    matches!(
        cause,
        "dispatch failure" | "other" | "an error occurred while loading credentials"
    ) || cause.starts_with("AccessDeniedException: AccessDeniedException")
}

#[cfg(test)]
mod tests {
    use anyhow::anyhow;

    use super::format_cli_error;

    #[test]
    fn formats_expired_aws_credentials_as_actionable_error() {
        let error = anyhow!("AccessDeniedException: The refresh token has expired.")
            .context("failed to refresh cached Login token: Your session has expired.")
            .context("calling sts:GetCallerIdentity");

        let formatted = format_cli_error(&error);

        assert!(formatted.contains("cloudmapper error: AWS credentials are expired"));
        assert!(formatted.contains("context: calling sts:GetCallerIdentity"));
        assert!(formatted.contains("aws sso login"));
        assert!(!formatted.contains("Caused by:"));
    }

    #[test]
    fn formats_generic_errors_with_context_and_details() {
        let error = anyhow!("missing file").context("reading Terraform state terraform.tfstate");

        let formatted = format_cli_error(&error);

        assert!(formatted.contains("cloudmapper error: command failed"));
        assert!(formatted.contains("context: reading Terraform state terraform.tfstate"));
        assert!(formatted.contains("details:"));
    }
}
