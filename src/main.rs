mod agent_export;
mod aws_scan;
mod cli_progress;
mod compare;
mod cost;
mod db;
mod demo;
mod k8s_demo;
mod k8s_scan;
mod model;
mod terraform_state;
mod ui;
mod writer;

use std::path::PathBuf;

use anyhow::{Error, Result};
use clap::{CommandFactory, Parser, ValueEnum};
use clap_complete::{Shell, generate};
use tracing_subscriber::FmtSubscriber;

use crate::agent_export::{AgentExportOptions, export_agent_bundle};
use crate::aws_scan::{ScanOptions, scan_account};
use crate::cli_progress::IngestAnimation;
use crate::compare::compare_infra;
use crate::cost::{
    CostActualOptions, default_cost_metric, import_actual_costs, write_estimated_costs,
};
use crate::demo::write_demo_bundle;
use crate::k8s_demo::write_k8s_demo_bundle;
use crate::k8s_scan::{K8sScanOptions, scan_cluster, write_k8s_findings};
use crate::terraform_state::{export_terraform_state, import_terraform_state_file};
use crate::ui::serve_ui;
use crate::writer::write_infra;

#[derive(Debug, Parser)]
#[command(name = "cloudmapper")]
#[command(about = "Export cloud and Kubernetes infrastructure as agent-readable JSON")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, clap::Subcommand)]
enum Command {
    /// Scan a provider and write an infra/ JSON bundle.
    Scan {
        #[command(subcommand)]
        command: ScanCommand,
    },
    /// Write a zero-AWS large-org demo bundle with Terraform state and findings.
    Demo(DemoArgs),
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
    /// Calculate estimated and actual resource cost overlays.
    Cost {
        #[command(subcommand)]
        command: CostCommand,
    },
    /// Serve a local Cytoscape infrastructure graph UI.
    Ui(UiArgs),
    /// Print shell completions to stdout.
    Completions(CompletionsArgs),
}

#[derive(Debug, clap::Subcommand)]
enum ScanCommand {
    /// Scan an AWS account and write an infra/ JSON bundle.
    Aws(AwsScanArgs),
    /// Scan a Kubernetes cluster through kubectl and write an infra/ JSON bundle.
    K8s(K8sScanArgs),
}

#[derive(Debug, Parser)]
struct AwsScanArgs {
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
struct K8sScanArgs {
    /// Kubernetes context. Defaults to the current kubectl context.
    #[arg(long)]
    context: Option<String>,

    /// kubeconfig path. Defaults to kubectl's normal kubeconfig resolution.
    #[arg(long)]
    kubeconfig: Option<PathBuf>,

    /// Namespace to scan, or "all" for every namespace.
    #[arg(long, default_value = "all")]
    namespace: String,

    /// kubectl executable path.
    #[arg(long, default_value = "kubectl")]
    kubectl: PathBuf,

    /// Directory for the generated infrastructure bundle.
    #[arg(long, default_value = "infra")]
    out: PathBuf,

    /// Include raw non-secret Kubernetes objects where supported.
    #[arg(long)]
    include_raw: bool,

    /// Allow writing cloudmapper files into a non-empty directory that was not created by cloudmapper.
    #[arg(long)]
    allow_non_empty_out: bool,
}

#[derive(Debug, Parser)]
struct DemoArgs {
    /// Demo provider to generate.
    #[arg(long, value_enum, default_value_t = DemoProvider::Aws)]
    provider: DemoProvider,

    /// Directory for the generated large-org demo infrastructure bundle.
    #[arg(long, default_value = "infra")]
    out: PathBuf,

    /// Allow writing cloudmapper demo files into a non-empty directory.
    #[arg(long)]
    allow_non_empty_out: bool,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum DemoProvider {
    Aws,
    K8s,
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

    /// Include raw scan details and Terraform attributes in the agent export.
    #[arg(long)]
    include_sensitive: bool,
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

#[derive(Debug, clap::Subcommand)]
enum CostCommand {
    /// Recalculate estimated list-price costs from resources in map.db.
    Estimate(CostEstimateArgs),
    /// Import actual billed costs from AWS Cost Explorer and allocation tags.
    Actual(CostActualArgs),
}

#[derive(Debug, Parser)]
struct CostEstimateArgs {
    /// Map database path.
    #[arg(long, default_value = "infra/map.db")]
    db: PathBuf,

    /// AWS scan id. Defaults to the latest scan in the database.
    #[arg(long)]
    scan_id: Option<String>,
}

#[derive(Debug, Parser)]
struct CostActualArgs {
    /// Map database path.
    #[arg(long, default_value = "infra/map.db")]
    db: PathBuf,

    /// AWS scan id. Defaults to the latest scan in the database.
    #[arg(long)]
    scan_id: Option<String>,

    /// AWS profile name. Falls back to AWS_PROFILE or the default credential chain.
    #[arg(long)]
    profile: Option<String>,

    /// Billing API region for Cost Explorer.
    #[arg(long, default_value = "us-east-1")]
    billing_region: String,

    /// Number of trailing days to read from Cost Explorer.
    #[arg(long, default_value_t = 30)]
    days: i64,

    /// Cost allocation tag key. May be repeated or comma-separated.
    #[arg(long = "tag", value_delimiter = ',', default_values = ["Environment", "Application", "Owner", "Name"])]
    tags: Vec<String>,

    /// Cost Explorer metric to import.
    #[arg(long, default_value_t = default_cost_metric().to_string())]
    metric: String,
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

#[derive(Debug, Parser)]
struct CompletionsArgs {
    /// Shell to generate completions for.
    #[arg(value_enum)]
    shell: Shell,
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
        Command::Scan { command } => match command {
            ScanCommand::Aws(args) => {
                let options = ScanOptions {
                    profile: args.profile,
                    regions: args.regions,
                    home_region: args.home_region,
                    include_raw: args.include_raw,
                };
                let progress = IngestAnimation::start("aws", args.out.join("map.db"));
                progress.stage("discovering AWS resources");
                let inventory = match scan_account(options).await {
                    Ok(inventory) => inventory,
                    Err(error) => {
                        progress.fail();
                        return Err(error);
                    }
                };
                progress.stage("writing bundle and map.db");
                let scan_id = match write_infra(&args.out, &inventory, args.allow_non_empty_out) {
                    Ok(scan_id) => scan_id,
                    Err(error) => {
                        progress.fail();
                        return Err(error);
                    }
                };
                progress.finish(format!(
                    "{} resources, {} relationships, scan {}",
                    inventory.resources.len(),
                    inventory.relationships.len(),
                    scan_id
                ));
                println!(
                    "wrote {} AWS resources, {} relationships, and {} scan errors to {}",
                    inventory.resources.len(),
                    inventory.relationships.len(),
                    inventory.errors.len(),
                    args.out.display()
                );
                println!(
                    "next: cloudmapper ui --db {} --bind 127.0.0.1:8765",
                    args.out.join("map.db").display()
                );
            }
            ScanCommand::K8s(args) => {
                let scan_options = K8sScanOptions {
                    context: args.context,
                    kubeconfig: args.kubeconfig,
                    namespace: args.namespace,
                    kubectl: args.kubectl,
                    include_raw: args.include_raw,
                };
                let progress = IngestAnimation::start("k8s", args.out.join("map.db"));
                progress.stage("reading Kubernetes API");
                let output = match scan_cluster(scan_options) {
                    Ok(output) => output,
                    Err(error) => {
                        progress.fail();
                        return Err(error);
                    }
                };
                progress.stage("writing bundle and map.db");
                let scan_id =
                    match write_infra(&args.out, &output.inventory, args.allow_non_empty_out) {
                        Ok(scan_id) => scan_id,
                        Err(error) => {
                            progress.fail();
                            return Err(error);
                        }
                    };
                progress.stage("storing findings");
                let findings_run_id = match write_k8s_findings(
                    &args.out.join("map.db"),
                    &scan_id,
                    &output.findings,
                ) {
                    Ok(run_id) => run_id,
                    Err(error) => {
                        progress.fail();
                        return Err(error);
                    }
                };
                progress.finish(format!(
                    "{} resources, {} relationships, {} findings",
                    output.inventory.resources.len(),
                    output.inventory.relationships.len(),
                    output.findings.len()
                ));
                println!(
                    "wrote {} Kubernetes resources, {} relationships, {} findings, and {} scan errors to {}",
                    output.inventory.resources.len(),
                    output.inventory.relationships.len(),
                    output.findings.len(),
                    output.inventory.errors.len(),
                    args.out.display()
                );
                println!("findings: {findings_run_id}");
                println!(
                    "next: cloudmapper ui --db {} --bind 127.0.0.1:8765",
                    args.out.join("map.db").display()
                );
            }
        },
        Command::Demo(args) => match args.provider {
            DemoProvider::Aws => {
                let progress = IngestAnimation::start("demo aws", args.out.join("map.db"));
                progress.stage("generating demo cloud inventory");
                let summary = match write_demo_bundle(&args.out, args.allow_non_empty_out) {
                    Ok(summary) => summary,
                    Err(error) => {
                        progress.fail();
                        return Err(error);
                    }
                };
                progress.finish(format!(
                    "{} resources, {} relationships, {} findings",
                    summary.resources, summary.relationships, summary.findings
                ));
                println!(
                    "wrote AWS large-org demo bundle with {} resources, {} relationships, and {} findings to {}",
                    summary.resources,
                    summary.relationships,
                    summary.findings,
                    summary.out.display()
                );
                println!(
                    "terraform: {} ({})",
                    summary.state_path.display(),
                    summary.terraform_state_id
                );
                println!("findings: {}", summary.findings_path.display());
                println!(
                    "next: cloudmapper ui --db {} --bind 127.0.0.1:8765",
                    summary.db_path.display()
                );
            }
            DemoProvider::K8s => {
                let progress = IngestAnimation::start("demo k8s", args.out.join("map.db"));
                progress.stage("generating demo cluster inventory");
                let summary = match write_k8s_demo_bundle(&args.out, args.allow_non_empty_out) {
                    Ok(summary) => summary,
                    Err(error) => {
                        progress.fail();
                        return Err(error);
                    }
                };
                progress.finish(format!(
                    "{} resources, {} relationships, {} findings",
                    summary.resources, summary.relationships, summary.findings
                ));
                println!(
                    "wrote Kubernetes platform demo bundle with {} resources, {} relationships, and {} findings to {}",
                    summary.resources,
                    summary.relationships,
                    summary.findings,
                    summary.out.display()
                );
                println!(
                    "findings: {} ({})",
                    summary.findings_path.display(),
                    summary.run_id
                );
                println!(
                    "next: cloudmapper ui --db {} --bind 127.0.0.1:8765",
                    summary.db_path.display()
                );
            }
        },
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
                println!(
                    "next: cloudmapper ui --db {} --bind 127.0.0.1:8765",
                    args.db.display()
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
                    AgentExportOptions {
                        include_sensitive: args.include_sensitive,
                    },
                )?;
                let json = serde_json::to_string_pretty(&export)?;
                if args.out.as_os_str() == "-" {
                    println!("{json}");
                } else {
                    std::fs::write(&args.out, format!("{json}\n"))?;
                    println!(
                        "wrote {} agent export with {} resources, {} relationships, and {} findings from {} to {}",
                        export.redaction.mode,
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
                println!(
                    "next: cloudmapper compare --db {} --out findings.json",
                    args.db.display()
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
        Command::Cost { command } => match command {
            CostCommand::Estimate(args) => {
                let summary = write_estimated_costs(&args.db, args.scan_id.as_deref())?;
                println!(
                    "wrote estimated list-price costs for {}/{} resources in {} ({:.2} USD/month)",
                    summary.costed_resources,
                    summary.resources,
                    summary.scan_id,
                    summary.monthly_usd
                );
                println!(
                    "next: cloudmapper ui --db {} --bind 127.0.0.1:8765",
                    args.db.display()
                );
            }
            CostCommand::Actual(args) => {
                let summary = import_actual_costs(CostActualOptions {
                    db: args.db.clone(),
                    scan_id: args.scan_id,
                    profile: args.profile,
                    billing_region: args.billing_region,
                    days: args.days,
                    tags: args.tags,
                    metric: args.metric,
                })
                .await?;
                println!(
                    "wrote actual Cost Explorer cost overlay for {}/{} resources in {} ({:.2} USD/month run rate)",
                    summary.costed_resources,
                    summary.resources,
                    summary.scan_id,
                    summary.monthly_usd
                );
                println!(
                    "period: {} to {} grouped by tags: {}",
                    summary.period_start,
                    summary.period_end,
                    summary.tags.join(", ")
                );
                println!(
                    "next: cloudmapper ui --db {} --bind 127.0.0.1:8765",
                    args.db.display()
                );
            }
        },
        Command::Ui(args) => {
            serve_ui(&args.db, &args.bind)?;
        }
        Command::Completions(args) => {
            let mut command = Cli::command();
            let name = command.get_name().to_string();
            generate(args.shell, &mut command, name, &mut std::io::stdout());
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

    if classification.show_details {
        let details = dedup_details(&chain)
            .into_iter()
            .filter(|detail| Some(detail) != context.as_ref())
            .collect::<Vec<_>>();
        append_details(&mut lines, details);
    }

    lines.join("\n")
}

fn append_details(lines: &mut Vec<String>, details: Vec<String>) {
    if !details.is_empty() {
        lines.push("details:".to_string());
        for detail in details.into_iter().take(4) {
            lines.push(format!("  - {}", shorten_detail(&detail)));
        }
    }
}

struct ErrorClassification {
    summary: &'static str,
    hint: &'static str,
    show_details: bool,
}

fn classify_error(text: &str) -> ErrorClassification {
    if text.contains("refresh token has expired")
        || text.contains("session has expired")
        || text.contains("failed to refresh cached login token")
    {
        return ErrorClassification {
            summary: "AWS credentials are expired",
            hint: "refresh AWS credentials and retry; for AWS SSO run `aws sso login`, or pass `--profile <name>` for a valid profile",
            show_details: false,
        };
    }

    if text.contains("no credentials")
        || text.contains("failed to load credentials")
        || text.contains("no providers in chain provided credentials")
        || text.contains("credential provider was not enabled")
    {
        return ErrorClassification {
            summary: "AWS credentials are not available",
            hint: "configure AWS credentials, set AWS_PROFILE, or pass `--profile <name>`",
            show_details: false,
        };
    }

    if text.contains("accessdenied") || text.contains("access denied") {
        return ErrorClassification {
            summary: "AWS API access was denied",
            hint: "check the selected AWS profile and IAM permissions for the requested scan",
            show_details: true,
        };
    }

    ErrorClassification {
        summary: "command failed",
        hint: "rerun with a valid input path, database, or AWS profile depending on the command context",
        show_details: true,
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
    let lower = cause.to_lowercase();
    matches!(
        cause,
        "dispatch failure" | "other" | "an error occurred while loading credentials"
    ) || cause.starts_with("AccessDeniedException: AccessDeniedException")
        || lower.contains("providererror(")
        || lower.contains("aws_request_id")
}

fn shorten_detail(detail: &str) -> String {
    const MAX_DETAIL_LEN: usize = 240;

    let mut chars = detail.chars();
    let shortened = chars.by_ref().take(MAX_DETAIL_LEN).collect::<String>();
    if chars.next().is_some() {
        format!("{shortened}...")
    } else {
        shortened
    }
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
        assert!(!formatted.contains("details:"));
        assert!(!formatted.contains("Caused by:"));
    }

    #[test]
    fn hides_repeated_aws_sdk_provider_chain_for_expired_sso() {
        let error = anyhow!(
            "AccessDeniedException: The refresh token has expired. (ProviderError(ProviderError {{ source: RefreshFailed, aws_request_id: abc }}))"
        )
        .context("failed to refresh cached Login token: Your session has expired.")
        .context("an error occurred while loading credentials")
        .context("dispatch failure")
        .context("calling sts:GetCallerIdentity");

        let formatted = format_cli_error(&error);

        assert_eq!(
            formatted,
            "cloudmapper error: AWS credentials are expired\ncontext: calling sts:GetCallerIdentity\nhint: refresh AWS credentials and retry; for AWS SSO run `aws sso login`, or pass `--profile <name>` for a valid profile"
        );
    }

    #[test]
    fn formats_generic_errors_with_context_and_details() {
        let error = anyhow!("missing file").context("reading Terraform state terraform.tfstate");

        let formatted = format_cli_error(&error);

        assert!(formatted.contains("cloudmapper error: command failed"));
        assert!(formatted.contains("context: reading Terraform state terraform.tfstate"));
        assert!(formatted.contains("details:"));
    }

    #[test]
    fn formats_missing_aws_credentials_as_actionable_error() {
        let error = anyhow!("the credential provider was not enabled")
            .context("no providers in chain provided credentials")
            .context("calling sts:GetCallerIdentity");

        let formatted = format_cli_error(&error);

        assert_eq!(
            formatted,
            "cloudmapper error: AWS credentials are not available\ncontext: calling sts:GetCallerIdentity\nhint: configure AWS credentials, set AWS_PROFILE, or pass `--profile <name>`"
        );
    }
}
