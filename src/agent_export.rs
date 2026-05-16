use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context, Result};
use chrono::Utc;
use rusqlite::{Connection, OptionalExtension, params};
use serde::Serialize;
use serde_json::Value;

use crate::db::{latest_terraform_state_id, open_cloudmapper_db};

const AGENT_SCHEMA_VERSION: &str = "cloudmapper.agent.v1";

#[derive(Debug, Serialize)]
pub struct AgentExport {
    pub schema_version: String,
    pub generated_at: String,
    pub scan: AgentScan,
    pub counts: AgentCounts,
    pub resources: Vec<AgentResource>,
    pub relationships: Vec<AgentRelationship>,
    pub terraform: AgentTerraform,
    pub findings: Vec<AgentFinding>,
    pub graph: AgentGraph,
}

#[derive(Clone, Debug, Serialize)]
pub struct AgentScan {
    pub id: String,
    pub schema_version: String,
    pub generator: AgentGenerator,
    pub account: AgentAccount,
    pub home_region: String,
    pub regions: Vec<String>,
    pub collected_at: String,
    pub errors: Vec<AgentScanError>,
}

#[derive(Clone, Debug, Serialize)]
pub struct AgentGenerator {
    pub name: String,
    pub version: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct AgentAccount {
    pub id: String,
    pub partition: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct AgentScanError {
    pub service: String,
    pub region: String,
    pub operation: String,
    pub message: String,
}

#[derive(Debug, Serialize)]
pub struct AgentCounts {
    pub resources: usize,
    pub relationships: usize,
    pub terraform_resource_instances: usize,
    pub findings: usize,
    pub scan_errors: usize,
}

#[derive(Debug, Serialize)]
pub struct AgentResource {
    pub uid: String,
    pub provider: String,
    pub account_id: String,
    pub partition: String,
    pub region: String,
    pub service: String,
    #[serde(rename = "type")]
    pub resource_type: String,
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arn: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub tags: Value,
    pub attributes: Value,
    pub evidence: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw: Option<Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub terraform_addresses: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub finding_ids: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct AgentRelationship {
    pub uid: String,
    pub from: String,
    pub to: String,
    #[serde(rename = "type")]
    pub relationship_type: String,
    pub attributes: Value,
    pub evidence: Value,
}

#[derive(Debug, Serialize)]
pub struct AgentTerraform {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<AgentTerraformState>,
    pub resource_instances: Vec<AgentTerraformResource>,
}

#[derive(Debug, Serialize)]
pub struct AgentTerraformState {
    pub state_id: String,
    pub source_path: String,
    pub terraform_version: Option<String>,
    pub serial: Option<i64>,
    pub lineage: Option<String>,
    pub imported_at: String,
}

#[derive(Debug, Serialize)]
pub struct AgentTerraformResource {
    pub address: String,
    pub module: Option<String>,
    pub mode: String,
    #[serde(rename = "type")]
    pub resource_type: String,
    pub name: String,
    pub provider: Option<String>,
    pub index_key: Option<Value>,
    pub schema_version: Option<i64>,
    pub attributes: Value,
    pub sensitive_attributes: Value,
    pub dependencies: Value,
    pub aws_uid: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct AgentFinding {
    pub id: String,
    #[serde(rename = "type")]
    pub finding_type: String,
    pub severity: String,
    pub aws_uid: Option<String>,
    pub terraform_address: Option<String>,
    pub reason: String,
    pub recommended_action: String,
    pub blast_radius: Vec<String>,
    pub evidence: Value,
    pub attributes: Value,
}

#[derive(Debug, Serialize)]
pub struct AgentGraph {
    pub nodes: Vec<AgentGraphNode>,
    pub edges: Vec<AgentGraphEdge>,
}

#[derive(Debug, Serialize)]
pub struct AgentGraphNode {
    pub id: String,
    pub label: String,
    pub service: String,
    #[serde(rename = "type")]
    pub resource_type: String,
    pub region: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub terraform_addresses: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub finding_ids: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct AgentGraphEdge {
    pub id: String,
    pub source: String,
    pub target: String,
    #[serde(rename = "type")]
    pub relationship_type: String,
}

pub fn export_agent_bundle(
    db_path: &Path,
    scan_id: Option<&str>,
    terraform_state_id: Option<&str>,
    compare_run_id: Option<&str>,
) -> Result<AgentExport> {
    let connection = open_cloudmapper_db(db_path)?;
    let scan_id = match scan_id {
        Some(scan_id) => scan_id.to_string(),
        None => latest_scan_id(&connection)?.context("no AWS scan found in map database")?,
    };
    let terraform_state_id = match terraform_state_id {
        Some(state_id) => Some(state_id.to_string()),
        None => latest_terraform_state_id(&connection)?,
    };
    let compare_run_id = match compare_run_id {
        Some(run_id) => Some(run_id.to_string()),
        None => latest_compare_run_id(&connection)?,
    };

    let scan = load_scan(&connection, &scan_id)?;
    let terraform = load_terraform(&connection, terraform_state_id.as_deref())?;
    let terraform_by_uid = terraform_by_uid(&terraform.resource_instances);
    let findings = load_findings(&connection, compare_run_id.as_deref())?;
    let findings_by_uid = findings_by_uid(&findings);
    let resources = load_resources(&connection, &scan_id, &terraform_by_uid, &findings_by_uid)?;
    let relationships = load_relationships(&connection, &scan_id)?;
    let graph = agent_graph(&resources, &relationships);

    Ok(AgentExport {
        schema_version: AGENT_SCHEMA_VERSION.to_string(),
        generated_at: Utc::now().to_rfc3339(),
        counts: AgentCounts {
            resources: resources.len(),
            relationships: relationships.len(),
            terraform_resource_instances: terraform.resource_instances.len(),
            findings: findings.len(),
            scan_errors: scan.errors.len(),
        },
        scan,
        resources,
        relationships,
        terraform,
        findings,
        graph,
    })
}

fn latest_scan_id(connection: &Connection) -> Result<Option<String>> {
    connection
        .query_row(
            "SELECT id FROM scans ORDER BY collected_at DESC, id DESC LIMIT 1",
            [],
            |row| row.get(0),
        )
        .optional()
        .context("loading latest AWS scan id")
}

fn latest_compare_run_id(connection: &Connection) -> Result<Option<String>> {
    connection
        .query_row(
            "SELECT run_id FROM findings ORDER BY created_at DESC, run_id DESC LIMIT 1",
            [],
            |row| row.get(0),
        )
        .optional()
        .context("loading latest compare run id")
}

fn load_scan(connection: &Connection, scan_id: &str) -> Result<AgentScan> {
    let mut scan = connection
        .query_row(
            r#"
            SELECT schema_version, generator_name, generator_version, account_id,
                   partition, home_region, regions_json, collected_at
            FROM scans
            WHERE id = ?1
            "#,
            params![scan_id],
            |row| {
                Ok(AgentScan {
                    id: scan_id.to_string(),
                    schema_version: row.get(0)?,
                    generator: AgentGenerator {
                        name: row.get(1)?,
                        version: row.get(2)?,
                    },
                    account: AgentAccount {
                        id: row.get(3)?,
                        partition: row.get(4)?,
                    },
                    home_region: row.get(5)?,
                    regions: parse_json(row.get::<_, String>(6)?)?,
                    collected_at: row.get(7)?,
                    errors: Vec::new(),
                })
            },
        )
        .optional()?
        .with_context(|| format!("AWS scan {scan_id} is not present in map database"))?;
    scan.errors = load_scan_errors(connection, scan_id)?;
    Ok(scan)
}

fn load_scan_errors(connection: &Connection, scan_id: &str) -> Result<Vec<AgentScanError>> {
    let mut statement = connection.prepare(
        r#"
        SELECT service, region, operation, message
        FROM scan_errors
        WHERE scan_id = ?1
        ORDER BY service, region, operation
        "#,
    )?;
    let rows = statement.query_map(params![scan_id], |row| {
        Ok(AgentScanError {
            service: row.get(0)?,
            region: row.get(1)?,
            operation: row.get(2)?,
            message: row.get(3)?,
        })
    })?;
    rows.collect::<Result<Vec<_>, _>>()
        .context("loading scan errors")
}

fn load_resources(
    connection: &Connection,
    scan_id: &str,
    terraform_by_uid: &BTreeMap<String, Vec<String>>,
    findings_by_uid: &BTreeMap<String, ResourceFindings>,
) -> Result<Vec<AgentResource>> {
    let mut statement = connection.prepare(
        r#"
        SELECT uid, provider, account_id, partition, region, service, resource_type,
               resource_id, arn, name, tags_json, attributes_json, evidence_json, raw_json
        FROM resources
        WHERE scan_id = ?1
        ORDER BY service, resource_type, COALESCE(name, resource_id), uid
        "#,
    )?;
    let rows = statement.query_map(params![scan_id], |row| {
        let uid: String = row.get(0)?;
        let resource_findings = findings_by_uid.get(&uid);
        Ok(AgentResource {
            terraform_addresses: terraform_by_uid.get(&uid).cloned().unwrap_or_default(),
            finding_ids: resource_findings
                .map(|findings| findings.ids.clone())
                .unwrap_or_default(),
            severity: resource_findings.and_then(|findings| findings.severity.clone()),
            uid,
            provider: row.get(1)?,
            account_id: row.get(2)?,
            partition: row.get(3)?,
            region: row.get(4)?,
            service: row.get(5)?,
            resource_type: row.get(6)?,
            id: row.get(7)?,
            arn: row.get(8)?,
            name: row.get(9)?,
            tags: parse_json(row.get::<_, String>(10)?)?,
            attributes: parse_json(row.get::<_, String>(11)?)?,
            evidence: parse_json(row.get::<_, String>(12)?)?,
            raw: parse_optional_json(row.get::<_, Option<String>>(13)?)?,
        })
    })?;
    rows.collect::<Result<Vec<_>, _>>()
        .context("loading resources")
}

fn load_relationships(connection: &Connection, scan_id: &str) -> Result<Vec<AgentRelationship>> {
    let mut statement = connection.prepare(
        r#"
        SELECT uid, from_uid, to_uid, relationship_type, attributes_json, evidence_json
        FROM relationships
        WHERE scan_id = ?1
        ORDER BY relationship_type, uid
        "#,
    )?;
    let rows = statement.query_map(params![scan_id], |row| {
        Ok(AgentRelationship {
            uid: row.get(0)?,
            from: row.get(1)?,
            to: row.get(2)?,
            relationship_type: row.get(3)?,
            attributes: parse_json(row.get::<_, String>(4)?)?,
            evidence: parse_json(row.get::<_, String>(5)?)?,
        })
    })?;
    rows.collect::<Result<Vec<_>, _>>()
        .context("loading relationships")
}

fn load_terraform(connection: &Connection, state_id: Option<&str>) -> Result<AgentTerraform> {
    let Some(state_id) = state_id else {
        return Ok(AgentTerraform {
            state: None,
            resource_instances: Vec::new(),
        });
    };

    let state = connection
        .query_row(
            r#"
            SELECT source_path, terraform_version, serial, lineage, imported_at
            FROM terraform_states
            WHERE state_id = ?1
            "#,
            params![state_id],
            |row| {
                Ok(AgentTerraformState {
                    state_id: state_id.to_string(),
                    source_path: row.get(0)?,
                    terraform_version: row.get(1)?,
                    serial: row.get(2)?,
                    lineage: row.get(3)?,
                    imported_at: row.get(4)?,
                })
            },
        )
        .optional()?
        .with_context(|| format!("Terraform state {state_id} is not present in map database"))?;

    let mut statement = connection.prepare(
        r#"
        SELECT address, module, mode, resource_type, name, provider, index_key_json,
               schema_version, attributes_json, sensitive_attributes_json, dependencies_json,
               aws_uid
        FROM terraform_resource_instances
        WHERE state_id = ?1
        ORDER BY address
        "#,
    )?;
    let rows = statement.query_map(params![state_id], |row| {
        Ok(AgentTerraformResource {
            address: row.get(0)?,
            module: row.get(1)?,
            mode: row.get(2)?,
            resource_type: row.get(3)?,
            name: row.get(4)?,
            provider: row.get(5)?,
            index_key: parse_optional_json(row.get::<_, Option<String>>(6)?)?,
            schema_version: row.get(7)?,
            attributes: parse_json(row.get::<_, String>(8)?)?,
            sensitive_attributes: parse_json(row.get::<_, String>(9)?)?,
            dependencies: parse_json(row.get::<_, String>(10)?)?,
            aws_uid: row.get(11)?,
        })
    })?;

    Ok(AgentTerraform {
        state: Some(state),
        resource_instances: rows
            .collect::<Result<Vec<_>, _>>()
            .context("loading Terraform resource instances")?,
    })
}

fn load_findings(connection: &Connection, run_id: Option<&str>) -> Result<Vec<AgentFinding>> {
    let Some(run_id) = run_id else {
        return Ok(Vec::new());
    };

    let mut statement = connection.prepare(
        r#"
        SELECT id, finding_type, severity, aws_uid, terraform_address, reason,
               recommended_action, blast_radius_json, evidence_json, attributes_json
        FROM findings
        WHERE run_id = ?1
        ORDER BY
          CASE severity
            WHEN 'critical' THEN 0
            WHEN 'high' THEN 1
            WHEN 'medium' THEN 2
            ELSE 3
          END,
          finding_type,
          COALESCE(aws_uid, terraform_address, id)
        "#,
    )?;
    let rows = statement.query_map(params![run_id], |row| {
        Ok(AgentFinding {
            id: row.get(0)?,
            finding_type: row.get(1)?,
            severity: row.get(2)?,
            aws_uid: row.get(3)?,
            terraform_address: row.get(4)?,
            reason: row.get(5)?,
            recommended_action: row.get(6)?,
            blast_radius: parse_json(row.get::<_, String>(7)?)?,
            evidence: parse_json(row.get::<_, String>(8)?)?,
            attributes: parse_json(row.get::<_, String>(9)?)?,
        })
    })?;
    rows.collect::<Result<Vec<_>, _>>()
        .context("loading findings")
}

fn agent_graph(resources: &[AgentResource], relationships: &[AgentRelationship]) -> AgentGraph {
    AgentGraph {
        nodes: resources
            .iter()
            .map(|resource| AgentGraphNode {
                id: resource.uid.clone(),
                label: resource.name.clone().unwrap_or_else(|| resource.id.clone()),
                service: resource.service.clone(),
                resource_type: resource.resource_type.clone(),
                region: resource.region.clone(),
                terraform_addresses: resource.terraform_addresses.clone(),
                finding_ids: resource.finding_ids.clone(),
                severity: resource.severity.clone(),
            })
            .collect(),
        edges: relationships
            .iter()
            .map(|relationship| AgentGraphEdge {
                id: relationship.uid.clone(),
                source: relationship.from.clone(),
                target: relationship.to.clone(),
                relationship_type: relationship.relationship_type.clone(),
            })
            .collect(),
    }
}

fn terraform_by_uid(
    resource_instances: &[AgentTerraformResource],
) -> BTreeMap<String, Vec<String>> {
    let mut map = BTreeMap::<String, Vec<String>>::new();
    for instance in resource_instances {
        let Some(aws_uid) = &instance.aws_uid else {
            continue;
        };
        map.entry(aws_uid.clone())
            .or_default()
            .push(instance.address.clone());
    }
    map
}

#[derive(Default)]
struct ResourceFindings {
    ids: Vec<String>,
    severity: Option<String>,
}

fn findings_by_uid(findings: &[AgentFinding]) -> BTreeMap<String, ResourceFindings> {
    let mut map = BTreeMap::<String, ResourceFindings>::new();
    for finding in findings {
        let Some(aws_uid) = &finding.aws_uid else {
            continue;
        };
        let entry = map.entry(aws_uid.clone()).or_default();
        entry.ids.push(finding.id.clone());
        entry.severity = max_severity(entry.severity.as_deref(), &finding.severity);
    }
    map
}

fn max_severity(current: Option<&str>, next: &str) -> Option<String> {
    let selected = match (
        severity_rank(current.unwrap_or("none")),
        severity_rank(next),
    ) {
        (current_rank, next_rank) if current_rank >= next_rank => current.unwrap_or(next),
        _ => next,
    };
    if selected == "none" {
        None
    } else {
        Some(selected.to_string())
    }
}

fn severity_rank(severity: &str) -> i32 {
    match severity {
        "critical" => 3,
        "high" => 2,
        "medium" => 1,
        _ => 0,
    }
}

fn parse_json<T: serde::de::DeserializeOwned>(value: String) -> rusqlite::Result<T> {
    serde_json::from_str(&value).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(error))
    })
}

fn parse_optional_json<T: serde::de::DeserializeOwned>(
    value: Option<String>,
) -> rusqlite::Result<Option<T>> {
    value.map(parse_json).transpose()
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use chrono::Utc;
    use rusqlite::params;
    use serde_json::json;
    use tempfile::tempdir;

    use crate::db::{open_cloudmapper_db, write_inventory_db};
    use crate::model::{Generator, Inventory, Relationship, Resource, SCHEMA_VERSION};
    use crate::terraform_state::import_terraform_state_file;

    use super::*;

    #[test]
    fn exports_single_agent_json_with_tf_mapping_and_findings() {
        let temp = tempdir().unwrap();
        let db_path = temp.path().join("map.db");
        let state_path = temp.path().join("terraform.tfstate");
        let scan_id = write_inventory_db(&db_path, &sample_inventory()).unwrap();
        std::fs::write(&state_path, SAMPLE_TFSTATE).unwrap();
        let tf_summary = import_terraform_state_file(&db_path, &state_path, None).unwrap();
        seed_finding(&db_path, &scan_id, &tf_summary.state_id);

        let export = export_agent_bundle(&db_path, None, None, None).unwrap();
        let json = serde_json::to_value(&export).unwrap();

        assert_eq!(json["schema_version"], "cloudmapper.agent.v1");
        assert_eq!(export.scan.account.id, "123456789012");
        assert_eq!(export.counts.resources, 2);
        assert_eq!(export.counts.relationships, 1);
        assert_eq!(export.counts.terraform_resource_instances, 1);
        assert_eq!(export.counts.findings, 1);

        let sg = export
            .resources
            .iter()
            .find(|resource| resource.id == "sg-123")
            .unwrap();
        assert_eq!(sg.terraform_addresses, vec!["aws_security_group.web"]);
        assert_eq!(sg.finding_ids, vec!["finding:public-sg"]);
        assert_eq!(sg.severity.as_deref(), Some("critical"));
        assert_eq!(export.findings[0].blast_radius, vec![instance_uid()]);
        assert_eq!(export.graph.nodes.len(), 2);
        assert_eq!(export.graph.edges.len(), 1);
    }

    #[test]
    fn export_requires_an_aws_scan() {
        let temp = tempdir().unwrap();
        let db_path = temp.path().join("map.db");
        open_cloudmapper_db(&db_path).unwrap();

        let error = export_agent_bundle(&db_path, None, None, None).unwrap_err();

        assert!(error.to_string().contains("no AWS scan found"));
    }

    fn seed_finding(db_path: &Path, scan_id: &str, state_id: &str) {
        let connection = open_cloudmapper_db(db_path).unwrap();
        let run_id = format!("compare:{scan_id}:{state_id}");
        connection
            .execute(
                r#"
                INSERT INTO findings (
                  run_id, id, finding_type, severity, aws_uid, terraform_address, reason,
                  recommended_action, blast_radius_json, evidence_json, attributes_json, created_at
                )
                VALUES (?1, 'finding:public-sg', 'terraform_owned_public_ingress', 'critical',
                        ?2, 'aws_security_group.web',
                        'Security group allows public ingress.',
                        'Restrict public ingress in Terraform.',
                        ?3, ?4, ?5, '2026-05-16T00:00:00Z')
                "#,
                params![
                    run_id,
                    security_group_uid(),
                    serde_json::to_string(&vec![instance_uid()]).unwrap(),
                    serde_json::to_string(&vec![json!({
                        "service": "ec2",
                        "operation": "DescribeSecurityGroups"
                    })])
                    .unwrap(),
                    serde_json::to_string(&json!({ "public_ports": ["22/tcp"] })).unwrap(),
                ],
            )
            .unwrap();
    }

    fn sample_inventory() -> Inventory {
        Inventory {
            schema_version: SCHEMA_VERSION.to_string(),
            generator: Generator {
                name: "cloudmapper".to_string(),
                version: "test".to_string(),
            },
            account_id: "123456789012".to_string(),
            partition: "aws".to_string(),
            home_region: "us-east-1".to_string(),
            regions: vec!["us-east-1".to_string()],
            collected_at: Utc::now(),
            resources: vec![
                Resource {
                    uid: security_group_uid(),
                    provider: "aws".to_string(),
                    account_id: "123456789012".to_string(),
                    partition: "aws".to_string(),
                    region: "us-east-1".to_string(),
                    service: "ec2".to_string(),
                    resource_type: "security-group".to_string(),
                    id: "sg-123".to_string(),
                    arn: Some(
                        "arn:aws:ec2:us-east-1:123456789012:security-group/sg-123".to_string(),
                    ),
                    name: Some("web".to_string()),
                    tags: BTreeMap::new(),
                    attributes: json!({
                        "ingress": [{
                            "ip_protocol": "tcp",
                            "from_port": 22,
                            "to_port": 22,
                            "ipv4_ranges": ["0.0.0.0/0"],
                            "ipv6_ranges": []
                        }]
                    }),
                    evidence: Vec::new(),
                    raw: None,
                },
                Resource {
                    uid: instance_uid(),
                    provider: "aws".to_string(),
                    account_id: "123456789012".to_string(),
                    partition: "aws".to_string(),
                    region: "us-east-1".to_string(),
                    service: "ec2".to_string(),
                    resource_type: "instance".to_string(),
                    id: "i-123".to_string(),
                    arn: Some("arn:aws:ec2:us-east-1:123456789012:instance/i-123".to_string()),
                    name: Some("web-1".to_string()),
                    tags: BTreeMap::new(),
                    attributes: json!({ "state": "running" }),
                    evidence: Vec::new(),
                    raw: None,
                },
            ],
            relationships: vec![Relationship {
                uid: "rel:i-123:sg-123".to_string(),
                from: instance_uid(),
                to: security_group_uid(),
                relationship_type: "uses_security_group".to_string(),
                attributes: json!({}),
                evidence: Vec::new(),
            }],
            errors: Vec::new(),
        }
    }

    fn security_group_uid() -> String {
        "aws:123456789012:us-east-1:ec2:security-group:sg-123".to_string()
    }

    fn instance_uid() -> String {
        "aws:123456789012:us-east-1:ec2:instance:i-123".to_string()
    }

    const SAMPLE_TFSTATE: &str = r#"
{
  "version": 4,
  "terraform_version": "1.8.0",
  "serial": 7,
  "lineage": "agent-export-test",
  "resources": [
    {
      "mode": "managed",
      "type": "aws_security_group",
      "name": "web",
      "provider": "provider[\"registry.terraform.io/hashicorp/aws\"]",
      "instances": [
        {
          "schema_version": 1,
          "attributes": {
            "id": "sg-123",
            "arn": "arn:aws:ec2:us-east-1:123456789012:security-group/sg-123",
            "name": "web"
          },
          "sensitive_attributes": [],
          "dependencies": []
        }
      ]
    }
  ]
}
"#;
}
