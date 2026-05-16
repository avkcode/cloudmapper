use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const SCHEMA_VERSION: &str = "cloudmapper.infra.v1";
pub const GENERATOR_NAME: &str = "cloudmapper";

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Inventory {
    pub schema_version: String,
    pub generator: Generator,
    pub account_id: String,
    pub partition: String,
    pub home_region: String,
    pub regions: Vec<String>,
    pub collected_at: DateTime<Utc>,
    pub resources: Vec<Resource>,
    pub relationships: Vec<Relationship>,
    pub errors: Vec<ScanError>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Generator {
    pub name: String,
    pub version: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Resource {
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
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub tags: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub attributes: Value,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<Evidence>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw: Option<Value>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Relationship {
    pub uid: String,
    pub from: String,
    pub to: String,
    #[serde(rename = "type")]
    pub relationship_type: String,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub attributes: Value,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<Evidence>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Evidence {
    pub service: String,
    pub operation: String,
    pub path: String,
    pub collected_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ScanError {
    pub service: String,
    pub region: String,
    pub operation: String,
    pub message: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Manifest {
    pub schema_version: String,
    pub generator: Generator,
    pub account_id: String,
    pub partition: String,
    pub home_region: String,
    pub regions: Vec<String>,
    pub collected_at: DateTime<Utc>,
    pub files: Vec<ManifestFile>,
    pub counts: ManifestCounts,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ManifestFile {
    pub path: String,
    pub description: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ManifestCounts {
    pub resources: usize,
    pub relationships: usize,
    pub errors: usize,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Graph {
    pub schema_version: String,
    pub nodes: Vec<GraphNode>,
    pub edges: Vec<GraphEdge>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GraphNode {
    pub id: String,
    pub label: String,
    pub service: String,
    #[serde(rename = "type")]
    pub resource_type: String,
    pub region: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arn: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub tags: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GraphEdge {
    pub id: String,
    pub from: String,
    pub to: String,
    #[serde(rename = "type")]
    pub relationship_type: String,
}

#[derive(Clone, Debug)]
pub struct ParsedArn {
    pub partition: String,
    pub service: String,
    pub region: String,
    pub account_id: String,
    pub resource_type: String,
    pub resource_id: String,
}

impl Inventory {
    pub fn manifest(&self) -> Manifest {
        Manifest {
            schema_version: self.schema_version.clone(),
            generator: self.generator.clone(),
            account_id: self.account_id.clone(),
            partition: self.partition.clone(),
            home_region: self.home_region.clone(),
            regions: self.regions.clone(),
            collected_at: self.collected_at,
            files: vec![
                ManifestFile {
                    path: "inventory.json".to_string(),
                    description: "Complete inventory, relationship, and scan-error document."
                        .to_string(),
                },
                ManifestFile {
                    path: "resources.jsonl".to_string(),
                    description:
                        "One normalized resource per line for embedding and agent ingestion."
                            .to_string(),
                },
                ManifestFile {
                    path: "relationships.jsonl".to_string(),
                    description: "One relationship fact per line with evidence pointers."
                        .to_string(),
                },
                ManifestFile {
                    path: "errors.jsonl".to_string(),
                    description: "Recoverable service or region scan failures.".to_string(),
                },
                ManifestFile {
                    path: "graph.json".to_string(),
                    description: "Node and edge graph derived from resources and relationships."
                        .to_string(),
                },
                ManifestFile {
                    path: "map.db".to_string(),
                    description: "Cloudmapper map database for resources, relationships, scan errors, imported Terraform state, findings, and UI/API workflows.".to_string(),
                },
            ],
            counts: ManifestCounts {
                resources: self.resources.len(),
                relationships: self.relationships.len(),
                errors: self.errors.len(),
            },
        }
    }

    pub fn graph(&self) -> Graph {
        Graph {
            schema_version: self.schema_version.clone(),
            nodes: self
                .resources
                .iter()
                .map(|resource| GraphNode {
                    id: resource.uid.clone(),
                    label: resource.name.clone().unwrap_or_else(|| resource.id.clone()),
                    service: resource.service.clone(),
                    resource_type: resource.resource_type.clone(),
                    region: resource.region.clone(),
                    arn: resource.arn.clone(),
                    tags: resource.tags.clone(),
                })
                .collect(),
            edges: self
                .relationships
                .iter()
                .map(|relationship| GraphEdge {
                    id: relationship.uid.clone(),
                    from: relationship.from.clone(),
                    to: relationship.to.clone(),
                    relationship_type: relationship.relationship_type.clone(),
                })
                .collect(),
        }
    }
}

pub fn resource_uid(
    account_id: &str,
    region: &str,
    service: &str,
    resource_type: &str,
    id: &str,
) -> String {
    format!(
        "aws:{account_id}:{region}:{service}:{resource_type}:{}",
        sanitize_uid_segment(id)
    )
}

pub fn relationship_uid(from: &str, relationship_type: &str, to: &str) -> String {
    format!("{from}->{relationship_type}->{}", sanitize_uid_segment(to))
}

pub fn parse_arn(arn: &str) -> Option<ParsedArn> {
    let mut parts = arn.splitn(6, ':');
    let prefix = parts.next()?;
    if prefix != "arn" {
        return None;
    }
    let partition = parts.next()?.to_string();
    let service = parts.next()?.to_string();
    let region = parts.next().unwrap_or_default().to_string();
    let account_id = parts.next().unwrap_or_default().to_string();
    let resource = parts.next()?.to_string();
    let (resource_type, resource_id) = split_arn_resource(&service, &resource);

    Some(ParsedArn {
        partition,
        service,
        region: empty_to_global(region),
        account_id,
        resource_type,
        resource_id,
    })
}

pub fn uid_for_arn(default_account_id: &str, arn: &str) -> Option<String> {
    let parsed = parse_arn(arn)?;
    let account_id = if parsed.account_id.is_empty() {
        default_account_id
    } else {
        &parsed.account_id
    };
    Some(resource_uid(
        account_id,
        &parsed.region,
        &parsed.service,
        &parsed.resource_type,
        &parsed.resource_id,
    ))
}

pub fn empty_to_global(region: String) -> String {
    if region.is_empty() {
        "global".to_string()
    } else {
        region
    }
}

fn split_arn_resource(service: &str, resource: &str) -> (String, String) {
    if service == "s3" && !resource.contains('/') && !resource.contains(':') {
        return ("bucket".to_string(), resource.to_string());
    }
    if let Some((resource_type, id)) = resource.split_once('/') {
        return (resource_type.to_string(), id.to_string());
    }
    if let Some((resource_type, id)) = resource.split_once(':') {
        return (resource_type.to_string(), id.to_string());
    }
    ("resource".to_string(), resource.to_string())
}

fn sanitize_uid_segment(value: &str) -> String {
    value.replace([' ', '\n', '\t'], "_")
}

pub fn json_object(entries: impl IntoIterator<Item = (&'static str, Value)>) -> Value {
    let mut object = serde_json::Map::new();
    for (key, value) in entries {
        if !value.is_null() {
            object.insert(key.to_string(), value);
        }
    }
    Value::Object(object)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_s3_bucket_arn_as_global_resource() {
        let parsed = parse_arn("arn:aws:s3:::example-bucket").unwrap();

        assert_eq!(parsed.partition, "aws");
        assert_eq!(parsed.service, "s3");
        assert_eq!(parsed.region, "global");
        assert_eq!(parsed.resource_type, "bucket");
        assert_eq!(parsed.resource_id, "example-bucket");
    }

    #[test]
    fn uid_for_arn_fills_missing_account() {
        let uid = uid_for_arn("123456789012", "arn:aws:s3:::example-bucket").unwrap();

        assert_eq!(uid, "aws:123456789012:global:s3:bucket:example-bucket");
    }
}
