use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use rusqlite::{Connection, OptionalExtension, params};
use serde::Serialize;
use serde_json::{Value, json};

use crate::db::{latest_terraform_state_id, open_cloudmapper_db};

const INDEX_HTML: &str = include_str!("ui_assets/index.html");
const APP_CSS: &str = include_str!("ui_assets/app.css");
const APP_JS: &str = include_str!("ui_assets/app.js");
const CYTOSCAPE_JS: &str = include_str!("ui_assets/cytoscape.min.js");
const D3_JS: &str = include_str!("ui_assets/d3.min.js");

#[derive(Clone)]
struct UiState {
    db_path: PathBuf,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct UiSummary {
    account_id: Option<String>,
    collected_at: Option<String>,
    scan_id: Option<String>,
    terraform_state_id: Option<String>,
    compare_run_id: Option<String>,
    resources: i64,
    relationships: i64,
    findings: i64,
    critical_findings: i64,
    high_findings: i64,
    managed_resources: i64,
    service_counts: Vec<ServiceCount>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ServiceCount {
    service: String,
    resource_type: String,
    count: i64,
}

#[derive(Debug, Serialize)]
struct GraphPayload {
    summary: UiSummary,
    nodes: Vec<GraphNode>,
    edges: Vec<GraphEdge>,
}

#[derive(Debug, Serialize)]
struct GraphNode {
    data: GraphNodeData,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct GraphNodeData {
    id: String,
    label: String,
    provider: String,
    account_id: String,
    partition: String,
    service: String,
    resource_type: String,
    region: String,
    namespace: Option<String>,
    arn: Option<String>,
    name: Option<String>,
    tags: Value,
    environment: Option<String>,
    application: Option<String>,
    owner: Option<String>,
    terraform_address: Option<String>,
    severity: Option<String>,
    finding_types: Vec<String>,
    attributes: Value,
    evidence: Value,
    raw: Option<Value>,
}

#[derive(Debug, Serialize)]
struct GraphEdge {
    data: GraphEdgeData,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct GraphEdgeData {
    id: String,
    source: String,
    target: String,
    relationship_type: String,
    attributes: Value,
    evidence: Value,
}

#[derive(Debug, Serialize)]
struct FindingsPayload {
    run_id: Option<String>,
    findings: Vec<FindingRow>,
}

#[derive(Debug, Serialize)]
struct FindingRow {
    id: String,
    finding_type: String,
    severity: String,
    aws_uid: Option<String>,
    terraform_address: Option<String>,
    reason: String,
    recommended_action: String,
    blast_radius: Vec<String>,
    evidence: Value,
    attributes: Value,
}

#[derive(Default)]
struct FindingOverlay {
    severity: Option<String>,
    finding_types: Vec<String>,
}

enum UiBody {
    Static {
        content_type: &'static str,
        body: &'static [u8],
    },
    Json(Vec<u8>),
}

pub fn serve_ui(db_path: &Path, bind: &str) -> Result<()> {
    let listener = TcpListener::bind(bind).with_context(|| format!("binding UI server {bind}"))?;
    let state = UiState {
        db_path: db_path.to_path_buf(),
    };
    println!("cloudmapper UI: http://{bind}");
    println!("database: {}", db_path.display());

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                if let Err(error) = handle_connection(stream, &state) {
                    eprintln!("ui request error: {error:#}");
                }
            }
            Err(error) => eprintln!("ui connection error: {error}"),
        }
    }
    Ok(())
}

fn handle_connection(mut stream: TcpStream, state: &UiState) -> Result<()> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut request_line = String::new();
    reader.read_line(&mut request_line)?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default();
    let target = parts.next().unwrap_or("/");

    let mut header = String::new();
    loop {
        header.clear();
        reader.read_line(&mut header)?;
        if header == "\r\n" || header.is_empty() {
            break;
        }
    }

    if method != "GET" {
        return write_response(
            &mut stream,
            405,
            "application/json",
            br#"{"error":"method not allowed"}"#,
        );
    }

    let path = target.split('?').next().unwrap_or("/");
    match route_request(path, state) {
        Ok(Some(UiBody::Static { content_type, body })) => {
            write_response(&mut stream, 200, content_type, body)
        }
        Ok(Some(UiBody::Json(body))) => write_response(&mut stream, 200, "application/json", &body),
        Ok(None) => write_response(
            &mut stream,
            404,
            "application/json",
            br#"{"error":"not found"}"#,
        ),
        Err(error) => {
            let body = serde_json::to_vec(&json!({ "error": error.to_string() }))?;
            write_response(&mut stream, 500, "application/json", &body)
        }
    }
}

fn route_request(path: &str, state: &UiState) -> Result<Option<UiBody>> {
    let body = match path {
        "/" | "/index.html" => UiBody::Static {
            content_type: "text/html; charset=utf-8",
            body: INDEX_HTML.as_bytes(),
        },
        "/app.css" => UiBody::Static {
            content_type: "text/css; charset=utf-8",
            body: APP_CSS.as_bytes(),
        },
        "/app.js" => UiBody::Static {
            content_type: "application/javascript; charset=utf-8",
            body: APP_JS.as_bytes(),
        },
        "/cytoscape.min.js" => UiBody::Static {
            content_type: "application/javascript; charset=utf-8",
            body: CYTOSCAPE_JS.as_bytes(),
        },
        "/d3.min.js" => UiBody::Static {
            content_type: "application/javascript; charset=utf-8",
            body: D3_JS.as_bytes(),
        },
        "/api/summary" => UiBody::Json(serde_json::to_vec(&load_summary(&state.db_path)?)?),
        "/api/graph" => UiBody::Json(serde_json::to_vec(&load_graph(&state.db_path)?)?),
        "/api/findings" => UiBody::Json(serde_json::to_vec(&load_findings(&state.db_path)?)?),
        _ => return Ok(None),
    };
    Ok(Some(body))
}

fn write_response(
    stream: &mut TcpStream,
    status: u16,
    content_type: &str,
    body: &[u8],
) -> Result<()> {
    let status_text = match status {
        200 => "OK",
        404 => "Not Found",
        405 => "Method Not Allowed",
        500 => "Internal Server Error",
        _ => "OK",
    };
    write!(
        stream,
        "HTTP/1.1 {status} {status_text}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
        body.len()
    )?;
    stream.write_all(body)?;
    Ok(())
}

fn load_summary(db_path: &Path) -> Result<UiSummary> {
    let connection = open_cloudmapper_db(db_path)?;
    let scan_id = latest_scan_id(&connection)?;
    let terraform_state_id = latest_terraform_state_id(&connection)?;
    let compare_run_id = latest_compare_run_id(&connection)?;
    summary_for(&connection, scan_id, terraform_state_id, compare_run_id)
}

fn load_graph(db_path: &Path) -> Result<GraphPayload> {
    let connection = open_cloudmapper_db(db_path)?;
    let scan_id = latest_scan_id(&connection)?;
    let terraform_state_id = latest_terraform_state_id(&connection)?;
    let compare_run_id = latest_compare_run_id(&connection)?;
    let summary = summary_for(
        &connection,
        scan_id.clone(),
        terraform_state_id.clone(),
        compare_run_id.clone(),
    )?;
    let terraform_map = terraform_map(&connection, terraform_state_id.as_deref())?;
    let finding_map = finding_overlay(&connection, compare_run_id.as_deref())?;

    let mut nodes = Vec::new();
    if let Some(scan_id) = scan_id.as_deref() {
        let mut statement = connection.prepare(
            r#"
            SELECT uid, provider, account_id, partition, service, resource_type, region,
                   resource_id, arn, name, tags_json, attributes_json, evidence_json, raw_json
            FROM resources
            WHERE scan_id = ?1
            ORDER BY service, resource_type, name, resource_id
            "#,
        )?;
        let rows = statement.query_map(params![scan_id], |row| {
            let id: String = row.get(0)?;
            let provider: String = row.get(1)?;
            let account_id: String = row.get(2)?;
            let partition: String = row.get(3)?;
            let service: String = row.get(4)?;
            let resource_type: String = row.get(5)?;
            let region: String = row.get(6)?;
            let resource_id: String = row.get(7)?;
            let arn: Option<String> = row.get(8)?;
            let name: Option<String> = row.get(9)?;
            let tags: Value = parse_json(row.get::<_, String>(10)?)?;
            let attributes_json: String = row.get(11)?;
            let evidence_json: String = row.get(12)?;
            let raw_json: Option<String> = row.get(13)?;
            let overlay = finding_map.get(&id);
            Ok(GraphNode {
                data: GraphNodeData {
                    id: id.clone(),
                    label: name.clone().unwrap_or(resource_id),
                    provider: provider.clone(),
                    account_id,
                    partition,
                    service,
                    resource_type,
                    namespace: namespace_value(&provider, &region, &tags),
                    region,
                    arn,
                    name,
                    environment: tag_value(&tags, "Environment"),
                    application: tag_value(&tags, "Application"),
                    owner: tag_value(&tags, "Owner"),
                    tags,
                    terraform_address: terraform_map.get(&id).cloned(),
                    severity: overlay.and_then(|overlay| overlay.severity.clone()),
                    finding_types: overlay
                        .map(|overlay| overlay.finding_types.clone())
                        .unwrap_or_default(),
                    attributes: parse_json(attributes_json)?,
                    evidence: parse_json(evidence_json)?,
                    raw: parse_optional_json(raw_json)?,
                },
            })
        })?;
        for row in rows {
            nodes.push(row?);
        }
    }

    let node_ids = nodes
        .iter()
        .map(|node| node.data.id.clone())
        .collect::<std::collections::BTreeSet<_>>();
    let mut edges = Vec::new();
    if let Some(scan_id) = scan_id.as_deref() {
        let mut statement = connection.prepare(
            r#"
            SELECT uid, from_uid, to_uid, relationship_type, attributes_json, evidence_json
            FROM relationships
            WHERE scan_id = ?1
            ORDER BY relationship_type, uid
            "#,
        )?;
        let rows = statement.query_map(params![scan_id], |row| {
            Ok(GraphEdge {
                data: GraphEdgeData {
                    id: row.get(0)?,
                    source: row.get(1)?,
                    target: row.get(2)?,
                    relationship_type: row.get(3)?,
                    attributes: parse_json(row.get::<_, String>(4)?)?,
                    evidence: parse_json(row.get::<_, String>(5)?)?,
                },
            })
        })?;
        for row in rows {
            let edge = row?;
            if node_ids.contains(&edge.data.source) && node_ids.contains(&edge.data.target) {
                edges.push(edge);
            }
        }
    }

    Ok(GraphPayload {
        summary,
        nodes,
        edges,
    })
}

fn namespace_value(provider: &str, region: &str, tags: &Value) -> Option<String> {
    tag_value(tags, "Namespace").or_else(|| {
        if provider == "k8s" && region != "cluster" && region != "global" {
            Some(region.to_string())
        } else {
            None
        }
    })
}

fn tag_value(tags: &Value, key: &str) -> Option<String> {
    tags.as_object()?
        .iter()
        .find(|(tag_key, _)| tag_key.eq_ignore_ascii_case(key))
        .and_then(|(_, value)| value.as_str())
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
}

fn load_findings(db_path: &Path) -> Result<FindingsPayload> {
    let connection = open_cloudmapper_db(db_path)?;
    let run_id = latest_compare_run_id(&connection)?;
    let Some(run_id_value) = run_id.as_deref() else {
        return Ok(FindingsPayload {
            run_id: None,
            findings: Vec::new(),
        });
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
    let rows = statement.query_map(params![run_id_value], |row| {
        let blast_radius_json: String = row.get(7)?;
        let evidence_json: String = row.get(8)?;
        let attributes_json: String = row.get(9)?;
        Ok(FindingRow {
            id: row.get(0)?,
            finding_type: row.get(1)?,
            severity: row.get(2)?,
            aws_uid: row.get(3)?,
            terraform_address: row.get(4)?,
            reason: row.get(5)?,
            recommended_action: row.get(6)?,
            blast_radius: parse_json(blast_radius_json)?,
            evidence: parse_json(evidence_json)?,
            attributes: parse_json(attributes_json)?,
        })
    })?;
    let mut findings = Vec::new();
    for row in rows {
        findings.push(row?);
    }

    Ok(FindingsPayload { run_id, findings })
}

fn summary_for(
    connection: &Connection,
    scan_id: Option<String>,
    terraform_state_id: Option<String>,
    compare_run_id: Option<String>,
) -> Result<UiSummary> {
    let resources = count_where(connection, "resources", "scan_id", scan_id.as_deref())?;
    let relationships = count_where(connection, "relationships", "scan_id", scan_id.as_deref())?;
    let findings = count_where(connection, "findings", "run_id", compare_run_id.as_deref())?;
    let critical_findings = count_findings(connection, compare_run_id.as_deref(), "critical")?;
    let high_findings = count_findings(connection, compare_run_id.as_deref(), "high")?;
    let managed_resources = count_where(
        connection,
        "terraform_resource_instances",
        "state_id",
        terraform_state_id.as_deref(),
    )?;
    let service_counts = service_counts(connection, scan_id.as_deref())?;
    let (account_id, collected_at) = scan_metadata(connection, scan_id.as_deref())?;

    Ok(UiSummary {
        account_id,
        collected_at,
        scan_id,
        terraform_state_id,
        compare_run_id,
        resources,
        relationships,
        findings,
        critical_findings,
        high_findings,
        managed_resources,
        service_counts,
    })
}

fn scan_metadata(
    connection: &Connection,
    scan_id: Option<&str>,
) -> Result<(Option<String>, Option<String>)> {
    let Some(scan_id) = scan_id else {
        return Ok((None, None));
    };
    connection
        .query_row(
            "SELECT account_id, collected_at FROM scans WHERE id = ?1",
            params![scan_id],
            |row| Ok((Some(row.get(0)?), Some(row.get(1)?))),
        )
        .optional()
        .context("loading scan metadata")
        .map(|value| value.unwrap_or((None, None)))
}

fn latest_scan_id(connection: &Connection) -> Result<Option<String>> {
    connection
        .query_row(
            "SELECT id FROM scans ORDER BY collected_at DESC, id DESC LIMIT 1",
            [],
            |row| row.get(0),
        )
        .optional()
        .context("loading latest scan id")
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

fn terraform_map(
    connection: &Connection,
    state_id: Option<&str>,
) -> Result<BTreeMap<String, String>> {
    let Some(state_id) = state_id else {
        return Ok(BTreeMap::new());
    };
    let mut statement = connection.prepare(
        r#"
        SELECT aws_uid, address
        FROM terraform_resource_instances
        WHERE state_id = ?1 AND aws_uid IS NOT NULL
        "#,
    )?;
    let rows = statement.query_map(params![state_id], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
    })?;
    let mut map = BTreeMap::new();
    for row in rows {
        let (uid, address) = row?;
        map.insert(uid, address);
    }
    Ok(map)
}

fn finding_overlay(
    connection: &Connection,
    run_id: Option<&str>,
) -> Result<BTreeMap<String, FindingOverlay>> {
    let Some(run_id) = run_id else {
        return Ok(BTreeMap::new());
    };
    let mut statement = connection.prepare(
        r#"
        SELECT aws_uid, finding_type, severity
        FROM findings
        WHERE run_id = ?1 AND aws_uid IS NOT NULL
        "#,
    )?;
    let rows = statement.query_map(params![run_id], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
        ))
    })?;
    let mut overlays = BTreeMap::<String, FindingOverlay>::new();
    for row in rows {
        let (uid, finding_type, severity) = row?;
        let overlay = overlays.entry(uid).or_default();
        overlay.finding_types.push(finding_type);
        overlay.severity = max_severity(overlay.severity.as_deref(), &severity);
    }
    Ok(overlays)
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

fn count_where(
    connection: &Connection,
    table: &str,
    column: &str,
    value: Option<&str>,
) -> Result<i64> {
    let Some(value) = value else {
        return Ok(0);
    };
    let sql = format!("SELECT COUNT(*) FROM {table} WHERE {column} = ?1");
    connection
        .query_row(&sql, params![value], |row| row.get(0))
        .with_context(|| format!("counting {table}"))
}

fn count_findings(connection: &Connection, run_id: Option<&str>, severity: &str) -> Result<i64> {
    let Some(run_id) = run_id else {
        return Ok(0);
    };
    connection
        .query_row(
            "SELECT COUNT(*) FROM findings WHERE run_id = ?1 AND severity = ?2",
            params![run_id, severity],
            |row| row.get(0),
        )
        .context("counting findings")
}

fn service_counts(connection: &Connection, scan_id: Option<&str>) -> Result<Vec<ServiceCount>> {
    let Some(scan_id) = scan_id else {
        return Ok(Vec::new());
    };
    let mut statement = connection.prepare(
        r#"
        SELECT service, resource_type, COUNT(*)
        FROM resources
        WHERE scan_id = ?1
        GROUP BY service, resource_type
        ORDER BY COUNT(*) DESC, service, resource_type
        "#,
    )?;
    let rows = statement.query_map(params![scan_id], |row| {
        Ok(ServiceCount {
            service: row.get(0)?,
            resource_type: row.get(1)?,
            count: row.get(2)?,
        })
    })?;
    rows.collect::<Result<Vec<_>, _>>()
        .context("loading service counts")
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
    use serde_json::json;
    use tempfile::tempdir;

    use crate::compare::compare_infra;
    use crate::db::write_inventory_db;
    use crate::demo::write_demo_bundle;
    use crate::model::{Generator, Inventory, Resource, SCHEMA_VERSION};

    use super::*;

    #[test]
    fn loads_graph_payload_from_map_db() {
        let temp = tempdir().unwrap();
        let db_path = temp.path().join("map.db");
        write_inventory_db(&db_path, &sample_inventory()).unwrap();

        let graph = load_graph(&db_path).unwrap();

        assert_eq!(graph.summary.resources, 1);
        assert_eq!(graph.nodes.len(), 1);
        assert_eq!(graph.nodes[0].data.provider, "aws");
        assert_eq!(graph.nodes[0].data.account_id, "123456789012");
        assert_eq!(graph.nodes[0].data.service, "ec2");
        assert_eq!(graph.nodes[0].data.environment.as_deref(), Some("prod"));
        assert_eq!(graph.nodes[0].data.application.as_deref(), Some("api"));

        let json = serde_json::to_value(&graph).unwrap();
        assert!(json["summary"]["scanId"].is_string());
        assert_eq!(json["nodes"][0]["data"]["owner"], "platform");
        assert_eq!(
            json["summary"]["serviceCounts"][0]["resourceType"],
            "instance"
        );
    }

    #[test]
    fn overlays_findings_on_graph_nodes() {
        let temp = tempdir().unwrap();
        let db_path = temp.path().join("map.db");
        write_inventory_db(&db_path, &sample_public_inventory()).unwrap();
        seed_terraform_state(&db_path);
        compare_infra(&db_path, None, None).unwrap();

        let graph = load_graph(&db_path).unwrap();
        let public = graph
            .nodes
            .iter()
            .find(|node| node.data.id.ends_with("sg-public"))
            .unwrap();

        assert_eq!(public.data.severity.as_deref(), Some("critical"));
        assert!(
            public
                .data
                .finding_types
                .contains(&"unmanaged_public_resource".to_string())
        );
    }

    #[test]
    fn large_demo_graph_payload_exposes_navigation_facets() {
        let temp = tempdir().unwrap();
        let summary = write_demo_bundle(temp.path(), false).unwrap();

        let graph = load_graph(&summary.db_path).unwrap();

        assert_eq!(graph.summary.resources, 414);
        assert_eq!(graph.summary.relationships, 528);
        assert_eq!(graph.summary.managed_resources, 100);
        assert_eq!(graph.summary.findings, 327);
        assert_eq!(graph.summary.critical_findings, 15);
        assert_eq!(graph.summary.high_findings, 3);
        assert_eq!(graph.nodes.len(), 414);
        assert_eq!(graph.edges.len(), 528);
        assert!(graph.nodes.iter().any(|node| {
            node.data.environment.as_deref() == Some("prod")
                && node.data.application.as_deref() == Some("payments")
                && node.data.owner.as_deref() == Some("payments-platform")
        }));

        let json = serde_json::to_value(&graph).unwrap();
        assert!(json["nodes"][0]["data"]["tags"].is_object());
        assert!(json["nodes"][0]["data"].get("environment").is_some());
        assert!(json["nodes"][0]["data"].get("application").is_some());
    }

    #[test]
    fn k8s_graph_payload_exposes_provider_facets() {
        let temp = tempdir().unwrap();
        let db_path = temp.path().join("map.db");
        write_inventory_db(&db_path, &sample_k8s_inventory()).unwrap();

        let graph = load_graph(&db_path).unwrap();

        assert_eq!(graph.nodes.len(), 1);
        assert_eq!(graph.nodes[0].data.provider, "k8s");
        assert_eq!(graph.nodes[0].data.account_id, "prod-platform-us-east-1");
        assert_eq!(graph.nodes[0].data.partition, "kubernetes");
        assert_eq!(
            graph.nodes[0].data.namespace.as_deref(),
            Some("prod-payments")
        );
        assert_eq!(graph.nodes[0].data.service, "core");
        assert_eq!(graph.nodes[0].data.resource_type, "pod");
        assert_eq!(
            graph.nodes[0].data.owner.as_deref(),
            Some("payments-platform")
        );

        let json = serde_json::to_value(&graph).unwrap();
        assert_eq!(json["nodes"][0]["data"]["provider"], "k8s");
        assert_eq!(json["nodes"][0]["data"]["namespace"], "prod-payments");
        assert!(json["nodes"][0]["data"]["attributes"]["owner_references"].is_array());
    }

    #[test]
    fn ui_assets_expose_spread_mode() {
        assert!(INDEX_HTML.contains("id=\"spread\""));
        assert!(INDEX_HTML.contains("id=\"toggle-inspector\""));
        assert!(INDEX_HTML.contains("id=\"toggle-findings\""));
        assert!(INDEX_HTML.contains("class=\"panel-toggle\""));
        assert!(INDEX_HTML.contains("data-theme=\"light\""));
        assert!(INDEX_HTML.contains("class=\"graph-header\""));
        assert!(INDEX_HTML.contains("icon-spread"));
        assert!(INDEX_HTML.contains("icon-panel-left"));
        assert!(INDEX_HTML.contains("icon-panel-right"));
        assert!(APP_CSS.contains("#spread.active"));
        assert!(APP_CSS.contains(".workspace.hide-inspector"));
        assert!(APP_CSS.contains(".workspace.hide-findings"));
        assert!(APP_JS.contains("function spreadGraph()"));
        assert!(APP_JS.contains("function toggleSpreadMode()"));
        assert!(APP_JS.contains("function togglePanel(panel)"));
        assert!(APP_JS.contains("? theme : \"light\""));
        assert!(APP_JS.contains("params.set(\"spread\", \"1\")"));
        assert!(APP_JS.contains("params.set(\"inspector\", \"0\")"));
        assert!(APP_JS.contains("params.set(\"findingsPanel\", \"0\")"));
        assert!(APP_JS.contains("Spread graph"));
        assert!(APP_JS.contains("Compact graph"));
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
            resources: vec![Resource {
                uid: "aws:123456789012:us-east-1:ec2:instance:i-123".to_string(),
                provider: "aws".to_string(),
                account_id: "123456789012".to_string(),
                partition: "aws".to_string(),
                region: "us-east-1".to_string(),
                service: "ec2".to_string(),
                resource_type: "instance".to_string(),
                id: "i-123".to_string(),
                arn: Some("arn:aws:ec2:us-east-1:123456789012:instance/i-123".to_string()),
                name: Some("api".to_string()),
                tags: tags(&[
                    ("Environment", "prod"),
                    ("Application", "api"),
                    ("Owner", "platform"),
                ]),
                attributes: json!({}),
                evidence: Vec::new(),
                raw: None,
            }],
            relationships: Vec::new(),
            errors: Vec::new(),
        }
    }

    fn sample_public_inventory() -> Inventory {
        let mut inventory = sample_inventory();
        inventory.resources.push(Resource {
            uid: "aws:123456789012:us-east-1:ec2:security-group:sg-public".to_string(),
            provider: "aws".to_string(),
            account_id: "123456789012".to_string(),
            partition: "aws".to_string(),
            region: "us-east-1".to_string(),
            service: "ec2".to_string(),
            resource_type: "security-group".to_string(),
            id: "sg-public".to_string(),
            arn: Some("arn:aws:ec2:us-east-1:123456789012:security-group/sg-public".to_string()),
            name: Some("public".to_string()),
            tags: tags(&[
                ("Environment", "prod"),
                ("Application", "api"),
                ("Owner", "platform"),
            ]),
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
        });
        inventory
    }

    fn sample_k8s_inventory() -> Inventory {
        Inventory {
            schema_version: SCHEMA_VERSION.to_string(),
            generator: Generator {
                name: "cloudmapper".to_string(),
                version: "test".to_string(),
            },
            account_id: "prod-platform-us-east-1".to_string(),
            partition: "kubernetes".to_string(),
            home_region: "cluster".to_string(),
            regions: vec!["prod-payments".to_string()],
            collected_at: Utc::now(),
            resources: vec![Resource {
                uid: "k8s:prod-platform-us-east-1:prod-payments:core:pod:prod-payments/payments-api-abc".to_string(),
                provider: "k8s".to_string(),
                account_id: "prod-platform-us-east-1".to_string(),
                partition: "kubernetes".to_string(),
                region: "prod-payments".to_string(),
                service: "core".to_string(),
                resource_type: "pod".to_string(),
                id: "prod-payments/payments-api-abc".to_string(),
                arn: None,
                name: Some("payments-api-abc".to_string()),
                tags: tags(&[
                    ("Namespace", "prod-payments"),
                    ("Environment", "prod"),
                    ("Application", "payments"),
                    ("Owner", "payments-platform"),
                ]),
                attributes: json!({
                    "kind": "Pod",
                    "namespace": "prod-payments",
                    "owner_references": [{"kind": "ReplicaSet", "name": "payments-api-6d"}],
                    "service_account": "payments-api",
                    "host_network": false,
                    "host_pid": false,
                    "host_ipc": false,
                    "containers": [{"name": "api", "image": "registry.local/payments-api:v1"}],
                    "mounts": [{"kind": "Secret", "name": "payments-api", "source": "volume"}]
                }),
                evidence: Vec::new(),
                raw: None,
            }],
            relationships: Vec::new(),
            errors: Vec::new(),
        }
    }

    fn tags(entries: &[(&str, &str)]) -> BTreeMap<String, String> {
        entries
            .iter()
            .map(|(key, value)| ((*key).to_string(), (*value).to_string()))
            .collect()
    }

    fn seed_terraform_state(db_path: &Path) {
        let connection = open_cloudmapper_db(db_path).unwrap();
        connection.execute(
            r#"
            INSERT INTO terraform_states (
              state_id, source_path, terraform_version, serial, lineage, imported_at, raw_json
            )
            VALUES ('tf:test', 'terraform.tfstate', '1.8.0', 1, 'test', '2026-05-16T00:00:00Z', '{}')
            "#,
            [],
        ).unwrap();
    }
}
