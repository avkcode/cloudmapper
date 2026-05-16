use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use rusqlite::{Connection, OptionalExtension, params};

use crate::model::Inventory;

pub fn open_cloudmapper_db(path: &Path) -> Result<Connection> {
    ensure_parent_dir(path)?;
    let connection = Connection::open(path)
        .with_context(|| format!("opening map database {}", path.display()))?;
    init_schema(&connection)?;
    Ok(connection)
}

pub fn init_schema(connection: &Connection) -> Result<()> {
    connection
        .execute_batch(
            r#"
            PRAGMA foreign_keys = ON;

            CREATE TABLE IF NOT EXISTS scans (
              id TEXT PRIMARY KEY,
              schema_version TEXT NOT NULL,
              generator_name TEXT NOT NULL,
              generator_version TEXT NOT NULL,
              account_id TEXT NOT NULL,
              partition TEXT NOT NULL,
              home_region TEXT NOT NULL,
              regions_json TEXT NOT NULL,
              collected_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS resources (
              scan_id TEXT NOT NULL,
              uid TEXT NOT NULL,
              provider TEXT NOT NULL,
              account_id TEXT NOT NULL,
              partition TEXT NOT NULL,
              region TEXT NOT NULL,
              service TEXT NOT NULL,
              resource_type TEXT NOT NULL,
              resource_id TEXT NOT NULL,
              arn TEXT,
              name TEXT,
              tags_json TEXT NOT NULL,
              attributes_json TEXT NOT NULL,
              evidence_json TEXT NOT NULL,
              raw_json TEXT,
              PRIMARY KEY (scan_id, uid),
              FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS relationships (
              scan_id TEXT NOT NULL,
              uid TEXT NOT NULL,
              from_uid TEXT NOT NULL,
              to_uid TEXT NOT NULL,
              relationship_type TEXT NOT NULL,
              attributes_json TEXT NOT NULL,
              evidence_json TEXT NOT NULL,
              PRIMARY KEY (scan_id, uid),
              FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS scan_errors (
              scan_id TEXT NOT NULL,
              service TEXT NOT NULL,
              region TEXT NOT NULL,
              operation TEXT NOT NULL,
              message TEXT NOT NULL,
              FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS terraform_states (
              state_id TEXT PRIMARY KEY,
              source_path TEXT NOT NULL,
              terraform_version TEXT,
              serial INTEGER,
              lineage TEXT,
              imported_at TEXT NOT NULL,
              raw_json TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS terraform_resource_instances (
              state_id TEXT NOT NULL,
              address TEXT NOT NULL,
              module TEXT,
              mode TEXT NOT NULL,
              resource_type TEXT NOT NULL,
              name TEXT NOT NULL,
              provider TEXT,
              index_key_json TEXT,
              schema_version INTEGER,
              attributes_json TEXT NOT NULL,
              sensitive_attributes_json TEXT NOT NULL,
              dependencies_json TEXT NOT NULL,
              raw_json TEXT NOT NULL,
              aws_uid TEXT,
              PRIMARY KEY (state_id, address),
              FOREIGN KEY (state_id) REFERENCES terraform_states(state_id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS findings (
              run_id TEXT NOT NULL,
              id TEXT NOT NULL,
              finding_type TEXT NOT NULL,
              severity TEXT NOT NULL,
              aws_uid TEXT,
              terraform_address TEXT,
              reason TEXT NOT NULL,
              recommended_action TEXT NOT NULL,
              blast_radius_json TEXT NOT NULL,
              evidence_json TEXT NOT NULL,
              attributes_json TEXT NOT NULL,
              created_at TEXT NOT NULL,
              PRIMARY KEY (run_id, id)
            );

            CREATE INDEX IF NOT EXISTS idx_resources_service_type
              ON resources(scan_id, service, resource_type);
            CREATE INDEX IF NOT EXISTS idx_resources_region
              ON resources(scan_id, region);
            CREATE INDEX IF NOT EXISTS idx_resources_arn
              ON resources(scan_id, arn);
            CREATE INDEX IF NOT EXISTS idx_relationships_from
              ON relationships(scan_id, from_uid);
            CREATE INDEX IF NOT EXISTS idx_relationships_to
              ON relationships(scan_id, to_uid);
            CREATE INDEX IF NOT EXISTS idx_relationships_type
              ON relationships(scan_id, relationship_type);
            CREATE INDEX IF NOT EXISTS idx_tf_instances_type
              ON terraform_resource_instances(state_id, resource_type);
            CREATE INDEX IF NOT EXISTS idx_tf_instances_aws_uid
              ON terraform_resource_instances(state_id, aws_uid);
            CREATE INDEX IF NOT EXISTS idx_findings_type
              ON findings(run_id, finding_type);
            CREATE INDEX IF NOT EXISTS idx_findings_aws_uid
              ON findings(run_id, aws_uid);

            PRAGMA user_version = 1;
            "#,
        )
        .context("initializing cloudmapper map schema")?;
    Ok(())
}

pub fn write_inventory_db(path: &Path, inventory: &Inventory) -> Result<String> {
    let mut connection = open_cloudmapper_db(path)?;
    let scan_id = scan_id(inventory);
    let transaction = connection.transaction()?;

    transaction.execute("DELETE FROM scans WHERE id = ?1", params![scan_id])?;
    transaction.execute(
        r#"
        INSERT INTO scans (
          id, schema_version, generator_name, generator_version, account_id, partition,
          home_region, regions_json, collected_at
        )
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
        "#,
        params![
            scan_id,
            inventory.schema_version,
            inventory.generator.name,
            inventory.generator.version,
            inventory.account_id,
            inventory.partition,
            inventory.home_region,
            serde_json::to_string(&inventory.regions)?,
            inventory.collected_at.to_rfc3339(),
        ],
    )?;

    {
        let mut statement = transaction.prepare(
            r#"
            INSERT INTO resources (
              scan_id, uid, provider, account_id, partition, region, service, resource_type,
              resource_id, arn, name, tags_json, attributes_json, evidence_json, raw_json
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)
            "#,
        )?;
        for resource in &inventory.resources {
            statement.execute(params![
                scan_id,
                resource.uid,
                resource.provider,
                resource.account_id,
                resource.partition,
                resource.region,
                resource.service,
                resource.resource_type,
                resource.id,
                resource.arn,
                resource.name,
                serde_json::to_string(&resource.tags)?,
                serde_json::to_string(&resource.attributes)?,
                serde_json::to_string(&resource.evidence)?,
                optional_json(&resource.raw)?,
            ])?;
        }
    }

    {
        let mut statement = transaction.prepare(
            r#"
            INSERT INTO relationships (
              scan_id, uid, from_uid, to_uid, relationship_type, attributes_json, evidence_json
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
            "#,
        )?;
        for relationship in &inventory.relationships {
            statement.execute(params![
                scan_id,
                relationship.uid,
                relationship.from,
                relationship.to,
                relationship.relationship_type,
                serde_json::to_string(&relationship.attributes)?,
                serde_json::to_string(&relationship.evidence)?,
            ])?;
        }
    }

    {
        let mut statement = transaction.prepare(
            r#"
            INSERT INTO scan_errors (scan_id, service, region, operation, message)
            VALUES (?1, ?2, ?3, ?4, ?5)
            "#,
        )?;
        for error in &inventory.errors {
            statement.execute(params![
                scan_id,
                error.service,
                error.region,
                error.operation,
                error.message,
            ])?;
        }
    }

    transaction.commit()?;
    Ok(scan_id)
}

pub fn latest_terraform_state_id(connection: &Connection) -> Result<Option<String>> {
    connection
        .query_row(
            "SELECT state_id FROM terraform_states ORDER BY imported_at DESC, state_id DESC LIMIT 1",
            [],
            |row| row.get(0),
        )
        .optional()
        .context("loading latest Terraform state id")
}

fn scan_id(inventory: &Inventory) -> String {
    format!(
        "aws:{}:{}",
        inventory.account_id,
        inventory.collected_at.to_rfc3339()
    )
}

fn ensure_parent_dir(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    }
    Ok(())
}

fn optional_json(value: &Option<serde_json::Value>) -> Result<Option<String>> {
    value
        .as_ref()
        .map(serde_json::to_string)
        .transpose()
        .context("serializing optional JSON value")
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use chrono::Utc;
    use rusqlite::Connection;
    use serde_json::json;
    use tempfile::tempdir;

    use crate::model::{
        Evidence, Generator, Inventory, Relationship, Resource, SCHEMA_VERSION, ScanError,
    };

    use super::*;

    #[test]
    fn writes_inventory_snapshot_to_map_db() {
        let temp = tempdir().unwrap();
        let db_path = temp.path().join("map.db");
        let inventory = sample_inventory();

        let scan_id = write_inventory_db(&db_path, &inventory).unwrap();
        let connection = Connection::open(db_path).unwrap();

        let resources: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM resources WHERE scan_id = ?1",
                params![scan_id],
                |row| row.get(0),
            )
            .unwrap();
        let relationships: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM relationships WHERE scan_id = ?1",
                params![scan_id],
                |row| row.get(0),
            )
            .unwrap();
        let errors: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM scan_errors WHERE scan_id = ?1",
                params![scan_id],
                |row| row.get(0),
            )
            .unwrap();

        assert_eq!(resources, 1);
        assert_eq!(relationships, 1);
        assert_eq!(errors, 1);
    }

    pub fn sample_inventory() -> Inventory {
        let collected_at = Utc::now();
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
            collected_at,
            resources: vec![Resource {
                uid: "aws:123456789012:us-east-1:ec2:security-group:sg-123".to_string(),
                provider: "aws".to_string(),
                account_id: "123456789012".to_string(),
                partition: "aws".to_string(),
                region: "us-east-1".to_string(),
                service: "ec2".to_string(),
                resource_type: "security-group".to_string(),
                id: "sg-123".to_string(),
                arn: Some("arn:aws:ec2:us-east-1:123456789012:security-group/sg-123".to_string()),
                name: Some("web".to_string()),
                tags: BTreeMap::from([("Name".to_string(), "web".to_string())]),
                attributes: json!({"group_name": "web"}),
                evidence: vec![Evidence {
                    service: "ec2".to_string(),
                    operation: "DescribeSecurityGroups".to_string(),
                    path: "$.SecurityGroups[]".to_string(),
                    collected_at,
                }],
                raw: None,
            }],
            relationships: vec![Relationship {
                uid: "rel-1".to_string(),
                from: "aws:123456789012:us-east-1:ec2:instance:i-123".to_string(),
                to: "aws:123456789012:us-east-1:ec2:security-group:sg-123".to_string(),
                relationship_type: "uses_security_group".to_string(),
                attributes: json!({}),
                evidence: Vec::new(),
            }],
            errors: vec![ScanError {
                service: "ec2".to_string(),
                region: "us-east-1".to_string(),
                operation: "DescribeInstances".to_string(),
                message: "access denied".to_string(),
            }],
        }
    }
}
