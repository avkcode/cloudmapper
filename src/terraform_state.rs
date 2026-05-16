use std::path::Path;

use anyhow::{Context, Result};
use chrono::Utc;
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::db::{latest_terraform_state_id, open_cloudmapper_db};
use crate::model::uid_for_arn;

#[derive(Debug, Serialize)]
pub struct TerraformImportSummary {
    pub state_id: String,
    pub resource_instances: usize,
}

#[derive(Debug, Serialize)]
pub struct TerraformStateExport {
    pub schema_version: String,
    pub state_id: String,
    pub source_path: String,
    pub terraform_version: Option<String>,
    pub serial: Option<i64>,
    pub lineage: Option<String>,
    pub resource_instances: Vec<TerraformResourceExport>,
}

#[derive(Debug, Serialize)]
pub struct TerraformResourceExport {
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

#[derive(Debug, Deserialize, Serialize)]
struct TerraformState {
    version: Option<i64>,
    terraform_version: Option<String>,
    serial: Option<i64>,
    lineage: Option<String>,
    #[serde(default)]
    resources: Vec<TerraformResource>,
    #[serde(flatten)]
    extra: serde_json::Map<String, Value>,
}

#[derive(Debug, Deserialize, Serialize)]
struct TerraformResource {
    module: Option<String>,
    mode: String,
    #[serde(rename = "type")]
    resource_type: String,
    name: String,
    provider: Option<String>,
    #[serde(default)]
    instances: Vec<TerraformInstance>,
    #[serde(flatten)]
    extra: serde_json::Map<String, Value>,
}

#[derive(Debug, Deserialize, Serialize)]
struct TerraformInstance {
    index_key: Option<Value>,
    schema_version: Option<i64>,
    #[serde(default)]
    attributes: Value,
    #[serde(default)]
    sensitive_attributes: Value,
    #[serde(default)]
    dependencies: Value,
    #[serde(flatten)]
    extra: serde_json::Map<String, Value>,
}

struct TerraformImportRecord {
    address: String,
    module: Option<String>,
    mode: String,
    resource_type: String,
    name: String,
    provider: Option<String>,
    index_key: Option<Value>,
    schema_version: Option<i64>,
    attributes: Value,
    sensitive_attributes: Value,
    dependencies: Value,
    raw: Value,
    aws_uid: Option<String>,
}

pub fn import_terraform_state_file(
    db_path: &Path,
    state_path: &Path,
    state_id: Option<String>,
) -> Result<TerraformImportSummary> {
    let state_json = std::fs::read_to_string(state_path)
        .with_context(|| format!("reading Terraform state {}", state_path.display()))?;
    let raw_state: Value = serde_json::from_str(&state_json)
        .with_context(|| format!("parsing Terraform state {}", state_path.display()))?;
    let state: TerraformState = serde_json::from_value(raw_state.clone())
        .with_context(|| format!("decoding Terraform state {}", state_path.display()))?;
    let state_id = state_id.unwrap_or_else(|| default_state_id(state_path, &state));
    let records = terraform_records(&state);

    let mut connection = open_cloudmapper_db(db_path)?;
    import_terraform_state(
        &mut connection,
        state_path,
        &state_id,
        &state,
        &raw_state,
        &records,
    )?;

    Ok(TerraformImportSummary {
        state_id,
        resource_instances: records.len(),
    })
}

pub fn export_terraform_state(
    db_path: &Path,
    state_id: Option<&str>,
) -> Result<TerraformStateExport> {
    let connection = open_cloudmapper_db(db_path)?;
    let state_id = match state_id {
        Some(state_id) => state_id.to_string(),
        None => latest_terraform_state_id(&connection)?
            .context("no imported Terraform state found in map database")?,
    };
    export_terraform_state_from_connection(&connection, &state_id)
}

fn import_terraform_state(
    connection: &mut Connection,
    source_path: &Path,
    state_id: &str,
    state: &TerraformState,
    raw_state: &Value,
    records: &[TerraformImportRecord],
) -> Result<()> {
    let transaction = connection.transaction()?;
    transaction.execute(
        "DELETE FROM terraform_states WHERE state_id = ?1",
        params![state_id],
    )?;
    transaction.execute(
        r#"
        INSERT INTO terraform_states (
          state_id, source_path, terraform_version, serial, lineage, imported_at, raw_json
        )
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
        "#,
        params![
            state_id,
            source_path.display().to_string(),
            state.terraform_version,
            state.serial,
            state.lineage,
            Utc::now().to_rfc3339(),
            serde_json::to_string(raw_state)?,
        ],
    )?;

    {
        let mut statement = transaction.prepare(
            r#"
            INSERT INTO terraform_resource_instances (
              state_id, address, module, mode, resource_type, name, provider, index_key_json,
              schema_version, attributes_json, sensitive_attributes_json, dependencies_json,
              raw_json, aws_uid
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)
            "#,
        )?;
        for record in records {
            statement.execute(params![
                state_id,
                record.address,
                record.module,
                record.mode,
                record.resource_type,
                record.name,
                record.provider,
                optional_json(&record.index_key)?,
                record.schema_version,
                serde_json::to_string(&record.attributes)?,
                serde_json::to_string(&record.sensitive_attributes)?,
                serde_json::to_string(&record.dependencies)?,
                serde_json::to_string(&record.raw)?,
                record.aws_uid,
            ])?;
        }
    }

    transaction.commit()?;
    Ok(())
}

fn export_terraform_state_from_connection(
    connection: &Connection,
    state_id: &str,
) -> Result<TerraformStateExport> {
    let metadata = connection
        .query_row(
            r#"
            SELECT source_path, terraform_version, serial, lineage
            FROM terraform_states
            WHERE state_id = ?1
            "#,
            params![state_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, Option<i64>>(2)?,
                    row.get::<_, Option<String>>(3)?,
                ))
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
        Ok(TerraformResourceExport {
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

    let resource_instances = rows.collect::<Result<Vec<_>, _>>()?;

    Ok(TerraformStateExport {
        schema_version: "cloudmapper.terraform.v1".to_string(),
        state_id: state_id.to_string(),
        source_path: metadata.0,
        terraform_version: metadata.1,
        serial: metadata.2,
        lineage: metadata.3,
        resource_instances,
    })
}

fn terraform_records(state: &TerraformState) -> Vec<TerraformImportRecord> {
    let mut records = Vec::new();
    for resource in &state.resources {
        for instance in &resource.instances {
            let address = terraform_address(resource, instance.index_key.as_ref());
            let attributes = normalize_json(instance.attributes.clone(), json!({}));
            let sensitive_attributes =
                normalize_json(instance.sensitive_attributes.clone(), json!([]));
            let dependencies = normalize_json(instance.dependencies.clone(), json!([]));
            let raw = json!({
                "resource": resource,
                "instance": instance
            });
            let aws_uid = infer_aws_uid(&attributes);
            records.push(TerraformImportRecord {
                address,
                module: resource.module.clone(),
                mode: resource.mode.clone(),
                resource_type: resource.resource_type.clone(),
                name: resource.name.clone(),
                provider: resource.provider.clone(),
                index_key: instance.index_key.clone(),
                schema_version: instance.schema_version,
                attributes,
                sensitive_attributes,
                dependencies,
                raw,
                aws_uid,
            });
        }
    }
    records
}

fn terraform_address(resource: &TerraformResource, index_key: Option<&Value>) -> String {
    let mut address = String::new();
    if let Some(module) = &resource.module {
        address.push_str(module);
        address.push('.');
    }
    address.push_str(&resource.resource_type);
    address.push('.');
    address.push_str(&resource.name);
    if let Some(index_key) = index_key {
        address.push('[');
        address.push_str(&serde_json::to_string(index_key).unwrap_or_else(|_| "null".to_string()));
        address.push(']');
    }
    address
}

fn infer_aws_uid(attributes: &Value) -> Option<String> {
    attributes
        .get("arn")
        .and_then(Value::as_str)
        .and_then(|arn| uid_for_arn("", arn))
}

fn default_state_id(path: &Path, state: &TerraformState) -> String {
    match (&state.lineage, state.serial) {
        (Some(lineage), Some(serial)) => format!("terraform:{lineage}:{serial}"),
        (Some(lineage), None) => format!("terraform:{lineage}"),
        _ => format!(
            "terraform:{}",
            path.file_stem()
                .and_then(|stem| stem.to_str())
                .unwrap_or("state")
        ),
    }
}

fn normalize_json(value: Value, default: Value) -> Value {
    if value.is_null() { default } else { value }
}

fn optional_json(value: &Option<Value>) -> Result<Option<String>> {
    value
        .as_ref()
        .map(serde_json::to_string)
        .transpose()
        .context("serializing optional Terraform JSON field")
}

fn parse_json(value: String) -> rusqlite::Result<Value> {
    serde_json::from_str(&value).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(error))
    })
}

fn parse_optional_json(value: Option<String>) -> rusqlite::Result<Option<Value>> {
    value.map(parse_json).transpose()
}

#[cfg(test)]
mod tests {
    use rusqlite::Connection;
    use tempfile::tempdir;

    use super::*;

    #[test]
    fn imports_and_exports_terraform_state_end_to_end() {
        let temp = tempdir().unwrap();
        let state_path = temp.path().join("terraform.tfstate");
        let db_path = temp.path().join("map.db");
        std::fs::write(&state_path, SAMPLE_TFSTATE).unwrap();

        let summary = import_terraform_state_file(&db_path, &state_path, None).unwrap();
        assert_eq!(summary.state_id, "terraform:test-lineage:42");
        assert_eq!(summary.resource_instances, 3);

        let connection = Connection::open(&db_path).unwrap();
        let count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM terraform_resource_instances WHERE state_id = ?1",
                params![summary.state_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 3);

        let export = export_terraform_state(&db_path, None).unwrap();
        assert_eq!(export.resource_instances.len(), 3);
        assert_eq!(export.resource_instances[0].address, "aws_instance.web[0]");
        assert_eq!(
            export.resource_instances[1].address,
            "aws_security_group.web"
        );
        assert_eq!(
            export.resource_instances[1].aws_uid.as_deref(),
            Some("aws:123456789012:us-east-1:ec2:security-group:sg-123")
        );
        assert_eq!(
            export.resource_instances[2].address,
            "module.app.aws_lambda_function.handler[\"blue\"]"
        );
    }

    #[test]
    fn builds_terraform_addresses() {
        let state: TerraformState = serde_json::from_str(SAMPLE_TFSTATE).unwrap();
        let records = terraform_records(&state);

        assert_eq!(records[0].address, "aws_security_group.web");
        assert_eq!(records[1].address, "aws_instance.web[0]");
        assert_eq!(
            records[2].address,
            "module.app.aws_lambda_function.handler[\"blue\"]"
        );
    }

    const SAMPLE_TFSTATE: &str = r#"
{
  "version": 4,
  "terraform_version": "1.8.0",
  "serial": 42,
  "lineage": "test-lineage",
  "outputs": {},
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
    },
    {
      "mode": "managed",
      "type": "aws_instance",
      "name": "web",
      "provider": "provider[\"registry.terraform.io/hashicorp/aws\"]",
      "instances": [
        {
          "index_key": 0,
          "schema_version": 1,
          "attributes": {
            "id": "i-123",
            "arn": "arn:aws:ec2:us-east-1:123456789012:instance/i-123"
          },
          "sensitive_attributes": [],
          "dependencies": ["aws_security_group.web"]
        }
      ]
    },
    {
      "module": "module.app",
      "mode": "managed",
      "type": "aws_lambda_function",
      "name": "handler",
      "provider": "provider[\"registry.terraform.io/hashicorp/aws\"]",
      "instances": [
        {
          "index_key": "blue",
          "schema_version": 1,
          "attributes": {
            "id": "handler-blue",
            "arn": "arn:aws:lambda:us-east-1:123456789012:function:handler-blue"
          },
          "sensitive_attributes": [],
          "dependencies": ["aws_iam_role.lambda"]
        }
      ]
    }
  ]
}
"#;
}
