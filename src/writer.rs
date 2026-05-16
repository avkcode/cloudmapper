use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::path::Path;

use anyhow::{Context, Result, bail};

use crate::db::write_inventory_db;
use crate::model::{GENERATOR_NAME, Inventory};

pub fn write_infra(out: &Path, inventory: &Inventory, allow_non_empty_out: bool) -> Result<()> {
    ensure_output_dir(out, allow_non_empty_out)?;

    write_json(out.join("manifest.json").as_path(), &inventory.manifest())?;
    write_json(out.join("inventory.json").as_path(), inventory)?;
    write_json(out.join("graph.json").as_path(), &inventory.graph())?;
    write_jsonl(out.join("resources.jsonl").as_path(), &inventory.resources)?;
    write_jsonl(
        out.join("relationships.jsonl").as_path(),
        &inventory.relationships,
    )?;
    write_jsonl(out.join("errors.jsonl").as_path(), &inventory.errors)?;
    write_inventory_db(&out.join("map.db"), inventory)?;
    write_schemas(&out.join("schemas"))?;

    Ok(())
}

fn ensure_output_dir(out: &Path, allow_non_empty_out: bool) -> Result<()> {
    if !out.exists() {
        fs::create_dir_all(out)
            .with_context(|| format!("creating output directory {}", out.display()))?;
        return Ok(());
    }

    if !out.is_dir() {
        bail!(
            "output path {} exists and is not a directory",
            out.display()
        );
    }

    if allow_non_empty_out || is_cloudmapper_dir(out)? || is_empty_dir(out)? {
        return Ok(());
    }

    bail!(
        "output directory {} is non-empty and has no cloudmapper manifest; pass --allow-non-empty-out to write there",
        out.display()
    );
}

fn is_empty_dir(path: &Path) -> Result<bool> {
    Ok(fs::read_dir(path)
        .with_context(|| format!("reading output directory {}", path.display()))?
        .next()
        .is_none())
}

fn is_cloudmapper_dir(path: &Path) -> Result<bool> {
    let manifest = path.join("manifest.json");
    if !manifest.exists() {
        return Ok(false);
    }
    let value: serde_json::Value = serde_json::from_reader(
        File::open(&manifest).with_context(|| format!("opening {}", manifest.display()))?,
    )
    .with_context(|| format!("parsing {}", manifest.display()))?;
    let name = value
        .get("generator")
        .and_then(|generator| generator.get("name"))
        .and_then(|name| name.as_str());
    Ok(name == Some(GENERATOR_NAME))
}

fn write_json(path: &Path, value: &impl serde::Serialize) -> Result<()> {
    let mut writer =
        BufWriter::new(File::create(path).with_context(|| format!("creating {}", path.display()))?);
    serde_json::to_writer_pretty(&mut writer, value)
        .with_context(|| format!("serializing {}", path.display()))?;
    writer
        .write_all(b"\n")
        .with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

fn write_jsonl<T: serde::Serialize>(path: &Path, values: &[T]) -> Result<()> {
    let mut writer =
        BufWriter::new(File::create(path).with_context(|| format!("creating {}", path.display()))?);
    for value in values {
        serde_json::to_writer(&mut writer, value)
            .with_context(|| format!("serializing {}", path.display()))?;
        writer
            .write_all(b"\n")
            .with_context(|| format!("writing {}", path.display()))?;
    }
    Ok(())
}

fn write_schemas(path: &Path) -> Result<()> {
    fs::create_dir_all(path).with_context(|| format!("creating {}", path.display()))?;
    fs::write(path.join("resource.schema.json"), RESOURCE_SCHEMA)
        .with_context(|| format!("writing {}", path.join("resource.schema.json").display()))?;
    fs::write(path.join("relationship.schema.json"), RELATIONSHIP_SCHEMA).with_context(|| {
        format!(
            "writing {}",
            path.join("relationship.schema.json").display()
        )
    })?;
    Ok(())
}

const RESOURCE_SCHEMA: &str = r#"{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://llmproxy.local/schemas/cloudmapper/resource.schema.json",
  "title": "Cloudmapper Resource",
  "type": "object",
  "required": ["uid", "provider", "account_id", "partition", "region", "service", "type", "id"],
  "properties": {
    "uid": { "type": "string" },
    "provider": { "const": "aws" },
    "account_id": { "type": "string" },
    "partition": { "type": "string" },
    "region": { "type": "string" },
    "service": { "type": "string" },
    "type": { "type": "string" },
    "id": { "type": "string" },
    "arn": { "type": "string" },
    "name": { "type": "string" },
    "tags": { "type": "object", "additionalProperties": { "type": "string" } },
    "attributes": { "type": "object" },
    "evidence": { "type": "array" },
    "raw": {}
  }
}
"#;

const RELATIONSHIP_SCHEMA: &str = r#"{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://llmproxy.local/schemas/cloudmapper/relationship.schema.json",
  "title": "Cloudmapper Relationship",
  "type": "object",
  "required": ["uid", "from", "to", "type"],
  "properties": {
    "uid": { "type": "string" },
    "from": { "type": "string" },
    "to": { "type": "string" },
    "type": { "type": "string" },
    "attributes": { "type": "object" },
    "evidence": { "type": "array" }
  }
}
"#;

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use chrono::Utc;
    use tempfile::tempdir;

    use crate::model::{Generator, Inventory, SCHEMA_VERSION};

    use super::*;

    #[test]
    fn writes_expected_bundle_files() {
        let temp = tempdir().unwrap();
        let inventory = Inventory {
            schema_version: SCHEMA_VERSION.to_string(),
            generator: Generator {
                name: GENERATOR_NAME.to_string(),
                version: "test".to_string(),
            },
            account_id: "123456789012".to_string(),
            partition: "aws".to_string(),
            home_region: "us-east-1".to_string(),
            regions: vec!["us-east-1".to_string()],
            collected_at: Utc::now(),
            resources: vec![crate::model::Resource {
                uid: "aws:123456789012:global:iam:account:123456789012".to_string(),
                provider: "aws".to_string(),
                account_id: "123456789012".to_string(),
                partition: "aws".to_string(),
                region: "global".to_string(),
                service: "iam".to_string(),
                resource_type: "account".to_string(),
                id: "123456789012".to_string(),
                arn: None,
                name: None,
                tags: BTreeMap::new(),
                attributes: serde_json::json!({}),
                evidence: Vec::new(),
                raw: None,
            }],
            relationships: Vec::new(),
            errors: Vec::new(),
        };

        write_infra(temp.path(), &inventory, false).unwrap();

        assert!(temp.path().join("manifest.json").exists());
        assert!(temp.path().join("inventory.json").exists());
        assert!(temp.path().join("resources.jsonl").exists());
        assert!(temp.path().join("relationships.jsonl").exists());
        assert!(temp.path().join("errors.jsonl").exists());
        assert!(temp.path().join("graph.json").exists());
        assert!(temp.path().join("map.db").exists());
        assert!(temp.path().join("schemas/resource.schema.json").exists());
    }

    #[test]
    fn refuses_unowned_non_empty_directory() {
        let temp = tempdir().unwrap();
        fs::write(temp.path().join("README.md"), "not a cloudmapper dir").unwrap();

        let inventory = Inventory {
            schema_version: SCHEMA_VERSION.to_string(),
            generator: Generator {
                name: GENERATOR_NAME.to_string(),
                version: "test".to_string(),
            },
            account_id: "123456789012".to_string(),
            partition: "aws".to_string(),
            home_region: "us-east-1".to_string(),
            regions: Vec::new(),
            collected_at: Utc::now(),
            resources: Vec::new(),
            relationships: Vec::new(),
            errors: Vec::new(),
        };

        let error = write_infra(temp.path(), &inventory, false).unwrap_err();
        assert!(error.to_string().contains("--allow-non-empty-out"));
    }
}
