use crate::errors::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct Rule {
    package: String,
    name: String,
}

impl Rule {
    pub fn load_list_from_buf(buf: &[u8]) -> Result<Vec<Rule>> {
        let list = serde_yaml::from_slice(buf).context("Failed to deserialize")?;
        Ok(list)
    }

    pub fn load_map_from_buf(buf: &[u8]) -> Result<HashMap<String, String>> {
        let list = Self::load_list_from_buf(buf)?;
        let mut map = HashMap::new();
        for rule in list {
            map.insert(rule.package, rule.name);
        }
        Ok(map)
    }

    pub fn load_map_from_file(path: &str) -> Result<HashMap<String, String>> {
        let buf = fs::read(path)
            .with_context(|| anyhow!("Failed to read appid rules file: {:?}", path))?;
        Self::load_map_from_buf(&buf)
    }
}
