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

#[cfg(test)]
mod tests {
    use super::*;
    use maplit::hashmap;

    #[test]
    fn test_parse_appid_yml() {
        let map = Rule::load_map_from_buf(b"
- package: com.vvt.android.syncmanager
  name: FlexiSpy
- package: com.telephony.android
  name: Flexispy
- package: android.sys.process
  name: mSpy
- package: system.framework
  name: mSpy
- package: com.mspy.lite
  name: mSpy
- package: med.mspy.mspy
  name: mspy
- package: android.helper.system
  name: mspy
").unwrap();
        assert_eq!(map, hashmap![
            "android.helper.system".to_string() => "mspy".to_string(),
            "android.sys.process".to_string() => "mSpy".to_string(),
            "com.mspy.lite".to_string() => "mSpy".to_string(),
            "com.telephony.android".to_string() => "Flexispy".to_string(),
            "com.vvt.android.syncmanager".to_string() => "FlexiSpy".to_string(),
            "med.mspy.mspy".to_string() => "mspy".to_string(),
            "system.framework".to_string() => "mSpy".to_string(),
        ]);
    }
}
