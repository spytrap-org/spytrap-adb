use crate::errors::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct Rule {
    names: Vec<String>,
    #[serde(default)]
    packages: Option<Vec<String>>,
    #[serde(default)]
    certificates: Option<Vec<String>>,
    #[serde(default)]
    websites: Option<Vec<String>>,
    #[serde(default)]
    c2: Option<Vec<String>>,
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
            let name = if let Some(name) = rule.names.first() {
                name
            } else {
                warn!("Entry has no names defined: {:?}", rule);
                continue;
            };
            if let Some(packages) = rule.packages {
                for package in packages {
                    map.insert(package, name.to_string());
                }
            }
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
    fn test_parse_ioc_yaml() {
        let map = Rule::load_map_from_buf(b"
- names:
    - Reptilicus
    - CyberNanny
    - Vkur
  packages:
    - com.brot.storage.work
    - com.thecybernanny.andapp
    - net.androidcoreapp.androidbackup
    - net.delphiboardlayer.androidcoreapp
    - net.reptilicus.clientapp
    - net.system_updater_abs341
    - net.vkurhandler
    - se.vkur.clientapp
    - yc.sysupd.client
  certificates:
    - 230E35A26E471352DF5DBDBCF9834E0711500CB0
    - 2C08279BCC8EB16B2B31ACFBD7E1D4BB28E49A87
    - 2FD8BEF4081F126D4DA655B40E9FC63F116DD857
    - 9256E291823DA741B64CB23F7E371D0940E5272E
    - 9BD494107EFED96F630D29D6E18AE4DCC47149E2
    - 6D0FF787BF4534F1077D1E4BF2E18BA381D97061
  websites:
    - reptilicus.net
    - thecybernanny.com
  c2:
    - 176.9.42.16
    - data.reptilicus.net
    - proxy.reptilicus.net
    - reptilicus.net
    - vkur1.se
    - phonecontrolapp-e2c64.firebaseio.com
    - rp.apollospy.com

- names:
    - PhoneTracker
  packages:
  certificates:
    - 483716998F0C092FE82B0B12B1A4BA399D941318
  websites:
    - phonetracking.net
  c2:
    - app.mobiletracking.app
    - phonetracking.net
").unwrap();
        assert_eq!(map, hashmap![
            "com.brot.storage.work".to_string() => "Reptilicus".to_string(),
            "com.thecybernanny.andapp".to_string() => "Reptilicus".to_string(),
            "net.androidcoreapp.androidbackup".to_string() => "Reptilicus".to_string(),
            "net.delphiboardlayer.androidcoreapp".to_string() => "Reptilicus".to_string(),
            "net.reptilicus.clientapp".to_string() => "Reptilicus".to_string(),
            "net.system_updater_abs341".to_string() => "Reptilicus".to_string(),
            "net.vkurhandler".to_string() => "Reptilicus".to_string(),
            "se.vkur.clientapp".to_string() => "Reptilicus".to_string(),
            "yc.sysupd.client".to_string() => "Reptilicus".to_string(),
        ]);
    }
}
