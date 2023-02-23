use crate::errors::*;
use std::collections::HashMap;
use std::fs;

pub fn load_map_from_buf(buf: &[u8]) -> Result<HashMap<String, String>> {
    let list = stalkerware_indicators::parse_from_buf(buf)?;
    let mut map = HashMap::new();
    for rule in list {
        let name = if let Some(name) = rule.names.first() {
            name
        } else {
            warn!("Entry has no names defined: {:?}", rule);
            continue;
        };
        for package in rule.packages {
            map.insert(package, name.to_string());
        }
    }
    Ok(map)
}

pub fn load_map_from_file(path: &str) -> Result<HashMap<String, String>> {
    let buf =
        fs::read(path).with_context(|| anyhow!("Failed to read appid rules file: {:?}", path))?;
    load_map_from_buf(&buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use maplit::hashmap;

    #[test]
    fn test_parse_ioc_yaml() {
        let map = load_map_from_buf(
            b"
- name: Reptilicus
  names:
  - Reptilicus
  - CyberNanny
  - Vkur
  type: stalkerware
  packages:
  - com.brot.storage.work
  - com.cycle.start.mess
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
  - D3A7E0E542A3E1112741806AC31F341C4200FBA1
  - B61326887306E5A65726AE6BFD1D720D2760CEFF
  websites:
  - reptilicus.net
  - thecybernanny.com
  c2:
    ips:
    - 176.9.42.16
    domains:
    - cabinet.ecohouse-eg.com
    - cabinet.gps-monitor.uz
    - cabinet.kfnm.ru
    - cabinet.vegosm.ru
    - cabinet.vkur.se
    - cabinet.vkur1.se
    - data.reptilicus.net
    - e2c64.firebaseio.com
    - mob.eurotrans.kz
    - phonecontrolapp-e2c64.firebaseio.com
    - proxy.reptilicus.net
    - reptilicus.net
    - rp.apollospy.com
    - vkur1.se
    - www.reptilicus.net

- name: Snoopza
  names:
  - Snoopza
  type: stalkerware
  packages:
  - com.android.core.mngi
  - com.android.core.mngj
  - com.android.core.mngk
  - com.android.core.mngl
  - com.android.core.mngn
  - com.android.core.mngo
  - com.android.core.mngp
  certificates: []
  websites:
  - snoopza.com
  c2:
    ips:
    - 217.182.250.165
    - 46.105.57.148
    domains:
    - snoopza.com
    - my.snoopza.com
    - my2.snoopza.com
    - api.snoopza.com
",
        )
        .unwrap();
        assert_eq!(
            map,
            hashmap![
                "com.brot.storage.work".to_string() => "Reptilicus".to_string(),
                "com.cycle.start.mess".to_string() => "Reptilicus".to_string(),
                "com.thecybernanny.andapp".to_string() => "Reptilicus".to_string(),
                "net.androidcoreapp.androidbackup".to_string() => "Reptilicus".to_string(),
                "net.delphiboardlayer.androidcoreapp".to_string() => "Reptilicus".to_string(),
                "net.reptilicus.clientapp".to_string() => "Reptilicus".to_string(),
                "net.system_updater_abs341".to_string() => "Reptilicus".to_string(),
                "net.vkurhandler".to_string() => "Reptilicus".to_string(),
                "se.vkur.clientapp".to_string() => "Reptilicus".to_string(),
                "yc.sysupd.client".to_string() => "Reptilicus".to_string(),

                "com.android.core.mngi".to_string() => "Snoopza".to_string(),
                "com.android.core.mngj".to_string() => "Snoopza".to_string(),
                "com.android.core.mngk".to_string() => "Snoopza".to_string(),
                "com.android.core.mngl".to_string() => "Snoopza".to_string(),
                "com.android.core.mngn".to_string() => "Snoopza".to_string(),
                "com.android.core.mngo".to_string() => "Snoopza".to_string(),
                "com.android.core.mngp".to_string() => "Snoopza".to_string(),
            ]
        );
    }
}
