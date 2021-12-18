use crate::errors::*;
use mozdevice::Device;
use std::borrow::Cow;
use std::collections::HashMap;
use std::str::FromStr;

const CMD: &str = "dumpsys package";

#[derive(Debug, PartialEq, Default)]
pub struct PackageInfo {
    fields: HashMap<String, String>,
    requested_permissions: Vec<Permission>,
    install_permissions: Vec<Permission>,
    runtime_permissions: Vec<Permission>,
}

#[derive(Debug, PartialEq, Default)]
pub struct Permission {
    name: String,
    fields: HashMap<String, String>,
}

impl FromStr for Permission {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let mut permission = Permission::default();

        if let Some((key, value)) = s.split_once(": ") {
            permission.name = key.to_string();
            for field in value.split(", ") {
                if let Some((key, value)) = field.split_once('=') {
                    permission.fields.insert(key.into(), value.into());
                }
            }
        } else {
            permission.name = s.to_string();
        }

        Ok(permission)
    }
}

impl PackageInfo {
    pub fn installer_package_name(&self) -> Option<&str> {
        self.fields.get("installerPackageName").map(String::as_str)
    }
}

pub fn dump_package(device: &Device, package: &str) -> Result<PackageInfo> {
    let cmd = format!("{} {}", CMD, shell_escape::escape(Cow::Borrowed(package)));
    debug!("Executing {:?}", cmd);
    let output = device
        .execute_host_shell_command(&cmd)
        .with_context(|| anyhow!("Failed to run: {:?}", CMD))?;
    parse_output(&output, package)
}

fn count_whitespace_prefix(line: &str) -> usize {
    let iter = line.chars();

    let mut count = 0;
    for c in iter {
        if c != ' ' {
            return count;
        }
        count += 1;
    }

    count
}

fn parse_output(output: &str, package: &str) -> Result<PackageInfo> {
    let mut prev_line = None;
    let mut section_stack = Vec::new();

    let mut info = PackageInfo::default();

    let mut indent = 0;
    for line in output.split('\n') {
        let trimmed_line = line.trim();

        match count_whitespace_prefix(line) {
            i if i < indent => {
                section_stack.truncate(i / 2);
                indent = i;
            }
            i if i > indent => {
                if let Some(prev_line) = prev_line {
                    section_stack.push(prev_line);
                }
                indent = i;
            }
            i if i == indent => (),
            // unreachable
            _ => (),
        }

        prev_line = Some(trimmed_line);

        match section_stack.last() {
            Some(&"requested permissions:") => {
                debug!("requested permission: {:?}", trimmed_line);
                info.requested_permissions.push(trimmed_line.parse()?);
            }
            Some(&"install permissions:") => {
                debug!("install permission: {:?}", trimmed_line);
                info.install_permissions.push(trimmed_line.parse()?);
            }
            Some(&"runtime permissions:") => {
                debug!("runtime permission: {:?}", trimmed_line);
                info.runtime_permissions.push(trimmed_line.parse()?);
            }
            _ => {
                if let Some(&"Packages:") = section_stack.first() {
                    trace!("package line: {:?}", line);
                    if let Some((key, value)) = trimmed_line.split_once('=') {
                        trace!("discovered for package {:?}: key={:?}, value={:?}", package, key, value);
                        info.fields.insert(key.to_string(), value.to_string());
                    }
                }
            }
        }
    }

    Ok(info)
}

#[cfg(test)]
mod tests {
    use super::*;
    use maplit::hashmap;

    #[test]
    fn count_whitespace() {
        assert_eq!(0, count_whitespace_prefix(""));
        assert_eq!(1, count_whitespace_prefix(" "));
        assert_eq!(1, count_whitespace_prefix(" a"));
        assert_eq!(2, count_whitespace_prefix("  "));
        assert_eq!(2, count_whitespace_prefix("  a"));
        assert_eq!(3, count_whitespace_prefix("   ab c d e f"));
        assert_eq!(3, count_whitespace_prefix("   User 0:"));
    }

    #[test]
    fn parse_spylive360() {
        let data = include_str!("../test_data/dumpsys/package/spylive360.txt");
        let pkginfo = parse_output(data, "com.wifi0").unwrap();
        assert_eq!(pkginfo, PackageInfo {
            fields: hashmap![
                "userId".to_string() => "10155".to_string(),
                "pkg".to_string() => "Package{19806ac com.wifi0}".to_string(),
                "codePath".to_string() => "/data/app/~~V5jud4ex5-s8L3x2B4lvUA==/com.wifi0-q-C29yRZYy55N91XTD2EoA==".to_string(),
                "resourcePath".to_string() => "/data/app/~~V5jud4ex5-s8L3x2B4lvUA==/com.wifi0-q-C29yRZYy55N91XTD2EoA==".to_string(),
                "legacyNativeLibraryDir".to_string() => "/data/app/~~V5jud4ex5-s8L3x2B4lvUA==/com.wifi0-q-C29yRZYy55N91XTD2EoA==/lib".to_string(),
                "primaryCpuAbi".to_string() => "null".to_string(),
                "secondaryCpuAbi".to_string() => "null".to_string(),
                "versionCode".to_string() => "140 minSdk=19 targetSdk=30".to_string(),
                "versionName".to_string() => "1.4.0".to_string(),
                "splits".to_string() => "[base]".to_string(),
                "apkSigningVersion".to_string() => "2".to_string(),
                "applicationInfo".to_string() => "ApplicationInfo{19806ac com.wifi0}".to_string(),
                "flags".to_string() => "[ HAS_CODE ALLOW_CLEAR_USER_DATA ]".to_string(),
                "privateFlags".to_string() => "[ PRIVATE_FLAG_ACTIVITIES_RESIZE_MODE_RESIZEABLE_VIA_SDK_VERSION ALLOW_AUDIO_PLAYBACK_CAPTURE PRIVATE_FLAG_REQUEST_LEGACY_EXTERNAL_STORAGE PARTIALLY_DIRECT_BOOT_AWARE PRIVATE_FLAG_ALLOW_NATIVE_HEAP_POINTER_TAGGING ]".to_string(),
                "forceQueryable".to_string() => "false".to_string(),
                "queriesPackages".to_string() => "[]".to_string(),
                "dataDir".to_string() => "/data/user/0/com.wifi0".to_string(),
                "supportsScreens".to_string() => "[small, medium, large, xlarge, resizeable, anyDensity]".to_string(),
                "timeStamp".to_string() => "2021-12-15 17:52:55".to_string(),
                "firstInstallTime".to_string() => "2021-12-15 17:51:52".to_string(),
                "lastUpdateTime".to_string() => "2021-12-15 17:52:55".to_string(),
                "installerPackageName".to_string() => "com.android.packageinstaller".to_string(),
                "signatures".to_string() => "PackageSignatures{4cb6f75 version:2, signatures:[74831dfd], past signatures:[]}".to_string(),
                "installPermissionsFixed".to_string() => "true".to_string(),
                "pkgFlags".to_string() => "[ HAS_CODE ALLOW_CLEAR_USER_DATA ]".to_string(),
                "User 0: ceDataInode".to_string() => "261852 installed=true hidden=false suspended=false distractionFlags=0 stopped=false notLaunched=false enabled=0 instant=false virtual=false".to_string(),
                "gids".to_string() => "[3003]".to_string(),
            ],
            requested_permissions: [
                "android.permission.ACCESS_FINE_LOCATION",
                "android.permission.ACCESS_COARSE_LOCATION",
                "android.permission.ACCESS_NETWORK_STATE",
                "android.permission.ACCESS_BACKGROUND_LOCATION: restricted=true",
                "android.permission.INTERNET",
                "ACTION_NOTIFICATION_LISTENER_SETTINGS",
                "android.permission.READ_SMS: restricted=true",
                "android.permission.READ_CONTACTS",
                "android.permission.READ_CALL_LOG: restricted=true",
                "android.permission.READ_PHONE_STATE",
                "android.permission.WRITE_EXTERNAL_STORAGE: restricted=true",
                "android.permission.CAMERA",
                "android.permission.SYSTEM_ALERT_WINDOW",
                "android.permission.ACTION_MANAGE_OVERLAY_PERMISSION",
                "android.permission.ACCESS_WIFI_STATE",
                "android.permission.CHANGE_WIFI_STATE",
                "android.permission.RECEIVE_BOOT_COMPLETED",
                "android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS",
                "com.android.browser.permission.READ_HISTORY_BOOKMARKS",
                "android.permission.READ_EXTERNAL_STORAGE: restricted=true",
                "android.permission.RECEIVE_SMS: restricted=true",
                "android.permission.RECORD_AUDIO",
                "android.permission.BIND_ACCESSIBILITY_SERVICE",
                "com.huawei.systemmanager.permission.ACCESS_INTERFACE",
                "android.permission.QUERY_ALL_PACKAGES",
                "android.permission.ACCESS_MEDIA_LOCATION",
                "android.permission.WRITE_SETTINGS",
                "android.permission.MANAGE_EXTERNAL_STORAGE",
                "android.permission.WAKE_LOCK",
                "com.google.android.c2dm.permission.RECEIVE",
                "com.google.android.providers.gsf.permission.READ_GSERVICES",
                "com.google.android.gms.permission.ACTIVITY_RECOGNITION",
                "android.permission.FOREGROUND_SERVICE",
                "com.google.android.finsky.permission.BIND_GET_INSTALL_REFERRER_SERVICE",
            ].into_iter().map(|s| s.parse().unwrap()).collect(),
            install_permissions: [
                "android.permission.FOREGROUND_SERVICE: granted=true",
                "android.permission.RECEIVE_BOOT_COMPLETED: granted=true",
                "android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS: granted=true",
                "android.permission.INTERNET: granted=true",
                "com.android.browser.permission.READ_HISTORY_BOOKMARKS: granted=true",
                "android.permission.CHANGE_WIFI_STATE: granted=true",
                "android.permission.ACCESS_NETWORK_STATE: granted=true",
                "android.permission.ACCESS_WIFI_STATE: granted=true",
                "android.permission.QUERY_ALL_PACKAGES: granted=true",
                "android.permission.WAKE_LOCK: granted=true",
            ].into_iter().map(|s| s.parse().unwrap()).collect(),
            runtime_permissions: [
                "android.permission.READ_SMS: granted=false, flags=[ USER_FIXED|USER_SENSITIVE_WHEN_GRANTED|USER_SENSITIVE_WHEN_DENIED|RESTRICTION_INSTALLER_EXEMPT]",
                "android.permission.READ_CALL_LOG: granted=false, flags=[ USER_FIXED|USER_SENSITIVE_WHEN_GRANTED|USER_SENSITIVE_WHEN_DENIED|RESTRICTION_INSTALLER_EXEMPT]",
                "android.permission.ACCESS_FINE_LOCATION: granted=false, flags=[ USER_FIXED|USER_SENSITIVE_WHEN_GRANTED|USER_SENSITIVE_WHEN_DENIED]",
                "android.permission.RECEIVE_SMS: granted=false, flags=[ USER_SENSITIVE_WHEN_GRANTED|USER_SENSITIVE_WHEN_DENIED|RESTRICTION_INSTALLER_EXEMPT]",
                "android.permission.READ_EXTERNAL_STORAGE: granted=false, flags=[ USER_FIXED|USER_SENSITIVE_WHEN_GRANTED|USER_SENSITIVE_WHEN_DENIED|RESTRICTION_INSTALLER_EXEMPT]",
                "android.permission.ACCESS_COARSE_LOCATION: granted=false, flags=[ USER_FIXED|USER_SENSITIVE_WHEN_GRANTED|USER_SENSITIVE_WHEN_DENIED]",
                "android.permission.READ_PHONE_STATE: granted=false, flags=[ USER_FIXED|USER_SENSITIVE_WHEN_GRANTED|USER_SENSITIVE_WHEN_DENIED]",
                "android.permission.CAMERA: granted=false, flags=[ USER_FIXED|USER_SENSITIVE_WHEN_GRANTED|USER_SENSITIVE_WHEN_DENIED]",
                "android.permission.WRITE_EXTERNAL_STORAGE: granted=false, flags=[ USER_FIXED|USER_SENSITIVE_WHEN_GRANTED|USER_SENSITIVE_WHEN_DENIED|RESTRICTION_INSTALLER_EXEMPT]",
                "android.permission.RECORD_AUDIO: granted=false, flags=[ USER_FIXED|USER_SENSITIVE_WHEN_GRANTED|USER_SENSITIVE_WHEN_DENIED]",
                "android.permission.READ_CONTACTS: granted=false, flags=[ USER_FIXED|USER_SENSITIVE_WHEN_GRANTED|USER_SENSITIVE_WHEN_DENIED]",
                "android.permission.ACCESS_BACKGROUND_LOCATION: granted=false, flags=[ USER_SENSITIVE_WHEN_GRANTED|USER_SENSITIVE_WHEN_DENIED|RESTRICTION_INSTALLER_EXEMPT]",
                "android.permission.ACCESS_MEDIA_LOCATION: granted=false, flags=[ USER_FIXED|USER_SENSITIVE_WHEN_GRANTED|USER_SENSITIVE_WHEN_DENIED]",
            ].into_iter().map(|s| s.parse().unwrap()).collect(),
        });
    }

    #[test]
    fn test_parse_permission_plain() {
        let line = "android.permission.ACCESS_FINE_LOCATION";
        let p = Permission::from_str(line).unwrap();
        assert_eq!(p, Permission {
            name: "android.permission.ACCESS_FINE_LOCATION".to_string(),
            fields: HashMap::new(),
        });
    }

    #[test]
    fn test_parse_permission_fields1() {
        let line = "android.permission.INTERNET: granted=true";
        let p = Permission::from_str(line).unwrap();
        assert_eq!(p, Permission {
            name: "android.permission.INTERNET".to_string(),
            fields: hashmap![
                "granted".to_string() => "true".to_string(),
            ],
        });
    }

    #[test]
    fn test_parse_permission_fields2() {
        let line = "android.permission.ACCESS_BACKGROUND_LOCATION: restricted=true";
        let p = Permission::from_str(line).unwrap();
        assert_eq!(p, Permission {
            name: "android.permission.ACCESS_BACKGROUND_LOCATION".to_string(),
            fields: hashmap![
                "restricted".to_string() => "true".to_string(),
            ],
        });
    }

    #[test]
    fn test_parse_permission_flags() {
        let line = "android.permission.READ_CALL_LOG: granted=false, flags=[ USER_FIXED|USER_SENSITIVE_WHEN_GRANTED|USER_SENSITIVE_WHEN_DENIED|RESTRICTION_INSTALLER_EXEMPT]";
        let p = Permission::from_str(line).unwrap();
        assert_eq!(p, Permission {
            name: "android.permission.READ_CALL_LOG".to_string(),
            fields: hashmap![
                "granted".to_string() => "false".to_string(),
                "flags".to_string() => "[ USER_FIXED|USER_SENSITIVE_WHEN_GRANTED|USER_SENSITIVE_WHEN_DENIED|RESTRICTION_INSTALLER_EXEMPT]".to_string(),
            ],
        });
    }
}
