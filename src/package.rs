use crate::errors::*;
use mozdevice::Device;
use std::borrow::Cow;
use std::collections::HashMap;

const CMD: &str = "dumpsys package";

#[derive(Debug, PartialEq, Default)]
pub struct PackageInfo {
    fields: HashMap<String, String>,
}

impl PackageInfo {
    pub fn installer_package_name(&self) -> Option<&String> {
        self.fields.get("installerPackageName")
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

fn parse_output(output: &str, package: &str) -> Result<PackageInfo> {
    let mut section = None;
    let mut info = PackageInfo::default();

    for line in output.split('\n') {
        if !line.starts_with(' ') {
            section = Some(line);
        } else if let Some("Packages:") = section {
            trace!("package section line: {:?}", line);

            // TODO: we also want the app permissions

            if let Some((key, value)) = line.trim().split_once('=') {
                trace!("discovered for package {:?}: key={:?}, value={:?}", package, key, value);
                info.fields.insert(key.to_string(), value.to_string());
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
                "android.permission.ACCESS_BACKGROUND_LOCATION: restricted".to_string() => "true".to_string(),
                "android.permission.READ_SMS: restricted".to_string() => "true".to_string(),
                "android.permission.READ_CALL_LOG: restricted".to_string() => "true".to_string(),
                "android.permission.WRITE_EXTERNAL_STORAGE: restricted".to_string() => "true".to_string(),
                "android.permission.READ_EXTERNAL_STORAGE: restricted".to_string() => "true".to_string(),
                "android.permission.RECEIVE_SMS: restricted".to_string() => "true".to_string(),
                "android.permission.FOREGROUND_SERVICE: granted".to_string() => "true".to_string(),
                "android.permission.RECEIVE_BOOT_COMPLETED: granted".to_string() => "true".to_string(),
                "android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS: granted".to_string() => "true".to_string(),
                "android.permission.INTERNET: granted".to_string() => "true".to_string(),
                "com.android.browser.permission.READ_HISTORY_BOOKMARKS: granted".to_string() => "true".to_string(),
                "android.permission.CHANGE_WIFI_STATE: granted".to_string() => "true".to_string(),
                "android.permission.ACCESS_NETWORK_STATE: granted".to_string() => "true".to_string(),
                "android.permission.ACCESS_WIFI_STATE: granted".to_string() => "true".to_string(),
                "android.permission.QUERY_ALL_PACKAGES: granted".to_string() => "true".to_string(),
                "android.permission.WAKE_LOCK: granted".to_string() => "true".to_string(),
                "User 0: ceDataInode".to_string() => "261852 installed=true hidden=false suspended=false distractionFlags=0 stopped=false notLaunched=false enabled=0 instant=false virtual=false".to_string(),
                "gids".to_string() => "[3003]".to_string(),
                "android.permission.READ_SMS: granted".to_string() => "false, flags=[ USER_FIXED|USER_SENSITIVE_WHEN_GRANTED|USER_SENSITIVE_WHEN_DENIED|RESTRICTION_INSTALLER_EXEMPT]".to_string(),
                "android.permission.READ_CALL_LOG: granted".to_string() => "false, flags=[ USER_FIXED|USER_SENSITIVE_WHEN_GRANTED|USER_SENSITIVE_WHEN_DENIED|RESTRICTION_INSTALLER_EXEMPT]".to_string(),
                "android.permission.ACCESS_FINE_LOCATION: granted".to_string() => "false, flags=[ USER_FIXED|USER_SENSITIVE_WHEN_GRANTED|USER_SENSITIVE_WHEN_DENIED]".to_string(),
                "android.permission.RECEIVE_SMS: granted".to_string() => "false, flags=[ USER_SENSITIVE_WHEN_GRANTED|USER_SENSITIVE_WHEN_DENIED|RESTRICTION_INSTALLER_EXEMPT]".to_string(),
                "android.permission.READ_EXTERNAL_STORAGE: granted".to_string() => "false, flags=[ USER_FIXED|USER_SENSITIVE_WHEN_GRANTED|USER_SENSITIVE_WHEN_DENIED|RESTRICTION_INSTALLER_EXEMPT]".to_string(),
                "android.permission.ACCESS_COARSE_LOCATION: granted".to_string() => "false, flags=[ USER_FIXED|USER_SENSITIVE_WHEN_GRANTED|USER_SENSITIVE_WHEN_DENIED]".to_string(),
                "android.permission.READ_PHONE_STATE: granted".to_string() => "false, flags=[ USER_FIXED|USER_SENSITIVE_WHEN_GRANTED|USER_SENSITIVE_WHEN_DENIED]".to_string(),
                "android.permission.CAMERA: granted".to_string() => "false, flags=[ USER_FIXED|USER_SENSITIVE_WHEN_GRANTED|USER_SENSITIVE_WHEN_DENIED]".to_string(),
                "android.permission.WRITE_EXTERNAL_STORAGE: granted".to_string() => "false, flags=[ USER_FIXED|USER_SENSITIVE_WHEN_GRANTED|USER_SENSITIVE_WHEN_DENIED|RESTRICTION_INSTALLER_EXEMPT]".to_string(),
                "android.permission.RECORD_AUDIO: granted".to_string() => "false, flags=[ USER_FIXED|USER_SENSITIVE_WHEN_GRANTED|USER_SENSITIVE_WHEN_DENIED]".to_string(),
                "android.permission.READ_CONTACTS: granted".to_string() => "false, flags=[ USER_FIXED|USER_SENSITIVE_WHEN_GRANTED|USER_SENSITIVE_WHEN_DENIED]".to_string(),
                "android.permission.ACCESS_BACKGROUND_LOCATION: granted".to_string() => "false, flags=[ USER_SENSITIVE_WHEN_GRANTED|USER_SENSITIVE_WHEN_DENIED|RESTRICTION_INSTALLER_EXEMPT]".to_string(),
                "android.permission.ACCESS_MEDIA_LOCATION: granted".to_string() => "false, flags=[ USER_FIXED|USER_SENSITIVE_WHEN_GRANTED|USER_SENSITIVE_WHEN_DENIED]".to_string(),
            ],
        });
    }
}
