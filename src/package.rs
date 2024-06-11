use crate::errors::*;
use crate::ioc::{Suspicion, SuspicionLevel};
use crate::parsers::{self, package::PackageInfo, package::Permission};
use forensic_adb::Device;
use std::borrow::Cow;

pub async fn dump(device: &Device, package: &str) -> Result<PackageInfo> {
    let cmd = format!(
        "dumpsys package {}",
        shell_escape::escape(Cow::Borrowed(package))
    );
    debug!("Executing {:?}", cmd);
    let output = device
        .execute_host_exec_out_command(&cmd)
        .await
        .with_context(|| anyhow!("Failed to run: {:?}", cmd))?;
    parsers::package::parse_output(&output, package)
}

fn is_permission_suspcious(permission: &Permission) -> Option<SuspicionLevel> {
    match permission.name.as_str() {
        // sus: high
        "ACTION_NOTIFICATION_LISTENER_SETTINGS" => Some(SuspicionLevel::High),
        "android.permission.ACTION_MANAGE_OVERLAY_PERMISSION" => Some(SuspicionLevel::High),
        "android.permission.BIND_ACCESSIBILITY_SERVICE" => Some(SuspicionLevel::High),
        // sus: medium
        "android.permission.ACCESS_BACKGROUND_LOCATION" => Some(SuspicionLevel::Medium),
        "android.permission.READ_SMS" => Some(SuspicionLevel::Medium),
        "android.permission.RECEIVE_SMS" => Some(SuspicionLevel::Medium),
        "android.permission.BIND_DEVICE_ADMIN" => Some(SuspicionLevel::Medium),
        // sus: low
        "android.permission.ACCESS_COARSE_LOCATION" => Some(SuspicionLevel::Low),
        "android.permission.ACCESS_FINE_LOCATION" => Some(SuspicionLevel::Low),
        "android.permission.ACCESS_LOCATION_EXTRA_COMMANDS" => Some(SuspicionLevel::Low),
        "android.permission.CAMERA" => Some(SuspicionLevel::Low),
        "android.permission.QUERY_ALL_PACKAGES" => Some(SuspicionLevel::Low),
        "android.permission.READ_CALL_LOG" => Some(SuspicionLevel::Low),
        "android.permission.READ_CONTACTS" => Some(SuspicionLevel::Low),
        "android.permission.RECORD_AUDIO" => Some(SuspicionLevel::Low),
        "android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS" => Some(SuspicionLevel::Low),
        "android.permission.MODIFY_AUDIO_SETTINGS" => Some(SuspicionLevel::Low),
        // none
        _ => None,
    }
}

impl PackageInfo {
    pub fn audit(&self) -> Vec<Suspicion> {
        debug!("Scanning package: {:?}", self.id);

        let mut sus = Vec::new();

        match self.installer_package_name() {
            Some("com.android.vending") => {
                // TODO: authenticate this application is a legitimate google play store .apk
            }
            Some("com.android.packageinstaller") => {
                sus.push(Suspicion {
                    level: SuspicionLevel::High,
                    description: format!("Package {:?} was manually installed", self.id),
                });
            }
            Some(installer) => {
                sus.push(Suspicion {
                    level: SuspicionLevel::High,
                    description: format!(
                        "Package {:?} was manually installed by an unknown installer: {:?}",
                        self.id, installer
                    ),
                });
            }
            None => (),
        }

        for permission in &self.requested_permissions {
            // warn!("requested permission: {:?}", permission);
            // println!("permission {:?}", permission.name);
            if let Some(level) = is_permission_suspcious(permission) {
                sus.push(Suspicion {
                    level,
                    description: format!(
                        "Package {:?} has requested permission {:?}",
                        self.id, permission
                    ),
                });
            }
        }

        for permission in &self.install_permissions {
            // warn!("install permission: {:?}", permission);
            // println!("permission {:?}", permission.name);
            if let Some(level) = is_permission_suspcious(permission) {
                sus.push(Suspicion {
                    level,
                    description: format!(
                        "Package {:?} has install permission {:?}",
                        self.id, permission
                    ),
                });
            }
        }

        for permission in &self.runtime_permissions {
            // warn!("runtime permission: {:?}", permission);
            // println!("permission {:?}", permission.name);
            if let Some(level) = is_permission_suspcious(permission) {
                sus.push(Suspicion {
                    level,
                    description: format!(
                        "Package {:?} has runtime permission {:?}",
                        self.id, permission
                    ),
                });
            }
        }

        sus
    }

    pub fn installer_package_name(&self) -> Option<&str> {
        self.fields.get("installerPackageName").map(String::as_str)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_package_spylive360() {
        let data = include_bytes!("../test_data/dumpsys/package/spylive360.txt");
        let pkginfo = parsers::package::parse_output(data, "com.wifi0").unwrap();
        let sus = pkginfo.audit();
        assert_eq!(&sus, &[
            Suspicion {
                level: SuspicionLevel::High,
                description: "Package \"com.wifi0\" was manually installed".to_string(),
            },
            Suspicion { level: SuspicionLevel::Low, description: "Package \"com.wifi0\" has requested permission Permission { name: \"android.permission.ACCESS_FINE_LOCATION\", fields: {} }".to_string() },
            Suspicion { level: SuspicionLevel::Low, description: "Package \"com.wifi0\" has requested permission Permission { name: \"android.permission.ACCESS_COARSE_LOCATION\", fields: {} }".to_string() },
            Suspicion { level: SuspicionLevel::Medium, description: "Package \"com.wifi0\" has requested permission Permission { name: \"android.permission.ACCESS_BACKGROUND_LOCATION\", fields: {\"restricted\": \"true\"} }".to_string() },
            Suspicion { level: SuspicionLevel::High, description: "Package \"com.wifi0\" has requested permission Permission { name: \"ACTION_NOTIFICATION_LISTENER_SETTINGS\", fields: {} }".to_string() },
            Suspicion { level: SuspicionLevel::Medium, description: "Package \"com.wifi0\" has requested permission Permission { name: \"android.permission.READ_SMS\", fields: {\"restricted\": \"true\"} }".to_string() },
            Suspicion { level: SuspicionLevel::Low, description: "Package \"com.wifi0\" has requested permission Permission { name: \"android.permission.READ_CONTACTS\", fields: {} }".to_string() },
            Suspicion { level: SuspicionLevel::Low, description: "Package \"com.wifi0\" has requested permission Permission { name: \"android.permission.READ_CALL_LOG\", fields: {\"restricted\": \"true\"} }".to_string() },
            Suspicion { level: SuspicionLevel::Low, description: "Package \"com.wifi0\" has requested permission Permission { name: \"android.permission.CAMERA\", fields: {} }".to_string() },
            Suspicion { level: SuspicionLevel::High, description: "Package \"com.wifi0\" has requested permission Permission { name: \"android.permission.ACTION_MANAGE_OVERLAY_PERMISSION\", fields: {} }".to_string() },
            Suspicion { level: SuspicionLevel::Low, description: "Package \"com.wifi0\" has requested permission Permission { name: \"android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS\", fields: {} }".to_string() },
            Suspicion { level: SuspicionLevel::Medium, description: "Package \"com.wifi0\" has requested permission Permission { name: \"android.permission.RECEIVE_SMS\", fields: {\"restricted\": \"true\"} }".to_string() },
            Suspicion { level: SuspicionLevel::Low, description: "Package \"com.wifi0\" has requested permission Permission { name: \"android.permission.RECORD_AUDIO\", fields: {} }".to_string() },
            Suspicion { level: SuspicionLevel::High, description: "Package \"com.wifi0\" has requested permission Permission { name: \"android.permission.BIND_ACCESSIBILITY_SERVICE\", fields: {} }".to_string() },
            Suspicion { level: SuspicionLevel::Low, description: "Package \"com.wifi0\" has requested permission Permission { name: \"android.permission.QUERY_ALL_PACKAGES\", fields: {} }".to_string() },
            Suspicion { level: SuspicionLevel::Low, description: "Package \"com.wifi0\" has install permission Permission { name: \"android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS\", fields: {\"granted\": \"true\"} }".to_string() },
            Suspicion { level: SuspicionLevel::Low, description: "Package \"com.wifi0\" has install permission Permission { name: \"android.permission.QUERY_ALL_PACKAGES\", fields: {\"granted\": \"true\"} }".to_string() },
            Suspicion { level: SuspicionLevel::Medium, description: "Package \"com.wifi0\" has runtime permission Permission { name: \"android.permission.READ_SMS\", fields: {\"flags\": \"[ USER_FIXED|USER_SENSITIVE_WHEN_GRANTED|USER_SENSITIVE_WHEN_DENIED|RESTRICTION_INSTALLER_EXEMPT]\", \"granted\": \"false\"} }".to_string() },
            Suspicion { level: SuspicionLevel::Low, description: "Package \"com.wifi0\" has runtime permission Permission { name: \"android.permission.READ_CALL_LOG\", fields: {\"flags\": \"[ USER_FIXED|USER_SENSITIVE_WHEN_GRANTED|USER_SENSITIVE_WHEN_DENIED|RESTRICTION_INSTALLER_EXEMPT]\", \"granted\": \"false\"} }".to_string() },
            Suspicion { level: SuspicionLevel::Low, description: "Package \"com.wifi0\" has runtime permission Permission { name: \"android.permission.ACCESS_FINE_LOCATION\", fields: {\"flags\": \"[ USER_FIXED|USER_SENSITIVE_WHEN_GRANTED|USER_SENSITIVE_WHEN_DENIED]\", \"granted\": \"false\"} }".to_string() },
            Suspicion { level: SuspicionLevel::Medium, description: "Package \"com.wifi0\" has runtime permission Permission { name: \"android.permission.RECEIVE_SMS\", fields: {\"flags\": \"[ USER_SENSITIVE_WHEN_GRANTED|USER_SENSITIVE_WHEN_DENIED|RESTRICTION_INSTALLER_EXEMPT]\", \"granted\": \"false\"} }".to_string() },
            Suspicion { level: SuspicionLevel::Low, description: "Package \"com.wifi0\" has runtime permission Permission { name: \"android.permission.ACCESS_COARSE_LOCATION\", fields: {\"flags\": \"[ USER_FIXED|USER_SENSITIVE_WHEN_GRANTED|USER_SENSITIVE_WHEN_DENIED]\", \"granted\": \"false\"} }".to_string() },
            Suspicion { level: SuspicionLevel::Low, description: "Package \"com.wifi0\" has runtime permission Permission { name: \"android.permission.CAMERA\", fields: {\"flags\": \"[ USER_FIXED|USER_SENSITIVE_WHEN_GRANTED|USER_SENSITIVE_WHEN_DENIED]\", \"granted\": \"false\"} }".to_string() },
            Suspicion { level: SuspicionLevel::Low, description: "Package \"com.wifi0\" has runtime permission Permission { name: \"android.permission.RECORD_AUDIO\", fields: {\"flags\": \"[ USER_FIXED|USER_SENSITIVE_WHEN_GRANTED|USER_SENSITIVE_WHEN_DENIED]\", \"granted\": \"false\"} }".to_string() },
            Suspicion { level: SuspicionLevel::Low, description: "Package \"com.wifi0\" has runtime permission Permission { name: \"android.permission.READ_CONTACTS\", fields: {\"flags\": \"[ USER_FIXED|USER_SENSITIVE_WHEN_GRANTED|USER_SENSITIVE_WHEN_DENIED]\", \"granted\": \"false\"} }".to_string() },
            Suspicion { level: SuspicionLevel::Medium, description: "Package \"com.wifi0\" has runtime permission Permission { name: \"android.permission.ACCESS_BACKGROUND_LOCATION\", fields: {\"flags\": \"[ USER_SENSITIVE_WHEN_GRANTED|USER_SENSITIVE_WHEN_DENIED|RESTRICTION_INSTALLER_EXEMPT]\", \"granted\": \"false\"} }".to_string() },
        ]);
    }

    #[test]
    fn test_audit_package_contacts() {
        let data = include_bytes!("../test_data/dumpsys/package/contacts.txt");
        let pkginfo = parsers::package::parse_output(data, "com.android.contacts").unwrap();
        let sus = pkginfo.audit();
        assert_eq!(&sus, &[
            Suspicion { level: SuspicionLevel::Low, description: "Package \"com.android.contacts\" has requested permission Permission { name: \"android.permission.READ_CONTACTS\", fields: {} }".to_string() },
            Suspicion { level: SuspicionLevel::Low, description: "Package \"com.android.contacts\" has runtime permission Permission { name: \"android.permission.READ_CONTACTS\", fields: {\"flags\": \"[ GRANTED_BY_DEFAULT|USER_SENSITIVE_WHEN_GRANTED|USER_SENSITIVE_WHEN_DENIED]\", \"granted\": \"true\"} }".to_string() },
        ]);
    }

    #[test]
    fn test_audit_package_fdroid() {
        let data = include_bytes!("../test_data/dumpsys/package/fdroid.txt");
        let pkginfo = parsers::package::parse_output(data, "org.fdroid.fdroid").unwrap();
        let sus = pkginfo.audit();
        assert_eq!(&sus, &[
            Suspicion {
                level: SuspicionLevel::High,
                description: "Package \"org.fdroid.fdroid\" was manually installed".to_string(),
            },
            Suspicion { level: SuspicionLevel::Low, description: "Package \"org.fdroid.fdroid\" has requested permission Permission { name: \"android.permission.ACCESS_COARSE_LOCATION\", fields: {} }".to_string() },
            Suspicion { level: SuspicionLevel::Medium, description: "Package \"org.fdroid.fdroid\" has requested permission Permission { name: \"android.permission.ACCESS_BACKGROUND_LOCATION\", fields: {\"restricted\": \"true\"} }".to_string() },
            Suspicion { level: SuspicionLevel::Low, description: "Package \"org.fdroid.fdroid\" has runtime permission Permission { name: \"android.permission.ACCESS_COARSE_LOCATION\", fields: {\"flags\": \"[ USER_SENSITIVE_WHEN_GRANTED|USER_SENSITIVE_WHEN_DENIED]\", \"granted\": \"false\"} }".to_string() },
            Suspicion { level: SuspicionLevel::Medium, description: "Package \"org.fdroid.fdroid\" has runtime permission Permission { name: \"android.permission.ACCESS_BACKGROUND_LOCATION\", fields: {\"flags\": \"[ REVOKE_WHEN_REQUESTED|USER_SENSITIVE_WHEN_GRANTED|USER_SENSITIVE_WHEN_DENIED|RESTRICTION_INSTALLER_EXEMPT]\", \"granted\": \"false\"} }".to_string() },
        ]);
    }

    #[test]
    fn test_audit_package_gpstest() {
        let data = include_bytes!("../test_data/dumpsys/package/gpstest.txt");
        let pkginfo = parsers::package::parse_output(data, "com.android.gpstest.osmdroid").unwrap();
        let sus = pkginfo.audit();
        assert_eq!(&sus, &[
            Suspicion {
                level: SuspicionLevel::High,
                description: "Package \"com.android.gpstest.osmdroid\" was manually installed".to_string(),
            },
            Suspicion { level: SuspicionLevel::Low, description: "Package \"com.android.gpstest.osmdroid\" has requested permission Permission { name: \"android.permission.ACCESS_FINE_LOCATION\", fields: {} }".to_string() },
            Suspicion { level: SuspicionLevel::Low, description: "Package \"com.android.gpstest.osmdroid\" has requested permission Permission { name: \"android.permission.ACCESS_LOCATION_EXTRA_COMMANDS\", fields: {} }".to_string() },
            Suspicion { level: SuspicionLevel::Low, description: "Package \"com.android.gpstest.osmdroid\" has requested permission Permission { name: \"android.permission.ACCESS_COARSE_LOCATION\", fields: {} }".to_string() },
            Suspicion { level: SuspicionLevel::Low, description: "Package \"com.android.gpstest.osmdroid\" has install permission Permission { name: \"android.permission.ACCESS_LOCATION_EXTRA_COMMANDS\", fields: {\"granted\": \"true\"} }".to_string() },
            Suspicion { level: SuspicionLevel::Low, description: "Package \"com.android.gpstest.osmdroid\" has runtime permission Permission { name: \"android.permission.ACCESS_FINE_LOCATION\", fields: {\"flags\": \"[ USER_SET|USER_SENSITIVE_WHEN_GRANTED|USER_SENSITIVE_WHEN_DENIED]\", \"granted\": \"true\"} }".to_string() },
            Suspicion { level: SuspicionLevel::Low, description: "Package \"com.android.gpstest.osmdroid\" has runtime permission Permission { name: \"android.permission.ACCESS_COARSE_LOCATION\", fields: {\"flags\": \"[ USER_SET|REVOKE_WHEN_REQUESTED|USER_SENSITIVE_WHEN_GRANTED|USER_SENSITIVE_WHEN_DENIED]\", \"granted\": \"true\"} }".to_string() },
        ]);
    }

    #[test]
    fn test_audit_package_jitsi() {
        let data = include_bytes!("../test_data/dumpsys/package/jitsi.txt");
        let pkginfo = parsers::package::parse_output(data, "org.jitsi.meet").unwrap();
        let sus = pkginfo.audit();
        assert_eq!(&sus, &[
            Suspicion { level: SuspicionLevel::High, description: "Package \"org.jitsi.meet\" was manually installed".to_string() },
            Suspicion { level: SuspicionLevel::Low, description: "Package \"org.jitsi.meet\" has requested permission Permission { name: \"android.permission.CAMERA\", fields: {} }".to_string() },
            Suspicion { level: SuspicionLevel::Low, description: "Package \"org.jitsi.meet\" has requested permission Permission { name: \"android.permission.MODIFY_AUDIO_SETTINGS\", fields: {} }".to_string() },
            Suspicion { level: SuspicionLevel::Low, description: "Package \"org.jitsi.meet\" has requested permission Permission { name: \"android.permission.RECORD_AUDIO\", fields: {} }".to_string() },
            Suspicion { level: SuspicionLevel::Low, description: "Package \"org.jitsi.meet\" has install permission Permission { name: \"android.permission.MODIFY_AUDIO_SETTINGS\", fields: {\"granted\": \"true\"} }".to_string() },
            Suspicion { level: SuspicionLevel::Low, description: "Package \"org.jitsi.meet\" has runtime permission Permission { name: \"android.permission.CAMERA\", fields: {\"flags\": \"[ USER_SET|USER_SENSITIVE_WHEN_GRANTED|USER_SENSITIVE_WHEN_DENIED]\", \"granted\": \"false\"} }".to_string() },
            Suspicion { level: SuspicionLevel::Low, description: "Package \"org.jitsi.meet\" has runtime permission Permission { name: \"android.permission.RECORD_AUDIO\", fields: {\"flags\": \"[ USER_SET|USER_SENSITIVE_WHEN_GRANTED|USER_SENSITIVE_WHEN_DENIED]\", \"granted\": \"true\"} }".to_string() },
        ]);
    }
}
