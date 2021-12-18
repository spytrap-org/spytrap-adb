use crate::errors::*;
use crate::iocs::{Suspicion, SuspicionLevel};
use crate::parsers::{self, package::PackageInfo};
use mozdevice::Device;
use std::borrow::Cow;

pub fn dump(device: &Device, package: &str) -> Result<PackageInfo> {
    let cmd = format!("dumpsys package {}", shell_escape::escape(Cow::Borrowed(package)));
    debug!("Executing {:?}", cmd);
    let output = device
        .execute_host_shell_command(&cmd)
        .with_context(|| anyhow!("Failed to run: {:?}", cmd))?;
    parsers::package::parse_output(&output, package)
}

impl PackageInfo {
    pub fn audit(&self) -> Vec<Suspicion> {
        let mut sus = Vec::new();

        match self.installer_package_name() {
            Some("com.android.packageinstaller") => {
                sus.push(Suspicion {
                    level: SuspicionLevel::Medium,
                    description: format!("Package {:?} was manually installed", self.id),
                });
            },
            Some(installer) => {
                sus.push(Suspicion {
                    level: SuspicionLevel::Medium,
                    description: format!("Package {:?} was manually installed by an unknown installer: {:?}", self.id, installer),
                });
            },
            None => (),
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
        let data = include_str!("../test_data/dumpsys/package/spylive360.txt");
        let pkginfo = parsers::package::parse_output(data, "com.wifi0").unwrap();
        let sus = pkginfo.audit();
        assert_eq!(&sus, &[
            Suspicion {
                level: SuspicionLevel::Medium,
                description: "Package \"com.wifi0\" was manually installed".to_string(),
            },
        ]);
    }

    #[test]
    fn test_audit_package_contacts() {
        let data = include_str!("../test_data/dumpsys/package/contacts.txt");
        let pkginfo = parsers::package::parse_output(data, "com.android.contacts").unwrap();
        let sus = pkginfo.audit();
        assert_eq!(&sus, &[]);
    }

    #[test]
    fn test_audit_package_fdroid() {
        let data = include_str!("../test_data/dumpsys/package/fdroid.txt");
        let pkginfo = parsers::package::parse_output(data, "org.fdroid.fdroid").unwrap();
        let sus = pkginfo.audit();
        assert_eq!(&sus, &[
            Suspicion {
                level: SuspicionLevel::Medium,
                description: "Package \"org.fdroid.fdroid\" was manually installed".to_string(),
            },
        ]);
    }

    #[test]
    fn test_audit_package_gpstest() {
        let data = include_str!("../test_data/dumpsys/package/gpstest.txt");
        let pkginfo = parsers::package::parse_output(data, "com.android.gpstest.osmdroid").unwrap();
        let sus = pkginfo.audit();
        assert_eq!(&sus, &[
            Suspicion {
                level: SuspicionLevel::Medium,
                description: "Package \"com.android.gpstest.osmdroid\" was manually installed".to_string(),
            },
        ]);
    }

    #[test]
    fn test_audit_package_jitsi() {
        let data = include_str!("../test_data/dumpsys/package/jitsi.txt");
        let pkginfo = parsers::package::parse_output(data, "org.jitsi.meet").unwrap();
        let sus = pkginfo.audit();
        assert_eq!(&sus, &[
            Suspicion {
                level: SuspicionLevel::Medium,
                description: "Package \"org.jitsi.meet\" was manually installed".to_string(),
            },
        ]);
    }
}
