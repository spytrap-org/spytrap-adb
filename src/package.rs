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

