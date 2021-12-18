use crate::errors::*;
use crate::parsers;
use crate::parsers::package::PackageInfo;
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
    pub fn installer_package_name(&self) -> Option<&str> {
        self.fields.get("installerPackageName").map(String::as_str)
    }
}

#[cfg(test)]
mod tests {
    // use super::*;
}
