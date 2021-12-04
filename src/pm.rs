use crate::errors::*;
use mozdevice::Device;

const CMD: &str = "pm list packages -f";

pub struct Apk {
    pub path: String,
    pub id: String,
}

pub fn list_packages(device: &Device) -> Result<Vec<Apk>> {
    let output = device
        .execute_host_shell_command(CMD)
        .with_context(|| anyhow!("Failed to run: {:?}", CMD))?;

    let mut pkgs = Vec::new();
    for line in output.split('\n') {
        if line.is_empty() {
            continue;
        }

        if let Some(package) = line.strip_prefix("package:") {
            if let Some((apk, id)) = package.split_once('=') {
                debug!("apk={:?}, id={:?}", apk, id);

                pkgs.push(Apk {
                    path: apk.to_string(),
                    id: id.to_string(),
                });
            }
        }
    }

    Ok(pkgs)
}
