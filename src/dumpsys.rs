use crate::errors::*;
use mozdevice::Device;
use std::collections::HashSet;

const CMD_LIST_SERVICES: &str = "dumpsys -l";

pub fn list_services(device: &Device) -> Result<HashSet<String>> {
    let output = device
        .execute_host_shell_command(CMD_LIST_SERVICES)
        .with_context(|| anyhow!("Failed to run: {:?}", CMD_LIST_SERVICES))?;

    let mut services = HashSet::new();
    for line in output.split('\n') {
        if line.is_empty() {
            continue;
        }

        if let Some(service) = line.strip_prefix("  ") {
            debug!("Found service: {:?}", service);
            services.insert(service.to_string());
        }
    }

    Ok(services)
}

pub fn dump_service(device: &Device, service: &str) -> Result<String> {
    let cmd = format!("dumpsys {}", service);
    let output = device
        .execute_host_shell_command(&cmd)
        .with_context(|| anyhow!("Failed to run: {:?}", cmd))?;
    Ok(output)
}
