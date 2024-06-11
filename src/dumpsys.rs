use crate::errors::*;
use bstr::ByteSlice;
use forensic_adb::Device;
use std::collections::HashSet;
use std::str;

const CMD_LIST_SERVICES: &str = "dumpsys -l";

pub async fn list_services(device: &Device) -> Result<HashSet<String>> {
    let cmd = CMD_LIST_SERVICES;
    debug!("Executing {:?}", cmd);
    let output = device
        .execute_host_exec_out_command(cmd)
        .await
        .with_context(|| anyhow!("Failed to run: {:?}", cmd))?;

    let mut services = HashSet::new();
    for line in output.lines() {
        if line.is_empty() {
            continue;
        }
        let line = String::from_utf8_lossy(line);

        if let Some(service) = line.strip_prefix("  ") {
            debug!("Found service: {:?}", service);
            services.insert(service.to_string());
        }
    }

    Ok(services)
}

pub async fn dump_service(device: &Device, service: &str) -> Result<String> {
    let cmd = format!("dumpsys {}", service);
    debug!("Executing {:?}", cmd);
    let output = device
        .execute_host_exec_out_command(&cmd)
        .await
        .with_context(|| anyhow!("Failed to run: {:?}", cmd))?;
    let output = String::from_utf8_lossy(&output);
    Ok(output.into_owned())
}
