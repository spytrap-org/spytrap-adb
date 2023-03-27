use crate::errors::*;
use crate::iocs::{Suspicion, SuspicionLevel};
use crate::parsers::settings::Settings;
use forensic_adb::Device;
use std::collections::HashMap;

pub async fn dump(device: &Device) -> Result<HashMap<String, Settings>> {
    let mut out = HashMap::new();
    for namespace in ["system", "secure", "global"] {
        let cmd = format!("settings list {}", namespace);
        debug!("Executing {:?}", cmd);
        let output = device
            .execute_host_shell_command(&cmd)
            .await
            .with_context(|| anyhow!("Failed to run: {:?}", cmd))?;

        let settings = output
            .parse::<Settings>()
            .context("Failed to parse settings from device")?;

        out.insert(namespace.to_string(), settings);
    }
    Ok(out)
}

impl Settings {
    pub fn audit(&self) -> Vec<Suspicion> {
        let mut sus = Vec::new();
        for (key, value) in &self.values {
            match key.as_str() {
                "package_verifier_enable" => {
                    if value != "1" {
                        warn!("Scanning apps with Google Play Protect has been disabled");
                        sus.push(Suspicion {
                            level: SuspicionLevel::High,
                            description: "Scanning apps with Google Play Protect has been disabled"
                                .to_string(),
                        });
                    }
                }
                "package_verifier_user_consent" => {
                    if value != "1" {
                        warn!("Mandatory user consent for app installations has been disabled");
                        sus.push(Suspicion {
                            level: SuspicionLevel::Medium,
                            description:
                                "Mandatory user consent for app installations has been disabled"
                                    .to_string(),
                        });
                    }
                }
                "upload_apk_enable" => {
                    if value != "1" {
                        warn!(
                            "Automatic upload of suspicious apps to Google Play has been disabled"
                        );
                        sus.push(Suspicion {
                            level: SuspicionLevel::High,
                            description: "Automatic upload of suspicious apps to Google Play has been disabled".to_string(),
                        });
                    }
                }
                _ => (),
            }
        }
        sus
    }
}
