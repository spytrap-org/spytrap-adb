use crate::errors::*;
use crate::ioc::{Suspicion, SuspicionLevel};
use forensic_adb::Device;
use std::collections::HashMap;

const SETTINGS: &[(&str, &[&str])] = &[(
    "global",
    &[
        "package_verifier_enable",
        "package_verifier_user_consent",
        "upload_apk_enable",
    ],
)];

pub async fn dump(device: &Device) -> Result<HashMap<String, Settings>> {
    let mut out = HashMap::<_, Settings>::new();

    for (namespace, keys) in SETTINGS {
        let settings = out.entry(namespace.to_string()).or_default();

        for key in *keys {
            let cmd = format!("settings get {namespace} {key}");
            debug!("Executing {:?}", cmd);
            let output = device
                .execute_host_exec_out_command(&cmd)
                .await
                .with_context(|| anyhow!("Failed to run: {:?}", cmd))?;
            let mut output = String::from_utf8_lossy(&output).into_owned();
            if output.ends_with('\n') {
                output.pop();
            }
            debug!(
                "Received setting for namespace={namespace:?} key={key:?} from device: {output:?}"
            );

            if output != "null" {
                settings.insert(key.to_string(), output);
            }
        }
    }

    Ok(out)
}

#[derive(Debug, PartialEq, Default)]
pub struct Settings {
    pub values: HashMap<String, String>,
}

impl Settings {
    pub fn insert(&mut self, key: String, value: String) {
        self.values.insert(key, value);
    }

    pub fn audit(&self) -> Vec<Suspicion> {
        let mut sus = Vec::new();
        for (key, value) in &self.values {
            match key.as_str() {
                "package_verifier_enable" => {
                    if value != "1" {
                        warn!("Google Play Protect is turned off");
                        sus.push(Suspicion {
                            level: SuspicionLevel::High,
                            description: "Google Play Protect is turned off".to_string(),
                        });
                    }
                }
                "package_verifier_user_consent" => {
                    if value == "1" {
                        info!("Scanning apps with Google Play Protect is enabled");
                        sus.push(Suspicion {
                            level: SuspicionLevel::Good,
                            description: "Scanning apps with Google Play Protect is enabled"
                                .to_string(),
                        });
                    } else {
                        warn!("Scanning apps with Google Play Protect is disabled");
                        sus.push(Suspicion {
                            level: SuspicionLevel::High,
                            description: "Scanning apps with Google Play Protect is disabled"
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
