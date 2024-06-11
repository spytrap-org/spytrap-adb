use crate::errors::*;
use bstr::ByteSlice;
use forensic_adb::Device;
use std::str;

const CMD: &str = "pm list packages";

#[derive(Debug, PartialEq)]
pub struct Apk {
    pub id: String,
}

pub async fn list_packages(device: &Device) -> Result<Vec<Apk>> {
    let output = device
        .execute_host_exec_out_command(CMD)
        .await
        .with_context(|| anyhow!("Failed to run: {:?}", CMD))?;
    parse_output(&output)
}

fn parse_output(output: &[u8]) -> Result<Vec<Apk>> {
    let mut pkgs = Vec::new();
    for line in output.lines() {
        if line.is_empty() {
            continue;
        }
        let line = String::from_utf8_lossy(line);

        if let Some(package) = line.strip_prefix("package:") {
            debug!("discovered package={:?}", package);

            pkgs.push(Apk {
                id: package.to_string(),
            });
        }
    }

    Ok(pkgs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    pub fn test_parse_output() {
        let data = b"package:org.jitsi.meet
package:org.lineageos.overlay.accent.black
package:com.android.cts.priv.ctsshim
package:org.lineageos.overlay.accent.brown
package:org.lineageos.overlay.accent.green
package:com.android.internal.display.cutout.emulation.corner
package:org.lineageos.overlay.customization.blacktheme
";

        let pkgs = parse_output(data).unwrap();
        assert_eq!(
            &pkgs,
            &[
                Apk {
                    id: "org.jitsi.meet".to_string()
                },
                Apk {
                    id: "org.lineageos.overlay.accent.black".to_string()
                },
                Apk {
                    id: "com.android.cts.priv.ctsshim".to_string()
                },
                Apk {
                    id: "org.lineageos.overlay.accent.brown".to_string()
                },
                Apk {
                    id: "org.lineageos.overlay.accent.green".to_string()
                },
                Apk {
                    id: "com.android.internal.display.cutout.emulation.corner".to_string()
                },
                Apk {
                    id: "org.lineageos.overlay.customization.blacktheme".to_string()
                }
            ]
        );
    }
}
