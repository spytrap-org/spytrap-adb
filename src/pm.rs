use crate::errors::*;
use mozdevice::Device;

const CMD: &str = "pm list packages -f";

#[derive(Debug, PartialEq)]
pub struct Apk {
    pub path: String,
    pub id: String,
}

pub fn list_packages(device: &Device) -> Result<Vec<Apk>> {
    let output = device
        .execute_host_shell_command(CMD)
        .with_context(|| anyhow!("Failed to run: {:?}", CMD))?;
    parse_output(&output)
}

fn parse_output(output: &str) -> Result<Vec<Apk>> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    pub fn test_parse_output() {
        let data = "package:/data/app/~~0aX7BWdP29TqZaPPXkHNIA==/org.jitsi.meet-hcYO-DrfCgXIZKdu4pcUeA==/base.apk=org.jitsi.meet
package:/system/product/overlay/LineageBlackAccent/LineageBlackAccent.apk=org.lineageos.overlay.accent.black
package:/system/priv-app/CtsShimPrivPrebuilt/CtsShimPrivPrebuilt.apk=com.android.cts.priv.ctsshim
package:/system/product/overlay/LineageBrownAccent/LineageBrownAccent.apk=org.lineageos.overlay.accent.brown
package:/system/product/overlay/LineageGreenAccent/LineageGreenAccent.apk=org.lineageos.overlay.accent.green
package:/system/product/overlay/DisplayCutoutEmulationCorner/DisplayCutoutEmulationCornerOverlay.apk=com.android.internal.display.cutout.emulation.corner
package:/system/product/overlay/LineageBlackTheme/LineageBlackTheme.apk=org.lineageos.overlay.customization.blacktheme
";

        let pkgs = parse_output(data).unwrap();
        assert_eq!(&pkgs, &[
            Apk { path: "/data/app/~~0aX7BWdP29TqZaPPXkHNIA".to_string(), id: "=/org.jitsi.meet-hcYO-DrfCgXIZKdu4pcUeA==/base.apk=org.jitsi.meet".to_string() },
            Apk { path: "/system/product/overlay/LineageBlackAccent/LineageBlackAccent.apk".to_string(), id: "org.lineageos.overlay.accent.black".to_string() },
            Apk { path: "/system/priv-app/CtsShimPrivPrebuilt/CtsShimPrivPrebuilt.apk".to_string(), id: "com.android.cts.priv.ctsshim".to_string() },
            Apk { path: "/system/product/overlay/LineageBrownAccent/LineageBrownAccent.apk".to_string(), id: "org.lineageos.overlay.accent.brown".to_string() },
            Apk { path: "/system/product/overlay/LineageGreenAccent/LineageGreenAccent.apk".to_string(), id: "org.lineageos.overlay.accent.green".to_string() },
            Apk { path: "/system/product/overlay/DisplayCutoutEmulationCorner/DisplayCutoutEmulationCornerOverlay.apk".to_string(), id: "com.android.internal.display.cutout.emulation.corner".to_string() },
            Apk { path: "/system/product/overlay/LineageBlackTheme/LineageBlackTheme.apk".to_string(), id: "org.lineageos.overlay.customization.blacktheme".to_string() }
        ]);
    }
}
