use crate::accessibility;
use crate::args;
use crate::dumpsys;
use crate::errors::*;
use crate::iocs::{Suspicion, SuspicionLevel};
use crate::package;
use crate::pm;
use crate::remote_clock;
use crate::settings;
use mozdevice::Device;
use std::collections::HashMap;

pub struct Settings {
    pub skip_apps: bool,
}

impl From<&args::Scan> for Settings {
    fn from(args: &args::Scan) -> Settings {
        Settings {
            skip_apps: args.skip_apps,
        }
    }
}

pub fn run(
    device: &Device,
    rules: &HashMap<String, String>,
    scan: &Settings,
) -> Result<Vec<Suspicion>> {
    let mut report = Vec::new();
    debug!("Using device: {:?}", device);

    if device.is_rooted {
        warn!("Device is rooted!");
    } else {
        info!("Device is not rooted");
    }

    info!("Fetching remote clock");
    let (local_time, remote_time, drift) = remote_clock::determine(device)?;
    info!(
        "Local time is {}, remote time is {}, drift={:#}",
        local_time, remote_time, drift
    );

    info!("Enumerating android settings");
    for (_namespace, settings) in settings::dump(device)? {
        for sus in settings.audit() {
            warn!("Suspicious {:?}: {}", sus.level, sus.description);
            report.push(sus);
        }
    }

    if !scan.skip_apps {
        // TODO: maybe `cmd package list packages -f`
        info!("Comparing list of installed apps with known stalkerware ids");

        let installed_apps = pm::list_packages(device)?;
        let mut progress = 0;
        for apps in installed_apps.chunks(100) {
            info!(
                "Scanning installed apps ({}/{})",
                progress,
                installed_apps.len()
            );

            for pkg in apps {
                progress += 1;

                // TODO: maybe fetch apk and inspect eg. cert

                if let Some(name) = rules.get(&pkg.id) {
                    let alert = format!(
                        "Found known stalkerware with rule: {:?} ({:?})",
                        pkg.id, name
                    );
                    warn!("Suspicious {:?}: {}", SuspicionLevel::High, alert);
                }

                // fetch infos about package
                let info = package::dump(device, &pkg.id)?;
                trace!("package infos {:?}: {:#?}", pkg.id, info);

                for sus in info.audit() {
                    warn!("Suspicious {:?}: {}", sus.level, sus.description);
                    report.push(sus);
                }
            }
        }
    }

    info!("Enumerating service list");
    let services = dumpsys::list_services(device)?;

    if services.contains("accessibility") {
        info!("Reading accessibility settings");
        let accessibility = accessibility::dump(device)?;
        for sus in accessibility.audit() {
            warn!("Suspicious {:?}: {}", sus.level, sus.description);
            report.push(sus);
        }
    }

    info!("Scan finished");

    Ok(report)
}
