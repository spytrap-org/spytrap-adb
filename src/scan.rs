use crate::accessibility;
use crate::args;
use crate::dumpsys;
use crate::errors::*;
use crate::ioc::{Suspicion, SuspicionLevel};
use crate::package;
use crate::pm;
use crate::remote_clock;
use crate::settings;
use crate::tui::Message;
use forensic_adb::Device;
use std::collections::HashMap;
use tokio::sync::mpsc;

pub enum ScanNotifier {
    Null,
    Channel(mpsc::Sender<Message>),
}

impl ScanNotifier {
    pub async fn sus(&mut self, sus: Suspicion) -> Result<()> {
        if let ScanNotifier::Channel(tx) = self {
            tx.send(Message::Suspicion(sus)).await?;
        }
        Ok(())
    }

    pub async fn app(&mut self, name: String, sus: Suspicion) -> Result<()> {
        if let ScanNotifier::Channel(tx) = self {
            tx.send(Message::App { name, sus }).await?;
        }
        Ok(())
    }
}

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

pub async fn run(
    device: &Device,
    rules: &HashMap<String, String>,
    scan: &Settings,
    report: &mut ScanNotifier,
) -> Result<()> {
    debug!("Using device: {:?}", device);

    info!("Fetching remote clock");
    let (local_time, remote_time, drift) = remote_clock::determine(device).await?;
    info!(
        "Local time is {}, remote time is {}, drift={:#}",
        local_time, remote_time, drift
    );

    info!("Enumerating android settings");
    for (_namespace, settings) in settings::dump(device).await? {
        for sus in settings.audit() {
            warn!("Suspicious {:?}: {}", sus.level, sus.description);
            report.sus(sus).await?;
        }
    }

    info!("Enumerating service list");
    let services = dumpsys::list_services(device).await?;

    if services.contains("accessibility") {
        info!("Reading accessibility settings");
        let accessibility = accessibility::dump(device).await?;
        for sus in accessibility.audit() {
            warn!("Suspicious {:?}: {}", sus.level, sus.description);
            report.sus(sus).await?;
        }
    }

    if !scan.skip_apps {
        // TODO: maybe `cmd package list packages -f`
        info!("Comparing list of installed apps with known stalkerware ids");

        let installed_apps = pm::list_packages(device).await?;
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
                let info = package::dump(device, &pkg.id).await?;
                trace!("package infos {:?}: {:#?}", pkg.id, info);

                for sus in info.audit() {
                    warn!("Suspicious {:?}: {}", sus.level, sus.description);
                    report.app(pkg.id.clone(), sus).await?;
                }
            }
        }
    }

    info!("Scan finished");

    Ok(())
}
