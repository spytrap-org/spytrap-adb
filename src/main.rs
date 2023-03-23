use clap::Parser;
use env_logger::Env;
use mozdevice::{AndroidStorageInput, Host};
use spytrap_adb::accessibility;
use spytrap_adb::args::{self, Args, SubCommand};
use spytrap_adb::dumpsys;
use spytrap_adb::errors::*;
use spytrap_adb::iocs::SuspicionLevel;
use spytrap_adb::package;
use spytrap_adb::pm;
use spytrap_adb::remote_clock;
use spytrap_adb::rules;
use std::process::Command;

fn human_option_str(x: Option<&String>) -> &str {
    if let Some(x) = x {
        x.as_str()
    } else {
        "-"
    }
}

fn run(args: Args) -> Result<()> {
    let adb_host = Host::default();

    match args.subcommand {
        SubCommand::Scan(scan) => {
            let rules = rules::load_map_from_file(&scan.rules).context("Failed to load rules")?;
            info!("Loaded {} rules from {:?}", rules.len(), scan.rules);

            if scan.test_load_only {
                info!("Rules loaded successfully");
                return Ok(());
            }

            let device = adb_host
                .device_or_default(scan.serial.as_ref(), AndroidStorageInput::Auto)
                .with_context(|| anyhow!("Failed to access device: {:?}", scan.serial))?;
            debug!("Using device: {:?}", device);

            if device.is_rooted {
                warn!("Device is rooted!");
            } else {
                info!("Device is not rooted");
            }

            info!("Fetching remote clock");
            let (local_time, remote_time, drift) = remote_clock::determine(&device)?;
            info!(
                "Local time is {}, remote time is {}, drift={:#}",
                local_time, remote_time, drift
            );

            if !scan.skip_apps {
                // TODO: maybe `cmd package list packages -f`
                info!("Comparing list of installed apps with known stalkerware ids");

                let installed_apps = pm::list_packages(&device)?;
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
                        let info = package::dump(&device, &pkg.id)?;
                        trace!("package infos {:?}: {:#?}", pkg.id, info);

                        for sus in info.audit() {
                            warn!("Suspicious {:?}: {}", sus.level, sus.description);
                        }
                    }
                }
            }

            info!("Enumerating service list");
            let services = dumpsys::list_services(&device)?;

            if services.contains("accessibility") {
                info!("Reading accessibility settings");
                let accessibility = accessibility::dump(&device)?;
                for sus in accessibility.audit() {
                    warn!("Suspicious {:?}: {}", sus.level, sus.description);
                }
            }

            info!("Scan finished");
        }
        SubCommand::List(_) => {
            debug!("Listing devices from adb...");
            let devices = adb_host
                .devices::<Vec<_>>()
                .map_err(|e| anyhow!("Failed to list devices from adb: {}", e))?;

            for device in devices {
                debug!("Found device: {:?}", device);
                println!(
                    "{:30} device={:?}, model={:?}, product={:?}",
                    device.serial,
                    human_option_str(device.info.get("device")),
                    human_option_str(device.info.get("model")),
                    human_option_str(device.info.get("product")),
                );
            }
        }
    }

    Ok(())
}

fn main() -> Result<()> {
    let args = Args::parse();

    let logging = match args.verbose {
        0 => "info",
        1 => "spytrap_adb=debug,info",
        2 => "debug",
        _ => "trace",
    };

    env_logger::init_from_env(Env::default().default_filter_or(logging));

    if args.start_adb_server != args::AdbServerChoice::Never {
        debug!("Making sure adb server is running...");
        let status = Command::new("adb")
            .arg("start-server")
            .status()
            .context("Failed to start adb binary")?;
        if !status.success() {
            bail!("Failed to ensure adb server is running: exited with status={status:?}");
        }
    }

    run(args)
}
