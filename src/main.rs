use clap::Parser;
use env_logger::Env;
use forensic_adb::{AndroidStorageInput, Host};
use spytrap_adb::args::{self, Args, SubCommand};
use spytrap_adb::errors::*;
use spytrap_adb::iocs;
use spytrap_adb::rules;
use spytrap_adb::scan;
use spytrap_adb::tui;
use spytrap_adb::utils;
use std::borrow::Cow;
use std::process::Command;

async fn run(args: Args) -> Result<()> {
    let adb_host = Host::default();

    match args.subcommand {
        Some(SubCommand::Scan(scan)) => {
            let rules_path = if let Some(path) = &scan.rules {
                Cow::Borrowed(path)
            } else {
                let path = iocs::Repository::ioc_file_path()?;
                Cow::Owned(path)
            };

            let (rules, sha256) =
                rules::load_map_from_file(rules_path.as_ref()).context("Failed to load rules")?;
            info!(
                "Loaded {} rules from {rules_path:?} (sha256={sha256})",
                rules.len()
            );

            let repo = iocs::Repository::init().await?;
            if let Some(update_state) = &repo.update_state {
                if update_state.sha256 == sha256 {
                    info!(
                        "Rules database was downloaded from commit={}",
                        update_state.git_commit
                    );
                }
            }

            if scan.test_load_only {
                info!("Rules loaded successfully");
                return Ok(());
            }

            let device = adb_host
                .device_or_default(scan.serial.as_ref(), AndroidStorageInput::Auto)
                .await
                .with_context(|| anyhow!("Failed to access device: {:?}", scan.serial))?;

            scan::run(&device, &rules, &scan::Settings::from(&scan)).await?;
        }
        Some(SubCommand::List(_)) => {
            debug!("Listing devices from adb...");
            let devices = adb_host
                .devices::<Vec<_>>()
                .await
                .map_err(|e| anyhow!("Failed to list devices from adb: {}", e))?;

            for device in devices {
                debug!("Found device: {:?}", device);
                println!(
                    "{:30} device={:?}, model={:?}, product={:?}",
                    device.serial,
                    utils::human_option_str(device.info.get("device")),
                    utils::human_option_str(device.info.get("model")),
                    utils::human_option_str(device.info.get("product")),
                );
            }
        }
        Some(SubCommand::Sync(_sync)) => {
            let mut repo = iocs::Repository::init().await?;
            repo.sync_ioc_file()
                .await
                .context("Failed to sync stalkerware-indicators ioc.yaml")?;
        }
        None => {
            let mut app = tui::App::new(adb_host);
            app.init().await?;
            let mut terminal = tui::setup()?;
            let ret = tui::run(&mut terminal, &mut app).await;
            tui::cleanup(&mut terminal).ok();
            ret?;
        }
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    if args.subcommand.is_some() {
        let logging = match args.verbose {
            0 => "info",
            1 => "spytrap_adb=debug,info",
            2 => "spytrap_adb=trace,debug",
            _ => "trace",
        };

        env_logger::init_from_env(Env::default().default_filter_or(logging));
    }

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

    run(args).await
}
