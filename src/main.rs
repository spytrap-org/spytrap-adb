use clap::Parser;
use env_logger::Env;
use forensic_adb::{AndroidStorageInput, Host};
use spytrap_adb::args::{self, Args, SubCommand};
use spytrap_adb::errors::*;
use spytrap_adb::rules;
use spytrap_adb::scan;
use spytrap_adb::tui;
use spytrap_adb::utils;
use std::process::Command;

async fn run(args: Args) -> Result<()> {
    let adb_host = Host::default();

    match args.subcommand {
        Some(SubCommand::Scan(scan)) => {
            let rules = rules::load_map_from_file(&scan.rules).context("Failed to load rules")?;
            info!("Loaded {} rules from {:?}", rules.len(), scan.rules);

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
            2 => "debug",
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
