use clap::Parser;
use env_logger::Env;
use forensic_adb::{AndroidStorageInput, Host};
use spytrap_adb::args::{self, Args, SubCommand};
use spytrap_adb::errors::*;
use spytrap_adb::ioc;
use spytrap_adb::rules;
use spytrap_adb::scan;
use spytrap_adb::tui;
use spytrap_adb::utils;
use tokio::fs;
use tokio::process::Command;

// replace this with .unwrap_or after it became const
// https://github.com/rust-lang/rust/issues/67792
const ADB_BINARY: &str = if let Some(path) = option_env!("SPYTRAP_ADB_BINARY") {
    path
} else {
    "adb"
};

async fn ensure_adb_running(choice: &args::AdbServerChoice) -> Result<()> {
    if *choice != args::AdbServerChoice::Never {
        debug!("Making sure adb server is running (using {ADB_BINARY:?} binary)...");
        let status = Command::new(ADB_BINARY)
            .arg("start-server")
            .status()
            .await
            .with_context(|| anyhow!("Failed to start adb binary: {ADB_BINARY:?}"))?;
        if !status.success() {
            bail!("Failed to ensure adb server is running: exited with status={status:?}");
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

    let adb_host = Host::default();

    match args.subcommand {
        Some(SubCommand::Scan(scan)) => {
            ensure_adb_running(&args.start_adb_server).await?;

            let rules = if scan.rules.is_empty() {
                let repo = ioc::Repository::init().await?;
                repo.parse_rules()?
            } else {
                let mut rules = rules::Rules::default();
                for path in &scan.rules {
                    let buf = fs::read(&path)
                        .await
                        .with_context(|| anyhow!("Failed to read rules from file: {path:?}"))?;
                    rules.load_yaml(path, &buf)?;
                }
                rules
            };

            if scan.test_load_only {
                info!("Rules loaded successfully");
                return Ok(());
            }

            let device = adb_host
                .device_or_default(scan.serial.as_ref(), AndroidStorageInput::Auto)
                .await
                .with_context(|| anyhow!("Failed to access device: {:?}", scan.serial))?;

            scan::run(
                &device,
                &rules,
                &scan::Settings::from(&scan),
                &mut scan::ScanNotifier::Null,
            )
            .await?;
        }
        Some(SubCommand::List(_)) => {
            ensure_adb_running(&args.start_adb_server).await?;

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
        Some(SubCommand::DownloadIoc(_download)) => {
            let mut repo = ioc::Repository::init().await?;
            repo.download_ioc_db()
                .await
                .context("Failed to download stalkerware-indicators ioc.yaml")?;
        }
        Some(SubCommand::Completions(completions)) => {
            completions.generate()?;
        }
        None => {
            ensure_adb_running(&args.start_adb_server).await?;

            let repo = ioc::Repository::init().await?;
            let mut app = tui::App::new(adb_host, repo);
            app.init().await?;
            let mut terminal = tui::setup()?;
            let ret = tui::run(&mut terminal, &mut app).await;
            tui::cleanup(&mut terminal).ok();
            ret?;
        }
    }

    Ok(())
}
