use crate::errors::*;
use clap::{ArgAction, CommandFactory, Parser};
use clap_complete::Shell;
use std::io::stdout;
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(version)]
pub struct Args {
    /// More verbose logs
    #[arg(short, long, global = true, action(ArgAction::Count))]
    pub verbose: u8,
    /// Configure if an adb server should be started if needed
    #[arg(
        long,
        global = true,
        value_name = "choice",
        env = "SPYTRAP_START_ADB_SERVER",
        default_value = "auto"
    )]
    pub start_adb_server: AdbServerChoice,
    #[command(subcommand)]
    pub subcommand: Option<SubCommand>,
}

#[derive(Debug, Clone, Copy, PartialEq, clap::ValueEnum)]
pub enum AdbServerChoice {
    Auto,
    Always,
    Never,
}

#[derive(Debug, Parser)]
pub enum SubCommand {
    Scan(Scan),
    List(List),
    DownloadIoc(DownloadIoc),
    Completions(Completions),
}

/// Run a scan on a given device
#[derive(Debug, Parser)]
pub struct Scan {
    pub serial: Option<String>,
    #[arg(long)]
    pub rules: Option<PathBuf>,
    #[arg(long)]
    pub test_load_only: bool,
    /// Do not scan apps for suspicious permissions
    #[arg(long)]
    pub skip_apps: bool,
}

/// List all available devices
#[derive(Debug, Parser)]
pub struct List {}

/// Download the latest version of stalkerware-indicators ioc.yaml
#[derive(Debug, Parser)]
pub struct DownloadIoc {}

/// Generate shell completions
#[derive(Debug, Parser)]
pub struct Completions {
    pub shell: Shell,
}

impl Completions {
    pub fn generate(&self) -> Result<()> {
        clap_complete::generate(self.shell, &mut Args::command(), "spytrap-adb", &mut stdout());
        Ok(())
    }
}
