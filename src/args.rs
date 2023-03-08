use clap::{ArgAction, Parser};

#[derive(Debug, Parser)]
pub struct Args {
    /// More verbose logs
    #[arg(short, long, global = true, action(ArgAction::Count))]
    pub verbose: u8,
    /// Configure if an adb server should be started if needed
    #[arg(
        long,
        global = true,
        value_name = "choice",
        env = "SPYTRAP_ADB_SERVER",
        default_value = "auto"
    )]
    pub adb_server: AdbServerChoice,
    #[command(subcommand)]
    pub subcommand: SubCommand,
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
}

/// Run a scan on a given device
#[derive(Debug, Parser)]
pub struct Scan {
    pub serial: Option<String>,
    #[arg(long, default_value = "./ioc.yaml")]
    pub rules: String,
    #[arg(long)]
    pub test_load_only: bool,
}

/// List all available devices
#[derive(Debug, Parser)]
pub struct List {}
