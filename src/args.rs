use clap::{ArgAction, Parser};

#[derive(Debug, Parser)]
pub struct Args {
    /// More verbose logs
    #[arg(short, long, global = true, action(ArgAction::Count))]
    pub verbose: u8,
    #[command(subcommand)]
    pub subcommand: SubCommand,
}

#[derive(Debug, Parser)]
pub enum SubCommand {
    Monitor,
    Scan(Scan),
    List,
}

#[derive(Debug, Parser)]
pub struct Scan {
    pub serial: Option<String>,
    #[arg(long, default_value = "./ioc.yaml")]
    pub rules: String,
    #[arg(long)]
    pub test_load_only: bool,
}
