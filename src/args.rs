use clap::Parser;

#[derive(Debug, Parser)]
pub struct Args {
    /// More verbose logs
    #[clap(short, long, global = true, parse(from_occurrences))]
    pub verbose: u8,
    #[clap(subcommand)]
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
    #[clap(long, default_value = "./ioc.yaml")]
    pub rules: String,
    #[clap(long)]
    pub test_load_only: bool,
}
