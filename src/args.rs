use structopt::{clap::AppSettings, StructOpt};

#[derive(Debug, StructOpt)]
#[structopt(global_settings = &[AppSettings::ColoredHelp])]
pub struct Args {
    /// More verbose logs
    #[structopt(short, long, global = true, parse(from_occurrences))]
    pub verbose: u8,
    #[structopt(subcommand)]
    pub subcommand: SubCommand,
}

#[derive(Debug, StructOpt)]
pub enum SubCommand {
    Monitor,
    Scan(Scan),
    List,
}

#[derive(Debug, StructOpt)]
pub struct Scan {
    pub serial: Option<String>,
    #[structopt(long, default_value = "./appid.yaml")]
    pub rules: String,
}
