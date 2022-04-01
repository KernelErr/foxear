pub mod check;

use clap::{arg, command, ArgMatches, Command};

pub struct Cli {}

impl Cli {
    pub fn matches() -> ArgMatches {
        let matches = command!()
            .propagate_version(true)
            .subcommand(
                Command::new("watch")
                    .about("Watch a process and log its events")
                    .arg(arg!(<PID> "PID of the process to watch")),
            )
            .subcommand(
                Command::new("check")
                    .about("Check previous log")
                    .arg(arg!(<Id> "Number of the directory to analyse"))
                    .arg(arg!([Command] "Command to run, empty for full list")),
            )
            .get_matches();

        matches
    }
}
