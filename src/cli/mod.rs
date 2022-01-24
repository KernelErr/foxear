pub mod check;

use clap::{app_from_crate, arg, App, AppSettings, ArgMatches};

pub struct Cli {}

impl Cli {
    pub fn matches() -> ArgMatches {
        let matches = app_from_crate!()
            .global_setting(AppSettings::PropagateVersion)
            .global_setting(AppSettings::UseLongFormatForHelpSubcommand)
            .subcommand(
                App::new("watch")
                    .about("Watch a process and log its events")
                    .arg(arg!(<PID> "PID of the process to watch")),
            )
            .subcommand(
                App::new("check")
                    .about("Check previous log")
                    .arg(arg!(<Id> "Number of the directory to analyse"))
                    .arg(arg!([Command] "Command to run, empty for full list")),
            )
            .get_matches();

        matches
    }
}
