mod cli;
mod ebpf;
mod server;
mod storage;
mod visualization;

use cli::Cli;

#[tokio::main]
async fn main() {
    storage::utils::ensure_directories();

    let args = Cli::matches();

    if let Some(matches) = args.subcommand_matches("watch") {
        let pid = matches.value_of("PID").unwrap().parse::<u32>().unwrap();
        println!("Watching PID {}", pid);
        server::start(pid).await;
    } else if let Some(matches) = args.subcommand_matches("check") {
        cli::check::exec(matches.value_of("Id").unwrap(), matches.value_of("Command"));
    } else {
        println!("No command specified, use --help for more information.");
    }
}
