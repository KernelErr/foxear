use crate::visualization::{connect, exec, open};
use std::process::exit;

pub fn exec(id: &str, command: Option<&str>) {
    if command.is_none() {
        print_commands();
        exit(0);
    }

    match command.unwrap() {
        "graph" => {
            let graph = exec::graph(id).unwrap();
            println!("Generated exec graph in {}", graph);
        }
        "ps" => {
            exec::ps(id);
        }
        "fs" => {
            open::fs(id);
        }
        "v4" => {
            connect::v4(id);
        }
        "v6" => {
            connect::v6(id);
        }
        _ => {
            println!("Unknown command {}", command.unwrap());
            print_commands();
            exit(1);
        }
    }
}

fn print_commands() {
    println!("Available commands:");
    println!("  ps: print process list");
    println!("  fs: print file access list (.so file omited)");
    println!("  graph: generate ps graph");
    println!("  v4: show IPv4 TCP connections");
    println!("  v6: show IPv6 TCP connections");
}
