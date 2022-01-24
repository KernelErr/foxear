use super::types::*;
use super::utils::{create_log_file, fliter_so_file};
use anyhow::Result;
use lockfree::channel::mpsc;
use std::fs;
use tokio::time::{sleep, Duration};

pub async fn event_logger(mut receiver: mpsc::Receiver<EventType>, pid: u32) -> Result<()> {
    let event_db = sled::open("/var/lib/foxear/logs/db")?;
    let last_id: u8 = match event_db.get(b"last_id")? {
        Some(id) => *id.first().unwrap(),
        None => 0,
    } + 1;
    event_db.insert(b"last_id", &[last_id]).unwrap();
    let log_dir = format!("/var/lib/foxear/logs/{}", last_id);
    println!("Logs are stored at {}", log_dir);
    fs::create_dir_all(&log_dir).unwrap();

    let mut watch_pid: Vec<u32> = vec![pid];

    loop {
        if let Ok(event) = receiver.recv() {
            let (event_type, header) = match event {
                EventType::Exec(_) => ("exec", "pid,ppid,uid,command,argv\n"),
                EventType::Open(_) => ("open", "pid,ts,uid,command,fname\n"),
                EventType::ConnectV4(_) => {
                    ("tcp_connectv4", "ts,pid,uid,saddr,daddr,lport,dport,task\n")
                }
                EventType::ConnectV6(_) => {
                    ("tcp_connectv6", "ts,pid,uid,saddr,daddr,lport,dport,task\n")
                }
            };
            let log_path = format!("{}/{}.csv", log_dir, event_type);
            let log_file = create_log_file(&log_path, header);
            let mut csv_writer = csv::WriterBuilder::new()
                .has_headers(false)
                .from_writer(log_file);
            match event {
                EventType::Exec(event) => {
                    if watch_pid.contains(&event.ppid) {
                        watch_pid.push(event.pid);
                        println!(
                            "Process {} created subprocess {}: {}",
                            event.ppid, event.pid, event.command
                        );
                    }
                    if watch_pid.contains(&event.pid) {
                        csv_writer.serialize(&event)?;
                        csv_writer.flush()?;
                    }
                }
                EventType::Open(event) => {
                    if watch_pid.contains(&event.pid) {
                        if !fliter_so_file(&event.fname) {
                            println!(
                                "Process {} {} try to access: {}",
                                event.pid, event.command, event.fname
                            );
                        }
                        csv_writer.serialize(&event)?;
                        csv_writer.flush()?;
                    }
                }
                EventType::ConnectV4(event) => {
                    if watch_pid.contains(&event.pid) {
                        println!(
                            "Process {} {} try to connect: {}:{}",
                            event.pid, event.task, event.daddr, event.dport
                        );
                        csv_writer.serialize(&event)?;
                        csv_writer.flush()?;
                    }
                }
                EventType::ConnectV6(event) => {
                    if watch_pid.contains(&event.pid) {
                        println!(
                            "Process {} {} try to connect: [{}]:{}",
                            event.pid, event.task, event.daddr, event.dport
                        );
                        csv_writer.serialize(&event)?;
                        csv_writer.flush()?;
                    }
                }
            };
        } else {
            sleep(Duration::from_millis(1000)).await;
        }
    }
}
