pub mod execsnoop;
pub mod opensnoop;
pub mod tcpconnect;
pub mod types;
pub mod utils;

use crate::storage::types::*;
use anyhow::Result;
use lockfree::channel::mpsc;
use std::collections::HashMap;
use tokio::time::{sleep, Duration};

type ArgvMap = HashMap<u32, String>;

pub trait AbtractProbe {
    fn load(sender: mpsc::Sender<types::EventEnum>) -> Result<()>;
}

pub async fn load(storage_sender: mpsc::Sender<EventType>) -> Result<()> {
    let mut exec_argv_map = ArgvMap::new();

    let (sender, mut receiver) = mpsc::create();
    let exec_sender = sender.clone();
    let open_sender = sender.clone();
    let tcp_sender = sender.clone();
    tokio::spawn(async move {
        if execsnoop::Probe::load(exec_sender).is_err() {
            panic!("Failed to load exec eBPF");
        }
    });
    tokio::spawn(async move {
        sleep(Duration::from_millis(1500)).await;
        if let Err(e) = opensnoop::Probe::load(open_sender) {
            panic!("Failed to load open eBPF: {}", e);
        }
    });
    tokio::spawn(async move {
        sleep(Duration::from_millis(3000)).await;
        if tcpconnect::Probe::load(tcp_sender).is_err() {
            panic!("Failed to load exec eBPF");
        }
    });
    println!("Waiting for building eBPF...");
    sleep(Duration::from_millis(5000)).await;
    println!("eBPF is ready");
    loop {
        if let Ok(message) = receiver.recv() {
            match message {
                types::EventEnum::Exec(event) => {
                    let argv = exec_argv_map.entry(event.pid).or_insert_with(String::new);
                    match event.event_type {
                        execsnoop::EventType::Arg => {
                            argv.push_str(&format!("{} ", utils::read_u8_string(&event.argv)));
                        }
                        execsnoop::EventType::Ret => {
                            argv.pop();
                            let send_event = ExecEvent {
                                pid: event.pid,
                                ppid: event.ppid,
                                uid: event.uid,
                                command: utils::read_u8_string(&event.comm),
                                argv: argv.clone(),
                            };
                            storage_sender.send(EventType::Exec(send_event)).unwrap();
                            exec_argv_map.remove(&event.pid);
                        }
                    }
                }
                types::EventEnum::Open(event) => {
                    let pid: u32 = (event.id >> 32) as u32;
                    let send_event = OpenEvent {
                        pid,
                        ts: event.ts,
                        uid: event.uid,
                        command: utils::read_u8_string(&event.comm),
                        fname: utils::read_u8_string(&event.fname),
                    };
                    storage_sender.send(EventType::Open(send_event)).unwrap();
                }
                types::EventEnum::ConnectV4(event) => {
                    let send_event = ConnectV4Event {
                        pid: event.pid,
                        ts: event.ts_us,
                        uid: event.uid,
                        task: utils::read_u8_string(&event.task),
                        saddr: u32::from_be(event.saddr).into(),
                        daddr: u32::from_be(event.daddr).into(),
                        lport: event.lport,
                        dport: event.dport,
                    };
                    storage_sender
                        .send(EventType::ConnectV4(send_event))
                        .unwrap();
                }
                types::EventEnum::ConnectV6(event) => {
                    let send_event = ConnectV6Event {
                        pid: event.pid,
                        ts: event.ts_us,
                        uid: event.uid,
                        task: utils::read_u8_string(&event.task),
                        saddr: u128::from_be(event.saddr).into(),
                        daddr: u128::from_be(event.daddr).into(),
                        lport: event.lport,
                        dport: event.dport,
                    };
                    storage_sender
                        .send(EventType::ConnectV6(send_event))
                        .unwrap();
                }
            }
        } else {
            sleep(Duration::from_millis(1000)).await;
        }
    }
}
