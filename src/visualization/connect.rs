use super::utils::ensure_exists;
use crate::storage::types::{ConnectV4Event, ConnectV6Event};
use crate::storage::utils::LOG_DIR;
use cli_table::{print_stdout, Table, WithTitle};
use std::fs::OpenOptions;

#[derive(Table)]
struct Output {
    pub pid: u32,
    pub uid: u32,
    pub task: String,
    pub source: String,
    pub target: String,
}

pub fn v4(path: &str) {
    let log_file = format!("{}/{}/tcp_connectv4.csv", LOG_DIR, path);
    ensure_exists(&log_file);
    let log_file = OpenOptions::new().read(true).open(log_file).unwrap();
    let mut rdr = csv::Reader::from_reader(log_file);
    let mut records = Vec::new();

    for result in rdr.deserialize() {
        let record: ConnectV4Event = result.unwrap();
        let record = Output {
            pid: record.pid,
            uid: record.uid,
            task: record.task,
            source: format!("{}:{}", record.saddr, record.lport),
            target: format!("{}:{}", record.daddr, record.dport),
        };
        records.push(record);
    }

    print_stdout(records.with_title()).unwrap();
}

pub fn v6(path: &str) {
    let log_file = format!("{}/{}/tcp_connectv6.csv", LOG_DIR, path);
    ensure_exists(&log_file);
    let log_file = OpenOptions::new().read(true).open(log_file).unwrap();
    let mut rdr = csv::Reader::from_reader(log_file);
    let mut records = Vec::new();

    for result in rdr.deserialize() {
        let record: ConnectV6Event = result.unwrap();
        let record = Output {
            pid: record.pid,
            uid: record.uid,
            task: record.task,
            source: format!("[{}]:{}", record.saddr, record.lport),
            target: format!("[{}]:{}", record.daddr, record.dport),
        };
        records.push(record);
    }

    print_stdout(records.with_title()).unwrap();
}
