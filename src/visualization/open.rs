use super::utils::ensure_exists;
use crate::storage::types::OpenEvent;
use crate::storage::utils::fliter_so_file;
use crate::storage::utils::LOG_DIR;
use cli_table::{print_stdout, Table, WithTitle};
use std::fs::OpenOptions;

#[derive(Table)]
struct Output {
    pid: u32,
    uid: u32,
    command: String,
    #[table(title = "path")]
    fname: String,
}

pub fn fs(path: &str) {
    let log_file = format!("{}/{}/open.csv", LOG_DIR, path);
    ensure_exists(&log_file);
    let log_file = OpenOptions::new().read(true).open(log_file).unwrap();
    let mut rdr = csv::Reader::from_reader(log_file);
    let mut records = Vec::new();

    for result in rdr.deserialize() {
        let record: OpenEvent = result.unwrap();
        let record = Output {
            pid: record.pid,
            uid: record.uid,
            command: record.command,
            fname: record.fname,
        };
        if fliter_so_file(&record.fname) {
            continue;
        }
        records.push(record);
    }

    print_stdout(records.with_title()).unwrap();
}
