use super::utils::ensure_exists;
use crate::storage::types::*;
use crate::storage::utils::LOG_DIR;
use anyhow::Result;
use cli_table::{print_stdout, TableStruct};
use csv::ReaderBuilder;
use petgraph::dot::Dot;
use petgraph::graph::NodeIndex;
use petgraph::Graph;
use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::Write;

pub fn ps(path: &str) {
    let log_file = format!("{}/{}/exec.csv", LOG_DIR, path);
    ensure_exists(&log_file);
    let log_file = OpenOptions::new().read(true).open(log_file).unwrap();

    let mut reader = ReaderBuilder::new().from_reader(log_file);
    let table = TableStruct::try_from(&mut reader).unwrap();

    print_stdout(table).unwrap();
}

pub fn graph(path: &str) -> Result<String> {
    let log_file = format!("{}/{}/exec.csv", LOG_DIR, path);
    ensure_exists(&log_file);
    fs::create_dir_all(format!("{}/{}/reports", LOG_DIR, path)).unwrap();
    let output_file = format!("{}/{}/reports/exec.dot", LOG_DIR, path);
    let mut reader = csv::Reader::from_path(log_file)?;
    let mut deps = Graph::<&str, &str>::new();
    let mut command_map: HashMap<u32, NodeIndex> = HashMap::new();
    let mut parent_map: HashMap<u32, u32> = HashMap::new();
    let mut command_relations: Vec<(NodeIndex, NodeIndex)> = Vec::new();
    let mut records = Vec::new();

    for result in reader.deserialize() {
        let mut record: ExecEvent = result?;
        if record.uid == 0 {
            record.command = format!("{} (root)", record.command);
        }
        records.push(record);
    }

    for record in &records {
        let node = deps.add_node(&record.command);
        command_map.insert(record.pid, node);
        parent_map.insert(record.pid, record.ppid);
    }

    for (pid, ppid) in parent_map {
        if let Some(parent) = command_map.get(&ppid) {
            command_relations.push((*parent, *command_map.get(&pid).unwrap()));
        }
    }

    deps.extend_with_edges(&command_relations);
    let dot = Dot::new(&deps);
    let mut file = fs::File::options()
        .create(true)
        .write(true)
        .open(&output_file)?;
    write!(file, "{}", dot)?;
    file.flush()?;

    Ok(output_file)
}
