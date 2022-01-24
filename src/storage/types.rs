use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Debug)]
pub enum EventType {
    Exec(ExecEvent),
    Open(OpenEvent),
    ConnectV4(ConnectV4Event),
    ConnectV6(ConnectV6Event),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecEvent {
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub command: String,
    pub argv: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenEvent {
    pub pid: u32,
    pub ts: u64,
    pub uid: u32,
    pub command: String,
    pub fname: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectV4Event {
    pub ts: u64,
    pub pid: u32,
    pub uid: u32,
    pub saddr: Ipv4Addr,
    pub daddr: Ipv4Addr,
    pub lport: u16,
    pub dport: u16,
    pub task: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectV6Event {
    pub ts: u64,
    pub pid: u32,
    pub uid: u32,
    pub saddr: Ipv6Addr,
    pub daddr: Ipv6Addr,
    pub lport: u16,
    pub dport: u16,
    pub task: String,
}
