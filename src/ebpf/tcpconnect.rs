use super::types::EventEnum;
use super::utils::*;
use super::AbtractProbe;
use anyhow::Result;
use bcc::perf_event::PerfMapBuilder;
use bcc::{Kprobe, Kretprobe, BPF};
use futures::executor::block_on;
use futures::lock::Mutex;
use lockfree::channel::mpsc::Sender;
use std::sync::{Arc, Once};
use tokio::time::{sleep, Duration};

static mut SENDER: Option<Sender<EventEnum>> = None;
static LOAD_INIT: Once = Once::new();

pub struct Probe {}

impl AbtractProbe for Probe {
    fn load(sender: Sender<EventEnum>, completed_probes: Arc<Mutex<i32>>) -> Result<()> {
        loop {
            let completed_guard = block_on(completed_probes.lock());
            if *completed_guard == 2 {
                drop(completed_guard);
                break;
            } else {
                drop(completed_guard);
                block_on(sleep(Duration::from_millis(1000)));
            }
        }

        LOAD_INIT.call_once(|| unsafe {
            SENDER = Some(sender);
        });
        let code = include_str!("../../probes/tcpconnect.c");
        let mut module = BPF::new(code)?;
        Kprobe::new()
            .handler("trace_connect_entry")
            .function("tcp_v4_connect")
            .attach(&mut module)?;
        Kprobe::new()
            .handler("trace_connect_entry")
            .function("tcp_v6_connect")
            .attach(&mut module)?;
        Kretprobe::new()
            .handler("trace_connect_v4_return")
            .function("tcp_v4_connect")
            .attach(&mut module)?;
        Kretprobe::new()
            .handler("trace_connect_v6_return")
            .function("tcp_v6_connect")
            .attach(&mut module)?;

        let v4_table = module.table("ipv4_events").unwrap();
        let v6_table = module.table("ipv6_events").unwrap();

        let mut v4_perf_map = PerfMapBuilder::new(v4_table, v4_callback).build().unwrap();
        let mut v6_perf_map = PerfMapBuilder::new(v6_table, v6_callback).build().unwrap();

        let mut completed_guard = block_on(completed_probes.lock());
        *completed_guard += 1;
        drop(completed_guard);

        loop {
            v4_perf_map.poll(200);
            v6_perf_map.poll(200);
        }
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct V4Event {
    pub ts_us: u64,
    pub pid: u32,
    pub uid: u32,
    pub saddr: u32,
    pub daddr: u32,
    pub ip: u64,
    pub lport: u16,
    pub dport: u16,
    pub task: [u8; 16],
}

#[repr(C)]
#[derive(Debug)]
pub struct V6Event {
    pub ts_us: u64,
    pub pid: u32,
    pub uid: u32,
    pub saddr: u128,
    pub daddr: u128,
    pub ip: u64,
    pub lport: u16,
    pub dport: u16,
    pub task: [u8; 16],
}

fn v4_callback() -> Box<dyn FnMut(&[u8]) + Send> {
    Box::new(|x| {
        let data: V4Event = read_struct(x);
        unsafe {
            let tx = SENDER.as_ref().unwrap().clone();
            tx.send(EventEnum::ConnectV4(data)).unwrap();
        }
    })
}

fn v6_callback() -> Box<dyn FnMut(&[u8]) + Send> {
    Box::new(|x| {
        let data: V6Event = read_struct(x);
        unsafe {
            let tx = SENDER.as_ref().unwrap().clone();
            tx.send(EventEnum::ConnectV6(data)).unwrap();
        }
    })
}
