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
const SYSCALL_PREFIX: &str = env!("SYSCALL_PREFIX");
const OPENAT2_CHECK: &str = env!("OPENAT2_CHECK");

pub struct Probe {}

impl AbtractProbe for Probe {
    fn load(sender: Sender<EventEnum>, completed_probes: Arc<Mutex<i32>>) -> Result<()> {
        loop {
            let completed_guard = block_on(completed_probes.lock());
            if *completed_guard == 1 {
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
        let code = include_str!("../../probes/opensnoop.c");
        let fname_open = format!("{}open", SYSCALL_PREFIX);
        let fnname_openat = format!("{}openat", SYSCALL_PREFIX);
        let fnname_openat2 = format!("{}openat2", SYSCALL_PREFIX);
        let mut module = BPF::new(code)?;
        Kprobe::new()
            .handler("syscall__trace_entry_open")
            .function(&fname_open)
            .attach(&mut module)?;
        Kretprobe::new()
            .handler("trace_return")
            .function(&fname_open)
            .attach(&mut module)?;
        Kprobe::new()
            .handler("syscall__trace_entry_openat")
            .function(&fnname_openat)
            .attach(&mut module)?;
        Kretprobe::new()
            .handler("trace_return")
            .function(&fnname_openat)
            .attach(&mut module)?;
        if OPENAT2_CHECK.eq("YES") {
            Kprobe::new()
                .handler("syscall__trace_entry_openat2")
                .function(&fnname_openat2)
                .attach(&mut module)?;
            Kretprobe::new()
                .handler("trace_return")
                .function(&fnname_openat2)
                .attach(&mut module)?;
        }
        let table = module.table("events").unwrap();

        let mut perf_map = PerfMapBuilder::new(table, callback).build().unwrap();

        let mut completed_guard = block_on(completed_probes.lock());
        *completed_guard += 1;
        drop(completed_guard);

        loop {
            perf_map.poll(103);
        }
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct Event {
    pub id: u64,
    pub ts: u64,
    pub uid: u32,
    pub ret: libc::c_int,
    pub comm: [u8; 16],
    pub fname: [u8; 255],
}

fn callback() -> Box<dyn FnMut(&[u8]) + Send> {
    Box::new(|x| {
        let data: Event = read_struct(x);
        unsafe {
            let tx = SENDER.as_ref().unwrap().clone();
            tx.send(EventEnum::Open(data)).unwrap();
        }
    })
}
