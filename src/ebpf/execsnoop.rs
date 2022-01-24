use super::types::EventEnum;
use super::utils::*;
use super::AbtractProbe;
use anyhow::Result;
use bcc::perf_event::PerfMapBuilder;
use bcc::{Kprobe, Kretprobe, BPF};
use lockfree::channel::mpsc::Sender;
use std::sync::Once;

static mut SENDER: Option<Sender<EventEnum>> = None;
static LOAD_INIT: Once = Once::new();
const EXEC_FUNC: &str = env!("EXEC_FUNC");

pub struct Probe {}

impl AbtractProbe for Probe {
    fn load(sender: Sender<EventEnum>) -> Result<()> {
        LOAD_INIT.call_once(|| unsafe {
            SENDER = Some(sender);
        });
        let code = include_str!("../../probes/execsnoop.c");
        let mut module = BPF::new(code)?;

        Kprobe::new()
            .handler("syscall__execve")
            .function(EXEC_FUNC)
            .attach(&mut module)?;
        Kretprobe::new()
            .handler("do_ret_sys_execve")
            .function(EXEC_FUNC)
            .attach(&mut module)?;

        let table = module.table("events").unwrap();

        let mut perf_map = PerfMapBuilder::new(table, callback).build().unwrap();
        loop {
            perf_map.poll(100);
        }
    }
}

#[repr(C)]
#[derive(Debug)]
#[allow(dead_code)]
pub enum EventType {
    Arg,
    Ret,
}

#[repr(C)]
#[derive(Debug)]
pub struct Event {
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub comm: [u8; 16],
    pub event_type: EventType,
    pub argv: [u8; 128],
    pub ret: libc::c_int,
}

fn callback() -> Box<dyn FnMut(&[u8]) + Send> {
    Box::new(|x| {
        let data: Event = read_struct(x);
        unsafe {
            let tx = SENDER.as_ref().unwrap().clone();
            tx.send(EventEnum::Exec(data)).unwrap();
        }
    })
}
