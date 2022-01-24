use crate::ebpf;
use lockfree::channel::mpsc;

pub async fn start(pid: u32) {
    let (sender, receiver) = mpsc::create();

    let load_handler = tokio::spawn(async move {
        let res = ebpf::load(sender).await;
        if let Err(e) = res {
            println!("Failed to load eBPF: {}", e);
        }
    });

    let logger_handler = tokio::spawn(async move {
        let res = crate::storage::log::event_logger(receiver, pid).await;
        if let Err(e) = res {
            println!("Logger exited with error: {}", e);
        }
    });

    let (_, _) = (load_handler.await, logger_handler.await);
}
