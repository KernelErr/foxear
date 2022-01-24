use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

pub const LOG_DIR: &str = "/var/lib/foxear/logs";

pub fn ensure_directories() {
    fs::create_dir_all(LOG_DIR).unwrap();
}

pub fn create_log_file(path: &str, header: &str) -> fs::File {
    let exist = Path::new(path).exists();
    let mut log_file = OpenOptions::new()
        .write(true)
        .append(true)
        .create(true)
        .open(path)
        .unwrap();
    if !exist {
        log_file.write_all(header.as_bytes()).unwrap();
    }
    log_file
}

pub fn fliter_so_file(path: &str) -> bool {
    let path = Path::new(path);
    if let Some(extension) = path.extension() {
        if extension == "so" {
            return true;
        }
    }
    if let Some(file_stem) = path.file_stem() {
        if let Some(file_stem) = file_stem.to_str() {
            if file_stem.contains(".so.") || file_stem.ends_with(".so") {
                return true;
            }
        }
    }
    false
}
