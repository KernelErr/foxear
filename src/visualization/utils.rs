use std::path::Path;
use std::process::exit;

pub fn ensure_exists(path: &str) {
    if !Path::new(path).exists() {
        println!("{} does not exist", path);
        exit(1);
    }
}
