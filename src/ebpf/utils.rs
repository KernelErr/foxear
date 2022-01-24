use std::ptr;

pub fn read_struct<T>(x: &[u8]) -> T {
    unsafe { ptr::read_unaligned(x.as_ptr() as *const T) }
}

pub fn read_u8_string(x: &[u8]) -> String {
    match x.iter().position(|&r| r == 0) {
        Some(zero_pos) => String::from_utf8_lossy(&x[0..zero_pos]).to_string(),
        None => String::from_utf8_lossy(x).to_string(),
    }
}
