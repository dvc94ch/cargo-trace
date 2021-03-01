# cargo-trace
An ebpf oscilloscope for your rust programs. Unwinds the stack in ebpf when the probe is
triggered and increments the event count. After the program terminates, it generates a
flamegraph for analysis.

## One-Liners

The following one-liners demonstrate different capabilities:

```
# Find out where your program is consuming the most cpu time
cargo trace profile:hz:99
```

```
# Find out where your program is making the most memory allocations
cargo trace uprobe:/usr/lib/libc-2.33.so:malloc
```

### Almost working but not quite

```
# Find out where your program is blocking
cargo trace kprobe:finish_schedule_task
```

## bpf library
Also includes a bpf library with a specific focus on building program analysis tools for rust
programs. Most of the code is very generic so it can be easily adapted for other bpf use
cases. Supports most probe types supported by [`bpftrace`](https://github.com/iovisor/bpftrace).

## Background

### Kernel

- `bpf_sys` is used to load bpf programs and read/write to bpf maps that are used to read/write
data to/from user space.

- `perf_event_open_sys` is used to create various probe types. bpf programs can be attached with
an ioctl.

- `ptrace` allows setting breakpoints and control execution of the program under test. This is
needed to prevent the program from running before the unwind tables have been loaded and to
advance the program to the `_start` symbol (after all dynamic libraries have been loaded).

### Address map

When loading a program dynamic libraries etc. are loaded at an address. When you have an instruction
pointer, you need to be able to figure out which file the program was loaded from and what the
load address is of the program. This can be done either using `libc::dl_iterate_phdr` in the current
process or by reading `/proc/$pid/maps` for an external program.

### Unwinding

Based on the current instruction address, the binary and the load address is determined. To find
the relative instruction the load address is subtracted from the instruction address. Using this
offset the appropriate dwarf unwind table row is found in the `.ehframe` section. An unwind table
row has a start/end address it is valid for and a dwarf program for each cpu register that when
executed will yield the register value of the previous frame. It can be empirically determined that
almost all dwarf programs consist of a single instruction and use only three different instructions.
`rip+offset`, `rsp+offset` or `*cfa+offset`, where `cfa` is the `rsp` value of the current frame. The
result of the unwinding is an array of instruction pointers.

NOTE: kernel stacks use a different unwind mechanism and a backtrace can be captured using the
bpf helper `bpf_get_stack` and symbolized by looking up the symbols in `/proc/kallsyms`.

### Symbolization

Once we have an array of instruction pointers we again need the address map to find the load
address for each ip which is subtracted to get an offset and a file path of the binary. The binary
may contain debug symbols in which case we can return the function name and location. If it does
not we can look try looking up the symbol name in the symbol table. This is how the compiler
generated `main` and `_start` symbols and functions from dynamic libraries are symbolized.

NOTE: If debug symbols for stripped binaries from your distro are installed they are located by the
elf `build_id`, a random 20 byte sequence contained in every elf file. But these are unnecessary for
cargo-trace to work.

## License
MIT OR Apache-2.0
