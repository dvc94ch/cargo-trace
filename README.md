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

## License
MIT OR Apache-2.0
