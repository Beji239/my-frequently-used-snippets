# eBPF camera

Good for seeing every program that starts and every outgoing connection on a Linux machine, straight from the kernel, with the parent process and user of each. Nothing can start or connect without passing these two tracepoints.

How it works:

- `camera.bpf.c` hooks `sched_process_exec` and `sys_enter_connect` and puts one event per call on a ring buffer. Events that do not fit are counted in a `dropped` map instead of lost silently.
- `camera.py` loads the program through libbpf with ctypes, attaches it, reads the ring buffer and prints one JSON line per event.
- The kernel half and the user half are separate, so the part that runs as root stays small.

It needs root to load, a kernel 5.8 or newer built with BTF, and libbpf.

## Files

- `camera.bpf.c`
- `camera.py`
- `build.sh`

## How I use it

Build with `./build.sh` (needs clang and bpftool), then run `sudo ./camera.py`. In a real app I write the events into SQLite instead of printing them.
