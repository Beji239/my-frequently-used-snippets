#!/usr/bin/env python3

import ctypes
import errno
import json
import os
import signal
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
OBJECT = HERE / "camera.bpf.o"

EVENT_FMT = "<IIIIQII16s16s256sIHH16s"
EVENT_SIZE = struct.calcsize(EVENT_FMT)
KIND_EXEC, KIND_CONNECT = 1, 2

TRACEPOINTS = (("sched/sched_process_exec", b"handle_exec"),
               ("syscalls/sys_enter_connect", b"handle_connect"))


def decode(raw: bytes) -> dict:
    (kind, pid, tgid, ppid, ts_ns, uid, _pad, comm, parent, filename,
     daddr, dport, family, addr6) = struct.unpack(EVENT_FMT, raw)

    def s(b):
        return b.split(b"\x00", 1)[0].decode("utf-8", "replace")

    rec = {"kind": "exec" if kind == KIND_EXEC else "connect",
           "ts_ns": ts_ns, "pid": pid, "tgid": tgid, "ppid": ppid, "uid": uid,
           "comm": s(comm), "parent": s(parent)}
    if kind == KIND_EXEC:
        rec["filename"] = s(filename)
    elif kind == KIND_CONNECT:
        if family == 2:
            rec["daddr"] = ".".join(str((daddr >> shift) & 0xFF)
                                    for shift in (0, 8, 16, 24))
        elif family == 10:
            rec["daddr"] = ":".join(f"{int.from_bytes(addr6[i:i+2], 'big'):x}"
                                    for i in range(0, 16, 2))
        rec["dport"] = dport
        rec["family"] = {2: "inet", 10: "inet6"}.get(family, str(family))
    return rec


def libbpf():
    for name in ("libbpf.so.1", "libbpf.so"):
        try:
            lib = ctypes.CDLL(name, use_errno=True)
            break
        except OSError:
            continue
    else:
        raise RuntimeError("libbpf is not installed (apt install libbpf1).")
    lib.libbpf_get_error.restype = ctypes.c_long
    lib.libbpf_get_error.argtypes = [ctypes.c_void_p]
    lib.bpf_object__open_file.restype = ctypes.c_void_p
    lib.bpf_object__open_file.argtypes = [ctypes.c_char_p, ctypes.c_void_p]
    lib.bpf_object__load.argtypes = [ctypes.c_void_p]
    lib.bpf_object__close.argtypes = [ctypes.c_void_p]
    lib.bpf_object__find_map_by_name.restype = ctypes.c_void_p
    lib.bpf_object__find_map_by_name.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
    lib.bpf_object__find_program_by_name.restype = ctypes.c_void_p
    lib.bpf_object__find_program_by_name.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
    lib.bpf_program__attach_tracepoint.restype = ctypes.c_void_p
    lib.bpf_program__attach_tracepoint.argtypes = [ctypes.c_void_p, ctypes.c_char_p,
                                                   ctypes.c_char_p]
    lib.bpf_map__fd.restype = ctypes.c_int
    lib.bpf_map__fd.argtypes = [ctypes.c_void_p]
    lib.ring_buffer__new.restype = ctypes.c_void_p
    lib.ring_buffer__new.argtypes = [ctypes.c_int, ctypes.c_void_p,
                                     ctypes.c_void_p, ctypes.c_void_p]
    lib.ring_buffer__poll.restype = ctypes.c_int
    lib.ring_buffer__poll.argtypes = [ctypes.c_void_p, ctypes.c_int]
    lib.ring_buffer__free.argtypes = [ctypes.c_void_p]
    return lib


class Camera:
    def __init__(self, on_event):
        self.lib = libbpf()
        self.on_event = on_event
        self.obj = None
        self.links = []
        self.ring = None
        self._cb = None

    def load(self, object_path: Path):
        lib = self.lib
        self.obj = lib.bpf_object__open_file(str(object_path).encode(), None)
        if not self.obj:
            raise RuntimeError(f"libbpf could not open {object_path.name}.")
        rc = lib.bpf_object__load(self.obj)
        if rc:
            raise RuntimeError(f"The kernel refused the program (libbpf error {rc}).")

    def attach(self):
        lib = self.lib
        for tp, name in TRACEPOINTS:
            prog = lib.bpf_object__find_program_by_name(self.obj, name)
            if not prog:
                raise RuntimeError(f"The object has no program named {name.decode()}.")
            category, _, event = tp.partition("/")
            link = lib.bpf_program__attach_tracepoint(prog, category.encode(),
                                                      event.encode())
            if not link:
                raise RuntimeError(f"Could not attach to tracepoint {tp}.")
            self.links.append(link)

    def open_ring(self):
        lib = self.lib
        events = lib.bpf_object__find_map_by_name(self.obj, b"events")
        if not events:
            raise RuntimeError("The object has no events map.")

        def trampoline(ctx, data, size):
            raw = ctypes.string_at(data, size)
            if len(raw) >= EVENT_SIZE:
                self.on_event(decode(raw[:EVENT_SIZE]))
            return 0

        self._cb = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_void_p,
                                    ctypes.c_void_p, ctypes.c_size_t)(trampoline)
        self.ring = lib.ring_buffer__new(lib.bpf_map__fd(events), self._cb, None, None)
        if not self.ring:
            raise RuntimeError("Could not create the ring buffer.")

    def poll(self, timeout_ms: int = 200) -> int:
        n = self.lib.ring_buffer__poll(self.ring, timeout_ms)
        if n == -errno.EINTR:
            return 0
        if n < 0:
            raise RuntimeError(f"ring_buffer__poll failed ({n}).")
        return n

    def close(self):
        if self.ring:
            self.lib.ring_buffer__free(self.ring)
            self.ring = None
        if self.obj:
            self.lib.bpf_object__close(self.obj)
            self.obj = None


def main() -> int:
    if os.geteuid() != 0:
        print("Loading a BPF program needs root.", file=sys.stderr)
        return 1
    stop = {"asked": False}

    def ask_stop(sig, frame):
        stop["asked"] = True

    signal.signal(signal.SIGINT, ask_stop)
    signal.signal(signal.SIGTERM, ask_stop)

    cam = Camera(lambda ev: print(json.dumps(ev), flush=True))
    try:
        cam.load(OBJECT)
        cam.attach()
        cam.open_ring()
        while not stop["asked"]:
            cam.poll()
    finally:
        cam.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
