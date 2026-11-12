#!/usr/bin/python3 -I

import ipaddress
import json
import os
import select
import signal
import stat
import subprocess
import sys
import time

SCHEMA = 1

LOG_DIR = "/var/log/agentalsec"
LOG_PATH = LOG_DIR + "/action_helper.log"
NFT_TABLE = "agentalsec_helper"
MAX_BLOCKS = 512
MAX_REQUEST_BYTES = 64 * 1024
DEFAULT_MAX_AGE_HOURS = 12.0

VERBS = {
    "block_ip": ["ip"],
    "unblock_ip": ["ip"],
    "list_blocks": [],
    "kill": ["pid", "comm", "start_ticks"],
}


CRITICAL_PROCESSES = {
    "init", "systemd", "kthreadd",
    "xorg", "x", "gnome-shell", "gnome-session-binary", "gdm", "gdm3",
    "plasmashell", "kwin_x11", "kwin_wayland", "sddm", "lightdm",
    "cinnamon", "cinnamon-session", "cinnamon-session-binary", "muffin",
    "systemd-journald", "systemd-journal", "rsyslogd", "syslog-ng", "syslogd",
    "auditd", "systemd-logind", "polkitd", "dbus-daemon", "dbus-broker",
    "systemd-udevd", "udisksd", "upowerd", "accounts-daemon",
    "systemd-resolved", "systemd-timesyncd", "chronyd", "ntpd",
    "login", "systemd-oomd", "irqbalance", "thermald",
    "networkmanager", "systemd-networkd", "wpa_supplicant", "dhclient",
    "cron", "crond", "atd", "dockerd", "containerd", "kubelet",
    "cupsd", "snapd", "fail2ban-server", "pkexec", "sudo",
}


AGENTALSEC_PATHS = ("/usr/local/lib/agentalsec", "/var/lib/agental_sec")


class Refusal(Exception):
    pass


def self_problems() -> list:
    path = os.path.realpath(__file__)
    problems = []
    while True:
        try:
            st = os.stat(path)
        except OSError as e:
            problems.append(f"{path}: cannot be stat'ed ({e})")
            break
        if st.st_uid != 0:
            problems.append(f"{path} is owned by uid {st.st_uid}, not root")
        if st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            problems.append(f"{path} is group- or world-writable")
        parent = os.path.dirname(path)
        if parent == path:
            break
        path = parent
    return problems


def preflight():
    problems = self_problems()
    if problems:
        raise Refusal(
            "This helper refused to run because the path it is installed at "
            "could be replaced by a non-root account: " + "; ".join(problems)
            + ". Nothing ran.")
    if os.geteuid() != 0:
        raise Refusal(
            f"This helper is running as uid {os.geteuid()}, not root, so it "
            f"cannot do anything the app could not. pkexec did not elevate.")


def log(entry: dict):
    try:
        os.makedirs(LOG_DIR, mode=0o700, exist_ok=True)
        fd = os.open(LOG_PATH, os.O_WRONLY | os.O_APPEND | os.O_CREAT
                     | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "a") as fh:
            fh.write(json.dumps(entry, default=str) + "\n")
        return None
    except OSError as e:
        return f"{type(e).__name__}: {e}"


def _run(argv, timeout=30):
    try:
        res = subprocess.run(argv, capture_output=True, text=True,
                             timeout=timeout, env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
                                                   "LC_ALL": "C"})
    except subprocess.TimeoutExpired:
        return 124, "", f"{argv[0]} did not finish within {timeout}s"
    except OSError as e:
        return 127, "", f"{type(e).__name__}: {e}"
    return res.returncode, res.stdout, res.stderr.strip()


def _host_addresses() -> set:
    found = set()
    rc, out, _ = _run(["ip", "-j", "addr"])
    if rc == 0:
        try:
            for iface in json.loads(out):
                for a in iface.get("addr_info", []):
                    if a.get("local"):
                        found.add(a["local"].split("%")[0])
        except ValueError:
            pass
    for fam in ("-4", "-6"):
        rc, out, _ = _run(["ip", "-j", fam, "route", "show", "default"])
        if rc == 0:
            try:
                for r in json.loads(out):
                    if r.get("gateway"):
                        found.add(r["gateway"].split("%")[0])
            except ValueError:
                pass
    for conf in ("/etc/resolv.conf", "/run/systemd/resolve/resolv.conf"):
        try:
            with open(conf, encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    parts = line.split()
                    if len(parts) >= 2 and parts[0] == "nameserver":
                        found.add(parts[1].split("%")[0])
        except OSError:
            pass
    return found


def _validated_ip(value: str):
    if not isinstance(value, str) or "/" in value or len(value) > 64:
        raise Refusal(f"{value!r} is not one address. This helper blocks a "
                      f"single host, never a range.")
    try:
        ip = ipaddress.ip_address(value.strip())
    except ValueError:
        raise Refusal(f"{value!r} is not an IP address.")
    if (ip.is_loopback or ip.is_unspecified or ip.is_multicast
            or ip.is_link_local or ip.is_reserved
            or str(ip) == "255.255.255.255"):
        raise Refusal(f"{ip} is a loopback, unspecified, multicast, link-local "
                      f"or reserved address. Blocking it would break this "
                      f"host's own networking rather than stop a peer.")
    return ip


def _set_name(ip) -> str:
    return "blocked4" if ip.version == 4 else "blocked6"


NFT_SKELETON = f"""
table inet {NFT_TABLE} {{
    set blocked4 {{ type ipv4_addr; }}
    set blocked6 {{ type ipv6_addr; }}
    chain input {{
        type filter hook input priority -5; policy accept;
        ip saddr @blocked4 drop
        ip6 saddr @blocked6 drop
    }}
    chain output {{
        type filter hook output priority -5; policy accept;
        ip daddr @blocked4 drop
        ip6 daddr @blocked6 drop
    }}
    chain forward {{
        type filter hook forward priority -5; policy accept;
        ip saddr @blocked4 drop
        ip daddr @blocked4 drop
        ip6 saddr @blocked6 drop
        ip6 daddr @blocked6 drop
    }}
}}
"""


def _nft_ensure():
    rc, _, _ = _run(["nft", "list", "table", "inet", NFT_TABLE])
    if rc == 0:
        return
    try:
        res = subprocess.run(["nft", "-f", "-"], input=NFT_SKELETON, text=True,
                             capture_output=True, timeout=30,
                             env={"PATH": "/usr/sbin:/usr/bin", "LC_ALL": "C"})
    except (OSError, subprocess.SubprocessError) as e:
        raise Refusal(f"nft could not be run: {type(e).__name__}: {e}")
    if res.returncode != 0:
        raise Refusal(f"nft refused to create the {NFT_TABLE} table: "
                      f"{res.stderr.strip()[:300]}")


def _nft_elements(set_name: str) -> list:
    rc, out, err = _run(["nft", "-j", "list", "set", "inet", NFT_TABLE,
                         set_name])
    if rc != 0:
        raise Refusal(f"nft could not read the {set_name} set: {err[:300]}")
    found = []
    try:
        for item in json.loads(out).get("nftables", []):
            for elem in (item.get("set") or {}).get("elem", []) or []:
                found.append(elem if isinstance(elem, str) else str(elem))
    except (ValueError, AttributeError):
        raise Refusal("nft returned a listing this helper could not parse.")
    return found


def verb_block_ip(ip_text):
    ip = _validated_ip(ip_text)
    if str(ip) in _host_addresses():
        raise Refusal(f"{ip} is this host, its default gateway or its DNS "
                      f"resolver. Blocking it would cut this machine off "
                      f"rather than stop a peer. Nothing was changed.")
    _nft_ensure()
    name = _set_name(ip)
    before = _nft_elements(name)
    if str(ip) in before:
        return {"blocked": str(ip), "already": True, "set": name}
    if len(_nft_elements("blocked4")) + len(_nft_elements("blocked6")) >= MAX_BLOCKS:
        raise Refusal(f"This helper already holds {MAX_BLOCKS} blocks, its "
                      f"cap. Lift some before adding more.")
    rc, _, err = _run(["nft", "add", "element", "inet", NFT_TABLE, name,
                       "{", str(ip), "}"])
    if rc != 0:
        raise Refusal(f"nft refused to add {ip}: {err[:300]}")
    if str(ip) not in _nft_elements(name):
        raise Refusal(f"nft reported success but {ip} is not in the set when "
                      f"read back. Treat it as NOT blocked.")
    return {"blocked": str(ip), "already": False, "set": name,
            "verified_by": "read back from the nft set"}


def verb_unblock_ip(ip_text):
    ip = _validated_ip(ip_text)
    name = _set_name(ip)
    rc, _, _ = _run(["nft", "list", "table", "inet", NFT_TABLE])
    if rc != 0 or str(ip) not in _nft_elements(name):
        return {"unblocked": str(ip), "was_blocked": False,
                "note": "this helper held no block on that address"}
    rc, _, err = _run(["nft", "delete", "element", "inet", NFT_TABLE, name,
                       "{", str(ip), "}"])
    if rc != 0:
        raise Refusal(f"nft refused to remove {ip}: {err[:300]}")
    if str(ip) in _nft_elements(name):
        raise Refusal(f"{ip} is still in the set after the delete. It is "
                      f"STILL BLOCKED.")
    return {"unblocked": str(ip), "was_blocked": True,
            "verified_by": "read back from the nft set"}


def verb_list_blocks():
    rc, _, _ = _run(["nft", "list", "table", "inet", NFT_TABLE])
    if rc != 0:
        return {"table": False, "blocked": []}
    return {"table": True,
            "blocked": _nft_elements("blocked4") + _nft_elements("blocked6")}


def _stat_fields(pid: int):
    try:
        with open(f"/proc/{pid}/stat", "rb") as fh:
            data = fh.read(4096).decode("utf-8", errors="replace")
    except OSError:
        return None
    head, _, rest = data.rpartition(")")
    comm = head.split("(", 1)[-1]
    fields = rest.split()
    try:
        return comm, int(fields[6]), int(fields[19])
    except (IndexError, ValueError):
        return None


def _cmdline(pid: int) -> list:
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as fh:
            return [a.decode("utf-8", errors="replace")
                    for a in fh.read(65536).split(b"\0") if a]
    except OSError:
        return []


PF_KTHREAD = 0x00200000


def _protected_reason(pid: int, comm: str, flags: int) -> str:
    if pid <= 1:
        return f"pid {pid} is init or not a process"
    if pid in (os.getpid(), os.getppid()):
        return f"pid {pid} is this helper or the app that started it"
    if flags & PF_KTHREAD:
        return f"pid {pid} ({comm}) is a kernel thread"
    try:
        exe = os.readlink(f"/proc/{pid}/exe")
    except OSError:
        exe = ""
    exe_base = os.path.basename(exe.split(" (deleted)")[0]).lower()
    for label, value in (("comm", comm.lower()), ("exe", exe_base)):
        if value in CRITICAL_PROCESSES:
            return (f"pid {pid} is {value} (from its {label}), which this "
                    f"helper never signals: it would take the desktop, the "
                    f"logs, the network or a security control with it. If it "
                    f"is a service, stop_unit is the door")
    args = [exe] + _cmdline(pid)
    if any(a.startswith(p) for a in args for p in AGENTALSEC_PATHS):
        return (f"pid {pid} is part of AgentalSec ({exe or comm}). This "
                f"helper does not end its own camera or sensors")
    return ""


def _pinned(pid_text, comm_expected, ticks_text):
    try:
        pid = int(pid_text)
        ticks = int(ticks_text)
    except (TypeError, ValueError):
        raise Refusal("pid and start_ticks must be integers.")
    if pid <= 1:
        raise Refusal(f"pid {pid} is init or not a process. Never signalled.")
    if pid in (os.getpid(), os.getppid()):
        raise Refusal(f"pid {pid} is this helper or the app that started it.")
    fields = _stat_fields(pid)
    if fields is None:
        return None, ticks, comm_expected
    comm, flags, start = fields
    if start != ticks or comm != comm_expected:
        raise Refusal(
            f"pid {pid} is now {comm!r} started at tick {start}, and the "
            f"approval named {comm_expected!r} at tick {ticks}. The pid was "
            f"reused or the wrong process was named. Nothing was signalled.")
    why = _protected_reason(pid, comm, flags)
    if why:
        raise Refusal(why + ". Nothing was signalled.")
    return pid, ticks, comm


def verb_kill(pid_text, comm_expected, ticks_text):
    pid, ticks, comm = _pinned(pid_text, comm_expected, ticks_text)
    if pid is None:
        return {"pid": int(pid_text), "gone": True, "note": "the process had "
                "already exited, so nothing was signalled"}
    try:
        exe = os.readlink(f"/proc/{pid}/exe")
    except OSError:
        exe = ""

    try:
        pidfd = os.pidfd_open(pid)
    except ProcessLookupError:
        return {"pid": pid, "gone": True,
                "note": "exited before it could be signalled"}
    try:
        again = _stat_fields(pid)
        if again is None or again[2] != ticks:
            raise Refusal(f"pid {pid} changed while it was being checked. "
                          f"Nothing was signalled.")
        signal.pidfd_send_signal(pidfd, signal.SIGTERM)
        poller = select.poll()
        poller.register(pidfd, select.POLLIN)
        sent = ["SIGTERM"]
        if not poller.poll(5000):
            signal.pidfd_send_signal(pidfd, signal.SIGKILL)
            sent.append("SIGKILL")
            poller.poll(3000)
        gone = bool(poller.poll(0))
    finally:
        os.close(pidfd)
    return {"pid": pid, "comm": comm, "exe": exe, "signals": sent,
            "gone": gone,
            "note": ("confirmed exited through its pidfd" if gone else
                     "STILL RUNNING after SIGKILL: likely stuck in the kernel "
                     "or already a zombie waiting on its parent")}


HANDLERS = {
    "block_ip": verb_block_ip,
    "unblock_ip": verb_unblock_ip,
    "list_blocks": verb_list_blocks,
    "kill": verb_kill,
}


def handle(verb, args) -> dict:
    started = time.time()
    entry = {"at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
             "verb": verb, "args": args,
             "caller_uid": os.environ.get("PKEXEC_UID"),
             "caller_pid": os.getppid()}
    if verb not in VERBS:
        reply = {"ok": False, "refused": f"No verb named {verb!r}. The table "
                 f"is fixed: {sorted(VERBS)}."}
    elif not isinstance(args, list) or len(args) != len(VERBS[verb]) \
            or not all(isinstance(a, str) for a in args):
        reply = {"ok": False, "refused": f"{verb} takes exactly "
                 f"{len(VERBS[verb])} text argument(s): {VERBS[verb]}."}
    else:
        try:
            reply = {"ok": True, "result": HANDLERS[verb](*args)}
        except Refusal as e:
            reply = {"ok": False, "refused": str(e)}
        except Exception as e:
            reply = {"ok": False, "refused": f"{verb} failed: "
                     f"{type(e).__name__}: {e}. Treat it as not done."}
    reply.update({"schema": SCHEMA, "verb": verb,
                  "seconds": round(time.time() - started, 2)})
    entry.update({"ok": reply["ok"], "refused": reply.get("refused"),
                  "result": reply.get("result")})
    problem = log(entry)
    if problem:
        reply["log_problem"] = problem
    return reply


def serve(max_age_hours: float):
    deadline = (time.monotonic() + max_age_hours * 3600
                if max_age_hours > 0 else None)
    log({"at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
         "verb": "session_start", "caller_uid": os.environ.get("PKEXEC_UID"),
         "caller_pid": os.getppid(), "max_age_hours": max_age_hours})
    print(json.dumps({"ready": True, "schema": SCHEMA, "verbs": sorted(VERBS),
                      "max_age_hours": max_age_hours}), flush=True)
    stdin = sys.stdin.buffer
    while True:
        line = stdin.readline(MAX_REQUEST_BYTES + 1)
        if not line:
            break
        if deadline is not None and time.monotonic() > deadline:
            print(json.dumps({"ok": False, "expired": True, "refused":
                              f"This root session reached its "
                              f"{max_age_hours:g} hour cap and closed. The "
                              f"next action asks for the password again. "
                              f"Nothing ran."}), flush=True)
            break
        if len(line) > MAX_REQUEST_BYTES:
            print(json.dumps({"ok": False, "refused": "request too large"}),
                  flush=True)
            break
        try:
            req = json.loads(line)
            reply = handle(req.get("verb"), req.get("args"))
            reply["id"] = req.get("id")
        except (ValueError, AttributeError):
            reply = {"ok": False, "refused": "the request was not a JSON "
                     "object with verb and args"}
        print(json.dumps(reply, default=str), flush=True)
    log({"at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
         "verb": "session_end", "caller_pid": os.getppid()})


def main(argv):
    args = argv[1:]
    if not args or args[0] in ("-h", "--help"):
        sys.stderr.write("AgentalSec action helper. Verbs:\n"
                         + "".join(f"    {v} {' '.join('<'+a+'>' for a in VERBS[v])}\n"
                                   for v in sorted(VERBS))
                         + "\n    serve [--max-age-hours N]\n")
        return 2
    if args[0] == "--verbs":
        print(json.dumps({"ok": True, "schema": SCHEMA, "verbs": VERBS}))
        return 0
    try:
        preflight()
    except Refusal as e:
        print(json.dumps({"ok": False, "schema": SCHEMA, "refused": str(e)}))
        return 1
    if args[0] == "serve":
        hours = DEFAULT_MAX_AGE_HOURS
        if len(args) == 3 and args[1] == "--max-age-hours":
            try:
                hours = max(0.0, float(args[2]))
            except ValueError:
                pass
        elif len(args) != 1:
            print(json.dumps({"ok": False, "refused": "serve takes only "
                              "--max-age-hours N"}))
            return 1
        serve(hours)
        return 0
    reply = handle(args[0], args[1:])
    print(json.dumps(reply, indent=2, default=str))
    return 0 if reply["ok"] else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
