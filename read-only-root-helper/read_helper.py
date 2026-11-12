#!/usr/bin/env python3

import hashlib
import json
import os
import stat
import sys
import time

SCHEMA = 1

VERBS = {
    "sudoers": {
        "paths": ["/etc/sudoers"],
        "why": "sudoers is root-only (mode 440), so an unprivileged sensor "
               "sees its mode, owner, size and mtime but never a content edit.",
    },
    "root_ssh": {
        "paths": ["/root/.ssh/authorized_keys"],
        "why": "root's authorized_keys grants standing root access, and /root "
               "is mode 700 so an unprivileged sensor cannot list it.",
    },
    "proc_exe": {
        "paths": ["/proc"],
        "why": "/proc/<pid>/exe of another account's process is refused to an "
               "unprivileged sensor. Every process is listed with its start "
               "time, so a reused pid can be told apart.",
    },
}

MAX_BYTES = 4 * 1024 * 1024
MAX_KEYS = 500
MAX_PIDS = 65536


class Refusal(Exception):
    pass


def _refuse(msg: str):
    json.dump({"ok": False, "schema": SCHEMA, "refused": msg,
               "at": time.strftime("%Y-%m-%dT%H:%M:%S%z")}, sys.stdout)
    sys.stdout.write("\n")
    sys.exit(1)


def _ok(payload: dict):
    payload["ok"] = True
    payload["schema"] = SCHEMA
    payload["at"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    json.dump(payload, sys.stdout, indent=2)
    sys.stdout.write("\n")
    sys.exit(0)


def assert_self_is_safe():
    path = os.path.realpath(__file__)
    problems = []
    while True:
        try:
            st = os.stat(path)
        except OSError as e:
            problems.append(f"{path}: cannot be stat'ed ({e})")
            break
        if st.st_uid != 0:
            problems.append(
                f"{path} is owned by uid {st.st_uid}, not root. A sudoers "
                f"rule naming this path would grant root to whatever that "
                f"account chooses to put there.")
        if st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            problems.append(
                f"{path} is group- or world-writable (mode "
                f"{format(stat.S_IMODE(st.st_mode), '03o')}). Anybody who "
                f"can write it can run code as root through this verb table.")
        if path == "/":
            break
        parent = os.path.dirname(path)
        if parent == path:
            break
        path = parent
    if problems:
        _refuse(
            "This helper refused to run because the path it is installed at "
            "could be replaced by a non-root account, which would turn the "
            "sudoers rule that names it into arbitrary root execution: "
            + " ".join(problems)
            + " Install it under a root-owned folder such as "
              "/usr/local/lib/agentalsec/. Nothing was read.")


def assert_elevated():
    if not hasattr(os, "geteuid"):
        _refuse("This platform reports no effective uid, so this helper "
                "cannot tell whether it has the privilege it needs.")
    if os.geteuid() != 0:
        _refuse(
            "This helper is running as uid %d, not root, so it can read no "
            "more than the sensor already could. That is not an error in the "
            "sensor: it means `sudo -n` did not elevate, which happens when "
            "the sudoers drop-in has not been installed, or when a password "
            "would be required and there is nobody to type it."
            % os.geteuid())


def _read(path, limit=MAX_BYTES):
    try:
        with open(path, "rb") as fh:
            data = fh.read(limit + 1)
    except FileNotFoundError:
        return None, "gone"
    except PermissionError:
        return None, "permission denied"
    except OSError as e:
        return None, f"{type(e).__name__}: {e}"
    if len(data) > limit:
        return None, f"larger than {limit} bytes, not read"
    return data, None


def _meta(path) -> dict:
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return {"exists": False}
    except PermissionError:
        return {"exists": None, "reason": "permission denied"}
    except OSError as e:
        return {"exists": None, "reason": f"{type(e).__name__}: {e}"}
    return {"exists": True,
            "mode": format(stat.S_IMODE(st.st_mode), "03o"),
            "uid": st.st_uid, "gid": st.st_gid, "size": st.st_size,
            "mtime_ns": st.st_mtime_ns, "ctime_ns": st.st_ctime_ns,
            "ino": st.st_ino,
            "type": ("dir" if stat.S_ISDIR(st.st_mode) else
                     "link" if stat.S_ISLNK(st.st_mode) else
                     "file" if stat.S_ISREG(st.st_mode) else "other")}


def verb_sudoers():
    path = "/etc/sudoers"
    meta = _meta(path)
    data, reason = _read(path)
    return {"verb": "sudoers",
            "note": VERBS["sudoers"]["why"],
            "entries": {path: {"meta": meta,
                               "readable": data is not None,
                               "unreadable_reason": reason,
                               "sha256": (_sha(data) if data is not None
                                          else None)},
                        "content": (data.decode("utf-8", errors="replace")
                                    if data is not None else None)}}


def verb_root_ssh():
    path = "/root/.ssh/authorized_keys"
    meta = _meta(path)
    data, reason = _read(path)
    out = {"verb": "root_ssh", "note": VERBS["root_ssh"]["why"],
           "path": path, "meta": meta, "readable": data is not None,
           "unreadable_reason": reason,
           "sha256": _sha(data) if data is not None else None,
           "keys": {}}
    if data is None:
        return out
    for line in data.decode("utf-8", errors="replace").splitlines():
        text = line.strip()
        if not text or text.startswith("#"):
            continue
        if len(out["keys"]) >= MAX_KEYS:
            out["keys_capped"] = True
            break
        parts = text.split()
        out["keys"][_sha(text.encode())] = {
            "type": parts[0] if parts else "",
            "comment": " ".join(parts[2:])[:80] if len(parts) > 2 else "",
        }
    return out


def _start_ticks(pid: str):
    data, _ = _read(f"/proc/{pid}/stat", 4096)
    if data is None:
        return None
    rest = data.decode("utf-8", errors="replace").rsplit(")", 1)[-1].split()
    try:
        return int(rest[19])
    except (IndexError, ValueError):
        return None


def verb_proc_exe():
    out = {"verb": "proc_exe", "note": VERBS["proc_exe"]["why"],
           "processes": {}, "no_exe": 0, "capped": False}
    try:
        names = [n for n in os.listdir("/proc") if n.isdigit()]
    except OSError as e:
        raise Refusal(f"/proc could not be listed: {type(e).__name__}: {e}")
    for pid in sorted(names, key=int):
        if len(out["processes"]) >= MAX_PIDS:
            out["capped"] = True
            break
        entry = {"exe": None, "start_ticks": _start_ticks(pid), "reason": None}
        try:
            entry["exe"] = os.readlink(f"/proc/{pid}/exe")
        except FileNotFoundError:
            entry["reason"] = "no executable (kernel thread, or exited)"
            out["no_exe"] += 1
        except OSError as e:
            entry["reason"] = f"{type(e).__name__}: {e}"
            out["no_exe"] += 1
        out["processes"][pid] = entry
    out["total"] = len(out["processes"])
    return out


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()[:16]


HANDLERS = {
    "sudoers": verb_sudoers,
    "root_ssh": verb_root_ssh,
    "proc_exe": verb_proc_exe,
}


def main(argv):
    args = [a for a in argv[1:] if a]

    if not args or args[0] in ("-h", "--help"):
        sys.stderr.write(
            "AgentalSec read-only helper. Verbs, and nothing else:\n"
            + "".join(f"    {v}\n" for v in sorted(VERBS))
            + "\nUsage: read_helper.py <verb>\n"
              "       read_helper.py --verbs      # print the table, read nothing\n"
              "\nThere is no verb that takes a path. A helper that did would "
              "be sudo cat, which is not an allowlist.\n")
        return 2

    if len(args) > 1:
        _refuse(
            f"This helper takes exactly one argument and {len(args)} were "
            f"supplied. NO VERB TAKES A PARAMETER: every verb names one fixed "
            f"file or directory chosen in this source, so an argument here "
            f"would be a value chosen by the caller, which is the thing this "
            f"design exists to prevent. A sudoers rule ending in '*' would "
            f"allow exactly this call. NOTHING WAS READ.")

    if args[0] == "--verbs":
        print(json.dumps({"ok": True, "schema": SCHEMA,
                          "at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                          "verbs": {v: {"paths": d["paths"], "why": d["why"]}
                                    for v, d in sorted(VERBS.items())},
                          "refuses": {
                              "/etc/shadow": (
                                  "NOT IN THE VERB TABLE AND MUST NOT BE ADDED. "
                                  "It holds password hashes and has no business "
                                  "in any database."),
                              "/etc/gshadow": "same rule as /etc/shadow",
                              "<any caller-supplied path>": (
                                  "there is no verb that takes a path"),
                          }},
                         indent=2))
        return 0

    verb = args[0]
    if verb not in VERBS:
        _refuse(
            f"No verb named {verb!r}. The table is fixed and this is not in "
            f"it: {sorted(VERBS)}. An unrecognised verb is refused rather than "
            f"guessed at, because a helper that accepts a near-miss is a helper "
            f"somebody will talk into reading something else. Nothing was read.")

    assert_self_is_safe()
    assert_elevated()

    try:
        payload = HANDLERS[verb]()
    except Refusal as e:
        _refuse(str(e))
    except Exception as e:
        _refuse(f"The verb {verb!r} failed: {type(e).__name__}: {e}. Nothing "
                f"here says the file is fine; it says this helper could not "
                f"read it.")
    _ok(payload)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
