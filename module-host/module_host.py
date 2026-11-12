import hmac
import http.client
import json
import os
import re
import secrets
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

MODULES_DIR = Path(__file__).resolve().parent / "modules"
RUN_DIR = Path(os.environ.get("XDG_RUNTIME_DIR") or "/tmp")
TOKEN_HEADER = "X-Module-Token"
STOP_WAIT = 4.0
CALL_TIMEOUT = 15.0
ENV_PASS = ("PATH", "HOME", "LANG", "LC_ALL", "TZ", "SSL_CERT_FILE", "SSL_CERT_DIR")
NAME_RE = re.compile(r"^[a-z][a-z0-9_]{1,30}$")

_lock = threading.RLock()
_running = {}


def socket_path(name: str) -> Path:
    return RUN_DIR / f"module-{name}.sock"


def _child_env(name: str, token: str, secrets_to_pass=()) -> dict:
    env = {k: os.environ[k] for k in ENV_PASS if os.environ.get(k)}
    for key in secrets_to_pass:
        if os.environ.get(key):
            env[key] = os.environ[key]
    env.update({
        "MODULE_NAME": name,
        "MODULE_TOKEN": token,
        "MODULE_SOCKET": str(socket_path(name)),
    })
    return env


def start(name: str, entry: str = "service.py", secrets_to_pass=()) -> dict:
    if not NAME_RE.match(name):
        return {"ok": False, "reason": "bad module name"}
    folder = MODULES_DIR / name
    if not (folder / entry).is_file():
        return {"ok": False, "reason": f"No module called {name} is installed."}
    with _lock:
        run = _running.get(name)
        if run and run["proc"].poll() is None:
            return {"ok": True, "pid": run["proc"].pid, "already": True}
        try:
            socket_path(name).unlink()
        except OSError:
            pass
        token = secrets.token_urlsafe(32)
        log_path = folder / f"{name}.log"
        log = os.fdopen(os.open(log_path, os.O_WRONLY | os.O_APPEND | os.O_CREAT
                                | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600), "ab")
        try:
            proc = subprocess.Popen(
                [sys.executable, "-B", "-s", "-E", str(folder / entry)],
                cwd=str(folder), env=_child_env(name, token, secrets_to_pass),
                stdin=subprocess.PIPE, stdout=log, stderr=log, close_fds=True)
        except OSError as e:
            return {"ok": False, "reason": f"It could not start: {e}"}
        finally:
            log.close()
        _running[name] = {"proc": proc, "token": token, "started_at": time.time()}
        return {"ok": True, "pid": proc.pid}


def stop(name: str) -> dict:
    with _lock:
        run = _running.pop(name, None)
    if not run:
        return {"ok": True, "was_running": False}
    proc = run["proc"]
    try:
        if proc.stdin:
            proc.stdin.close()
    except OSError:
        pass
    try:
        proc.wait(STOP_WAIT)
    except subprocess.TimeoutExpired:
        proc.terminate()
        try:
            proc.wait(2)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(2)
    try:
        socket_path(name).unlink()
    except OSError:
        pass
    return {"ok": True, "was_running": True, "exit": proc.returncode}


def stop_all() -> None:
    for name in list(_running):
        stop(name)


def token_ok(name: str, token: str) -> bool:
    run = _running.get(name)
    if not run or not token or run["proc"].poll() is not None:
        return False
    return hmac.compare_digest(run["token"].encode(),
                               str(token).encode("utf-8", "surrogateescape"))


def module_for_token(token: str) -> str | None:
    for name in list(_running):
        if token_ok(name, token):
            return name
    return None


class _UnixConnection(http.client.HTTPConnection):
    def __init__(self, path: str, timeout: float):
        super().__init__("localhost", timeout=timeout)
        self._path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self._path)


def call(name: str, method: str, path: str, body: dict = None) -> tuple:
    run = _running.get(name)
    if not run or run["proc"].poll() is not None:
        return 503, {"error": "not running"}
    if not re.match(r"^/[A-Za-z0-9_/\-]*(\?[A-Za-z0-9_=&\-]*)?$", path or ""):
        return 400, {"error": "Unexpected path."}
    conn = _UnixConnection(str(socket_path(name)), CALL_TIMEOUT)
    try:
        payload = json.dumps(body or {}).encode() if method == "POST" else None
        conn.request(method, path, body=payload,
                     headers={"Content-Type": "application/json",
                              TOKEN_HEADER: run["token"]})
        resp = conn.getresponse()
        raw = resp.read(1024 * 1024)
        try:
            data = json.loads(raw or b"{}")
        except ValueError:
            data = {"error": "The module answered something that is not JSON."}
        return resp.status, data
    except (OSError, http.client.HTTPException) as e:
        if time.time() - run["started_at"] < 10:
            return 503, {"error": "starting"}
        return 502, {"error": f"The module did not answer: {e}"}
    finally:
        conn.close()
