import hmac
import json
import os
import socketserver
import sys
import threading
from http.server import BaseHTTPRequestHandler

TOKEN = os.environ.get("MODULE_TOKEN", "")
SOCKET = os.environ["MODULE_SOCKET"]


class Handler(BaseHTTPRequestHandler):
    def address_string(self):
        return "local"

    def _send(self, code: int, data: dict):
        body = json.dumps(data).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _allowed(self) -> bool:
        sent = self.headers.get("X-Module-Token", "")
        return bool(TOKEN) and hmac.compare_digest(sent.encode(), TOKEN.encode())

    def do_GET(self):
        if not self._allowed():
            return self._send(403, {"error": "Forbidden"})
        if self.path == "/status":
            return self._send(200, {"ok": True, "pid": os.getpid()})
        self._send(404, {"error": "Not found"})

    def log_message(self, fmt, *args):
        pass


class UnixServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True


def main():
    try:
        os.unlink(SOCKET)
    except OSError:
        pass
    old = os.umask(0o177)
    server = UnixServer(SOCKET, Handler)
    os.umask(old)
    stopping = threading.Event()

    def watch_stdin():
        try:
            while sys.stdin.buffer.read(1024):
                pass
        except (OSError, ValueError):
            pass
        stopping.set()

    threading.Thread(target=watch_stdin, daemon=True).start()
    threading.Thread(target=server.serve_forever, daemon=True).start()
    stopping.wait()
    server.shutdown()
    server.server_close()
    try:
        os.unlink(SOCKET)
    except OSError:
        pass


if __name__ == "__main__":
    main()
