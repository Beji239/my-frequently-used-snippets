import secrets
from pathlib import Path

from flask import Flask, Response, jsonify, request

LOOPBACK_NAMES = {"127.0.0.1", "localhost", "::1", "[::1]"}
MAX_BODY_BYTES = 1 * 1024 * 1024

ISOLATION_HEADERS = (
    ("Cross-Origin-Opener-Policy", "same-origin"),
    ("Cross-Origin-Embedder-Policy", "require-corp"),
    ("Cross-Origin-Resource-Policy", "same-origin"),
    ("Permissions-Policy", "camera=(), microphone=(), geolocation=(), "
                           "usb=(), serial=(), payment=(), display-capture=()"),
)


def csp(nonce: str) -> str:
    return "; ".join([
        "default-src 'self'",
        "base-uri 'none'",
        "object-src 'none'",
        "frame-ancestors 'none'",
        "form-action 'none'",
        f"script-src 'self' 'nonce-{nonce}'",
        "style-src 'self' 'unsafe-inline'",
        "font-src 'self'",
        "img-src 'self' data:",
        "connect-src 'self'",
    ])


def with_nonce(html: str, nonce: str) -> str:
    return html.replace("<script>", f'<script nonce="{nonce}">')


def allowed_hosts(bind: str, extra=()) -> set:
    hosts = set(LOOPBACK_NAMES)
    bind = bind.strip().lower()
    if bind and bind not in {"0.0.0.0", "::", ""}:
        hosts.add(bind)
    for name in extra:
        name = str(name).strip().lower().rstrip(".")
        if name:
            hosts.add(name)
    return hosts


def add_guards(app: Flask, hosts: set) -> None:
    app.config["MAX_CONTENT_LENGTH"] = MAX_BODY_BYTES

    @app.before_request
    def block_foreign_host():
        raw_host = (request.host or "").strip().lower().rstrip(".")
        if raw_host.startswith("["):
            host = raw_host.split("]")[0].lstrip("[")
        else:
            host = raw_host.split(":")[0]
        if host in hosts or raw_host.split("]")[0] + "]" in hosts:
            return None
        return jsonify({"error": "Forbidden",
                        "detail": f"Host '{host}' is not an address this "
                                  f"server answers to."}), 403

    @app.before_request
    def json_body_is_an_object():
        if request.method not in ("POST", "PUT", "PATCH") or not request.is_json:
            return None
        if not request.get_data(cache=True):
            return None
        try:
            body = request.get_json(silent=False)
        except RecursionError:
            body = None
        except Exception:
            return jsonify({"error": "Bad request",
                            "detail": "The body is not valid JSON."}), 400
        if not isinstance(body, dict):
            return jsonify({"error": "Bad request",
                            "detail": "The body must be a JSON object."}), 400
        return None

    @app.after_request
    def response_headers(resp):
        for name, value in ISOLATION_HEADERS:
            resp.headers.setdefault(name, value)
        if request.path.startswith("/api/"):
            resp.headers.setdefault("Cache-Control", "no-store")
            resp.headers.setdefault("X-Content-Type-Options", "nosniff")
            resp.headers.setdefault("Referrer-Policy", "no-referrer")
        return resp


def page_response(html_path: Path) -> Response:
    nonce = secrets.token_urlsafe(18)
    html = html_path.read_text(encoding="utf-8")
    resp = Response(with_nonce(html, nonce), mimetype="text/html")
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Content-Security-Policy"] = csp(nonce)
    return resp


if __name__ == "__main__":
    app = Flask(__name__)
    add_guards(app, allowed_hosts("127.0.0.1"))

    @app.route("/api/ping")
    def ping():
        return jsonify({"ok": True})

    app.run(host="127.0.0.1", port=5000)
