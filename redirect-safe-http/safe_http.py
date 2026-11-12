import ipaddress
import socket
from urllib.parse import urljoin, urlsplit

import requests


class RedirectRefused(requests.exceptions.InvalidURL):
    pass


def is_local(host: str) -> bool:
    if not host:
        return True
    try:
        addrs = {ipaddress.ip_address(host.strip("[]"))}
    except ValueError:
        try:
            addrs = {ipaddress.ip_address(info[4][0].split("%")[0])
                     for info in socket.getaddrinfo(host, None)}
        except (OSError, ValueError):
            return True
    return not addrs or any(not a.is_global for a in addrs)


MAX_REDIRECTS = 10
KEY_HEADERS = {"authorization", "proxy-authorization", "cookie", "key",
               "apikey", "api-key", "x-api-key"}


def _check(origin_url: str, target_url: str, same_host: bool):
    parts, origin = urlsplit(target_url), urlsplit(origin_url)
    if parts.scheme not in ("http", "https"):
        raise RedirectRefused(f"redirect to {parts.scheme}: refused")
    if origin.scheme == "https" and parts.scheme != "https":
        raise RedirectRefused(
            "HTTPS redirected to unencrypted HTTP; refused")
    if same_host and parts.netloc.lower() != origin.netloc.lower():
        raise RedirectRefused(
            f"{origin.hostname} redirected a request carrying a key to "
            f"{parts.hostname}; refused, the key stays with its host")
    if is_local(parts.hostname):
        raise RedirectRefused(
            f"{origin.hostname} redirected to {parts.hostname}, a local or "
            f"private address; refused")


def _send(method: str, url: str, same_host: bool, kwargs: dict):
    kwargs = dict(kwargs, allow_redirects=False)
    for _ in range(MAX_REDIRECTS + 1):
        call = requests.post if method == "POST" else requests.get
        resp = call(url, **kwargs)
        if not getattr(resp, "is_redirect", False):
            return resp
        try:
            target = urljoin(url, resp.headers.get("location", ""))
            _check(url, target, same_host)
        finally:
            resp.close()
        code = resp.status_code
        if method == "POST" and code in (301, 302, 303):
            method = "GET"
            kwargs = {k: v for k, v in kwargs.items()
                      if k not in ("data", "json", "files")}
        kwargs.pop("params", None)
        if urlsplit(target).netloc.lower() != urlsplit(url).netloc.lower():
            kwargs["headers"] = {k: v for k, v in
                                 (kwargs.get("headers") or {}).items()
                                 if k.lower() not in KEY_HEADERS}
        url = target
    raise requests.exceptions.TooManyRedirects(
        f"more than {MAX_REDIRECTS} redirects from {url}")


def get(url, same_host: bool = False, **kwargs):
    return _send("GET", url, same_host, kwargs)


def post(url, same_host: bool = False, **kwargs):
    return _send("POST", url, same_host, kwargs)
