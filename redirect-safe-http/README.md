# Redirect safe HTTP

Good for any app that calls outside services from inside a home network. If a feed or lookup service is compromised, or simply answers with a redirect, a normal client would follow it to the router, a local dashboard or another device on the LAN.

What it does:

- Follows redirects by hand, up to 10.
- Refuses a redirect to a local or private address, and from HTTPS to plain HTTP.
- With `same_host=True`, a request that carries a key may not be redirected to another host at all.
- Drops key headers whenever a redirect changes host.

The first address is not checked, so a local model server still works.

## Files

- `safe_http.py`

## How I use it

`safe_http.get(url, headers=..., timeout=10)` in place of `requests.get`. Needs requests.
