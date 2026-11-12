# Local web guards

Good for any Flask app that should only be reached from this machine. Binding to 127.0.0.1 keeps other machines out but not a web page you have open: with DNS rebinding, a site can point its own name at 127.0.0.1 and read your server's answers. These guards close that and a few other gaps.

What it adds:

- Refuses any Host header except the names the server really answers to.
- Caps the request body at 1 MB while it is being read.
- Refuses a JSON body that is not an object, in one place, before any route runs.
- A strict Content Security Policy with a fresh nonce per page and no inline script.
- Isolation headers and a Permissions-Policy that turns off camera, microphone, location and USB.
- `no-store` and `nosniff` on every API answer.

## Files

- `guards.py`

## How I use it

Call `add_guards(app, allowed_hosts("127.0.0.1"))` after creating the app, and serve pages through `page_response(path)` so they get the nonce. Needs Flask.
