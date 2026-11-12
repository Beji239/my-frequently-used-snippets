# Dashboard one-time link

Good for opening a local web dashboard safely. The app makes a link that works once and only for two minutes, signed with HMAC SHA-256 and the app's key. The server answers that link with a small page that saves a 30 day session token in the browser's storage and sends the browser on to the dashboard. After that the page sends the token in its own header.

Why I like it:

- The key never sits in the page, the address bar or the browser history.
- The link goes into a private file in `XDG_RUNTIME_DIR`, so it never shows in `ps` to other accounts.
- It uses page storage instead of a cookie, because a browser sends a 127.0.0.1 cookie to every port on that address.

## Files

- `dashboard_session.py`

## How I use it

1. `open_link_token(key)` makes the link token, and `write_opener(url)` writes the private file to start the browser on.
2. The server's `/open?t=` route calls `redeem_link(key, token)`, then returns `handoff_page(new_session(key), nonce)`.
3. Every API route checks `session_valid(key, request.headers.get(HEADER))`.

Standard library only.
