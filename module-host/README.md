# Module host

Good for keeping an app light while still offering optional features. Each add-on runs as its own child process only while it is switched on, so a switched-off module uses no memory at all.

How it works:

- The host starts the module with a clean environment and a fresh random token.
- The module serves its routes on a private Unix socket, and the host calls them with that token.
- The host keeps the module's stdin open. When the app exits, even if it is killed, the pipe closes and the module stops by itself.
- Stopping closes stdin first, then terminates, then kills if it has to.

## Files

- `module_host.py`: the app side.
- `modules/example/service.py`: a small module to copy from.

## How I use it

```python
import module_host
module_host.start("example")
module_host.call("example", "GET", "/status")
module_host.stop("example")
```

Standard library only.
