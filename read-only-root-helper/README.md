# Read-only root helper

Good when a sensor running as a normal user needs to read a few root-only things. The code that parses hostile input never runs as root; only this helper does, and it can only read what is named inside it.

How it works:

- Each verb reads one fixed thing. No verb takes an argument, so there is no "read this path" verb.
- It runs through `sudo -n` with a sudoers line that names each verb exactly, with no wildcard.
- It refuses to run unless its own file and every folder above it are owned by root and not writable by anyone else.
- It answers in JSON with an `ok` key, exit 0 for a read and 1 for a refusal.
- `/etc/shadow` and `/etc/gshadow` must never be added.

The three verbs here are `sudoers`, `root_ssh` (root's authorized keys, fingerprinted) and `proc_exe` (the running file and start time of every process).

## Files

- `read_helper.py`
- `sudoers.example`: the sudoers line, with `<user>` to fill in.

## How I use it

Install it as `/usr/local/lib/agentalsec/read_helper.py`, owned by root and mode 755, put the sudoers line in `/etc/sudoers.d/` with `visudo -f`, then call `sudo -n /usr/local/lib/agentalsec/read_helper.py proc_exe`. Standard library only.
