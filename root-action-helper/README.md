# Root action helper

Good for an app that runs as a normal user but sometimes has to do something as root, like blocking an address or ending a process, after a person approved it. Only this small helper ever runs as root, and it accepts nothing but a fixed list of actions.

How it works:

- The first approved action starts the helper through `pkexec`, which asks for the password once.
- The helper then stays up and reads one JSON request per line from a pipe only the app holds. No socket file, so no other process can reach it.
- The session closes after 12 hours by default, and the next action asks for the password again.
- It runs with `python3 -I` and imports nothing from the app, so no file the user can write ever runs as root.
- It refuses to run if its own file or any folder above it can be written by someone other than root.
- Every action is read back after it runs, and every request goes to a root-only log.

The four actions here:

- `block_ip` and `unblock_ip`: one address at a time, in its own nftables table and set. It refuses this host, its gateway and its DNS server.
- `list_blocks`
- `kill`: the request names the pid, the process name and its start time, so a reused pid is refused. It never signals important system processes, and it uses a pidfd so the signal reaches the right process.

## Files

- `action_helper.py`: the root side.
- `action_broker.py`: the app side.
- `org.agentalsec.action-helper.policy`: the polkit policy that lets pkexec run the helper.

## How I use it

Install `action_helper.py` as `/usr/local/lib/agentalsec/action_helper.py`, owned by root and mode 755, and the policy into `/usr/share/polkit-1/actions/`. The running app sets `action_broker.LIVE = True`, then calls `action_broker.call("block_ip", "203.0.113.5")`. `action_helper.py --verbs` prints the list without root. Needs nftables.
