# My frequently used snippets

I keep this repo for my own reference. These are pieces of code I come back to often, taken from AgentalSec, my security monitor for Linux, and trimmed so each one stands on its own. The code carries no comments on purpose; the README in each folder says what the snippet is good for and how I use it.

They are written for Python 3.10 or newer on Linux.

## The snippets

- [dashboard-one-time-link](dashboard-one-time-link): open a local web dashboard without putting a key in the page or the address bar.
- [local-web-guards](local-web-guards): the headers and checks I put on any Flask app that listens on 127.0.0.1.
- [untrusted-data-fence](untrusted-data-fence): clean and wrap text an attacker can write before a language model reads it.
- [redirect-safe-http](redirect-safe-http): outgoing requests that a redirect cannot turn toward the local network.
- [model-provider-adapter](model-provider-adapter): talk to OpenAI-style and Anthropic-style model APIs with one conversation format.
- [root-action-helper](root-action-helper): run a few fixed actions as root after one password, from an app that runs as a normal user.
- [read-only-root-helper](read-only-root-helper): read a few root-only files through `sudo -n` with no argument the caller controls.
- [secrets-split-and-encryption](secrets-split-and-encryption): keep keys in `.env`, out of the config file, and encrypted to this machine.
- [hash-chained-journal](hash-chained-journal): a SQLite journal where editing or deleting a row breaks the chain.
- [own-activity-check](own-activity-check): tell from the process tree whether a process came from my own test run.
- [module-host](module-host): start optional add-ons as child processes that use no memory while switched off.
- [ebpf-camera](ebpf-camera): watch every program start and every outgoing connection from the kernel.

## License

MIT, see [LICENSE](LICENSE).
