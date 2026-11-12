# Untrusted data fence

Good for any tool that hands text from the outside world to a language model. Process names, log lines, hostnames and packet contents can all be chosen by an attacker, and without a boundary a process name can read like an instruction.

What it does:

- Strips control codes, ANSI escapes, bidirectional overrides and zero-width characters.
- Removes anything that looks like the fence marker, including look-alike brackets, so text cannot close the fence early.
- Caps each string at 8,000 characters and a whole result at 120,000, and says plainly when a result was cut.
- Wraps the result between `<<<UNTRUSTED_SENSOR_DATA>>>` markers.

It does not filter keywords on purpose. The system prompt states once that everything inside the fence is data. It is one layer; actions that change anything should still need a person's approval.

## Files

- `sanitize.py`

## How I use it

`fence(json.dumps(scrub(result)))` on every tool result before it goes back to the model. Standard library only.
