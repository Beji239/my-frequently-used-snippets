# Hash-chained journal

Good for any app whose record has to be believable afterwards. Each important write adds a journal entry whose hash covers the entry before it, so deleting, inserting or editing a row breaks the chain at that exact entry.

What it catches:

- Someone editing the database directly, a script, a wiper or a careless repair.
- A deleted row, a changed value, an inserted entry.
- A chain rebuilt from scratch, if you saved its last hash somewhere else earlier and pass it as `expected_head`.

What it cannot catch alone: someone who knows the scheme and rebuilds the whole chain. That is what the saved hash is for, so keep it off the machine.

## Files

- `journal.py`

## How I use it

`ensure(conn)` once, then `record(conn, "dismiss", "findings", row_id, payload)` in the same transaction as the write it covers. `verify_chain(db_path)` opens the database read only and returns `intact`, `broken` or `rebuilt`. Standard library only.
