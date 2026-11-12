# Own activity check

Good for a security tool whose own tests plant fake suspicious programs. It answers whether a process was started by my own test run, so those alerts can be held back without hiding real ones.

It decides from the kernel's process tree, never from a name or a path, because whoever starts a process chooses both. A process counts when one of its ancestors, under the same account, is Python running the project's `scripts/run_tests.py` or one of its `tests/test_*.py` files.

## Files

- `own_activity.py`

## How I use it

Put it one folder below the project root, or change `ROOT`. `test_run(pid)` returns a short reason when the process came from a test run, and `None` when it did not. Reads only `/proc`.
