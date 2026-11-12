# Secrets split and encryption

Good for any project that keeps API keys. Keys live in `.env`, never in `config.json`, so the config file is safe to commit and share as an example.

How it works:

- A secret is read from a real environment variable first, then from `.env`, then from an old config key with a warning to move it.
- Values written by the app are stored as `fernet:v1:...`, encrypted with a key made from the machine ID and the user name.
- A plain value in `.env` still works, so editing the file by hand is fine.
- The app's own key is generated on first start and saved, so it stays the same across restarts.
- `.env` is always written with mode 600.

This is not protection from root or from programs running as the same user. It makes a copied `.env` useless on another machine and stops an accidental leak.

## Files

- `secret_crypto.py`: the encryption.
- `secret_store.py`: loading, looking up and saving.

## How I use it

`load_dotenv(project_root / ".env")` at start, then `get_secret("MODEL_API_KEY", config, "api_key")`, and `persist_env_value(path, name, value)` from the settings page. Needs cryptography.
