import logging
import os
import secrets
from datetime import datetime
from pathlib import Path

import secret_crypto as crypto

logger = logging.getLogger(__name__)

_DECRYPT_FAILURES: list[tuple[str, str]] = []


def decrypt_failures() -> list[tuple[str, str]]:
    return list(_DECRYPT_FAILURES)


def load_dotenv(path: Path) -> int:
    if not path.exists():
        return 0
    loaded = 0
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as e:
        logger.warning(f"Could not read {path.name}: {e}")
        return 0

    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        if line.startswith("export "):
            line = line[7:].lstrip()
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
            value = value[1:-1]
        if not key or key in os.environ:
            continue
        if crypto.is_protected(value):
            try:
                value = crypto.unprotect(value)
            except crypto.SecretCryptoError as e:
                _DECRYPT_FAILURES.append((key, str(e)))
                logger.warning(f"{key}: {e}")
                continue
        os.environ[key] = value
        loaded += 1
    return loaded


def get_secret(name: str, config: dict, legacy_key: str = None) -> str:
    value = os.environ.get(name, "").strip()
    if value:
        return value
    if legacy_key and (config.get(legacy_key) or "").strip():
        logger.warning(f"{legacy_key} is in config.json. Move it to .env as {name}.")
        return config[legacy_key].strip()
    return ""


def _write_private(path: Path, body: str) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        os.fchmod(fd, 0o600)
        f.write(body)


def persist_env_value(path: Path, name: str, value: str, encrypt: bool = True) -> bool:
    if encrypt and crypto.enabled():
        value = crypto.protect(value)
    try:
        existing = path.read_text(encoding="utf-8") if path.exists() else ""
    except OSError as e:
        logger.warning(f"Could not read {path.name}: {e}")
        return False

    line = f"{name}={value}"
    lines = existing.splitlines()
    for i, raw in enumerate(lines):
        stripped = raw.strip()
        if stripped.startswith("#") or "=" not in stripped:
            continue
        if stripped.split("=", 1)[0].strip() == name:
            lines[i] = line
            break
    else:
        if lines and lines[-1].strip():
            lines.append("")
        lines.append(f"# Written automatically on "
                     f"{datetime.now().isoformat(timespec='seconds')}.")
        lines.append(line)

    try:
        _write_private(path, "\n".join(lines) + "\n")
        return True
    except OSError as e:
        logger.warning(f"Could not write {path.name}: {e}")
        return False


def app_key(project_root: Path, name: str = "APP_API_KEY") -> str:
    key = os.environ.get(name, "").strip()
    if key:
        return key
    key = secrets.token_hex(32)
    if not persist_env_value(project_root / ".env", name, key):
        logger.warning(f"Generated {name} but could not save it; it changes on the next start.")
    os.environ[name] = key
    return key
