import base64
import hashlib
import logging
import os
from pathlib import Path

logger = logging.getLogger(__name__)

MARKER = "fernet:v1:"

try:
    from cryptography.fernet import Fernet
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    logger.warning("cryptography not available, .env values will be plain text")


def _account() -> str:
    import pwd
    uid = os.getuid()
    if uid == 0:
        raw = os.environ.get("SUDO_UID") or os.environ.get("PKEXEC_UID") or ""
        if raw.isdigit():
            uid = int(raw)
    return pwd.getpwuid(uid).pw_name


def _get_machine_key(username: str = None) -> bytes:
    salt = b"AgentalSec_Linux_v1_Machine_Binding_Salt_2026"

    machine_id = ""
    for path in ["/etc/machine-id", "/var/lib/dbus/machine-id"]:
        if Path(path).exists():
            try:
                machine_id = Path(path).read_text().strip()
                break
            except Exception:
                pass

    if not machine_id:
        import socket
        machine_id = socket.gethostname()

    if username is None:
        try:
            username = _account()
        except Exception:
            username = os.environ.get("USER", os.environ.get("USERNAME", "default"))

    combined = f"{machine_id}:{username}:{salt.decode()}".encode('utf-8')
    key_material = hashlib.sha256(combined).digest()

    return base64.urlsafe_b64encode(key_material)


def _get_fernet(username: str = None) -> Fernet | None:
    if not CRYPTO_AVAILABLE:
        return None

    try:
        key = _get_machine_key(username)
        return Fernet(key)
    except Exception as e:
        logger.debug(f"Could not initialize Fernet: {e}")
        return None


def available() -> bool:
    return CRYPTO_AVAILABLE and _get_fernet() is not None


def enabled() -> bool:
    if os.environ.get("AGENTAL_ENV_PLAINTEXT", "").strip() in ("1", "true", "yes"):
        return False
    return available()


def is_protected(value: str) -> bool:
    return isinstance(value, str) and value.startswith(MARKER)


def protect(plain: str) -> str:
    if not plain:
        return plain
    if is_protected(plain):
        return plain

    fernet = _get_fernet()
    if not fernet:
        raise SecretCryptoError(
            "This machine cannot encrypt .env values. "
            "Install 'cryptography' package: pip install cryptography"
        )

    try:
        encrypted = fernet.encrypt(plain.encode('utf-8'))
        return MARKER + base64.b64encode(encrypted).decode('ascii')
    except Exception as e:
        raise SecretCryptoError(f"Encryption failed: {e}")


def unprotect(value: str) -> str:
    if not is_protected(value):
        return value

    fernet = _get_fernet()
    if not fernet:
        raise SecretCryptoError(
            "This value was encrypted with Fernet and cryptography is not "
            "available. Install 'cryptography' package or put the plain key "
            "in .env on this machine."
        )

    try:
        encrypted_data = base64.b64decode(value[len(MARKER):], validate=True)
        try:
            decrypted = fernet.decrypt(encrypted_data)
        except Exception:
            older = _get_fernet("root")
            if older is None or _account() == "root":
                raise
            decrypted = older.decrypt(encrypted_data)
        return decrypted.decode('utf-8')
    except base64.binascii.Error:
        raise SecretCryptoError(
            "The fernet: value in .env is not valid base64. "
            "It looks truncated or hand-edited."
        )
    except Exception as e:
        raise SecretCryptoError(
            f"Could not decrypt this value. This normally means it was "
            f"encrypted on a DIFFERENT machine or by a DIFFERENT user. "
            f"The key itself is probably fine, it's just unreadable here. "
            f"Save it again on this machine, or copy the plain "
            f"value into .env. (Error: {e})"
        )


class SecretCryptoError(Exception):
    pass


def status() -> dict:
    return {
        "available": available(),
        "enabled": enabled(),
        "why": (
            "Values written from the settings panel are encrypted against "
            "this machine and user combination."
            if enabled() else
            "Values are stored in plain text. Install 'cryptography' package "
            "or set AGENTAL_ENV_PLAINTEXT=1 deliberately."
        ),
    }
