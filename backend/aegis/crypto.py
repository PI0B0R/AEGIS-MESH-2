"""Szyfrowanie pol wrazliwych w spoczynku (AES-256-GCM) i haszowanie hasel/tokenow."""
import base64
import hashlib
import hmac
import json
import os
import secrets
from typing import Any, Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import config

_PREFIX = "enc1:"


def _load_key() -> bytes:
    if config.ENCRYPTION_KEY:
        key = base64.b64decode(config.ENCRYPTION_KEY)
    else:
        key_file = config.BASE_DIR / "dev.key"
        if key_file.exists():
            key = base64.b64decode(key_file.read_text().strip())
        else:
            key = AESGCM.generate_key(bit_length=256)
            key_file.write_text(base64.b64encode(key).decode())
            os.chmod(key_file, 0o600)
            print(f"[crypto] UWAGA: wygenerowano klucz deweloperski {key_file}. "
                  "W produkcji ustaw AEGIS_KEY i trzymaj go poza repozytorium.")
    if len(key) != 32:
        raise ValueError("AEGIS_KEY musi miec 32 bajty (base64)")
    return key


_AES = AESGCM(_load_key())


def encrypt(value: Any) -> Optional[str]:
    """Szyfruje dowolna wartosc JSON. None zostaje None."""
    if value is None:
        return None
    raw = json.dumps(value, ensure_ascii=False).encode()
    nonce = os.urandom(12)
    return _PREFIX + base64.b64encode(nonce + _AES.encrypt(nonce, raw, None)).decode()


def decrypt(token: Optional[str]) -> Any:
    if token is None:
        return None
    if not token.startswith(_PREFIX):
        return token  # dane historyczne nieszyfrowane
    blob = base64.b64decode(token[len(_PREFIX):])
    return json.loads(_AES.decrypt(blob[:12], blob[12:], None))


def hash_password(password: str) -> str:
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000)
    return "pbkdf2$" + base64.b64encode(salt).decode() + "$" + base64.b64encode(dk).decode()


def verify_password(password: str, stored: str) -> bool:
    try:
        _, salt_b64, dk_b64 = stored.split("$")
        dk = hashlib.pbkdf2_hmac("sha256", password.encode(), base64.b64decode(salt_b64), 200_000)
        return hmac.compare_digest(dk, base64.b64decode(dk_b64))
    except Exception:
        return False


def new_token() -> str:
    return secrets.token_urlsafe(32)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()
