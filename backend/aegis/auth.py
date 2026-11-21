"""RBAC: role z listami uprawnien, uzytkownicy, sesje i tokeny API."""
import secrets
import time
from typing import Optional

from fastapi import Depends, HTTPException, Request

from . import config, db
from .crypto import hash_password, hash_token, new_token, verify_password

PERMISSIONS = {
    "read": "odczyt dashboardu, hostow, zmian, raportow i eksport",
    "modify": "edycja hostow, uslug, znalezisk, lokalizacji, notatek",
    "create": "dodawanie celow, harmonogramow, sygnatur, import",
    "delete": "usuwanie celow, harmonogramow, wynikow",
    "scan": "uruchamianie i zatrzymywanie skanow",
    "integrations": "konfiguracja i wysylka do DefectDojo",
    "admin": "uzytkownicy, role, klucze API",
    "telemetry": "wysylanie pomiarow Wi-Fi z telefonu",
}

BUILTIN_ROLES = {
    "admin": (["read", "modify", "create", "delete", "scan", "integrations", "admin"], "Administracja"),
    "editor": (["read", "modify", "create", "delete", "scan"], "Dodawanie, usuwanie, modyfikacja"),
    "analyst": (["read", "modify"], "Modyfikacja i odczyt"),
    "viewer": (["read"], "Odczyt"),
    "sensor": (["telemetry"], "Telefon Aegis: tylko wysylanie telemetrii"),
}
SESSION_HOURS = 12


def bootstrap() -> Optional[str]:
    """Tworzy role wbudowane i konto admina. Zwraca haslo, jesli zostalo wygenerowane."""
    with db.tx() as c:
        for name, (perms, desc) in BUILTIN_ROLES.items():
            c.execute("INSERT INTO roles(name, permissions, builtin, description) VALUES (?,?,1,?) "
                      "ON CONFLICT(name) DO UPDATE SET permissions=excluded.permissions, description=excluded.description",
                      (name, db.jdump(perms), desc))
        if c.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
            pw = config.ADMIN_PASSWORD or secrets.token_urlsafe(12)
            c.execute("INSERT INTO users(username, pw_hash, role, created) VALUES (?,?,?,?)",
                      (config.ADMIN_USER, hash_password(pw), "admin", time.time()))
            return None if config.ADMIN_PASSWORD else pw
    return None


def login(username: str, password: str) -> Optional[dict]:
    u = db.q1("SELECT * FROM users WHERE username=? AND active=1", (username,))
    if not u or not u["pw_hash"] or not verify_password(password, u["pw_hash"]):
        return None
    token = new_token()
    with db.tx() as c:
        c.execute("DELETE FROM sessions WHERE expires<?", (time.time(),))
        c.execute("INSERT INTO sessions(token_hash, user_id, expires) VALUES (?,?,?)",
                  (hash_token(token), u["id"], time.time() + SESSION_HOURS * 3600))
    return {"token": token, "username": u["username"], "role": u["role"], "permissions": permissions_of(u["role"])}


def logout(token: str) -> None:
    with db.tx() as c:
        c.execute("DELETE FROM sessions WHERE token_hash=?", (hash_token(token),))


def permissions_of(role: str) -> list[str]:
    r = db.q1("SELECT permissions FROM roles WHERE name=?", (role,))
    return db.jload(r["permissions"], []) if r else []


def issue_api_token(user_id: int) -> str:
    token = "aegis_" + new_token()
    with db.tx() as c:
        c.execute("UPDATE users SET api_token_hash=? WHERE id=?", (hash_token(token), user_id))
    return token


def _resolve(token: str) -> Optional[dict]:
    th = hash_token(token)
    u = db.q1("SELECT u.* FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires>? AND u.active=1",
              (th, time.time()))
    if not u:
        u = db.q1("SELECT * FROM users WHERE api_token_hash=? AND active=1", (th,))
    if not u:
        return None
    return {"id": u["id"], "username": u["username"], "role": u["role"], "permissions": permissions_of(u["role"])}


def current_user(request: Request) -> dict:
    auth = request.headers.get("authorization", "")
    token = auth[7:] if auth.lower().startswith("bearer ") else None
    if not token:
        raise HTTPException(401, "brak tokenu (naglowek Authorization: Bearer ...)")
    user = _resolve(token)
    if not user:
        raise HTTPException(401, "nieprawidlowy lub wygasly token")
    return user


def require(*perms: str):
    """Zaleznosc FastAPI: uzytkownik musi miec WSZYSTKIE podane uprawnienia."""
    def dep(user: dict = Depends(current_user)) -> dict:
        missing = [p for p in perms if p not in user["permissions"]]
        if missing:
            db.audit(user["username"], "access_denied", {"missing": missing})
            raise HTTPException(403, f"rola '{user['role']}' nie ma uprawnien: {', '.join(missing)}")
        return user
    return dep
