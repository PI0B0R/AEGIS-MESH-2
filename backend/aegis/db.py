"""Baza SQLite: schemat, polaczenia i proste helpery."""
import json
import sqlite3
import threading
import time
from contextlib import contextmanager
from typing import Any, Iterable, Optional

from . import config

_local = threading.local()
WRITE_LOCK = threading.RLock()

SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS roles (
    name TEXT PRIMARY KEY,
    permissions TEXT NOT NULL,          -- JSON lista uprawnien
    builtin INTEGER NOT NULL DEFAULT 0,
    description TEXT
);
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    pw_hash TEXT,
    role TEXT NOT NULL REFERENCES roles(name),
    api_token_hash TEXT,
    active INTEGER NOT NULL DEFAULT 1,
    created REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT                          -- JSON; wartosci wrazliwe zaszyfrowane
);
CREATE TABLE IF NOT EXISTS targets (
    id INTEGER PRIMARY KEY,
    value TEXT NOT NULL,
    kind TEXT NOT NULL,                 -- ip | cidr | domain
    source TEXT NOT NULL,               -- manual | csv | json
    owner TEXT, tags TEXT, notes_enc TEXT,
    enabled INTEGER NOT NULL DEFAULT 1,
    created REAL NOT NULL,
    UNIQUE(value)
);
CREATE TABLE IF NOT EXISTS schedules (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    target_ids TEXT,                    -- JSON lista; NULL = wszystkie aktywne cele
    interval_minutes INTEGER NOT NULL DEFAULT 1440,
    window_start TEXT,                  -- "HH:MM" lub NULL = zawsze
    window_end TEXT,
    ports TEXT,
    max_rate INTEGER,
    parallel_chunks INTEGER,
    enabled INTEGER NOT NULL DEFAULT 1,
    last_started REAL
);
CREATE TABLE IF NOT EXISTS scan_runs (
    id INTEGER PRIMARY KEY,
    schedule_id INTEGER REFERENCES schedules(id) ON DELETE SET NULL,
    kind TEXT NOT NULL DEFAULT 'scan',  -- scan | import
    status TEXT NOT NULL,               -- queued | running | paused | completed | failed | cancelled
    created REAL NOT NULL,
    started REAL, finished REAL,
    active_seconds REAL NOT NULL DEFAULT 0,
    params TEXT,                        -- JSON (porty, rate, cele)
    chunks_total INTEGER DEFAULT 0,
    chunks_done INTEGER DEFAULT 0,
    pending TEXT,                       -- JSON lista paczek do zrobienia (wznawianie)
    chunk_stats TEXT,                   -- JSON lista {size, seconds}
    stats TEXT,
    error TEXT,
    dojo_status TEXT
);
CREATE TABLE IF NOT EXISTS hosts (
    id INTEGER PRIMARY KEY,
    ip TEXT UNIQUE NOT NULL,
    mac TEXT, vendor TEXT, hostname TEXT, rdns_status TEXT, os_guess TEXT,
    first_seen REAL, last_seen REAL,
    status TEXT,                        -- NEW | ACTIVE | UNSTABLE | GONE
    misses INTEGER NOT NULL DEFAULT 0,
    confidence INTEGER,
    methods TEXT,
    seen_hours TEXT,                    -- JSON licznik godzin, w ktorych host odpowiada
    interest INTEGER NOT NULL DEFAULT 0,
    -- pola edytowane przez uzytkownika: skan ich nie nadpisuje
    user_name TEXT, user_owner TEXT, user_tags TEXT, user_notes_enc TEXT, user_location_enc TEXT,
    user_criticality TEXT,
    updated REAL
);
CREATE TABLE IF NOT EXISTS host_seen (
    run_id INTEGER NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
    host_id INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    alive INTEGER NOT NULL,
    ts REAL NOT NULL,
    PRIMARY KEY(run_id, host_id)
);
CREATE TABLE IF NOT EXISTS services (
    id INTEGER PRIMARY KEY,
    host_id INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    port INTEGER NOT NULL, proto TEXT NOT NULL,
    name TEXT, product TEXT, version TEXT, extrainfo TEXT, tunnel TEXT,
    first_seen REAL, last_seen REAL,
    status TEXT,                        -- NEW | ACTIVE | GONE | CHANGED
    fingerprint TEXT,                   -- hash cech do wykrywania zmian
    last_run_id INTEGER,
    user_notes_enc TEXT, user_tags TEXT, user_false_positive INTEGER NOT NULL DEFAULT 0,
    UNIQUE(host_id, port, proto)
);
CREATE TABLE IF NOT EXISTS service_seen (
    run_id INTEGER NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
    service_id INTEGER NOT NULL REFERENCES services(id) ON DELETE CASCADE,
    PRIMARY KEY(run_id, service_id)
);
CREATE TABLE IF NOT EXISTS http_obs (
    id INTEGER PRIMARY KEY,
    service_id INTEGER NOT NULL REFERENCES services(id) ON DELETE CASCADE,
    run_id INTEGER REFERENCES scan_runs(id) ON DELETE CASCADE,
    ts REAL NOT NULL,
    url TEXT, final_url TEXT, status_code INTEGER, title TEXT,
    server TEXT, technologies TEXT,     -- JSON
    redirects TEXT,                     -- JSON
    favicon_hash TEXT,
    headers_enc TEXT, cookies_enc TEXT, tls_enc TEXT,
    flags TEXT,                         -- JSON: staging, admin_panel, ciekawe naglowki...
    interest INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS signature_hits (
    id INTEGER PRIMARY KEY,
    run_id INTEGER REFERENCES scan_runs(id) ON DELETE CASCADE,
    service_id INTEGER REFERENCES services(id) ON DELETE CASCADE,
    signature_id TEXT NOT NULL, name TEXT, category TEXT, severity TEXT,
    evidence TEXT, version TEXT, ts REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS changes (
    id INTEGER PRIMARY KEY,
    run_id INTEGER REFERENCES scan_runs(id) ON DELETE CASCADE,
    ts REAL NOT NULL,
    object TEXT NOT NULL,               -- host | service | http | wifi
    object_id INTEGER,
    ip TEXT, port INTEGER,
    change TEXT NOT NULL,               -- NEW | GONE | CHANGED | UNSTABLE | RETURNED | ROGUE_AP | EVIL_TWIN | HOTSPOT
    detail TEXT,
    priority INTEGER NOT NULL DEFAULT 1,
    acknowledged INTEGER NOT NULL DEFAULT 0,
    note_enc TEXT
);
CREATE TABLE IF NOT EXISTS known_aps (
    bssid TEXT PRIMARY KEY, ssid TEXT, security TEXT,
    building TEXT, floor TEXT, room TEXT
);
CREATE TABLE IF NOT EXISTS wifi_obs (
    id INTEGER PRIMARY KEY,
    sensor TEXT NOT NULL, ts REAL NOT NULL,
    bssid TEXT NOT NULL, ssid TEXT, security TEXT, frequency INTEGER, channel INTEGER, rssi INTEGER,
    location_enc TEXT                   -- budynek/pietro/sala/wspolrzedne
);
CREATE TABLE IF NOT EXISTS wifi_aps (
    bssid TEXT PRIMARY KEY,
    ssid TEXT, security TEXT, channel INTEGER,
    classification TEXT, confidence INTEGER, reasons TEXT,
    first_seen REAL, last_seen REAL, best_rssi INTEGER,
    location_enc TEXT,                  -- szacowana pozycja
    linked_host_ip TEXT, link_confidence INTEGER
);
CREATE TABLE IF NOT EXISTS audit (
    id INTEGER PRIMARY KEY, ts REAL NOT NULL, username TEXT, action TEXT NOT NULL, detail TEXT
);
CREATE INDEX IF NOT EXISTS ix_changes_run ON changes(run_id);
CREATE INDEX IF NOT EXISTS ix_services_host ON services(host_id);
CREATE INDEX IF NOT EXISTS ix_http_service ON http_obs(service_id);
CREATE INDEX IF NOT EXISTS ix_wifi_bssid ON wifi_obs(bssid);
"""


def conn() -> sqlite3.Connection:
    c = getattr(_local, "conn", None)
    if c is None:
        c = sqlite3.connect(config.DB_PATH, timeout=30, check_same_thread=False)
        c.row_factory = sqlite3.Row
        c.execute("PRAGMA foreign_keys=ON")
        _local.conn = c
    return c


def init() -> None:
    c = conn()
    c.executescript(SCHEMA)
    c.commit()


@contextmanager
def tx():
    """Transakcja zapisu (jeden pisarz naraz)."""
    with WRITE_LOCK:
        c = conn()
        try:
            yield c
            c.commit()
        except Exception:
            c.rollback()
            raise


def q(sql: str, params: Iterable[Any] = ()) -> list[dict]:
    return [dict(r) for r in conn().execute(sql, tuple(params)).fetchall()]


def q1(sql: str, params: Iterable[Any] = ()) -> Optional[dict]:
    r = conn().execute(sql, tuple(params)).fetchone()
    return dict(r) if r else None


def jload(v: Optional[str], default: Any = None) -> Any:
    if v in (None, ""):
        return default
    try:
        return json.loads(v)
    except Exception:
        return default


def jdump(v: Any) -> str:
    return json.dumps(v, ensure_ascii=False)


def now() -> float:
    return time.time()


def audit(username: Optional[str], action: str, detail: Any = None) -> None:
    with tx() as c:
        c.execute("INSERT INTO audit(ts, username, action, detail) VALUES (?,?,?,?)",
                  (now(), username, action, jdump(detail) if detail is not None else None))


def get_setting(key: str, default: Any = None) -> Any:
    from .crypto import decrypt
    row = q1("SELECT value FROM settings WHERE key=?", (key,))
    if not row:
        return default
    return decrypt(row["value"]) if row["value"] and row["value"].startswith("enc1:") else jload(row["value"], default)


def set_setting(key: str, value: Any, secret: bool = False) -> None:
    from .crypto import encrypt
    stored = encrypt(value) if secret else jdump(value)
    with tx() as c:
        c.execute("INSERT INTO settings(key, value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                  (key, stored))
