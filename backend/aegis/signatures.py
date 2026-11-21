"""Silnik bezpiecznych sygnatur detekcyjnych.

Sygnatura tylko WYKRYWA cechy (naglowek, ciasteczko, fragment HTML, hash favicony,
sciezka typu /admin). Wykonujemy wylacznie GET bez parametrow, bez logowania.
"""
import json
import re
from pathlib import Path
from typing import Any, Optional

from . import config, db

ALLOWED_TYPES = {"body", "header", "cookie", "title", "status", "favicon", "meta_generator", "cert"}
ALLOWED_CATEGORIES = {"cms", "framework", "server", "iot", "admin_panel", "staging", "header", "cookie",
                      "devops", "database", "other"}
SAFE_PATH = re.compile(r"^/[A-Za-z0-9._~/\-]*$")  # bez ?, &, %, ..: tylko odczyt statycznej sciezki
MAX_PATHS_PER_SERVICE = 30


class SignatureError(ValueError):
    pass


def validate(sig: dict) -> dict:
    if not isinstance(sig, dict):
        raise SignatureError("sygnatura musi byc obiektem")
    for key in ("id", "name", "rules"):
        if key not in sig:
            raise SignatureError(f"brak pola {key}")
    if not re.match(r"^[a-z0-9_.-]{2,64}$", sig["id"]):
        raise SignatureError("id: male litery, cyfry, _ . - (2-64 znaki)")
    sig.setdefault("category", "other")
    sig.setdefault("severity", "info")
    sig.setdefault("match", "any")
    sig.setdefault("path", "/")
    if sig["category"] not in ALLOWED_CATEGORIES:
        raise SignatureError(f"kategoria spoza listy: {sorted(ALLOWED_CATEGORIES)}")
    if sig["severity"] not in ("info", "low", "medium"):
        raise SignatureError("severity: info | low | medium")
    if sig["match"] not in ("any", "all"):
        raise SignatureError("match: any | all")
    if not SAFE_PATH.match(sig["path"]) or ".." in sig["path"]:
        raise SignatureError("path: tylko statyczna sciezka bez parametrow (np. /admin)")
    if not sig["rules"]:
        raise SignatureError("rules nie moze byc puste")
    for r in sig["rules"]:
        if r.get("type") not in ALLOWED_TYPES:
            raise SignatureError(f"typ reguly spoza listy: {sorted(ALLOWED_TYPES)}")
        for k in ("regex", "name_regex"):
            if k in r:
                try:
                    re.compile(r[k])
                except re.error as e:
                    raise SignatureError(f"zly regex {r[k]!r}: {e}")
    if sig["path"] != "/" and all(r["type"] == "status" for r in sig["rules"]):
        raise SignatureError("sygnatura sciezki potrzebuje reguly innej niz sam status (ochrona przed soft-404)")
    if "version" in sig:
        re.compile(sig["version"].get("regex", ""))
    return sig


def load_all() -> list[dict]:
    sigs: dict[str, dict] = {}
    if config.SIGNATURES_DIR.exists():
        for f in sorted(Path(config.SIGNATURES_DIR).glob("*.json")):
            for s in json.loads(f.read_text()):
                s = validate(dict(s))
                s["source"] = f.name
                sigs[s["id"]] = s
    for s in db.get_setting("custom_signatures", []) or []:
        try:
            s = validate(dict(s))
            s["source"] = "custom"
            sigs[s["id"]] = s
        except SignatureError:
            continue
    return list(sigs.values())


def extra_paths(sigs: list[dict]) -> list[str]:
    paths = sorted({s["path"] for s in sigs if s["path"] != "/"})
    return paths[:MAX_PATHS_PER_SERVICE]


def _rule(rule: dict, resp: dict) -> Optional[str]:
    """Zwraca dowod (krotki tekst) gdy regula pasuje, inaczej None."""
    t = rule["type"]
    rx = re.compile(rule["regex"], re.I) if rule.get("regex") else None
    if t == "status":
        return f"status {resp['status']}" if resp["status"] == rule.get("code") else None
    if t == "body":
        m = rx.search(resp.get("body", "")) if rx else None
        return f"body: {m.group(0)[:80]}" if m else None
    if t == "title":
        title = resp.get("title") or ""
        m = rx.search(title) if rx else None
        return f"title: {title[:80]}" if m else None
    if t == "header":
        val = resp["headers"].get(rule["name"].lower())
        if val is None:
            return None
        if rx and not rx.search(val):
            return None
        return f"{rule['name']}: {val[:80]}"
    if t == "cookie":
        crx = re.compile(rule.get("name_regex", ".*"), re.I)
        for c in resp.get("cookies", []):
            if crx.search(c["name"]):
                return f"cookie {c['name']}"
        return None
    if t == "favicon":
        return f"favicon {resp.get('favicon_hash')}" if str(resp.get("favicon_hash")) == str(rule.get("hash")) else None
    if t == "meta_generator":
        gen = resp.get("meta_generator") or ""
        return f"generator: {gen[:80]}" if gen and (not rx or rx.search(gen)) else None
    if t == "cert":
        text = resp.get("cert_text") or ""
        m = rx.search(text) if rx else None
        return f"cert: {m.group(0)[:80]}" if m else None
    return None


def _version(sig: dict, resp: dict) -> Optional[str]:
    v = sig.get("version")
    if not v:
        return None
    src = v.get("source", "body")
    if src == "body":
        text = resp.get("body", "")
    elif src == "meta_generator":
        text = resp.get("meta_generator") or ""
    elif src.startswith("header:"):
        text = resp["headers"].get(src.split(":", 1)[1].lower(), "")
    else:
        text = ""
    m = re.search(v["regex"], text, re.I)
    return m.group(1) if m and m.groups() else None


def evaluate(sigs: list[dict], responses: dict[str, dict]) -> list[dict]:
    """responses: sciezka -> odpowiedz (z odfiltrowanym soft-404). Zwraca liste trafien."""
    hits = []
    for s in sigs:
        resp = responses.get(s["path"])
        if not resp:
            continue
        evidence = [_rule(r, resp) for r in s["rules"]]
        ok = all(evidence) if s["match"] == "all" else any(evidence)
        if ok:
            hits.append({
                "signature_id": s["id"], "name": s["name"], "category": s["category"],
                "severity": s["severity"], "path": s["path"],
                "evidence": "; ".join(e for e in evidence if e)[:300],
                "version": _version(s, resp),
            })
    return hits


def save_custom(sigs: list[Any]) -> list[dict]:
    clean = [validate(dict(s)) for s in sigs]
    db.set_setting("custom_signatures", clean)
    return clean
