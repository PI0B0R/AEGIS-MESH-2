"""Cele skanowania: walidacja, import CSV/JSON i podzial na paczki."""
import csv
import io
import ipaddress
import json
import re
from typing import Iterator

from . import config, db

_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)([a-zA-Z0-9-]{1,63}(?<!-)\.)+[a-zA-Z]{2,63}$")
MAX_SINGLE_RANGE = 2 ** 20  # ochrona przed literowka typu /8


def classify(value: str) -> tuple[str, str]:
    """Zwraca (znormalizowana_wartosc, rodzaj). Rzuca ValueError dla nieprawidlowych."""
    v = value.strip()
    if not v:
        raise ValueError("pusta wartosc")
    if "/" in v:
        net = ipaddress.ip_network(v, strict=False)
        if net.version != 4:
            raise ValueError("obslugiwane sa zakresy IPv4")
        if net.num_addresses > MAX_SINGLE_RANGE:
            raise ValueError(f"zakres {net} jest za duzy (max /12)")
        return str(net), "cidr"
    try:
        ip = ipaddress.ip_address(v)
        return str(ip), "ip"
    except ValueError:
        pass
    if "-" in v and v.count(".") >= 3 and re.match(r"^\d+\.\d+\.\d+\.\d+-\d+$", v):
        base, last = v.rsplit("-", 1)
        start = ipaddress.ip_address(base)
        end = ipaddress.ip_address(".".join(base.split(".")[:3] + [last]))
        nets = list(ipaddress.summarize_address_range(start, end))
        if len(nets) == 1:
            return str(nets[0]), "cidr"
        raise ValueError("zakres a.b.c.d-e zapisz jako CIDR lub kilka wpisow")
    if _DOMAIN_RE.match(v):
        return v.lower(), "domain"
    raise ValueError(f"nieprawidlowy cel: {value!r}")


def parse_csv(text: str) -> list[dict]:
    """CSV z naglowkiem: value[,owner,tags,notes] albo pojedyncza kolumna bez naglowka."""
    rows = []
    sample = text.strip().splitlines()
    if not sample:
        return rows
    has_header = "value" in sample[0].lower() or "target" in sample[0].lower()
    reader = csv.DictReader(io.StringIO(text)) if has_header else csv.reader(io.StringIO(text))
    for r in reader:
        if isinstance(r, dict):
            val = r.get("value") or r.get("target") or ""
            rows.append({"value": val, "owner": r.get("owner"), "tags": r.get("tags"), "notes": r.get("notes")})
        elif r:
            rows.append({"value": r[0]})
    return rows


def parse_json(text: str) -> list[dict]:
    """JSON: lista stringow, lista obiektow {value, owner, tags, notes} lub {"targets": [...]}."""
    data = json.loads(text)
    if isinstance(data, dict):
        data = data.get("targets", [])
    out = []
    for item in data:
        out.append({"value": item} if isinstance(item, str) else dict(item))
    return out


def add_targets(items: list[dict], source: str) -> dict:
    from .crypto import encrypt
    added, skipped, errors = 0, 0, []
    with db.tx() as c:
        for it in items:
            try:
                value, kind = classify(str(it.get("value", "")))
            except ValueError as e:
                errors.append(str(e))
                continue
            cur = c.execute(
                "INSERT OR IGNORE INTO targets(value, kind, source, owner, tags, notes_enc, created) VALUES (?,?,?,?,?,?,?)",
                (value, kind, source, it.get("owner"), it.get("tags"), encrypt(it.get("notes")) if it.get("notes") else None,
                 db.now()))
            if cur.rowcount:
                added += 1
            else:
                skipped += 1
    return {"added": added, "skipped_duplicates": skipped, "errors": errors[:50], "error_count": len(errors)}


def expand(target_rows: list[dict]) -> Iterator[str]:
    """Rozwija cele do pojedynczych adresow/domen (generator: nie trzyma 65k obiektow naraz)."""
    seen = set()
    for t in target_rows:
        if t["kind"] == "cidr":
            net = ipaddress.ip_network(t["value"])
            hosts = net.hosts() if net.num_addresses > 2 else iter(net)
            for ip in hosts:
                s = str(ip)
                if s not in seen:
                    seen.add(s)
                    yield s
        elif t["value"] not in seen:
            seen.add(t["value"])
            yield t["value"]


def adaptive_chunk_size() -> int:
    """Rozmiar paczki z historii: celujemy w TARGET_CHUNK_SECONDS na paczke."""
    rows = db.q("SELECT chunk_stats FROM scan_runs WHERE chunk_stats IS NOT NULL ORDER BY id DESC LIMIT 5")
    sizes, secs = 0, 0.0
    for r in rows:
        for s in db.jload(r["chunk_stats"], []):
            sizes += s["size"]
            secs += s["seconds"]
    if sizes < 50 or secs <= 0:
        return config.DEFAULT_CHUNK_SIZE
    per_host = secs / sizes
    size = int(config.TARGET_CHUNK_SECONDS / max(per_host, 0.001))
    return max(16, min(size, 4096))


def make_chunks(items: Iterator[str], size: int) -> list[list[str]]:
    chunks, batch = [], []
    for it in items:
        batch.append(it)
        if len(batch) >= size:
            chunks.append(batch)
            batch = []
    if batch:
        chunks.append(batch)
    return chunks


def in_scope(ip: str, target_rows: list[dict]) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for t in target_rows:
        if t["kind"] == "cidr" and addr in ipaddress.ip_network(t["value"]):
            return True
        if t["kind"] == "ip" and t["value"] == ip:
            return True
    return False
