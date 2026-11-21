"""Orkiestracja przebiegu skanu: paczki, okno czasowe, wznawianie, zapis i wykrywanie zmian."""
import concurrent.futures
import hashlib
import ipaddress
import logging
import threading
import time
from datetime import datetime
from typing import Optional

from . import config, db, http_fp, nmap_runner, signatures, targets
from .crypto import encrypt

log = logging.getLogger("aegis.scanner")
_running: dict[int, threading.Thread] = {}
_running_lock = threading.Lock()

# reasons z nmapa, ktore same w sobie sa slabym dowodem (moga pochodzic od firewalla)
WEAK_REASONS = {"reset", "conn-refused"}


# --------------------------------------------------------------------------- tworzenie przebiegu
def create_run(target_ids: Optional[list[int]] = None, schedule_id: Optional[int] = None,
               ports: Optional[str] = None, max_rate: Optional[int] = None,
               parallel: Optional[int] = None) -> int:
    if target_ids:
        rows = db.q(f"SELECT * FROM targets WHERE enabled=1 AND id IN ({','.join('?' * len(target_ids))})", target_ids)
    else:
        rows = db.q("SELECT * FROM targets WHERE enabled=1")
    if not rows:
        raise ValueError("brak aktywnych celow do skanowania")
    size = targets.adaptive_chunk_size()
    chunks = targets.make_chunks(targets.expand(rows), size)
    params = {
        "ports": ports or config.DEFAULT_PORTS, "max_rate": max_rate or config.DEFAULT_MAX_RATE,
        "parallel": parallel or config.DEFAULT_PARALLEL_CHUNKS, "chunk_size": size,
        "targets": [{"value": r["value"], "kind": r["kind"]} for r in rows],
        "addresses": sum(len(c) for c in chunks),
    }
    with db.tx() as c:
        cur = c.execute(
            "INSERT INTO scan_runs(schedule_id, kind, status, created, params, chunks_total, chunks_done, pending, chunk_stats) "
            "VALUES (?,?,?,?,?,?,?,?,?)",
            (schedule_id, "scan", "queued", db.now(), db.jdump(params), len(chunks), 0, db.jdump(chunks), db.jdump([])))
        return cur.lastrowid


def start_async(run_id: int, deadline: Optional[float] = None) -> bool:
    with _running_lock:
        if run_id in _running and _running[run_id].is_alive():
            return False
        t = threading.Thread(target=execute, args=(run_id, deadline), daemon=True, name=f"scan-{run_id}")
        _running[run_id] = t
        t.start()
        return True


def is_running(run_id: int) -> bool:
    t = _running.get(run_id)
    return bool(t and t.is_alive())


def cancel(run_id: int) -> None:
    with db.tx() as c:
        c.execute("UPDATE scan_runs SET status='cancelled' WHERE id=? AND status IN ('queued','running','paused')", (run_id,))


# --------------------------------------------------------------------------- wykonanie
def execute(run_id: int, deadline: Optional[float] = None) -> None:
    run = db.q1("SELECT * FROM scan_runs WHERE id=?", (run_id,))
    if not run or run["status"] in ("completed", "cancelled"):
        return
    params = db.jload(run["params"], {})
    pending: list[list[str]] = db.jload(run["pending"], [])
    t_start = time.time()
    with db.tx() as c:
        c.execute("UPDATE scan_runs SET status='running', started=COALESCE(started, ?), error=NULL WHERE id=?",
                  (t_start, run_id))
    sigs = signatures.load_all()
    run_dir = config.RUNS_DIR / str(run_id)
    pending_lock = threading.Lock()
    stats_lock = threading.Lock()
    chunk_stats = db.jload(run["chunk_stats"], [])
    returned: list[list[str]] = []

    def stop_requested() -> bool:
        r = db.q1("SELECT status FROM scan_runs WHERE id=?", (run_id,))
        return bool(r and r["status"] == "cancelled")

    def work(index: int, chunk: list[str]) -> None:
        if stop_requested():
            with pending_lock:
                returned.append(chunk)
            return
        remaining = (deadline - time.time()) if deadline else None
        if remaining is not None and remaining < 15:
            with pending_lock:
                returned.append(chunk)
            return
        t0 = time.time()
        tag = hashlib.sha1("|".join(chunk).encode()).hexdigest()[:10]
        try:
            alive = nmap_runner.run(chunk, nmap_runner.discovery_args(params["max_rate"]),
                                    run_dir / f"alive_{tag}.xml", remaining)
            up = [h for h in alive["hosts"] if h["state"] == "up"]
            svc = {"hosts": []}
            if up:
                remaining = (deadline - time.time()) if deadline else None
                svc = nmap_runner.run([h["ip"] for h in up], nmap_runner.service_args(params["ports"], params["max_rate"]),
                                      run_dir / f"svc_{tag}.xml", remaining)
            record_chunk(run_id, chunk, up, svc["hosts"], sigs)
        except nmap_runner.ChunkTimeout as e:
            log.info("run %s: paczka %s wraca do kolejki (%s)", run_id, tag, e)
            with pending_lock:
                returned.append(chunk)
            return
        with stats_lock:
            chunk_stats.append({"size": len(chunk), "seconds": round(time.time() - t0, 2)})
            with db.tx() as c:
                c.execute("UPDATE scan_runs SET chunks_done=chunks_done+1, chunk_stats=? WHERE id=?",
                          (db.jdump(chunk_stats[-200:]), run_id))

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, params.get("parallel", 1))) as pool:
            futures = [pool.submit(work, i, ch) for i, ch in enumerate(pending)]
            for f in concurrent.futures.as_completed(futures):
                f.result()
        active = (db.q1("SELECT active_seconds FROM scan_runs WHERE id=?", (run_id,)) or {}).get("active_seconds", 0)
        active += time.time() - t_start
        if stop_requested():
            with db.tx() as c:
                c.execute("UPDATE scan_runs SET pending=?, active_seconds=?, finished=? WHERE id=?",
                          (db.jdump(returned), active, db.now(), run_id))
            return
        if returned:
            with db.tx() as c:
                c.execute("UPDATE scan_runs SET status='paused', pending=?, active_seconds=? WHERE id=?",
                          (db.jdump(returned), active, run_id))
            log.info("run %s: okno czasowe minelo, %d paczek czeka na kolejne okno", run_id, len(returned))
            return
        stats = finalize(run_id, params)
        with db.tx() as c:
            c.execute("UPDATE scan_runs SET status='completed', pending='[]', finished=?, active_seconds=?, stats=? WHERE id=?",
                      (db.now(), active, db.jdump(stats), run_id))
        merged = nmap_runner.merge_xml(sorted(run_dir.glob("svc_*.xml")), run_dir / "nmap_merged.xml")
        if merged and db.get_setting("dojo_auto_push", False):
            from . import defectdojo
            defectdojo.push_run_safe(run_id)
    except Exception as e:  # noqa: BLE001
        log.exception("run %s failed", run_id)
        with db.tx() as c:
            c.execute("UPDATE scan_runs SET status='failed', error=? WHERE id=?", (str(e)[:500], run_id))


# --------------------------------------------------------------------------- zapis wynikow paczki
def _host_confidence(h: dict, services: list[dict]) -> int:
    score = 40
    if h.get("reason") and h["reason"] not in WEAK_REASONS:
        score += 20
    if h.get("reason") == "arp-response":
        score += 20
    if services:
        score += 25
    if h.get("ptr"):
        score += 5
    return min(score, 100)


def _change(c, run_id, obj, obj_id, ip, port, change, detail, priority=1):
    c.execute("INSERT INTO changes(run_id, ts, object, object_id, ip, port, change, detail, priority) VALUES (?,?,?,?,?,?,?,?,?)",
              (run_id, db.now(), obj, obj_id, ip, port, change, detail, priority))


def _service_fp(s: dict) -> str:
    return hashlib.sha1(f"{s.get('name')}|{s.get('product')}|{s.get('version')}".encode()).hexdigest()[:16]


def record_chunk(run_id: int, chunk: list[str], up: list[dict], svc_hosts: list[dict], sigs: list[dict]) -> None:
    services_by_ip = {h["ip"]: h["ports"] for h in svc_hosts}
    os_by_ip = {h["ip"]: h.get("os") for h in svc_hosts}
    ts = db.now()
    hour = datetime.now().strftime("%H")
    web_jobs = []
    # Wykrycie "firewalla odpowiadajacego za wszystkich": >90% paczki zywe tylko po RST, bez uslug
    weak_flood = len(chunk) >= 32 and len(up) > 0.9 * len(chunk) and \
        sum(1 for h in up if h.get("reason") in WEAK_REASONS and not services_by_ip.get(h["ip"])) > 0.8 * len(up)

    with db.tx() as c:
        for h in up:
            ports = services_by_ip.get(h["ip"], [])
            conf = _host_confidence(h, ports)
            if weak_flood and not ports:
                conf = min(conf, 20)
            name = h.get("ptr") or h.get("user_name")
            rdns = None
            if h.get("ptr"):
                rdns = "ORG_DOMAIN" if h["ptr"].lower().endswith(config.ORG_DOMAIN_SUFFIX) else "OTHER_PTR"
            elif not h.get("user_name"):
                rdns = "NO_PTR"
            row = c.execute("SELECT * FROM hosts WHERE ip=?", (h["ip"],)).fetchone()
            if row is None:
                cur = c.execute(
                    "INSERT INTO hosts(ip, mac, vendor, hostname, rdns_status, os_guess, first_seen, last_seen, status, "
                    "misses, confidence, methods, seen_hours, updated) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (h["ip"], h["mac"], h["vendor"], name, rdns, os_by_ip.get(h["ip"]), ts, ts, "NEW", 0, conf,
                     h.get("reason"), db.jdump({hour: 1}), ts))
                host_id = cur.lastrowid
                _change(c, run_id, "host", host_id, h["ip"], None, "NEW",
                        f"nowy host ({h.get('reason')}){' ' + name if name else ''}", 3 if conf >= 50 else 1)
            else:
                host_id = row["id"]
                hours = db.jload(row["seen_hours"], {})
                hours[hour] = hours.get(hour, 0) + 1
                if row["status"] == "GONE":
                    _change(c, run_id, "host", host_id, h["ip"], None, "RETURNED", "host znow odpowiada", 2)
                c.execute("UPDATE hosts SET mac=COALESCE(?, mac), vendor=COALESCE(?, vendor), hostname=COALESCE(?, hostname), "
                          "rdns_status=COALESCE(?, rdns_status), os_guess=COALESCE(?, os_guess), last_seen=?, confidence=?, "
                          "methods=?, seen_hours=?, updated=? WHERE id=?",
                          (h["mac"], h["vendor"], name, rdns, os_by_ip.get(h["ip"]), ts, conf, h.get("reason"),
                           db.jdump(hours), ts, host_id))
            c.execute("INSERT OR REPLACE INTO host_seen(run_id, host_id, alive, ts) VALUES (?,?,1,?)", (run_id, host_id, ts))

            for s in ports:
                fp = _service_fp(s)
                srow = c.execute("SELECT * FROM services WHERE host_id=? AND port=? AND proto=?",
                                 (host_id, s["port"], s["proto"])).fetchone()
                label = " ".join(filter(None, [s.get("name"), s.get("product"), s.get("version")]))
                if srow is None:
                    cur = c.execute(
                        "INSERT INTO services(host_id, port, proto, name, product, version, extrainfo, tunnel, first_seen, "
                        "last_seen, status, fingerprint, last_run_id) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                        (host_id, s["port"], s["proto"], s["name"], s["product"], s["version"], s["extrainfo"], s["tunnel"],
                         ts, ts, "NEW", fp, run_id))
                    sid = cur.lastrowid
                    if row is not None:  # nowa usluga na znanym hoscie (dla nowego hosta wystarczy zdarzenie hosta)
                        _change(c, run_id, "service", sid, h["ip"], s["port"], "NEW", f"nowa usluga {label}", 2)
                else:
                    sid = srow["id"]
                    status = "ACTIVE"
                    if srow["fingerprint"] and srow["fingerprint"] != fp:
                        status = "CHANGED"
                        old = " ".join(filter(None, [srow["name"], srow["product"], srow["version"]]))
                        _change(c, run_id, "service", sid, h["ip"], s["port"], "CHANGED", f"{old} -> {label}", 2)
                    elif srow["status"] == "GONE":
                        status = "ACTIVE"
                        _change(c, run_id, "service", sid, h["ip"], s["port"], "RETURNED", f"usluga znow dostepna: {label}", 1)
                    c.execute("UPDATE services SET name=?, product=?, version=?, extrainfo=?, tunnel=?, last_seen=?, status=?, "
                              "fingerprint=?, last_run_id=? WHERE id=?",
                              (s["name"], s["product"], s["version"], s["extrainfo"], s["tunnel"], ts, status, fp, run_id, sid))
                c.execute("INSERT OR IGNORE INTO service_seen(run_id, service_id) VALUES (?,?)", (run_id, sid))
                if http_fp.is_web(s) and not s.get("_noweb"):
                    web_jobs.append((sid, host_id, h["ip"], dict(s), h.get("user_name") or h.get("ptr")))

        # Hosty z tej paczki, ktore nie odpowiedzialy: odnotuj brak (status liczony w finalize)
        alive_ips = {h["ip"] for h in up}
        for t in chunk:
            if t in alive_ips:
                continue
            row = c.execute("SELECT id FROM hosts WHERE ip=?", (t,)).fetchone()
            if row:
                c.execute("INSERT OR REPLACE INTO host_seen(run_id, host_id, alive, ts) VALUES (?,?,0,?)", (run_id, row["id"], ts))

    # Fingerprint HTTP rownolegle, poza transakcja
    if web_jobs:
        with concurrent.futures.ThreadPoolExecutor(max_workers=config.HTTP_WORKERS) as pool:
            futs = {pool.submit(_safe_fp, ip, s, hn, sigs): (sid, ip, s) for sid, _hid, ip, s, hn in web_jobs}
            for f in concurrent.futures.as_completed(futs):
                sid, ip, s = futs[f]
                res = f.result()
                if res:
                    record_http(run_id, sid, ip, s["port"], res)


def _safe_fp(ip, s, hostname, sigs):
    try:
        return http_fp.fingerprint(ip, s, hostname, sigs)
    except Exception as e:  # noqa: BLE001
        log.warning("fingerprint %s:%s nieudany: %s", ip, s["port"], e)
        return None


def record_http(run_id: int, service_id: int, ip: str, port: int, res: dict) -> None:
    ts = db.now()
    tls = res.get("tls")
    with db.tx() as c:
        prev = c.execute("SELECT * FROM http_obs WHERE service_id=? ORDER BY ts DESC LIMIT 1", (service_id,)).fetchone()
        c.execute(
            "INSERT INTO http_obs(service_id, run_id, ts, url, final_url, status_code, title, server, technologies, redirects, "
            "favicon_hash, headers_enc, cookies_enc, tls_enc, flags, interest) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (service_id, run_id, ts, res["url"], res["final_url"], res["status_code"], res["title"], res["server"],
             db.jdump(res["technologies"]), db.jdump(res["redirects"]), res["favicon_hash"], encrypt(res["headers"]),
             encrypt(res["cookies"]), encrypt(tls), db.jdump(res["flags"]), res["interest"]))
        for hit in res["signature_hits"]:
            c.execute("INSERT INTO signature_hits(run_id, service_id, signature_id, name, category, severity, evidence, version, ts) "
                      "VALUES (?,?,?,?,?,?,?,?,?)",
                      (run_id, service_id, hit["signature_id"], hit["name"], hit["category"], hit["severity"],
                       hit["evidence"], hit.get("version"), ts))
        if prev is not None:
            diffs = []
            if prev["status_code"] != res["status_code"]:
                diffs.append(f"kod {prev['status_code']} -> {res['status_code']}")
            if (prev["title"] or "") != (res["title"] or ""):
                diffs.append(f"tytul '{prev['title']}' -> '{res['title']}'")
            if db.jload(prev["technologies"], []) != res["technologies"]:
                diffs.append("technologie: " + ", ".join(res["technologies"]))
            from .crypto import decrypt
            old_tls = decrypt(prev["tls_enc"]) or {}
            if (old_tls.get("sha256") if old_tls else None) != (tls.get("sha256") if tls else None):
                diffs.append("nowy certyfikat TLS")
            if diffs:
                _change(c, run_id, "http", service_id, ip, port, "CHANGED", "; ".join(diffs)[:500], 2)
                c.execute("UPDATE services SET status='CHANGED' WHERE id=?", (service_id,))
        c.execute("UPDATE hosts SET interest=MAX(interest, ?) WHERE id=(SELECT host_id FROM services WHERE id=?)",
                  (res["interest"], service_id))
        if res["interest"] >= 3 and prev is None:
            _change(c, run_id, "http", service_id, ip, port, "INTERESTING",
                    "; ".join(res["flags"].get("reasons", []))[:500], 3)


# --------------------------------------------------------------------------- zakonczenie przebiegu
def _scope_hosts(params: dict) -> list[dict]:
    rows = params.get("targets", [])
    all_hosts = db.q("SELECT * FROM hosts")
    names = {t["value"] for t in rows if t["kind"] == "domain"}
    return [h for h in all_hosts if targets.in_scope(h["ip"], rows) or (h["hostname"] in names)]


def finalize(run_id: int, params: dict) -> dict:
    """Statusy NEW/ACTIVE/UNSTABLE/GONE + uslugi znikniete. Przed GONE: jedno ponowne sprawdzenie."""
    scope = _scope_hosts(params)
    seen = {r["host_id"]: r["alive"] for r in db.q("SELECT host_id, alive FROM host_seen WHERE run_id=?", (run_id,))}
    to_recheck = []
    for h in scope:
        if seen.get(h["id"]) == 1:
            continue
        if h["status"] != "GONE" and h["misses"] + 1 >= config.GONE_AFTER_MISSES:
            to_recheck.append(h["ip"])

    rechecked_alive = set()
    if to_recheck:
        try:
            res = nmap_runner.run(to_recheck, nmap_runner.discovery_args(params.get("max_rate", 100)),
                                  config.RUNS_DIR / str(run_id) / "recheck.xml", 300)
            rechecked_alive = {h["ip"] for h in res["hosts"] if h["state"] == "up"}
        except Exception as e:  # noqa: BLE001
            log.warning("recheck nieudany: %s", e)

    counts = {"NEW": 0, "ACTIVE": 0, "UNSTABLE": 0, "GONE": 0, "services_gone": 0}
    with db.tx() as c:
        for h in scope:
            alive = seen.get(h["id"]) == 1 or h["ip"] in rechecked_alive
            if alive:
                if h["ip"] in rechecked_alive and seen.get(h["id"]) != 1:
                    c.execute("INSERT OR REPLACE INTO host_seen(run_id, host_id, alive, ts) VALUES (?,?,1,?)",
                              (run_id, h["id"], db.now()))
                history = [r["alive"] for r in c.execute(
                    "SELECT alive FROM host_seen WHERE host_id=? ORDER BY run_id DESC LIMIT ?",
                    (h["id"], config.UNSTABLE_WINDOW)).fetchall()]
                if h["first_seen"] and h["status"] == "NEW" and len(history) <= 1:
                    status = "NEW"
                elif 0 in history:
                    status = "UNSTABLE"
                else:
                    status = "ACTIVE"
                if status == "UNSTABLE" and h["status"] != "UNSTABLE":
                    _change(c, run_id, "host", h["id"], h["ip"], None, "UNSTABLE",
                            f"odpowiada nieregularnie ({sum(history)}/{len(history)} ostatnich przebiegow)", 1)
                c.execute("UPDATE hosts SET status=?, misses=0 WHERE id=?", (status, h["id"]))
                # uslugi, ktore zniknely z zywego hosta
                for s in c.execute("SELECT * FROM services WHERE host_id=? AND status!='GONE' AND "
                                   "(last_run_id IS NULL OR last_run_id!=?)", (h["id"], run_id)).fetchall():
                    if seen.get(h["id"]) == 1:  # tylko gdy faktycznie skanowalismy uslugi w tym przebiegu
                        c.execute("UPDATE services SET status='GONE' WHERE id=?", (s["id"],))
                        _change(c, run_id, "service", s["id"], h["ip"], s["port"], "GONE",
                                f"usluga zniknela: {s['name'] or ''} {s['product'] or ''}".strip(), 2)
                        counts["services_gone"] += 1
                counts[status] += 1
            else:
                misses = h["misses"] + 1
                if misses >= config.GONE_AFTER_MISSES:
                    if h["status"] != "GONE":
                        _change(c, run_id, "host", h["id"], h["ip"], None, "GONE",
                                f"brak odpowiedzi w {misses} kolejnych przebiegach (potwierdzone ponownym sprawdzeniem)", 2)
                    status = "GONE"
                else:
                    status = "UNSTABLE" if h["status"] != "GONE" else "GONE"
                    if status == "UNSTABLE" and h["status"] != "UNSTABLE":
                        _change(c, run_id, "host", h["id"], h["ip"], None, "UNSTABLE",
                                f"brak odpowiedzi w tym przebiegu ({misses}/{config.GONE_AFTER_MISSES} do uznania za nieaktywny)", 1)
                c.execute("UPDATE hosts SET status=?, misses=? WHERE id=?", (status, misses, h["id"]))
                counts[status] += 1
    counts["changes"] = (db.q1("SELECT COUNT(*) n FROM changes WHERE run_id=?", (run_id,)) or {}).get("n", 0)
    counts["services_total"] = (db.q1("SELECT COUNT(*) n FROM services WHERE status!='GONE'") or {}).get("n", 0)
    return counts


# --------------------------------------------------------------------------- import wynikow (JSON/CSV)
def import_results(hosts: list[dict], fingerprint_web: bool = True) -> int:
    """Import gotowych wynikow: przechodza ten sam proces co skan (zapis, HTTP, porownanie)."""
    ips = [h["ip"] for h in hosts]
    for ip in ips:
        ipaddress.ip_address(ip)
    params = {"targets": [{"value": ip, "kind": "ip"} for ip in ips], "ports": config.DEFAULT_PORTS,
              "max_rate": config.DEFAULT_MAX_RATE, "imported": True}
    with db.tx() as c:
        run_id = c.execute("INSERT INTO scan_runs(kind, status, created, started, params, chunks_total, chunks_done) "
                           "VALUES ('import','running',?,?,?,1,0)", (db.now(), db.now(), db.jdump(params))).lastrowid
    up = [{"ip": h["ip"], "state": "up", "reason": h.get("reason", "imported"), "mac": h.get("mac"), "vendor": h.get("vendor"),
           "ptr": h.get("hostname"), "user_name": None} for h in hosts]
    svc = [{"ip": h["ip"], "os": h.get("os"), "ports": [
        {"port": int(p["port"]), "proto": p.get("proto", "tcp"), "name": p.get("name") or p.get("service"),
         "product": p.get("product"), "version": p.get("version"), "extrainfo": p.get("extrainfo"),
         "tunnel": p.get("tunnel")} for p in h.get("services", [])]} for h in hosts]
    sigs = signatures.load_all() if fingerprint_web else []
    if not fingerprint_web:
        for s in svc:
            for p in s["ports"]:
                p["_noweb"] = True
    record_chunk(run_id, ips, up, svc, sigs)
    stats = finalize(run_id, params)
    with db.tx() as c:
        c.execute("UPDATE scan_runs SET status='completed', finished=?, chunks_done=1, stats=? WHERE id=?",
                  (db.now(), db.jdump(stats), run_id))
    return run_id
