"""REST API + dashboard. Uruchomienie: uvicorn aegis.api:app --host 0.0.0.0 --port 8000"""
import csv
import io
import ipaddress
import json
import logging
import time
from pathlib import Path
from typing import Any, Optional

from fastapi import Body, Depends, FastAPI, File, HTTPException, Query, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles

from . import auth, config, db, defectdojo, scanner, scheduler, signatures, targets, wifi
from .crypto import decrypt, encrypt

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logging.getLogger("httpx").setLevel(logging.WARNING)
log = logging.getLogger("aegis.api")
STATIC = Path(__file__).parent / "static"

app = FastAPI(title="AEGIS-MESH", version="1.0", description="Attack Surface Intelligence middleware (nmap + HTTP + Wi-Fi -> DefectDojo)")
app.mount("/static", StaticFiles(directory=STATIC), name="static")

R = auth.require


@app.on_event("startup")
def startup() -> None:
    db.init()
    pw = auth.bootstrap()
    if pw:
        log.warning("Utworzono konto '%s' z haslem: %s  (zmien je po zalogowaniu)", config.ADMIN_USER, pw)
    # przebiegi przerwane restartem wracaja do kolejki
    with db.tx() as c:
        c.execute("UPDATE scan_runs SET status='paused' WHERE status='running' AND kind='scan' AND schedule_id IS NOT NULL")
        c.execute("UPDATE scan_runs SET status='failed', error='przerwany restartem serwera' WHERE status='running'")
    if config.SCHEDULER_ENABLED:
        scheduler.start()


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    return (STATIC / "index.html").read_text(encoding="utf-8")


@app.get("/api/health")
def health() -> dict:
    return {"ok": True, "time": time.time()}


# ------------------------------------------------------------------ autoryzacja
@app.post("/api/auth/login")
def login(body: dict = Body(...)) -> dict:
    res = auth.login(body.get("username", ""), body.get("password", ""))
    db.audit(body.get("username"), "login", {"ok": bool(res)})
    if not res:
        raise HTTPException(401, "zly login lub haslo")
    return res


@app.post("/api/auth/logout")
def logout(request: Request, user=Depends(auth.current_user)) -> dict:
    auth.logout(request.headers["authorization"][7:])
    return {"ok": True}


@app.get("/api/me")
def me(user=Depends(auth.current_user)) -> dict:
    return user


# ------------------------------------------------------------------ dashboard
@app.get("/api/dashboard")
def dashboard(user=Depends(R("read"))) -> dict:
    counts = {r["status"]: r["n"] for r in db.q("SELECT status, COUNT(*) n FROM hosts GROUP BY status")}
    svc = db.q1("SELECT COUNT(*) n FROM services WHERE status!='GONE'")["n"]
    last = db.q("SELECT id, kind, status, created, started, finished, active_seconds, chunks_done, chunks_total, stats, "
                "error, dojo_status FROM scan_runs ORDER BY id DESC LIMIT 8")
    for r in last:
        r["stats"] = db.jload(r["stats"])
        r["dojo_status"] = db.jload(r["dojo_status"])
    changes = db.q("SELECT * FROM changes WHERE acknowledged=0 ORDER BY priority DESC, ts DESC LIMIT 40")
    interesting = db.q("SELECT h.id, h.ip, h.hostname, h.status, h.interest, h.user_name FROM hosts h "
                       "WHERE h.interest>0 ORDER BY h.interest DESC LIMIT 10")
    techs: dict[str, int] = {}
    for r in db.q("SELECT name, COUNT(DISTINCT service_id) n FROM signature_hits WHERE category IN "
                  "('cms','framework','server','iot','devops','database') GROUP BY name ORDER BY n DESC LIMIT 12"):
        techs[r["name"]] = r["n"]
    wifi_alerts = db.q1("SELECT COUNT(*) n FROM wifi_aps WHERE classification IN ('EVIL_TWIN','HOTSPOT','ROGUE')")["n"]
    return {"hosts": counts, "services": svc, "runs": last, "changes": changes, "interesting": interesting,
            "technologies": techs, "wifi_alerts": wifi_alerts,
            "change_counts": {r["change"]: r["n"] for r in db.q(
                "SELECT change, COUNT(*) n FROM changes WHERE acknowledged=0 GROUP BY change")}}


# ------------------------------------------------------------------ cele
@app.get("/api/targets")
def list_targets(user=Depends(R("read"))) -> list:
    rows = db.q("SELECT * FROM targets ORDER BY id")
    for r in rows:
        r["notes"] = decrypt(r.pop("notes_enc"))
    return rows


@app.post("/api/targets")
def add_targets(body: dict = Body(...), user=Depends(R("create"))) -> dict:
    """{"values": "10.0.0.0/24\\nexample.org", "owner": "...", "tags": "..."} albo {"items": [...]}"""
    items = body.get("items") or [{"value": v, "owner": body.get("owner"), "tags": body.get("tags"), "notes": body.get("notes")}
                                  for v in str(body.get("values", "")).replace(",", "\n").splitlines() if v.strip()]
    res = targets.add_targets(items, "manual")
    db.audit(user["username"], "targets_add", res)
    return res


@app.post("/api/targets/import")
async def import_targets(file: UploadFile = File(...), user=Depends(R("create"))) -> dict:
    text = (await file.read()).decode("utf-8-sig")
    kind = "json" if file.filename.lower().endswith(".json") or text.lstrip().startswith(("[", "{")) else "csv"
    try:
        items = targets.parse_json(text) if kind == "json" else targets.parse_csv(text)
    except (ValueError, json.JSONDecodeError) as e:
        raise HTTPException(400, f"nie mozna odczytac pliku: {e}")
    res = targets.add_targets(items, kind)
    db.audit(user["username"], "targets_import", {"file": file.filename, **res})
    return res


@app.patch("/api/targets/{tid}")
def edit_target(tid: int, body: dict = Body(...), user=Depends(R("modify"))) -> dict:
    t = db.q1("SELECT * FROM targets WHERE id=?", (tid,))
    if not t:
        raise HTTPException(404)
    value, kind = t["value"], t["kind"]
    if "value" in body and body["value"] != value:
        value, kind = targets.classify(body["value"])
    with db.tx() as c:
        c.execute("UPDATE targets SET value=?, kind=?, owner=?, tags=?, enabled=?, notes_enc=? WHERE id=?",
                  (value, kind, body.get("owner", t["owner"]), body.get("tags", t["tags"]),
                   int(body.get("enabled", t["enabled"])),
                   encrypt(body["notes"]) if "notes" in body else t["notes_enc"], tid))
    db.audit(user["username"], "target_edit", {"id": tid, **{k: v for k, v in body.items() if k != "notes"}})
    return {"ok": True}


@app.delete("/api/targets/{tid}")
def delete_target(tid: int, user=Depends(R("delete"))) -> dict:
    with db.tx() as c:
        c.execute("DELETE FROM targets WHERE id=?", (tid,))
    db.audit(user["username"], "target_delete", {"id": tid})
    return {"ok": True}


# ------------------------------------------------------------------ harmonogramy
SCHED_FIELDS = ("name", "target_ids", "interval_minutes", "window_start", "window_end", "ports", "max_rate",
                "parallel_chunks", "enabled")


def _check_sched(body: dict) -> dict:
    out = {k: body[k] for k in SCHED_FIELDS if k in body}
    for k in ("window_start", "window_end"):
        if out.get(k):
            h, m = out[k].split(":")
            if not (0 <= int(h) < 24 and 0 <= int(m) < 60):
                raise HTTPException(400, f"{k}: format HH:MM")
    if "target_ids" in out:
        out["target_ids"] = db.jdump(out["target_ids"]) if out["target_ids"] else None
    if out.get("interval_minutes") is not None and int(out["interval_minutes"]) < 5:
        raise HTTPException(400, "interval_minutes >= 5")
    return out


@app.get("/api/schedules")
def list_schedules(user=Depends(R("read"))) -> list:
    rows = db.q("SELECT * FROM schedules ORDER BY id")
    for r in rows:
        r["target_ids"] = db.jload(r["target_ids"])
        r["in_window"], deadline = scheduler.window_deadline(r)
    return rows


@app.post("/api/schedules")
def add_schedule(body: dict = Body(...), user=Depends(R("create"))) -> dict:
    data = _check_sched({"interval_minutes": 1440, "enabled": 1, **body})
    if not data.get("name"):
        raise HTTPException(400, "podaj nazwe")
    cols = ",".join(data)
    with db.tx() as c:
        sid = c.execute(f"INSERT INTO schedules({cols}) VALUES ({','.join('?' * len(data))})", tuple(data.values())).lastrowid
    db.audit(user["username"], "schedule_add", body)
    return {"id": sid}


@app.patch("/api/schedules/{sid}")
def edit_schedule(sid: int, body: dict = Body(...), user=Depends(R("modify"))) -> dict:
    data = _check_sched(body)
    if data:
        with db.tx() as c:
            c.execute(f"UPDATE schedules SET {', '.join(k + '=?' for k in data)} WHERE id=?", (*data.values(), sid))
    db.audit(user["username"], "schedule_edit", {"id": sid, **body})
    return {"ok": True}


@app.delete("/api/schedules/{sid}")
def delete_schedule(sid: int, user=Depends(R("delete"))) -> dict:
    with db.tx() as c:
        c.execute("DELETE FROM schedules WHERE id=?", (sid,))
    db.audit(user["username"], "schedule_delete", {"id": sid})
    return {"ok": True}


# ------------------------------------------------------------------ przebiegi
def _run_out(r: dict) -> dict:
    r = dict(r)
    r.pop("pending", None)
    for k in ("params", "stats", "chunk_stats", "dojo_status"):
        r[k] = db.jload(r.get(k))
    if r.get("params"):
        r["params"].pop("targets", None)
    r["running"] = scanner.is_running(r["id"])
    end = r.get("finished") or time.time()
    r["duration_seconds"] = round(r["active_seconds"] if r["status"] in ("completed", "paused") else
                                  (end - r["started"]) if r.get("started") else 0, 1)
    cs = r.get("chunk_stats") or []
    if cs:
        r["avg_seconds_per_address"] = round(sum(x["seconds"] for x in cs) / max(1, sum(x["size"] for x in cs)), 3)
    r["chunk_stats"] = cs[-20:]
    return r


@app.get("/api/runs")
def list_runs(limit: int = 50, user=Depends(R("read"))) -> list:
    return [_run_out(r) for r in db.q("SELECT * FROM scan_runs ORDER BY id DESC LIMIT ?", (limit,))]


@app.get("/api/runs/{rid}")
def get_run(rid: int, user=Depends(R("read"))) -> dict:
    r = db.q1("SELECT * FROM scan_runs WHERE id=?", (rid,))
    if not r:
        raise HTTPException(404)
    out = _run_out(r)
    out["pending_chunks"] = len(db.jload(r["pending"], []))
    out["changes"] = db.q("SELECT * FROM changes WHERE run_id=? ORDER BY priority DESC, id", (rid,))
    return out


@app.post("/api/runs")
def start_run(body: dict = Body(default={}), user=Depends(R("scan"))) -> dict:
    try:
        rid = scanner.create_run(body.get("target_ids"), None, body.get("ports"), body.get("max_rate"), body.get("parallel"))
    except ValueError as e:
        raise HTTPException(400, str(e))
    deadline = time.time() + int(body["max_minutes"]) * 60 if body.get("max_minutes") else None
    scanner.start_async(rid, deadline)
    db.audit(user["username"], "scan_start", {"run": rid, **body})
    return {"id": rid}


@app.post("/api/runs/{rid}/cancel")
def cancel_run(rid: int, user=Depends(R("scan"))) -> dict:
    scanner.cancel(rid)
    db.audit(user["username"], "scan_cancel", {"run": rid})
    return {"ok": True}


@app.post("/api/runs/{rid}/resume")
def resume_run(rid: int, body: dict = Body(default={}), user=Depends(R("scan"))) -> dict:
    r = db.q1("SELECT status FROM scan_runs WHERE id=?", (rid,))
    if not r or r["status"] not in ("paused", "failed", "queued"):
        raise HTTPException(400, "mozna wznowic tylko przebieg wstrzymany/nieudany")
    deadline = time.time() + int(body["max_minutes"]) * 60 if body.get("max_minutes") else None
    scanner.start_async(rid, deadline)
    db.audit(user["username"], "scan_resume", {"run": rid})
    return {"ok": True}


@app.delete("/api/runs/{rid}")
def delete_run(rid: int, user=Depends(R("delete"))) -> dict:
    if scanner.is_running(rid):
        raise HTTPException(400, "najpierw zatrzymaj przebieg")
    with db.tx() as c:
        c.execute("DELETE FROM scan_runs WHERE id=?", (rid,))
    db.audit(user["username"], "run_delete", {"run": rid})
    return {"ok": True}


@app.get("/api/compare")
def compare(a: int, b: int, user=Depends(R("read"))) -> dict:
    """Porownanie dwoch przebiegow: hosty i uslugi."""
    def snap(rid):
        hosts = {r["ip"] for r in db.q("SELECT h.ip FROM host_seen hs JOIN hosts h ON h.id=hs.host_id "
                                         "WHERE hs.run_id=? AND hs.alive=1", (rid,))}
        svcs = {(r["ip"], r["port"], r["proto"]) for r in db.q(
            "SELECT h.ip, s.port, s.proto FROM service_seen ss JOIN services s ON s.id=ss.service_id "
            "JOIN hosts h ON h.id=s.host_id WHERE ss.run_id=?", (rid,))}
        return hosts, svcs
    ha, sa = snap(a)
    hb, sb = snap(b)
    return {
        "hosts_new": sorted(hb - ha, key=lambda x: ipaddress.ip_address(x)),
        "hosts_gone": sorted(ha - hb, key=lambda x: ipaddress.ip_address(x)),
        "services_new": [f"{i}:{p}/{t}" for i, p, t in sorted(sb - sa)],
        "services_gone": [f"{i}:{p}/{t}" for i, p, t in sorted(sa - sb)],
        "changes_in_b": db.q("SELECT change, ip, port, detail FROM changes WHERE run_id=? ORDER BY priority DESC", (b,)),
    }


# ------------------------------------------------------------------ hosty i uslugi
USER_HOST_FIELDS = {"user_name", "user_owner", "user_tags", "user_criticality"}


def _host_out(h: dict) -> dict:
    h = dict(h)
    h["user_notes"] = decrypt(h.pop("user_notes_enc"))
    h["user_location"] = decrypt(h.pop("user_location_enc"))
    h["seen_hours"] = db.jload(h["seen_hours"], {})
    return h


@app.get("/api/hosts")
def list_hosts(status: Optional[str] = None, q: Optional[str] = None, with_services: bool = True,
               limit: int = Query(500, le=20000), user=Depends(R("read"))) -> list:
    sql, args = "SELECT * FROM hosts WHERE 1=1", []
    if status:
        sql += " AND status=?"
        args.append(status)
    if q:
        sql += " AND (ip LIKE ? OR hostname LIKE ? OR user_name LIKE ? OR user_tags LIKE ?)"
        args += [f"%{q}%"] * 4
    rows = [_host_out(h) for h in db.q(sql + " ORDER BY interest DESC, id LIMIT ?", (*args, limit))]
    if with_services and rows:
        ids = [h["id"] for h in rows]
        svc: dict[int, list] = {}
        for s in db.q(f"SELECT id, host_id, port, proto, name, product, version, status FROM services WHERE host_id IN "
                      f"({','.join('?' * len(ids))}) ORDER BY port", ids):
            svc.setdefault(s["host_id"], []).append(s)
        for h in rows:
            h["services"] = svc.get(h["id"], [])
    return sorted(rows, key=lambda h: (-h["interest"], ipaddress.ip_address(h["ip"])))


@app.get("/api/hosts/{hid}")
def get_host(hid: int, user=Depends(R("read"))) -> dict:
    h = db.q1("SELECT * FROM hosts WHERE id=?", (hid,))
    if not h:
        raise HTTPException(404)
    out = _host_out(h)
    out["services"] = []
    for s in db.q("SELECT * FROM services WHERE host_id=? ORDER BY port", (hid,)):
        s["user_notes"] = decrypt(s.pop("user_notes_enc"))
        o = db.q1("SELECT * FROM http_obs WHERE service_id=? ORDER BY ts DESC LIMIT 1", (s["id"],))
        if o:
            s["http"] = {**{k: o[k] for k in ("url", "final_url", "status_code", "title", "server", "favicon_hash", "interest")},
                         "technologies": db.jload(o["technologies"], []), "redirects": db.jload(o["redirects"], []),
                         "flags": db.jload(o["flags"], {}), "headers": decrypt(o["headers_enc"]),
                         "cookies": decrypt(o["cookies_enc"]), "tls": decrypt(o["tls_enc"]), "ts": o["ts"]}
        s["signatures"] = db.q("SELECT signature_id, name, category, severity, evidence, version, MAX(ts) ts FROM signature_hits "
                               "WHERE service_id=? GROUP BY signature_id ORDER BY ts DESC", (s["id"],))
        out["services"].append(s)
    out["history"] = db.q("SELECT hs.run_id, hs.alive, hs.ts FROM host_seen hs WHERE host_id=? ORDER BY run_id DESC LIMIT 30", (hid,))
    out["changes"] = db.q("SELECT * FROM changes WHERE ip=? ORDER BY ts DESC LIMIT 50", (h["ip"],))
    out["wifi_links"] = db.q("SELECT bssid, ssid, classification, link_confidence FROM wifi_aps WHERE linked_host_ip=?", (h["ip"],))
    return out


@app.patch("/api/hosts/{hid}")
def edit_host(hid: int, body: dict = Body(...), user=Depends(R("modify"))) -> dict:
    """Pola uzytkownika - niezalezne od stanu skanu i zachowywane przy kolejnych skanach."""
    sets, args = [], []
    for k in USER_HOST_FIELDS & body.keys():
        sets.append(f"{k}=?")
        args.append(body[k])
    if "user_notes" in body:
        sets.append("user_notes_enc=?")
        args.append(encrypt(body["user_notes"]))
    if "user_location" in body:
        sets.append("user_location_enc=?")
        args.append(encrypt(body["user_location"]) if body["user_location"] else None)
    if not sets:
        raise HTTPException(400, f"dozwolone pola: {sorted(USER_HOST_FIELDS | {'user_notes', 'user_location'})}")
    with db.tx() as c:
        c.execute(f"UPDATE hosts SET {', '.join(sets)}, updated=? WHERE id=?", (*args, time.time(), hid))
    db.audit(user["username"], "host_edit", {"id": hid, "fields": sorted(body)})
    return {"ok": True}


@app.delete("/api/hosts/{hid}")
def delete_host(hid: int, user=Depends(R("delete"))) -> dict:
    with db.tx() as c:
        c.execute("DELETE FROM hosts WHERE id=?", (hid,))
    db.audit(user["username"], "host_delete", {"id": hid})
    return {"ok": True}


@app.patch("/api/services/{sid}")
def edit_service(sid: int, body: dict = Body(...), user=Depends(R("modify"))) -> dict:
    sets, args = [], []
    if "user_tags" in body:
        sets.append("user_tags=?")
        args.append(body["user_tags"])
    if "user_false_positive" in body:
        sets.append("user_false_positive=?")
        args.append(int(bool(body["user_false_positive"])))
    if "user_notes" in body:
        sets.append("user_notes_enc=?")
        args.append(encrypt(body["user_notes"]))
    if not sets:
        raise HTTPException(400, "dozwolone pola: user_tags, user_false_positive, user_notes")
    with db.tx() as c:
        c.execute(f"UPDATE services SET {', '.join(sets)} WHERE id=?", (*args, sid))
    db.audit(user["username"], "service_edit", {"id": sid, "fields": sorted(body)})
    return {"ok": True}


@app.get("/api/changes")
def list_changes(run_id: Optional[int] = None, unacked: bool = False, limit: int = 500, user=Depends(R("read"))) -> list:
    sql, args = "SELECT * FROM changes WHERE 1=1", []
    if run_id:
        sql += " AND run_id=?"
        args.append(run_id)
    if unacked:
        sql += " AND acknowledged=0"
    rows = db.q(sql + " ORDER BY ts DESC LIMIT ?", (*args, limit))
    for r in rows:
        r["note"] = decrypt(r.pop("note_enc"))
    return rows


@app.patch("/api/changes/{cid}")
def edit_change(cid: int, body: dict = Body(...), user=Depends(R("modify"))) -> dict:
    with db.tx() as c:
        if "acknowledged" in body:
            c.execute("UPDATE changes SET acknowledged=? WHERE id=?", (int(bool(body["acknowledged"])), cid))
        if "note" in body:
            c.execute("UPDATE changes SET note_enc=? WHERE id=?", (encrypt(body["note"]), cid))
        if "priority" in body:
            c.execute("UPDATE changes SET priority=? WHERE id=?", (int(body["priority"]), cid))
    db.audit(user["username"], "change_edit", {"id": cid, **{k: v for k, v in body.items() if k != "note"}})
    return {"ok": True}


# ------------------------------------------------------------------ sygnatury
@app.get("/api/signatures")
def get_signatures(user=Depends(R("read"))) -> dict:
    return {"all": signatures.load_all(), "custom": db.get_setting("custom_signatures", []),
            "rule_types": sorted(signatures.ALLOWED_TYPES), "categories": sorted(signatures.ALLOWED_CATEGORIES)}


@app.put("/api/signatures/custom")
def put_signatures(body: Any = Body(...), user=Depends(R("create"))) -> dict:
    try:
        saved = signatures.save_custom(body if isinstance(body, list) else body.get("signatures", []))
    except signatures.SignatureError as e:
        raise HTTPException(400, str(e))
    db.audit(user["username"], "signatures_save", {"count": len(saved)})
    return {"saved": len(saved)}


# ------------------------------------------------------------------ import / eksport wynikow
@app.post("/api/import/results")
async def import_results(file: UploadFile = File(...), fingerprint_web: bool = True, user=Depends(R("create"))) -> dict:
    """JSON: [{"ip", "hostname"?, "mac"?, "services": [{"port","proto","name","product","version"}]}]
    lub eksport AEGIS; CSV: ip,port,proto,service,product,version,hostname."""
    text = (await file.read()).decode("utf-8-sig")
    hosts: dict[str, dict] = {}
    try:
        if file.filename.lower().endswith(".json") or text.lstrip().startswith(("[", "{")):
            data = json.loads(text)
            data = data.get("hosts", data) if isinstance(data, dict) else data
            for h in data:
                hosts[h["ip"]] = {"ip": h["ip"], "hostname": h.get("hostname"), "mac": h.get("mac"),
                                  "services": [s for s in h.get("services", []) if s.get("status") != "GONE"]}
        else:
            for row in csv.DictReader(io.StringIO(text)):
                h = hosts.setdefault(row["ip"], {"ip": row["ip"], "hostname": row.get("hostname") or None, "services": []})
                if row.get("port"):
                    h["services"].append({"port": int(row["port"]), "proto": row.get("proto") or "tcp",
                                          "name": row.get("service"), "product": row.get("product"), "version": row.get("version")})
        rid = scanner.import_results(list(hosts.values()), fingerprint_web)
    except (KeyError, ValueError, json.JSONDecodeError) as e:
        raise HTTPException(400, f"nieprawidlowy plik: {e}")
    db.audit(user["username"], "results_import", {"file": file.filename, "hosts": len(hosts), "run": rid})
    return {"run_id": rid, "hosts": len(hosts)}


@app.get("/api/export/hosts.{fmt}")
def export_hosts(fmt: str, status: Optional[str] = None, user=Depends(R("read"))):
    rows = list_hosts(status=status, q=None, with_services=True, limit=20000, user=user)
    db.audit(user["username"], "export_hosts", {"format": fmt})
    if fmt == "json":
        return JSONResponse({"exported": time.time(), "hosts": rows},
                            headers={"Content-Disposition": "attachment; filename=aegis_hosts.json"})
    if fmt == "csv":
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["ip", "hostname", "status", "confidence", "interest", "port", "proto", "service", "product", "version",
                    "service_status", "user_name", "user_owner", "user_tags", "first_seen", "last_seen"])
        for h in rows:
            for s in h["services"] or [{}]:
                w.writerow([h["ip"], h["hostname"], h["status"], h["confidence"], h["interest"], s.get("port"), s.get("proto"),
                            s.get("name"), s.get("product"), s.get("version"), s.get("status"), h["user_name"],
                            h["user_owner"], h["user_tags"], h["first_seen"], h["last_seen"]])
        return Response(buf.getvalue(), media_type="text/csv",
                        headers={"Content-Disposition": "attachment; filename=aegis_hosts.csv"})
    raise HTTPException(400, "format: json | csv")


@app.get("/api/export/changes.csv")
def export_changes(run_id: Optional[int] = None, user=Depends(R("read"))):
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["ts", "run_id", "object", "ip", "port", "change", "priority", "detail", "acknowledged"])
    for c in list_changes(run_id=run_id, unacked=False, limit=100000, user=user):
        w.writerow([c["ts"], c["run_id"], c["object"], c["ip"], c["port"], c["change"], c["priority"], c["detail"], c["acknowledged"]])
    return Response(buf.getvalue(), media_type="text/csv", headers={"Content-Disposition": "attachment; filename=aegis_changes.csv"})


@app.get("/api/export/run/{rid}/dojo/{kind}")
def export_dojo_file(rid: int, kind: str, user=Depends(R("read"))):
    files = defectdojo.prepare_files(rid)
    if kind not in files:
        raise HTTPException(404, f"dostepne: {sorted(files)}")
    return FileResponse(files[kind], filename=files[kind].name)


# ------------------------------------------------------------------ Wi-Fi / telefon Aegis
@app.post("/api/mobile-telemetry")
def mobile_telemetry(body: dict = Body(...), user=Depends(R("telemetry"))) -> dict:
    sensor = f"{user['username']}/{str(body.get('sensor_id', 'phone'))[:40]}"
    return wifi.ingest(sensor, body)


@app.get("/api/wifi/aps")
def wifi_aps(user=Depends(R("read"))) -> list:
    rows = db.q("SELECT * FROM wifi_aps ORDER BY CASE classification WHEN 'EVIL_TWIN' THEN 0 WHEN 'ROGUE' THEN 1 "
                "WHEN 'HOTSPOT' THEN 2 WHEN 'UNKNOWN' THEN 3 ELSE 4 END, best_rssi DESC")
    for r in rows:
        r["reasons"] = db.jload(r["reasons"], [])
        r["location"] = decrypt(r.pop("location_enc"))
    return rows


@app.get("/api/wifi/{bssid}/live")
def wifi_live(bssid: str, seconds: int = 120, user=Depends(auth.current_user)) -> list:
    if not ({"read", "telemetry"} & set(user["permissions"])):
        raise HTTPException(403)
    return wifi.live(bssid, seconds)


@app.get("/api/wifi/known")
def known_aps(user=Depends(R("read"))) -> list:
    return db.q("SELECT * FROM known_aps ORDER BY ssid, bssid")


@app.post("/api/wifi/known/import")
async def import_known(file: UploadFile = File(...), user=Depends(R("create"))) -> dict:
    """CSV: bssid,ssid,security,building,floor,room"""
    text = (await file.read()).decode("utf-8-sig")
    n = wifi.import_known(list(csv.DictReader(io.StringIO(text))))
    db.audit(user["username"], "known_aps_import", {"count": n})
    return {"imported": n}


# ------------------------------------------------------------------ DefectDojo
@app.get("/api/integrations/defectdojo")
def get_dojo(user=Depends(R("integrations"))) -> dict:
    s = defectdojo.settings()
    s["api_key"] = "********" if s["api_key"] else None
    return s


@app.put("/api/integrations/defectdojo")
def put_dojo(body: dict = Body(...), user=Depends(R("integrations"))) -> dict:
    for k in ("url", "product_type", "product", "engagement", "verify_tls", "auto_push"):
        if k in body:
            db.set_setting(f"dojo_{k}", body[k])
    if body.get("api_key") and body["api_key"] != "********":
        db.set_setting("dojo_api_key", body["api_key"], secret=True)
    db.audit(user["username"], "dojo_settings", {k: v for k, v in body.items() if k != "api_key"})
    return {"ok": True}


@app.post("/api/integrations/defectdojo/test")
def test_dojo(user=Depends(R("integrations"))) -> dict:
    try:
        return defectdojo.test_connection()
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": str(e)[:300]}


@app.post("/api/runs/{rid}/push-dojo")
def push_dojo(rid: int, user=Depends(R("integrations"))) -> dict:
    try:
        res = defectdojo.push_run(rid)
    except Exception as e:  # noqa: BLE001
        raise HTTPException(502, f"DefectDojo: {e}")
    db.audit(user["username"], "dojo_push", {"run": rid})
    return res


# ------------------------------------------------------------------ uzytkownicy i role
@app.get("/api/users")
def list_users(user=Depends(R("admin"))) -> list:
    return db.q("SELECT id, username, role, active, created, api_token_hash IS NOT NULL AS has_api_token FROM users ORDER BY id")


@app.post("/api/users")
def add_user(body: dict = Body(...), user=Depends(R("admin"))) -> dict:
    if not db.q1("SELECT 1 FROM roles WHERE name=?", (body.get("role"),)):
        raise HTTPException(400, "nieznana rola")
    from .crypto import hash_password
    pw = body.get("password")
    if pw is not None and len(pw) < 10:
        raise HTTPException(400, "haslo min. 10 znakow")
    try:
        with db.tx() as c:
            uid = c.execute("INSERT INTO users(username, pw_hash, role, created) VALUES (?,?,?,?)",
                            (body["username"], hash_password(pw) if pw else None, body["role"], time.time())).lastrowid
    except Exception:
        raise HTTPException(400, "uzytkownik juz istnieje")
    out = {"id": uid}
    if body.get("api_token") or body["role"] == "sensor":
        out["api_token"] = auth.issue_api_token(uid)
    db.audit(user["username"], "user_add", {"username": body["username"], "role": body["role"]})
    return out


@app.patch("/api/users/{uid}")
def edit_user(uid: int, body: dict = Body(...), user=Depends(R("admin"))) -> dict:
    from .crypto import hash_password
    with db.tx() as c:
        if "role" in body:
            if not c.execute("SELECT 1 FROM roles WHERE name=?", (body["role"],)).fetchone():
                raise HTTPException(400, "nieznana rola")
            c.execute("UPDATE users SET role=? WHERE id=?", (body["role"], uid))
        if "active" in body:
            c.execute("UPDATE users SET active=? WHERE id=?", (int(bool(body["active"])), uid))
            c.execute("DELETE FROM sessions WHERE user_id=?", (uid,))
        if body.get("password"):
            if len(body["password"]) < 10:
                raise HTTPException(400, "haslo min. 10 znakow")
            c.execute("UPDATE users SET pw_hash=? WHERE id=?", (hash_password(body["password"]), uid))
    db.audit(user["username"], "user_edit", {"id": uid, "fields": sorted(k for k in body if k != "password")})
    return {"ok": True}


@app.post("/api/users/{uid}/token")
def user_token(uid: int, user=Depends(R("admin"))) -> dict:
    db.audit(user["username"], "api_token_issue", {"id": uid})
    return {"api_token": auth.issue_api_token(uid)}


@app.get("/api/roles")
def list_roles(user=Depends(R("read"))) -> dict:
    rows = db.q("SELECT * FROM roles ORDER BY builtin DESC, name")
    for r in rows:
        r["permissions"] = db.jload(r["permissions"], [])
    return {"roles": rows, "permissions": auth.PERMISSIONS}


@app.post("/api/roles")
def add_role(body: dict = Body(...), user=Depends(R("admin"))) -> dict:
    perms = body.get("permissions", [])
    bad = set(perms) - set(auth.PERMISSIONS)
    if bad or not body.get("name"):
        raise HTTPException(400, f"nazwa wymagana; nieznane uprawnienia: {sorted(bad)}")
    if body["name"] in auth.BUILTIN_ROLES:
        raise HTTPException(400, "nie mozna nadpisac roli wbudowanej")
    with db.tx() as c:
        c.execute("INSERT OR REPLACE INTO roles(name, permissions, builtin, description) VALUES (?,?,0,?)",
                  (body["name"], db.jdump(perms), body.get("description")))
    db.audit(user["username"], "role_save", body)
    return {"ok": True}


@app.delete("/api/roles/{name}")
def delete_role(name: str, user=Depends(R("admin"))) -> dict:
    if name in auth.BUILTIN_ROLES:
        raise HTTPException(400, "rola wbudowana")
    if db.q1("SELECT 1 FROM users WHERE role=?", (name,)):
        raise HTTPException(400, "rola jest przypisana do uzytkownikow")
    with db.tx() as c:
        c.execute("DELETE FROM roles WHERE name=?", (name,))
    db.audit(user["username"], "role_delete", {"name": name})
    return {"ok": True}


@app.get("/api/audit")
def get_audit(limit: int = 200, user=Depends(R("admin"))) -> list:
    return db.q("SELECT * FROM audit ORDER BY id DESC LIMIT ?", (limit,))
