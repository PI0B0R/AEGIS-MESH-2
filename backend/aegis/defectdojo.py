"""Integracja z DefectDojo (API v2).

- XML nmapa -> wbudowany parser "Nmap Scan" (reimport: kolejne przebiegi aktualizuja ten sam test).
- Obserwacje AEGIS (HTTP, sygnatury, zmiany, Wi-Fi) -> "Generic Findings Import" jako findingi Info/Low.
- Lokalizacja -> tagi na endpointach (geo:, budynek:, pietro:, sala:).
Kazdy finding ma staly unique_id_from_tool, wiec ponowny import nie tworzy duplikatow.
"""
import datetime
import json
import logging
from pathlib import Path
from typing import Optional

import httpx

from . import config, db
from .crypto import decrypt

log = logging.getLogger("aegis.dojo")


def settings() -> dict:
    return {
        "url": (db.get_setting("dojo_url") or "").rstrip("/"),
        "api_key": db.get_setting("dojo_api_key"),
        "product_type": db.get_setting("dojo_product_type", "AEGIS-MESH"),
        "product": db.get_setting("dojo_product", "Siec AGH"),
        "engagement": db.get_setting("dojo_engagement", "Discovery cykliczny"),
        "verify_tls": db.get_setting("dojo_verify_tls", True),
        "auto_push": db.get_setting("dojo_auto_push", False),
    }


def _client(s: dict) -> httpx.Client:
    if not s["url"] or not s["api_key"]:
        raise RuntimeError("DefectDojo nie jest skonfigurowany (URL i klucz API w ustawieniach)")
    return httpx.Client(base_url=s["url"], headers={"Authorization": f"Token {s['api_key']}"},
                        verify=s["verify_tls"], timeout=120)


def test_connection() -> dict:
    s = settings()
    with _client(s) as c:
        r = c.get("/api/v2/user_contact_infos/", params={"limit": 1})
        if r.status_code == 404:
            r = c.get("/api/v2/products/", params={"limit": 1})
        return {"ok": r.status_code < 400, "status": r.status_code}


def _reimport(c: httpx.Client, s: dict, scan_type: str, test_title: str, file_path: Path, close_old: bool) -> dict:
    data = {
        "scan_type": scan_type, "test_title": test_title, "auto_create_context": "true",
        "product_type_name": s["product_type"], "product_name": s["product"], "engagement_name": s["engagement"],
        "close_old_findings": "true" if close_old else "false", "minimum_severity": "Info",
        "active": "true", "verified": "false", "scan_date": datetime.date.today().isoformat(),
        "tags": "aegis-mesh",
    }
    with open(file_path, "rb") as fh:
        r = c.post("/api/v2/reimport-scan/", data=data, files={"file": (file_path.name, fh)})
    if r.status_code >= 400:
        raise RuntimeError(f"{scan_type}: HTTP {r.status_code} {r.text[:300]}")
    body = r.json()
    return {"test": body.get("test") or body.get("test_id"), "statistics": body.get("statistics")}


def _finding(title, desc, uid, severity="Info", host=None, port=None, proto=None, component=None, version=None, tags=None):
    f = {"title": title[:500], "description": desc, "severity": severity, "date": datetime.date.today().isoformat(),
         "unique_id_from_tool": uid, "static_finding": False, "dynamic_finding": True}
    if host:
        ep = {"host": host}
        if port:
            ep["port"] = int(port)
        if proto:
            ep["protocol"] = proto
        f["endpoints"] = [ep]
    if component:
        f["component_name"] = component
        if version:
            f["component_version"] = version
    if tags:
        f["tags"] = tags
    return f


def _location_tags(loc: Optional[dict]) -> list[str]:
    if not loc:
        return []
    tags = []
    if loc.get("lat") is not None:
        tags.append(f"geo:{loc['lat']:.5f},{loc['lng']:.5f}")
    for k, name in (("building", "budynek"), ("floor", "pietro"), ("room", "sala")):
        if loc.get(k):
            tags.append(f"{name}:{loc[k]}".replace(" ", "_"))
    return tags


def build_generic(run_id: int) -> dict:
    findings = []
    hosts = {h["id"]: h for h in db.q("SELECT * FROM hosts")}
    for o in db.q("SELECT o.*, s.port, s.host_id FROM http_obs o JOIN services s ON s.id=o.service_id WHERE o.run_id=?", (run_id,)):
        h = hosts[o["host_id"]]
        flags = db.jload(o["flags"], {})
        tls = decrypt(o["tls_enc"])
        desc = [f"URL: {o['url']}", f"Kod HTTP: {o['status_code']}", f"Tytul: {o['title']}",
                f"Technologie: {', '.join(db.jload(o['technologies'], []))}"]
        if flags.get("reasons"):
            desc.append("Powody priorytetu: " + "; ".join(flags["reasons"]))
        if tls:
            desc.append(f"TLS: CN={tls['subject_cn']} wystawca={tls['issuer_cn']} wazny do {tls['not_after']} ({tls['tls_version']})")
        loc = decrypt(h["user_location_enc"])
        sev = "Low" if o["interest"] >= 5 else "Info"
        findings.append(_finding(f"HTTP: {o['title'] or o['url']}", "\n".join(desc), f"aegis:http:{h['ip']}:{o['port']}",
                                 sev, h["ip"], o["port"], o["url"].split(":")[0], tags=_location_tags(loc) or None))
    for hit in db.q("SELECT sh.*, s.port, s.host_id FROM signature_hits sh JOIN services s ON s.id=sh.service_id WHERE sh.run_id=?", (run_id,)):
        h = hosts[hit["host_id"]]
        findings.append(_finding(f"{hit['name']} na {h['ip']}:{hit['port']}",
                                 f"Sygnatura: {hit['signature_id']} ({hit['category']})\nDowod: {hit['evidence']}",
                                 f"aegis:sig:{hit['signature_id']}:{h['ip']}:{hit['port']}",
                                 "Low" if hit["severity"] in ("low", "medium") else "Info", h["ip"], hit["port"],
                                 component=hit["name"], version=hit["version"]))
    for ch in db.q("SELECT * FROM changes WHERE run_id=? AND object!='wifi'", (run_id,)):
        findings.append(_finding(f"[{ch['change']}] {ch['ip']}{':' + str(ch['port']) if ch['port'] else ''}",
                                 ch["detail"] or "", f"aegis:change:{ch['change']}:{ch['ip']}:{ch['port']}:{run_id}",
                                 "Info", ch["ip"], ch["port"]))
    return {"findings": findings}


def build_wifi() -> dict:
    findings = []
    for ap in db.q("SELECT * FROM wifi_aps WHERE classification IN ('EVIL_TWIN','HOTSPOT','ROGUE')"):
        est = decrypt(ap["location_enc"]) or {}
        where = ", ".join(f"{k}: {est[k]}" for k in ("building", "floor", "room", "lat", "lng") if est.get(k) is not None)
        desc = (f"SSID: {ap['ssid']}\nBSSID: {ap['bssid']}\nZabezpieczenie: {ap['security']}\nKanal: {ap['channel']}\n"
                f"Pewnosc: {ap['confidence']}%\nPowody: {'; '.join(db.jload(ap['reasons'], []))}\n"
                f"Szacowane miejsce: {where or 'brak'}\n"
                f"Powiazany host: {ap['linked_host_ip'] or 'brak'} ({ap['link_confidence'] or 0}%)")
        findings.append(_finding(f"Wi-Fi {ap['classification']}: {ap['ssid'] or '(ukryty)'} {ap['bssid']}", desc,
                                 f"aegis:wifi:{ap['bssid']}", "Low" if ap["classification"] == "EVIL_TWIN" else "Info",
                                 ap["linked_host_ip"], tags=_location_tags(est) or None))
    return {"findings": findings}


def tag_endpoints(c: httpx.Client) -> int:
    n = 0
    for h in db.q("SELECT ip, user_location_enc, user_tags FROM hosts WHERE user_location_enc IS NOT NULL"):
        tags = _location_tags(decrypt(h["user_location_enc"])) + [t.strip() for t in (h["user_tags"] or "").split(",") if t.strip()]
        if not tags:
            continue
        r = c.get("/api/v2/endpoints/", params={"host": h["ip"], "limit": 50})
        if r.status_code >= 400:
            continue
        for ep in r.json().get("results", []):
            merged = sorted(set(ep.get("tags") or []) | set(tags))
            if c.patch(f"/api/v2/endpoints/{ep['id']}/", json={"tags": merged}).status_code < 400:
                n += 1
    return n


def prepare_files(run_id: int) -> dict[str, Path]:
    out = config.RUNS_DIR / str(run_id) / "dojo"
    out.mkdir(parents=True, exist_ok=True)
    files = {}
    merged = config.RUNS_DIR / str(run_id) / "nmap_merged.xml"
    if merged.exists():
        files["nmap"] = merged
    g = out / "aegis_findings.json"
    g.write_text(json.dumps(build_generic(run_id), ensure_ascii=False, indent=1))
    files["generic"] = g
    w = out / "aegis_wifi.json"
    w.write_text(json.dumps(build_wifi(), ensure_ascii=False, indent=1))
    files["wifi"] = w
    return files


def push_run(run_id: int) -> dict:
    s = settings()
    files = prepare_files(run_id)
    result = {}
    with _client(s) as c:
        if "nmap" in files:
            result["nmap"] = _reimport(c, s, "Nmap Scan", "AEGIS nmap discovery", files["nmap"], close_old=True)
        if json.loads(files["generic"].read_text())["findings"]:
            result["observations"] = _reimport(c, s, "Generic Findings Import", "AEGIS obserwacje", files["generic"], close_old=False)
        if json.loads(files["wifi"].read_text())["findings"]:
            result["wifi"] = _reimport(c, s, "Generic Findings Import", "AEGIS Wi-Fi", files["wifi"], close_old=True)
        result["tagged_endpoints"] = tag_endpoints(c)
    with db.tx() as cx:
        cx.execute("UPDATE scan_runs SET dojo_status=? WHERE id=?", (db.jdump({"ok": True, **result}), run_id))
    return result


def push_run_safe(run_id: int) -> None:
    try:
        push_run(run_id)
    except Exception as e:  # noqa: BLE001
        log.warning("DefectDojo: %s", e)
        with db.tx() as c:
            c.execute("UPDATE scan_runs SET dojo_status=? WHERE id=?", (db.jdump({"ok": False, "error": str(e)[:300]}), run_id))
