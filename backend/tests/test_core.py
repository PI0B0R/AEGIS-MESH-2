"""Testy logiki bez sieci: statusy hostow (NEW/UNSTABLE/GONE/RETURNED), okno czasowe, sygnatury, Wi-Fi.
Uruchomienie: cd backend && python -m pytest -q
"""
import os
import tempfile
import time

os.environ["AEGIS_DATA_DIR"] = tempfile.mkdtemp()
os.environ["AEGIS_CHUNK"] = "2"

import pytest  # noqa: E402

from aegis import db, nmap_runner, scanner, signatures, targets, wifi  # noqa: E402

UP: set = set()
DELAY = {"s": 0.0}


def fake_run(tlist, args, out, timeout):
    if DELAY["s"]:
        if timeout is not None and DELAY["s"] > timeout:
            raise nmap_runner.ChunkTimeout("test")
        time.sleep(DELAY["s"])
    if "-sn" in args:
        return {"hosts": [{"ip": t, "state": "up", "reason": "echo-reply", "mac": None, "vendor": None, "ptr": None,
                           "user_name": None, "ports": [], "os": None} for t in tlist if t in UP]}
    return {"hosts": [{"ip": t, "os": None, "ports": [{"port": 22, "proto": "tcp", "name": "ssh", "product": "OpenSSH",
                                                       "version": "9.6", "extrainfo": None, "tunnel": None, "conf": 10}]}
                      for t in tlist]}


@pytest.fixture(autouse=True, scope="module")
def setup():
    db.init()
    nmap_runner.run = fake_run
    targets.add_targets([{"value": "10.0.0.0/29"}], "manual")


def scan(up):
    UP.clear()
    UP.update(up)
    rid = scanner.create_run()
    scanner.execute(rid)
    return rid, {h["ip"]: h for h in db.q("SELECT * FROM hosts")}


def test_host_lifecycle():
    base = {"10.0.0.1", "10.0.0.2", "10.0.0.3"}
    _, h = scan(base)
    assert h["10.0.0.3"]["status"] == "NEW"
    _, h = scan(base - {"10.0.0.3"})
    assert h["10.0.0.3"]["status"] == "UNSTABLE"
    scan(base - {"10.0.0.3"})
    rid, h = scan(base - {"10.0.0.3"})
    assert h["10.0.0.3"]["status"] == "GONE"
    assert db.q1("SELECT 1 FROM changes WHERE run_id=? AND change='GONE' AND ip='10.0.0.3'", (rid,))
    rid, h = scan(base)
    assert db.q1("SELECT 1 FROM changes WHERE run_id=? AND change='RETURNED' AND ip='10.0.0.3'", (rid,))
    assert h["10.0.0.1"]["status"] == "ACTIVE"


def test_user_edits_survive_scans():
    hid = db.q1("SELECT id FROM hosts WHERE ip='10.0.0.1'")["id"]
    with db.tx() as c:
        c.execute("UPDATE hosts SET user_name='Serwer A' WHERE id=?", (hid,))
    scan({"10.0.0.1"})
    assert db.q1("SELECT user_name FROM hosts WHERE id=?", (hid,))["user_name"] == "Serwer A"


def test_time_window_pause_and_resume():
    UP.update({"10.0.0.1", "10.0.0.2"})
    rid = scanner.create_run(parallel=1)
    DELAY["s"] = 3
    scanner.execute(rid, deadline=time.time() + 17)
    r = db.q1("SELECT * FROM scan_runs WHERE id=?", (rid,))
    assert r["status"] == "paused" and db.jload(r["pending"])
    DELAY["s"] = 0
    scanner.execute(rid, deadline=time.time() + 60)
    assert db.q1("SELECT status FROM scan_runs WHERE id=?", (rid,))["status"] == "completed"


def test_signature_validation():
    with pytest.raises(signatures.SignatureError):
        signatures.validate({"id": "x1", "name": "x", "path": "/a?b=1", "rules": [{"type": "body", "regex": "a"}]})
    with pytest.raises(signatures.SignatureError):
        signatures.validate({"id": "x2", "name": "x", "path": "/admin", "rules": [{"type": "status", "code": 200}]})
    ok = signatures.validate({"id": "x3", "name": "x", "path": "/admin", "rules": [{"type": "title", "regex": "Admin"}]})
    hits = signatures.evaluate([ok], {"/admin": {"status": 200, "headers": {}, "cookies": [], "body": "", "title": "Admin panel"}})
    assert hits and hits[0]["signature_id"] == "x3"


def test_wifi_classification():
    known = {"aa:bb:cc:00:00:01": {"security": "802.1X"}}
    ssids = {"AGH-LAB": {"802.1X"}}
    assert wifi.classify("aa:bb:cc:00:00:01", "AGH-LAB", "802.1X", known, ssids)[0] == "KNOWN"
    cls, conf, _ = wifi.classify("de:ad:be:ef:00:10", "AGH-LAB", "OPEN", known, ssids)
    assert cls == "EVIL_TWIN" and conf >= 85
    assert wifi.classify("62:11:22:33:44:55", "iPhone (Marek)", "WPA2-PSK", known, ssids)[0] == "HOTSPOT"
    assert wifi.norm_security("[WPA2-EAP-CCMP][ESS]") == "802.1X"
    assert wifi.freq_to_channel(5180) == 36
    loc = wifi.trusted_location({"lat": 1, "lng": 2, "accuracy": 120, "time": time.time() * 1000, "source": "gps"}, time.time())
    assert "lat" not in loc and "gps_rejected" in loc
