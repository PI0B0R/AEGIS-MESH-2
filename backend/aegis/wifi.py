"""Warstwa Wi-Fi z telefonu Aegis: przyjmowanie pomiarow, klasyfikacja AP, pozycja i powiazanie z hostami."""
import re
import time
from typing import Optional

from . import db
from .crypto import decrypt, encrypt

GPS_MAX_ACCURACY_M = 50
GPS_MAX_AGE_S = 15
HOTSPOT_SSID = re.compile(r"(iphone|android|galaxy|redmi|xiaomi|huawei|pixel|oneplus|direct-|hotspot|mi phone|"
                          r"moto|nokia|oppo|realme|vivo|honor|'s phone|telefon)", re.I)
BSSID_RE = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")


def norm_security(cap: Optional[str]) -> str:
    c = (cap or "").upper()
    if not c or c in ("[ESS]", "ESS", "OPEN", "NONE"):
        return "OPEN"
    if "EAP" in c or "802.1X" in c or "ENTERPRISE" in c:
        return "802.1X"
    if "SAE" in c or "WPA3" in c:
        return "WPA3-SAE"
    if "PSK" in c:
        return "WPA2-PSK" if "WPA2" in c or "RSN" in c else "WPA-PSK"
    if "WEP" in c:
        return "WEP"
    if "OWE" in c:
        return "OWE"
    return c[:40]


def freq_to_channel(freq: Optional[int]) -> Optional[int]:
    if not freq:
        return None
    if 2412 <= freq <= 2472:
        return (freq - 2407) // 5
    if freq == 2484:
        return 14
    if 5150 <= freq <= 5895:
        return (freq - 5000) // 5
    if 5955 <= freq <= 7115:  # 6 GHz
        return (freq - 5950) // 5
    return None


def is_locally_administered(mac: str) -> bool:
    return bool(int(mac.split(":")[0], 16) & 0x02)


def trusted_location(loc: dict, now: float) -> dict:
    """Reguly zaufania: QR/recznie zawsze; GPS tylko gdy dokladnosc <=50 m i wiek <=15 s."""
    out = {k: loc.get(k) for k in ("building", "floor", "room") if loc.get(k)}
    src = loc.get("source", "gps")
    out["source"] = src
    if loc.get("lat") is not None and loc.get("lng") is not None:
        acc = loc.get("accuracy")
        t = loc.get("time")
        age = (now - (t / 1000 if t and t > 1e11 else t)) if t else 0
        if src != "gps" or (acc is not None and acc <= GPS_MAX_ACCURACY_M and abs(age) <= GPS_MAX_AGE_S):
            out.update({"lat": loc["lat"], "lng": loc["lng"], "accuracy": acc})
        else:
            out["gps_rejected"] = f"dokladnosc {acc} m / wiek {age:.0f} s"
    return out


def classify(bssid: str, ssid: str, security: str, known: dict, known_ssids: dict) -> tuple[str, int, list[str]]:
    reasons: list[str] = []
    if bssid in known:
        k = known[bssid]
        if k.get("security") and k["security"] != security:
            return "EVIL_TWIN", 85, [f"znany BSSID, ale zabezpieczenie {security} zamiast {k['security']} (podszywanie)"]
        return "KNOWN", 95, ["BSSID na liscie autoryzowanych AP"]
    if ssid and ssid in known_ssids:
        conf = 60
        reasons.append(f"SSID '{ssid}' nalezy do sieci organizacji, ale BSSID jest nieznany")
        expected = known_ssids[ssid]
        if expected and security not in expected:
            conf += 30
            reasons.append(f"zabezpieczenie {security}, oczekiwane {', '.join(sorted(expected))}")
        return "EVIL_TWIN", conf, reasons
    score = 0
    if is_locally_administered(bssid):
        score += 40
        reasons.append("MAC lokalnie administrowany (typowe dla telefonow)")
    if ssid and HOTSPOT_SSID.search(ssid):
        score += 40
        reasons.append(f"nazwa SSID wyglada na telefon/Wi-Fi Direct: '{ssid}'")
    org_secs = {s for secs in known_ssids.values() for s in secs}
    if security in ("WPA2-PSK", "WPA-PSK", "WPA3-SAE") and org_secs and org_secs <= {"802.1X"}:
        score += 15
        reasons.append("siec z haslem tam, gdzie organizacja uzywa 802.1X")
    if score >= 50:
        return "HOTSPOT", min(score, 95), reasons
    if known:
        return "ROGUE", 50 + score // 2, reasons + ["AP spoza listy autoryzowanych"]
    return "UNKNOWN", 30, reasons + ["brak listy znanych AP: zaimportuj CSV, aby klasyfikowac obce AP"]


def _known():
    rows = db.q("SELECT * FROM known_aps")
    known = {r["bssid"].lower(): r for r in rows}
    ssids: dict[str, set] = {}
    for r in rows:
        if r["ssid"]:
            ssids.setdefault(r["ssid"], set())
            if r["security"]:
                ssids[r["ssid"]].add(norm_security(r["security"]))
    return known, ssids


def ingest(sensor: str, payload: dict) -> dict:
    now = time.time()
    loc = trusted_location(payload.get("location") or {}, now)
    known, known_ssids = _known()
    accepted, alerts, to_estimate = 0, [], set()
    with db.tx() as c:
        for n in payload.get("networks", [])[:500]:
            bssid = str(n.get("bssid", "")).lower()
            if not BSSID_RE.match(bssid) or bssid == "00:00:00:00:00:00":
                continue
            ssid = (n.get("ssid") or "").strip().strip('"')[:64]
            sec = norm_security(n.get("security"))
            freq = n.get("frequency_mhz")
            ch = n.get("channel") or freq_to_channel(freq)
            rssi = int(n.get("rssi_dbm", -100))
            ts = n.get("timestamp") or now
            c.execute("INSERT INTO wifi_obs(sensor, ts, bssid, ssid, security, frequency, channel, rssi, location_enc) "
                      "VALUES (?,?,?,?,?,?,?,?,?)", (sensor, ts, bssid, ssid, sec, freq, ch, rssi, encrypt(loc)))
            cls, conf, reasons = classify(bssid, ssid, sec, known, known_ssids)
            prev = c.execute("SELECT * FROM wifi_aps WHERE bssid=?", (bssid,)).fetchone()
            if prev is None:
                c.execute("INSERT INTO wifi_aps(bssid, ssid, security, channel, classification, confidence, reasons, first_seen, "
                          "last_seen, best_rssi) VALUES (?,?,?,?,?,?,?,?,?,?)",
                          (bssid, ssid, sec, ch, cls, conf, db.jdump(reasons), now, now, rssi))
            else:
                c.execute("UPDATE wifi_aps SET ssid=?, security=?, channel=?, classification=?, confidence=?, reasons=?, "
                          "last_seen=?, best_rssi=MAX(COALESCE(best_rssi,-100), ?) WHERE bssid=?",
                          (ssid, sec, ch, cls, conf, db.jdump(reasons), now, rssi, bssid))
            if cls != "KNOWN":
                to_estimate.add(bssid)
            if cls in ("EVIL_TWIN", "HOTSPOT", "ROGUE") and (prev is None or prev["classification"] != cls):
                where = " ".join(filter(None, [loc.get("building"), loc.get("floor") and f"p.{loc['floor']}",
                                               loc.get("room") and f"s.{loc['room']}"]))
                detail = f"{cls} '{ssid}' {bssid} ({sec}, {rssi} dBm){' @ ' + where if where else ''}: " + "; ".join(reasons)
                prio = 3 if cls == "EVIL_TWIN" else 2
                c.execute("INSERT INTO changes(run_id, ts, object, object_id, ip, port, change, detail, priority) "
                          "VALUES (NULL,?,?,?,?,?,?,?,?)", (now, "wifi", None, bssid, None, cls, detail[:500], prio))
                alerts.append({"bssid": bssid, "ssid": ssid, "classification": cls, "confidence": conf})
            accepted += 1
    for b in to_estimate:
        update_estimate(b)
    return {"accepted": accepted, "location": loc, "alerts": alerts}


def update_estimate(bssid: str) -> Optional[dict]:
    """Pozycja AP: srednia miejsc pomiarow wazona sila sygnalu + sala z najsilniejszym odczytem."""
    obs = db.q("SELECT rssi, location_enc FROM wifi_obs WHERE bssid=? AND ts>? ORDER BY ts DESC LIMIT 500",
               (bssid, time.time() - 7 * 86400))
    if not obs:
        return None
    wsum = lat = lng = 0.0
    best = None
    for o in obs:
        loc = decrypt(o["location_enc"]) or {}
        w = 10 ** (o["rssi"] / 10)
        if loc.get("lat") is not None:
            wsum += w
            lat += w * loc["lat"]
            lng += w * loc["lng"]
        if loc.get("room") and (best is None or o["rssi"] > best[0]):
            best = (o["rssi"], loc)
    est = {"samples": len(obs)}
    if wsum:
        est.update({"lat": round(lat / wsum, 6), "lng": round(lng / wsum, 6)})
    if best:
        est.update({k: best[1].get(k) for k in ("building", "floor", "room")}, room_rssi=best[0])
    link_ip, link_conf = correlate_host(bssid)
    with db.tx() as c:
        c.execute("UPDATE wifi_aps SET location_enc=?, linked_host_ip=?, link_confidence=? WHERE bssid=?",
                  (encrypt(est), link_ip, link_conf, bssid))
    return est


def correlate_host(bssid: str) -> tuple[Optional[str], Optional[int]]:
    """BSSID ~ MAC kablowy routera (ten sam OUI, roznica kilku). Zawsze z pewnoscia, nigdy jako pewnik."""
    b = int(bssid.replace(":", ""), 16)
    b_clear = b & ~(0x02 << 40)
    best = (None, None)
    for h in db.q("SELECT ip, mac FROM hosts WHERE mac IS NOT NULL"):
        try:
            m = int(h["mac"].lower().replace(":", ""), 16)
        except ValueError:
            continue
        for cand in (b, b_clear):
            if (cand >> 24) != (m >> 24):
                continue
            d = abs(cand - m)
            if d <= 8:
                conf = 75 if d <= 2 else 55
                if best[1] is None or conf > best[1]:
                    best = (h["ip"], conf)
    return best


def import_known(rows: list[dict]) -> int:
    n = 0
    with db.tx() as c:
        for r in rows:
            b = str(r.get("bssid", "")).lower().strip()
            if not BSSID_RE.match(b):
                continue
            c.execute("INSERT OR REPLACE INTO known_aps(bssid, ssid, security, building, floor, room) VALUES (?,?,?,?,?,?)",
                      (b, r.get("ssid"), norm_security(r.get("security")) if r.get("security") else None,
                       r.get("building"), r.get("floor"), r.get("room")))
            n += 1
    # przelicz klasyfikacje znanych juz AP
    known, ssids = _known()
    with db.tx() as c:
        for ap in c.execute("SELECT * FROM wifi_aps").fetchall():
            cls, conf, reasons = classify(ap["bssid"], ap["ssid"], ap["security"], known, ssids)
            c.execute("UPDATE wifi_aps SET classification=?, confidence=?, reasons=? WHERE bssid=?",
                      (cls, conf, db.jdump(reasons), ap["bssid"]))
    return n


def live(bssid: str, seconds: int = 120) -> list[dict]:
    """Ostatnie odczyty RSSI dla trybu ciepło-zimno."""
    rows = db.q("SELECT ts, rssi, sensor FROM wifi_obs WHERE bssid=? AND ts>? ORDER BY ts", (bssid.lower(), time.time() - seconds))
    return rows
