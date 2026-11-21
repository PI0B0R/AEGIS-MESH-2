"""Fingerprint HTTP/HTTPS: tytul, kod, naglowki, ciasteczka, certyfikat TLS, przekierowania,
technologie (sygnatury) oraz flagi "ciekawosci" (panel admina, staging, ujawnione wersje)."""
import base64
import hashlib
import html
import re
import secrets
import socket
import ssl
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urljoin, urlparse

import httpx
from cryptography import x509
from cryptography.x509.oid import ExtensionOID, NameOID

from . import config, signatures

USER_AGENT = "AEGIS-MESH-discovery/1.0 (security inventory; contact: security team)"
MAX_BODY = 512 * 1024
WEB_NAMES = {"http", "https", "http-proxy", "http-alt", "https-alt", "ssl/http", "http-mgmt", "upnp"}
WEB_PORTS = {80, 81, 443, 591, 3000, 5000, 7001, 8000, 8008, 8080, 8081, 8088, 8443, 8888, 9000, 9090, 9443}
TLS_PORTS = {443, 8443, 9443, 4443}

STAGING_RX = re.compile(r"(?<![a-z])(dev|devel|test|testing|stage|staging|stg|uat|qa|preprod|pre-prod|sandbox|demo|beta)(?![a-z])", re.I)
ADMIN_RX = re.compile(r"(admin|administrator|panel|dashboard|login|log in|sign in|zaloguj|logowanie|console|"
                      r"phpmyadmin|management|manager|webmin|cpanel|plesk|router|configuration)", re.I)
INTERESTING_HEADERS = {
    "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-generator", "x-drupal-cache", "x-drupal-dynamic-cache",
    "x-debug-token", "x-debug-token-link", "x-backend-server", "x-forwarded-server", "x-served-by", "via",
    "x-varnish", "x-jenkins", "x-hudson", "x-runtime", "x-amz-cf-id", "x-kubernetes-pf-flowschema-uid",
    "x-gitlab-meta", "x-grafana-version", "x-confluence-request-time", "x-redmine-version", "x-mod-pagespeed",
    "x-litespeed-cache", "x-envoy-upstream-service-time", "server-timing", "x-cache",
}
SESSION_COOKIES = re.compile(r"^(phpsessid|jsessionid|asp\.net_sessionid|aspsessionid.*|laravel_session|"
                             r"ci_session|connect\.sid|sessionid|csrftoken|wordpress_logged_in.*|wp-settings.*|"
                             r"_gitlab_session|grafana_session|jenkins.*|roundcube_sessid|sap-usercontext)$", re.I)
SECURITY_HEADERS = ("strict-transport-security", "content-security-policy", "x-frame-options", "x-content-type-options")


def is_web(service: dict) -> bool:
    name = (service.get("name") or "").lower()
    return service["proto"] == "tcp" and (name in WEB_NAMES or "http" in name or service["port"] in WEB_PORTS)


def _mmh3_32(data: bytes) -> int:
    """MurmurHash3 x86_32 (seed 0) - ten sam hash favicony co w Shodanie."""
    c1, c2, h, length = 0xcc9e2d51, 0x1b873593, 0, len(data)
    rounded = length & ~3
    for i in range(0, rounded, 4):
        k = data[i] | data[i + 1] << 8 | data[i + 2] << 16 | data[i + 3] << 24
        k = (k * c1) & 0xffffffff
        k = ((k << 15) | (k >> 17)) & 0xffffffff
        h ^= (k * c2) & 0xffffffff
        h = ((h << 13) | (h >> 19)) & 0xffffffff
        h = (h * 5 + 0xe6546b64) & 0xffffffff
    k, tail = 0, length & 3
    if tail == 3:
        k ^= data[rounded + 2] << 16
    if tail >= 2:
        k ^= data[rounded + 1] << 8
    if tail >= 1:
        k ^= data[rounded]
        k = (k * c1) & 0xffffffff
        k = ((k << 15) | (k >> 17)) & 0xffffffff
        h ^= (k * c2) & 0xffffffff
    h ^= length
    h ^= h >> 16
    h = (h * 0x85ebca6b) & 0xffffffff
    h ^= h >> 13
    h = (h * 0xc2b2ae35) & 0xffffffff
    h ^= h >> 16
    return h - 2 ** 32 if h & 0x80000000 else h


def favicon_hash(content: bytes) -> str:
    return str(_mmh3_32(base64.encodebytes(content)))


def _cookies(resp: httpx.Response) -> list[dict]:
    out = []
    for raw in resp.headers.get_list("set-cookie"):
        parts = [p.strip() for p in raw.split(";")]
        name = parts[0].split("=", 1)[0]
        attrs = {p.split("=", 1)[0].lower() for p in parts[1:]}
        samesite = next((p.split("=", 1)[1] for p in parts[1:] if p.lower().startswith("samesite=")), None)
        out.append({"name": name, "secure": "secure" in attrs, "httponly": "httponly" in attrs, "samesite": samesite})
    return out


def _title(body: str) -> Optional[str]:
    m = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
    return html.unescape(re.sub(r"\s+", " ", m.group(1))).strip()[:200] if m else None


def _generator(body: str) -> Optional[str]:
    m = re.search(r"<meta[^>]+name=[\"']generator[\"'][^>]+content=[\"']([^\"']+)", body, re.I) or \
        re.search(r"<meta[^>]+content=[\"']([^\"']+)[\"'][^>]+name=[\"']generator", body, re.I)
    return m.group(1)[:120] if m else None


def tls_info(host: str, port: int, sni: Optional[str]) -> Optional[dict]:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=config.HTTP_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=sni or None) as ss:
                der = ss.getpeercert(binary_form=True)
                version, cipher = ss.version(), ss.cipher()[0] if ss.cipher() else None
    except (OSError, ssl.SSLError):
        return None
    cert = x509.load_der_x509_certificate(der)

    def cn(name):
        v = name.get_attributes_for_oid(NameOID.COMMON_NAME)
        return v[0].value if v else name.rfc4514_string()
    try:
        sans = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        sans = []
    not_after = cert.not_valid_after_utc
    days_left = (not_after - datetime.now(timezone.utc)).days
    return {
        "subject_cn": cn(cert.subject), "issuer_cn": cn(cert.issuer), "sans": sans[:50],
        "not_before": cert.not_valid_before_utc.isoformat(), "not_after": not_after.isoformat(),
        "days_left": days_left, "expired": days_left < 0, "self_signed": cert.subject == cert.issuer,
        "serial": format(cert.serial_number, "x"), "sha256": hashlib.sha256(der).hexdigest(),
        "tls_version": version, "cipher": cipher,
    }


def _fetch(client: httpx.Client, url: str, base_host: str, max_redirects: int = 5) -> tuple[Optional[httpx.Response], list[dict], str]:
    """GET z recznym sledzeniem przekierowan; nie wychodzimy poza ten sam host (zakres skanu)."""
    chain = []
    current = url
    for _ in range(max_redirects + 1):
        try:
            resp = client.get(current)
        except httpx.HTTPError:
            return None, chain, current
        if resp.is_redirect and resp.headers.get("location"):
            nxt = urljoin(current, resp.headers["location"])
            chain.append({"from": current, "to": nxt, "status": resp.status_code})
            if urlparse(nxt).hostname != base_host:
                return resp, chain, current  # przekierowanie poza zakres: notujemy, nie podazamy
            current = nxt
            continue
        return resp, chain, current
    return resp, chain, current


def _snapshot(resp: httpx.Response) -> dict:
    body = resp.content[:MAX_BODY].decode(resp.encoding or "utf-8", errors="replace")
    return {
        "status": resp.status_code,
        "headers": {k.lower(): v for k, v in resp.headers.items()},
        "cookies": _cookies(resp), "body": body, "title": _title(body), "meta_generator": _generator(body),
        "body_hash": hashlib.sha1(resp.content[:MAX_BODY]).hexdigest(), "length": len(resp.content),
    }


def fingerprint(ip: str, service: dict, hostname: Optional[str], sigs: list[dict]) -> Optional[dict]:
    port = service["port"]
    host_for_url = hostname or ip
    tls_first = service.get("tunnel") == "ssl" or "https" in (service.get("name") or "") or port in TLS_PORTS
    schemes = ["https", "http"] if tls_first else ["http", "https"]
    headers = {"User-Agent": USER_AGENT, "Accept": "*/*"}
    with httpx.Client(verify=False, timeout=config.HTTP_TIMEOUT, follow_redirects=False, headers=headers,
                      transport=httpx.HTTPTransport(retries=0, verify=False), trust_env=False) as client:
        resp, chain, final_url, scheme = None, [], None, None
        for scheme in schemes:
            base = f"{scheme}://{host_for_url}:{port}"
            resp, chain, final_url = _fetch(client, base + "/", host_for_url)
            if resp is not None:
                break
        if resp is None:
            return None
        root = _snapshot(resp)
        tls = tls_info(ip, port, hostname) if scheme == "https" else None
        root["cert_text"] = " ".join([tls["subject_cn"], tls["issuer_cn"], *tls["sans"]]) if tls else ""

        # favicon (hash jak w Shodanie)
        fav = None
        try:
            r = client.get(f"{scheme}://{host_for_url}:{port}/favicon.ico")
            if r.status_code == 200 and r.content and len(r.content) < 200_000:
                fav = favicon_hash(r.content)
        except httpx.HTTPError:
            pass
        root["favicon_hash"] = fav

        # Ochrona przed soft-404: odpowiedz na losowa nieistniejaca sciezke
        soft404 = set()
        try:
            r = client.get(f"{scheme}://{host_for_url}:{port}/aegis-{secrets.token_hex(6)}")
            if r.status_code == 200:
                soft404.add(hashlib.sha1(r.content[:MAX_BODY]).hexdigest())
        except httpx.HTTPError:
            pass

        responses = {"/": root}
        for path in signatures.extra_paths(sigs):
            try:
                r = client.get(f"{scheme}://{host_for_url}:{port}{path}")
            except httpx.HTTPError:
                continue
            snap = _snapshot(r)
            if r.status_code >= 400 or snap["body_hash"] in soft404 or (snap["body_hash"] == root["body_hash"] and path != "/"):
                continue
            snap["favicon_hash"], snap["cert_text"] = fav, root["cert_text"]
            responses[path] = snap

    hits = signatures.evaluate(sigs, responses)
    flags, interest = assess(root, tls, hits, hostname, scheme)
    techs = sorted({h["name"] + (f" {h['version']}" if h.get("version") else "") for h in hits
                    if h["category"] in ("cms", "framework", "server", "iot", "devops", "database")})
    if root["headers"].get("server"):
        techs.append("Server: " + root["headers"]["server"][:60])
    return {
        "url": f"{scheme}://{host_for_url}:{port}/", "final_url": final_url, "scheme": scheme,
        "status_code": root["status"], "title": root["title"], "server": root["headers"].get("server"),
        "headers": root["headers"], "cookies": root["cookies"], "tls": tls, "redirects": chain,
        "favicon_hash": fav, "technologies": techs, "signature_hits": hits, "flags": flags, "interest": interest,
    }


def assess(root: dict, tls: Optional[dict], hits: list[dict], hostname: Optional[str], scheme: str) -> tuple[dict, int]:
    """Ocena 'ciekawosci' (priorytetu analitycznego) z uzasadnieniem."""
    flags: dict = {"reasons": []}
    score = 0
    h = root["headers"]

    def add(key, value, pts, reason):
        nonlocal score
        flags[key] = value
        score += pts
        flags["reasons"].append(reason)

    names = " ".join(filter(None, [hostname, root.get("title"), root.get("cert_text")]))
    m = STAGING_RX.search(names)
    if m or any(x["category"] == "staging" for x in hits):
        add("staging", True, 3, f"srodowisko testowe/staging ({m.group(0) if m else 'sygnatura'})")
    admin_hits = [x for x in hits if x["category"] == "admin_panel"]
    if admin_hits or (root.get("title") and ADMIN_RX.search(root["title"])):
        add("admin_panel", [x["path"] for x in admin_hits] or ["/"], 3, "panel administracyjny lub logowanie")
    interesting = {k: v[:120] for k, v in h.items() if k in INTERESTING_HEADERS}
    if h.get("access-control-allow-origin") == "*":
        interesting["access-control-allow-origin"] = "*"
    if interesting:
        add("interesting_headers", interesting, 1, "naglowki ujawniajace technologie: " + ", ".join(sorted(interesting)))
    if re.search(r"\d", h.get("server", "")) or "x-powered-by" in h or "x-aspnet-version" in h:
        add("version_disclosure", True, 1, "ujawniona wersja oprogramowania")
    sess = [c for c in root["cookies"] if SESSION_COOKIES.match(c["name"])]
    weak = [c["name"] for c in root["cookies"] if (scheme == "https" and not c["secure"]) or not c["httponly"]]
    if sess:
        add("session_cookies", [c["name"] for c in sess], 1, "ciasteczka sesyjne: " + ", ".join(c["name"] for c in sess))
    if weak:
        add("weak_cookies", weak, 1, "ciasteczka bez Secure/HttpOnly: " + ", ".join(weak[:5]))
    missing = [x for x in SECURITY_HEADERS if x not in h and not (x == "strict-transport-security" and scheme != "https")]
    if missing:
        flags["missing_security_headers"] = missing
    if tls:
        if tls["expired"]:
            add("tls_expired", True, 2, "certyfikat wygasl")
        elif tls["days_left"] < 30:
            add("tls_expiring", tls["days_left"], 1, f"certyfikat wygasa za {tls['days_left']} dni")
        if tls["self_signed"]:
            add("tls_self_signed", True, 1, "certyfikat samopodpisany")
        if tls["tls_version"] in ("TLSv1", "TLSv1.1", "SSLv3"):
            add("tls_old", tls["tls_version"], 2, f"stary protokol {tls['tls_version']}")
    if any(x["category"] in ("devops", "database") for x in hits):
        add("sensitive_tooling", True, 2, "narzedzie devops/bazodanowe wystawione przez HTTP")
    if any(x["category"] == "iot" for x in hits):
        add("iot", True, 2, "urzadzenie IoT/sieciowe")
    return flags, score
