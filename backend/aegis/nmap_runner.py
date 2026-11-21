"""Uruchamianie nmapa i parsowanie wyniku XML.

Krok 1: wykrycie zywych hostow (kaskada sond jak w Qualys host discovery).
Krok 2: identyfikacja uslug tylko na zywych hostach i tylko na dozwolonych portach.
"""
import os
import shutil
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Optional

IS_ROOT = hasattr(os, "geteuid") and os.geteuid() == 0


class NmapMissing(RuntimeError):
    pass


class ChunkTimeout(RuntimeError):
    """Paczka nie zmiescila sie w oknie czasowym - wroci do kolejki."""


def nmap_path() -> str:
    p = shutil.which("nmap")
    if not p:
        raise NmapMissing("nmap nie jest zainstalowany (apt install nmap)")
    return p


def discovery_args(max_rate: int) -> list[str]:
    args = ["-sn", "-PS21,22,25,80,135,443,445,3389,8080", "-PA80,443"]
    if IS_ROOT:
        # ICMP echo + timestamp + UDP i ARP (w lokalnym segmencie nmap uzywa ARP automatycznie)
        args += ["-PE", "-PP", "-PU53,161"]
    return args + ["--max-rate", str(max_rate), "--max-retries", "2", "--host-timeout", "30s"]


def service_args(ports: str, max_rate: int) -> list[str]:
    return [
        "-sS" if IS_ROOT else "-sT", "-Pn", "-n", "-sV", "--version-light", "--open",
        "-p", ports, "--max-rate", str(max_rate), "--max-retries", "2", "--host-timeout", "180s",
    ]


def run(targets: list[str], args: list[str], out_xml: Path, timeout: Optional[float]) -> dict:
    """Uruchamia nmap dla listy celow (przez plik -iL), zwraca sparsowany wynik."""
    out_xml.parent.mkdir(parents=True, exist_ok=True)
    list_file = out_xml.with_suffix(".targets")
    list_file.write_text("\n".join(targets) + "\n")
    # Discovery: nmap sam robi rDNS dla zywych hostow. Skan uslug: -n (nazwy juz mamy).
    cmd = [nmap_path(), *args, "-oX", str(out_xml), "-iL", str(list_file)]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        raise ChunkTimeout(f"nmap przerwany po {timeout:.0f}s")
    if proc.returncode != 0 and not out_xml.exists():
        raise RuntimeError(f"nmap blad {proc.returncode}: {proc.stderr[-500:]}")
    return parse_xml(out_xml)


def parse_xml(path: Path) -> dict:
    tree = ET.parse(path)
    root = tree.getroot()
    hosts = []
    for h in root.findall("host"):
        status = h.find("status")
        state = status.get("state") if status is not None else "unknown"
        reason = status.get("reason") if status is not None else None
        ip, mac, vendor = None, None, None
        for a in h.findall("address"):
            if a.get("addrtype") == "ipv4":
                ip = a.get("addr")
            elif a.get("addrtype") == "mac":
                mac, vendor = a.get("addr"), a.get("vendor")
        names = [(n.get("name"), n.get("type")) for n in h.findall("hostnames/hostname")]
        ports = []
        os_types = set()
        for p in h.findall("ports/port"):
            st = p.find("state")
            if st is None or st.get("state") != "open":
                continue
            svc = p.find("service")
            s = {
                "port": int(p.get("portid")), "proto": p.get("protocol"),
                "name": svc.get("name") if svc is not None else None,
                "product": svc.get("product") if svc is not None else None,
                "version": svc.get("version") if svc is not None else None,
                "extrainfo": svc.get("extrainfo") if svc is not None else None,
                "tunnel": svc.get("tunnel") if svc is not None else None,
                "conf": int(svc.get("conf", "0")) if svc is not None else 0,
            }
            if svc is not None and svc.get("ostype"):
                os_types.add(svc.get("ostype"))
            ports.append(s)
        if ip:
            hosts.append({
                "ip": ip, "state": state, "reason": reason, "mac": mac, "vendor": vendor,
                "ptr": next((n for n, t in names if t == "PTR"), None),
                "user_name": next((n for n, t in names if t == "user"), None),
                "ports": ports, "os": ", ".join(sorted(os_types)) or None,
            })
    runstats = root.find("runstats/finished")
    return {
        "hosts": hosts,
        "elapsed": float(runstats.get("elapsed", 0)) if runstats is not None else None,
        "args": root.get("args"),
    }


def merge_xml(files: list[Path], out: Path) -> Optional[Path]:
    """Laczy XML-e paczek w jeden nmaprun (do importu w DefectDojo jako jeden test)."""
    files = [f for f in files if f.exists()]
    if not files:
        return None
    base = ET.parse(files[0])
    root = base.getroot()
    insert_at = list(root).index(root.find("runstats")) if root.find("runstats") is not None else len(root)
    for f in files[1:]:
        for h in ET.parse(f).getroot().findall("host"):
            root.insert(insert_at, h)
            insert_at += 1
    base.write(out, encoding="utf-8", xml_declaration=True)
    return out
