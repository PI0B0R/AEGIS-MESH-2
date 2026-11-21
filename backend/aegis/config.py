"""Konfiguracja z zmiennych srodowiskowych (z rozsadnymi wartosciami domyslnymi)."""
import os
from pathlib import Path

BASE_DIR = Path(os.environ.get("AEGIS_DATA_DIR", Path(__file__).resolve().parents[2] / "data"))
BASE_DIR.mkdir(parents=True, exist_ok=True)

DB_PATH = Path(os.environ.get("AEGIS_DB", BASE_DIR / "aegis.db"))
RUNS_DIR = BASE_DIR / "runs"
RUNS_DIR.mkdir(exist_ok=True)

SIGNATURES_DIR = Path(os.environ.get("AEGIS_SIGNATURES", Path(__file__).resolve().parents[2] / "signatures"))

# Klucz do szyfrowania pol wrazliwych (base64, 32 bajty). Bez niego generujemy plik w data/ (tylko dev).
ENCRYPTION_KEY = os.environ.get("AEGIS_KEY")

# Bezpieczne wartosci domyslne skanowania
DEFAULT_PORTS = os.environ.get(
    "AEGIS_PORTS", "21,22,23,25,53,80,110,143,443,445,3306,3389,5432,5900,6379,8000,8080,8081,8443,8888,9000,9200"
)
DEFAULT_MAX_RATE = int(os.environ.get("AEGIS_MAX_RATE", "300"))      # pakiety/s na proces nmap
DEFAULT_PARALLEL_CHUNKS = int(os.environ.get("AEGIS_PARALLEL", "4"))  # rownolegle procesy nmap
DEFAULT_CHUNK_SIZE = int(os.environ.get("AEGIS_CHUNK", "256"))
TARGET_CHUNK_SECONDS = int(os.environ.get("AEGIS_CHUNK_SECONDS", "90"))  # docelowy czas paczki
GONE_AFTER_MISSES = int(os.environ.get("AEGIS_GONE_AFTER", "3"))
UNSTABLE_WINDOW = int(os.environ.get("AEGIS_UNSTABLE_WINDOW", "5"))
HTTP_TIMEOUT = float(os.environ.get("AEGIS_HTTP_TIMEOUT", "6"))
HTTP_WORKERS = int(os.environ.get("AEGIS_HTTP_WORKERS", "16"))

# Organizacja: sufiks domeny do klasyfikacji PTR
ORG_DOMAIN_SUFFIX = os.environ.get("AEGIS_ORG_SUFFIX", ".agh.edu.pl")

# Bootstrap konta admina
ADMIN_USER = os.environ.get("AEGIS_ADMIN_USER", "admin")
ADMIN_PASSWORD = os.environ.get("AEGIS_ADMIN_PASSWORD")  # brak = losowe haslo wypisane w logu

SCHEDULER_ENABLED = os.environ.get("AEGIS_SCHEDULER", "1") == "1"
