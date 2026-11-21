# AEGIS-MESH (Team Panda)

Prototyp na zadanie **Attack Surface Intelligence** (CBI AGH). AEGIS-MESH to middleware:
steruje nmapem, sam robi fingerprint HTTP/HTTPS, pilnuje zmian między przebiegami
i wysyła wyniki do DefectDojo. Telefon z aplikacją Aegis dokłada warstwę Wi-Fi i lokalizacji.

```
Wejście (formularz/CSV/JSON) → Scheduler (paczki, okno czasowe) → nmap -sn → nmap -sV → fingerprint HTTP + sygnatury
                                                                                     ↓
         Telefon Aegis → Korelacja Wi-Fi  →  Baza (szyfrowana) + porównanie przebiegów → Dashboard (RBAC), eksport
                                                                                     ↓
                                                                                 DefectDojo
```

## Co spełnia z wymagań

| Wymaganie z PDF | Gdzie |
| --- | --- |
| Import IP / CIDR / domen: ręcznie, CSV, JSON | `targets.py`, `POST /api/targets`, `/api/targets/import` |
| Bezpieczny, wielowątkowy skan nmap, podział na paczki | `nmap_runner.py`, `scanner.py` (równoległe paczki, `--max-rate`, adaptacyjny rozmiar paczki) |
| Czas trwania skanu, czas na adres | `scan_runs.active_seconds`, `chunk_stats`, `avg_seconds_per_address` |
| Okna czasowe i częstotliwość; przerwanie i wznowienie w kolejnym oknie | `scheduler.py` (okna przez północ), status `paused` + `pending` |
| Aktywne hosty, usługi | kaskada sond jak w Qualysie (`-PS/-PA/-PE/-PP/-PU`, ARP lokalnie), `-sV --version-light` |
| HTTP: tytuł, kod, nagłówki, ciasteczka, TLS, przekierowania | `http_fp.py` |
| Technologie, CMS, IoT, staging, panele admina | `signatures/default.json` (37 sygnatur) + heurystyki w `http_fp.assess` |
| Ciekawe nagłówki i ciasteczka, ocena priorytetu | `http_fp.assess` (punkty + uzasadnienie) |
| Porównanie przebiegów: nowe / znikające / zmienione | `scanner.finalize`, `GET /api/compare?a=&b=` |
| Hosty niestabilne | statusy `UNSTABLE`/`GONE` (3 kolejne braki + ponowne sprawdzenie), godziny odpowiedzi |
| Własne sygnatury (bezpieczne) | `PUT /api/signatures/custom`: walidacja, tylko GET bez parametrów, ochrona przed soft-404 |
| RBAC + role z PDF + własne role | `auth.py`: admin, editor, analyst, viewer, sensor; `POST /api/roles` |
| Edycja niezależna od skanu, zachowana przy kolejnych | pola `user_*` (skan ich nie dotyka) |
| Dashboard | `/` (pulpit, hosty, zmiany, skany, Wi-Fi, sygnatury, DefectDojo, użytkownicy, audyt) |
| Szyfrowanie w spoczynku | AES-256-GCM dla nagłówków, ciasteczek, TLS, notatek, lokalizacji, klucza API Dojo (`crypto.py`) |
| Import wyników JSON/CSV, eksport JSON/CSV | `/api/import/results`, `/api/export/hosts.{json,csv}`, `/api/export/changes.csv` |
| DefectDojo | `defectdojo.py`: Nmap Scan (reimport) + Generic Findings Import + tagi lokalizacji na endpointach |

## Uruchomienie (Linux / WSL)

```bash
sudo apt install nmap
cd backend
pip install -r requirements.txt
export AEGIS_KEY=$(python3 -c "import os,base64;print(base64.b64encode(os.urandom(32)).decode())")   # zapisz go!
export AEGIS_ADMIN_PASSWORD='ZmienMnie123!'
sudo -E uvicorn aegis.api:app --host 0.0.0.0 --port 8000     # sudo = SYN scan i ICMP; bez sudo dziala TCP connect
```
Otwórz `http://localhost:8000`, zaloguj się jako `admin`.
Docker: `AEGIS_KEY=... docker compose up -d`.

Najważniejsze zmienne: `AEGIS_PORTS` (lista dozwolonych portów), `AEGIS_MAX_RATE` (pakiety/s na proces),
`AEGIS_PARALLEL` (równoległe paczki), `AEGIS_GONE_AFTER` (po ilu brakach host jest nieaktywny, domyślnie 3),
`AEGIS_ORG_SUFFIX` (domena organizacji do oceny PTR).

## Demo w 5 minut (laboratorium bez Dockera)

```bash
python3 lab/lab_services.py --phase 1          # 7 usług na 127.0.0.2-8: WordPress, Jenkins, staging z TLS, IoT...
AEGIS_PORTS=2222,8000,8080,8081,8443,9000 uvicorn aegis.api:app --port 8000   # w katalogu backend
```
1. Cele i skany → dodaj `127.0.0.0/28` → Start. Pulpit pokazuje hosty, technologie, priorytety.
2. Zatrzymaj laboratorium, uruchom `--phase 2` (Jenkins znika, WordPress się aktualizuje, pojawia się Grafana) → drugi skan.
   Zmiany: `GONE 127.0.0.3:8080`, `CHANGED WordPress 6.4.2 → 6.5.0`, `NEW 127.0.0.8:9000`.
3. Użytkownicy → dodaj `viewer` → zaloguj się nim → próba edycji hosta = odmowa 403.
4. Wi-Fi: zaimportuj `examples/known_aps.csv`, wyślij `examples/telemetry_sample.json` tokenem czujnika:
   ```bash
   curl -X POST http://localhost:8000/api/mobile-telemetry -H "Authorization: Bearer <token sensora>" \
        -H 'Content-Type: application/json' -d @examples/telemetry_sample.json
   ```
   Wynik: `EVIL_TWIN` (AGH-LAB otwarte zamiast 802.1X), `HOTSPOT` (iPhone).
5. DefectDojo → URL + klucz API → „Do Dojo” przy przebiegu.

Na laboratorium w kontenerach skanujecie normalnie zakresy od organizatorów.
Uwaga: część środowisk (np. NAT/proxy) odpowiada SYN-ACK za każdy adres. AEGIS obniża wtedy pewność hostów bez usług.

## Testy
```bash
cd backend && python -m pytest -q     # statusy hostów, okno czasowe, sygnatury, klasyfikacja Wi-Fi
```

## Aplikacja Android (`android-app/`)
Kotlin + WebView, bez Compose. Otwórz folder w Android Studio (wygeneruje Gradle wrapper) i zbuduj APK.
- Ustawienia: adres serwera + **token API użytkownika z rolą `sensor`** (Użytkownicy → dodaj → rola sensor).
- Start uruchamia Foreground Service (typ `location`): skan Wi-Fi co 30 s, wysyłka tylko nowych wyników, kolejka offline.
- Miejsce pomiaru: kod QR na drzwiach z treścią `aegis://loc?b=B1&f=2&r=204` (zwykły aparat otwiera aplikację),
  albo przycisk „Sala”. GPS tylko przy dokładności ≤ 50 m i wieku ≤ 15 s.
- Tryb „Ciepło-zimno”: wpisz BSSID, aplikacja pokazuje RSSI na żywo. Na demo wyłącz w opcjach programisty
  „Ograniczanie skanowania Wi-Fi”.
- Ograniczenia: telefon widzi tylko punkty dostępowe i hotspoty, nie klientów sieci.

## API (skrót)
`POST /api/auth/login` → token (Bearer). Pełna dokumentacja: `http://localhost:8000/docs`.

## Zasady bezpieczeństwa
Skanujemy wyłącznie zakresy podane przez organizatora i dozwolone porty. Sygnatury tylko wykrywają (GET bez parametrów,
bez logowania, bez exploitów). Każda akcja trafia do dziennika audytu. Klucz `AEGIS_KEY` trzymaj poza repozytorium.

## Status
- Backend: przetestowany end-to-end (nmap 7.94, dwa przebiegi, zmiany, RBAC, import/eksport, Wi-Fi, wysyłka do atrapy API DefectDojo).
- Integracja z prawdziwym DefectDojo: zgodna z API v2 (`/api/v2/reimport-scan/`), ale nie była testowana na żywej instancji. Sprawdźcie ją na demo lub kontenerze z GitHuba.
- Aplikacja Android: kod gotowy, nie był budowany w tym środowisku (brak Android SDK).
