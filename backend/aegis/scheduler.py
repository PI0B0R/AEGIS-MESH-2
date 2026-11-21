"""Harmonogram cyklicznych skanow z oknami czasowymi.

- Skan startuje, gdy minal interwal i jestesmy w oknie.
- Gdy okno sie konczy, scanner oddaje niedokonczone paczki (status 'paused').
- W kolejnym oknie scheduler wznawia ten sam przebieg od pozostalych paczek.
"""
import logging
import threading
import time
from datetime import datetime, timedelta
from typing import Optional

from . import db, scanner

log = logging.getLogger("aegis.scheduler")
_stop = threading.Event()


def _parse(hm: Optional[str]):
    if not hm:
        return None
    h, m = hm.split(":")
    return int(h), int(m)


def window_deadline(sched: dict, now: Optional[datetime] = None) -> tuple[bool, Optional[float]]:
    """(czy_teraz_w_oknie, timestamp_konca_okna). Obsluguje okna przez polnoc (np. 22:00-06:00)."""
    now = now or datetime.now()
    start, end = _parse(sched.get("window_start")), _parse(sched.get("window_end"))
    if not start or not end:
        return True, None
    s = now.replace(hour=start[0], minute=start[1], second=0, microsecond=0)
    e = now.replace(hour=end[0], minute=end[1], second=0, microsecond=0)
    if s < e:
        return (s <= now < e), e.timestamp()
    # okno przez polnoc
    if now >= s:
        return True, (e + timedelta(days=1)).timestamp()
    if now < e:
        return True, e.timestamp()
    return False, None


def tick() -> None:
    for sched in db.q("SELECT * FROM schedules WHERE enabled=1"):
        inside, deadline = window_deadline(sched)
        if not inside:
            continue
        paused = db.q1("SELECT id FROM scan_runs WHERE schedule_id=? AND status='paused' ORDER BY id DESC LIMIT 1",
                       (sched["id"],))
        if paused:
            if scanner.start_async(paused["id"], deadline):
                log.info("harmonogram %s: wznawiam przebieg %s", sched["name"], paused["id"])
            continue
        busy = db.q1("SELECT id FROM scan_runs WHERE schedule_id=? AND status IN ('queued','running')", (sched["id"],))
        if busy:
            if not scanner.is_running(busy["id"]):  # np. po restarcie serwera
                scanner.start_async(busy["id"], deadline)
            continue
        due = not sched["last_started"] or time.time() - sched["last_started"] >= sched["interval_minutes"] * 60
        if not due:
            continue
        try:
            run_id = scanner.create_run(db.jload(sched["target_ids"]), sched["id"], sched["ports"],
                                        sched["max_rate"], sched["parallel_chunks"])
        except ValueError as e:
            log.warning("harmonogram %s: %s", sched["name"], e)
            continue
        with db.tx() as c:
            c.execute("UPDATE schedules SET last_started=? WHERE id=?", (time.time(), sched["id"]))
        scanner.start_async(run_id, deadline)
        log.info("harmonogram %s: start przebiegu %s", sched["name"], run_id)


def loop(interval: float = 30.0) -> None:
    while not _stop.is_set():
        try:
            tick()
        except Exception:  # noqa: BLE001
            log.exception("blad harmonogramu")
        _stop.wait(interval)


def start() -> threading.Thread:
    t = threading.Thread(target=loop, daemon=True, name="scheduler")
    t.start()
    return t


def stop() -> None:
    _stop.set()
