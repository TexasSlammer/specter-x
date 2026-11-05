"""Ingestion load test: throughput + memory at 10k / 100k / 1M events.

Run:  python benchmarks/load_test.py           (10k + 100k)
      python benchmarks/load_test.py --full    (adds 1,000,000)
Writes benchmarks/results/load_test.json. Synthetic events are derived from
the baseline dataset with deterministic unique ids (no duplicate keys).
"""
from __future__ import annotations

import hashlib
import json
import os
import resource
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

_TMP = tempfile.mkdtemp(prefix="specter-load-")
os.environ["DATABASE_URL"] = f"sqlite:///{_TMP}/load.db"

from app.bootstrap import DATASETS  # noqa: E402
from app.ingestion import ingest_batch, load_jsonl  # noqa: E402
from app.models import SessionLocal, init_db  # noqa: E402


def scale_events(base: list[dict], n: int) -> list[dict]:
    """Deterministically expand the baseline to n events with unique ids."""
    out = []
    for i in range(n):
        e = dict(base[i % len(base)])
        e["event_id"] = "evt-load-" + hashlib.md5(f"{n}:{i}".encode()).hexdigest()
        out.append(e)
    return out


def run(n: int) -> dict:
    base = load_jsonl(DATASETS / "normal" / "baseline.jsonl")
    events = scale_events(base, n)
    t0 = time.perf_counter()
    with SessionLocal() as db:
        stats = ingest_batch(db, events)
    elapsed = time.perf_counter() - t0
    rss_mb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024
    return {"events": n, "accepted": stats["accepted"], "seconds": round(elapsed, 2),
            "throughput_eps": int(n / elapsed), "peak_rss_mb": round(rss_mb, 1)}


if __name__ == "__main__":
    init_db()
    sizes = [10_000, 100_000] + ([1_000_000] if "--full" in sys.argv else [])
    out = {"sizes": [run(n) for n in sizes]}
    path = Path(__file__).parent / "results" / "load_test.json"
    path.parent.mkdir(exist_ok=True)
    path.write_text(json.dumps(out, indent=2))
    print(json.dumps(out, indent=2))
