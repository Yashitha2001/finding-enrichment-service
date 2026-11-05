import json
import sqlite3
import threading
from datetime import datetime, timezone

STATUSES = ("open", "acknowledged", "resolved")

SCHEMA = """
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    fingerprint TEXT NOT NULL UNIQUE,
    finding_type TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    region TEXT NOT NULL,
    title TEXT,
    severity TEXT NOT NULL,
    score INTEGER NOT NULL,
    priority TEXT NOT NULL,
    owner TEXT,
    team TEXT,
    environment TEXT,
    data_classification TEXT,
    internet_facing INTEGER NOT NULL DEFAULT 0,
    reasons TEXT,
    remediation TEXT,
    source TEXT,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    occurrences INTEGER NOT NULL DEFAULT 1,
    status TEXT NOT NULL DEFAULT 'open'
);
"""

# Columns that get refreshed every time a finding is (re)reported.
ENRICHED = (
    "title", "severity", "score", "priority", "owner", "team", "environment",
    "data_classification", "internet_facing", "reasons", "remediation", "source",
)


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class FindingStore:
    def __init__(self, path=":memory:"):
        # One shared connection guarded by a lock. Fine at this scale, and it
        # keeps ":memory:" databases working in tests.
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        with self._lock:
            self._conn.executescript(SCHEMA)

    def upsert(self, rec):
        """Insert a finding or fold it into an existing one.

        Returns (finding_id, was_duplicate).
        """
        now = _now()
        values = {
            **rec,
            "reasons": json.dumps(rec["reasons"]),
            "remediation": json.dumps(rec["remediation"]),
            "internet_facing": int(rec["internet_facing"]),
        }
        with self._lock:
            existing = self._conn.execute(
                "SELECT id, status FROM findings WHERE fingerprint = ?",
                (rec["fingerprint"],),
            ).fetchone()

            if existing:
                # A resolved finding that shows up again is a regression.
                status = "open" if existing["status"] == "resolved" else existing["status"]
                assignments = ", ".join(f"{c} = ?" for c in ENRICHED)
                self._conn.execute(
                    f"UPDATE findings SET {assignments}, last_seen = ?, "
                    "occurrences = occurrences + 1, status = ? WHERE id = ?",
                    [values[c] for c in ENRICHED] + [now, status, existing["id"]],
                )
                self._conn.commit()
                return existing["id"], True

            cols = ("fingerprint", "finding_type", "resource_id", "region") + ENRICHED
            placeholders = ", ".join("?" for _ in cols)
            cur = self._conn.execute(
                f"INSERT INTO findings ({', '.join(cols)}, first_seen, last_seen) "
                f"VALUES ({placeholders}, ?, ?)",
                [values[c] for c in cols] + [rec.get("detected_at") or now, now],
            )
            self._conn.commit()
            return cur.lastrowid, False

    def get(self, finding_id):
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM findings WHERE id = ?", (finding_id,)
            ).fetchone()
        return self._to_dict(row) if row else None

    def list(self, priority=None, environment=None, status=None):
        clauses, params = [], []
        for column, value in (("priority", priority),
                              ("environment", environment),
                              ("status", status)):
            if value:
                clauses.append(f"{column} = ?")
                params.append(value)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        with self._lock:
            rows = self._conn.execute(
                f"SELECT * FROM findings {where} ORDER BY score DESC, last_seen DESC",
                params,
            ).fetchall()
        return [self._to_dict(r) for r in rows]

    def set_status(self, finding_id, status):
        if status not in STATUSES:
            raise ValueError(f"status must be one of {', '.join(STATUSES)}")
        with self._lock:
            cur = self._conn.execute(
                "UPDATE findings SET status = ? WHERE id = ?", (status, finding_id)
            )
            self._conn.commit()
            return cur.rowcount > 0

    def summary(self):
        with self._lock:
            by_priority = self._conn.execute(
                "SELECT priority, COUNT(*) AS n FROM findings "
                "WHERE status != 'resolved' GROUP BY priority"
            ).fetchall()
            totals = self._conn.execute(
                "SELECT COUNT(*) AS total, "
                "COALESCE(SUM(occurrences - 1), 0) AS dupes FROM findings"
            ).fetchone()
        return {
            "total_findings": totals["total"],
            "duplicates_merged": totals["dupes"],
            "open_by_priority": {r["priority"]: r["n"] for r in by_priority},
        }

    @staticmethod
    def _to_dict(row):
        d = dict(row)
        d["reasons"] = json.loads(d["reasons"] or "[]")
        d["remediation"] = json.loads(d["remediation"] or "[]")
        d["internet_facing"] = bool(d["internet_facing"])
        return d
