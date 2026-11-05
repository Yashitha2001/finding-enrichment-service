from datetime import datetime, timedelta, timezone

SLA_HOURS = {"P1": 4, "P2": 24, "P3": 72, "P4": 168}


def parse_ts(value):
    """Parse an ISO-8601 timestamp. Naive values are treated as UTC."""
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def sla_info(priority, first_seen, status, now=None):
    now = now or datetime.now(timezone.utc)
    try:
        due = parse_ts(first_seen) + timedelta(hours=SLA_HOURS[priority])
    except (ValueError, TypeError, KeyError):
        return {"sla_due": None, "hours_left": None, "overdue": False}
    return {
        "sla_due": due.isoformat(timespec="seconds"),
        "hours_left": round((due - now).total_seconds() / 3600, 1),
        # Acknowledging a finding doesn't stop the clock, only resolving does.
        "overdue": status != "resolved" and now > due,
    }
