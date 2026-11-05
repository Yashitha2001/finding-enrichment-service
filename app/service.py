import logging

from .dedup import fingerprint
from .models import SEVERITIES, Asset, RawFinding
from .remediation import get_guidance
from .scoring import score_finding, to_priority
from .sla import parse_ts

log = logging.getLogger(__name__)


class FindingService:
    """Glue: take a raw finding, enrich it, score it, store it, alert on P1."""

    def __init__(self, inventory, store, notifiers=()):
        self.inventory = inventory
        self.store = store
        self.notifiers = list(notifiers)

    def ingest(self, raw: RawFinding):
        guidance = get_guidance(raw.finding_type)
        severity = self._pick_severity(raw, guidance)
        detected_at = parse_ts(raw.detected_at).isoformat(timespec="seconds") if raw.detected_at else None

        asset = self.inventory.lookup(raw.resource_id)
        known = asset is not None
        if not known:
            asset = Asset(resource_id=raw.resource_id)

        score, reasons = score_finding(severity, asset)
        if not known:
            reasons.append("resource not in inventory, owner and environment unknown")

        record = {
            "fingerprint": fingerprint(raw.finding_type, raw.resource_id, raw.region),
            "finding_type": raw.finding_type.strip().lower(),
            "resource_id": raw.resource_id.strip(),
            "region": raw.region.strip().lower(),
            "title": raw.title or guidance["summary"],
            "severity": severity,
            "score": score,
            "priority": to_priority(score),
            "owner": asset.owner,
            "team": asset.team,
            "environment": asset.environment,
            "data_classification": asset.data_classification,
            "internet_facing": asset.internet_facing,
            "reasons": reasons,
            "remediation": guidance["steps"],
            "source": raw.source,
            "detected_at": detected_at,
        }

        finding_id, duplicate = self.store.upsert(record)
        finding = self.store.get(finding_id)
        finding["duplicate"] = duplicate

        if not duplicate and finding["priority"] == "P1":
            self._notify(finding)
        return finding

    def _notify(self, finding):
        for notifier in self.notifiers:
            try:
                notifier.send(finding)
            except Exception:
                # An alerting outage must never lose the finding itself.
                log.exception("%s failed for finding %s", type(notifier).__name__, finding["id"])

    @staticmethod
    def _pick_severity(raw, guidance):
        if raw.severity is None:
            return guidance["default_severity"]
        severity = raw.severity.strip().lower()
        if severity not in SEVERITIES:
            raise ValueError(
                f"unknown severity '{raw.severity}', expected one of {', '.join(SEVERITIES)}"
            )
        return severity
