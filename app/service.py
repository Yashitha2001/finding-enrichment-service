from .dedup import fingerprint
from .models import SEVERITIES, Asset, RawFinding
from .remediation import get_guidance
from .scoring import score_finding, to_priority


class FindingService:
    """Glue: take a raw finding, enrich it, score it, store it."""

    def __init__(self, inventory, store):
        self.inventory = inventory
        self.store = store

    def ingest(self, raw: RawFinding):
        guidance = get_guidance(raw.finding_type)
        severity = self._pick_severity(raw, guidance)

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
            "detected_at": raw.detected_at,
        }

        finding_id, duplicate = self.store.upsert(record)
        finding = self.store.get(finding_id)
        finding["duplicate"] = duplicate
        return finding

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
