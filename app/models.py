from dataclasses import dataclass
from typing import Optional

SEVERITIES = ("low", "medium", "high", "critical")


@dataclass
class RawFinding:
    """A finding exactly as a scanner would send it, before enrichment."""
    finding_type: str
    resource_id: str
    region: str = "us-east-1"
    title: str = ""
    severity: Optional[str] = None
    source: str = "manual"
    detected_at: Optional[str] = None


@dataclass
class Asset:
    """What we know about a resource from the inventory.

    The defaults double as the "we know nothing about this resource" case.
    """
    resource_id: str
    resource_type: str = "unknown"
    owner: str = "unassigned"
    team: str = "unassigned"
    environment: str = "unknown"
    account_id: str = "unknown"
    data_classification: str = "unknown"
    internet_facing: bool = False
