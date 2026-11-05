"""Builds the service from environment variables. Shared by the API and the SQS worker."""
import os
from pathlib import Path

from .aws_inventory import AwsInventory, CachedInventory
from .inventory import Inventory
from .notify import SlackNotifier, WebhookNotifier
from .service import FindingService
from .storage import FindingStore

DATA_DIR = Path(__file__).resolve().parent.parent / "data"


def build_inventory():
    if os.getenv("INVENTORY_BACKEND", "mock") == "aws":
        return CachedInventory(
            AwsInventory(region=os.getenv("AWS_REGION")),
            ttl=int(os.getenv("INVENTORY_CACHE_TTL", "300")),
        )
    return Inventory.from_file(DATA_DIR / "mock_inventory.json")


def build_notifiers():
    notifiers = []
    if os.getenv("SLACK_WEBHOOK_URL"):
        notifiers.append(SlackNotifier(os.environ["SLACK_WEBHOOK_URL"]))
    if os.getenv("TICKET_WEBHOOK_URL"):
        notifiers.append(WebhookNotifier(os.environ["TICKET_WEBHOOK_URL"]))
    return notifiers


def build_service():
    store = FindingStore(os.getenv("FINDINGS_DB", "findings.db"))
    return FindingService(build_inventory(), store, build_notifiers())
