import json
import logging
import re

from .cache import MISSING, TTLCache
from .inventory import InventoryError
from .models import Asset

log = logging.getLogger(__name__)

# resource id prefix -> (AWS Config resource type, Config field to match on)
RESOURCE_MAP = (
    ("s3://", "AWS::S3::Bucket", "resourceName"),
    ("sg-", "AWS::EC2::SecurityGroup", "resourceId"),
    ("iam:user/", "AWS::IAM::User", "resourceName"),
    ("rds:", "AWS::RDS::DBInstance", "resourceName"),
)
ENV_ALIASES = {"production": "prod", "prd": "prod", "development": "dev", "stage": "staging"}

# Resource ids come from external scanners and end up inside a Config query,
# so anything outside this set is treated as "unknown resource".
SAFE_VALUE = re.compile(r"^[A-Za-z0-9._:/@+=-]+$")


def parse_resource_id(resource_id):
    for prefix, config_type, field in RESOURCE_MAP:
        if resource_id.startswith(prefix):
            value = resource_id[len(prefix):] if prefix != "sg-" else resource_id
            if prefix == "iam:user/":
                value = value.split("/")[-1]
            return (config_type, field, value) if SAFE_VALUE.match(value) else None
    return None


class AwsInventory:
    """Looks resources up in AWS Config and reads ownership from resource tags.

    Expected tags: Owner, Team, Environment, DataClassification, InternetFacing.
    """

    def __init__(self, client=None, region=None):
        if client is None:
            import boto3  # imported here so the mock setup doesn't need boto3
            client = boto3.client("config", region_name=region)
        self._client = client

    def lookup(self, resource_id):
        parsed = parse_resource_id(resource_id.strip())
        if parsed is None:
            return None
        config_type, field, value = parsed
        query = (
            "SELECT resourceType, accountId, tags "
            f"WHERE resourceType = '{config_type}' AND {field} = '{value}'"
        )
        try:
            rows = self._client.select_resource_config(Expression=query, Limit=1)["Results"]
        except Exception as exc:
            raise InventoryError(str(exc)) from exc
        if not rows:
            return None

        row = json.loads(rows[0])
        tags = {t["key"].lower(): t["value"] for t in row.get("tags", [])}
        env = tags.get("environment", "unknown").lower()
        return Asset(
            resource_id=resource_id,
            resource_type=row.get("resourceType", "unknown"),
            owner=tags.get("owner", "unassigned"),
            team=tags.get("team", "unassigned"),
            environment=ENV_ALIASES.get(env, env),
            account_id=row.get("accountId", "unknown"),
            data_classification=tags.get("dataclassification", "unknown").lower(),
            internet_facing=tags.get("internetfacing", "").lower() == "true",
        )


class CachedInventory:
    """Wraps any inventory so repeat lookups don't hit AWS every time."""

    def __init__(self, inner, ttl=300, miss_ttl=60, clock=None):
        self._inner = inner
        self._miss_ttl = miss_ttl
        self._cache = TTLCache(ttl, clock) if clock else TTLCache(ttl)

    def lookup(self, resource_id):
        cached = self._cache.get(resource_id)
        if cached is not MISSING:
            return cached
        try:
            asset = self._inner.lookup(resource_id)
        except InventoryError as exc:
            # Don't cache outages; the finding is kept with unknown context.
            log.warning("inventory lookup failed for %s: %s", resource_id, exc)
            return None
        self._cache.set(resource_id, asset, self._miss_ttl if asset is None else None)
        return asset
