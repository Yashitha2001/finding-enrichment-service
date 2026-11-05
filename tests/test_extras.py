import json
import unittest
from datetime import datetime, timedelta, timezone

from app.aws_inventory import AwsInventory, CachedInventory, parse_resource_id
from app.cache import MISSING, TTLCache
from app.inventory import Inventory, InventoryError
from app.models import Asset, RawFinding
from app.notify import SlackNotifier, WebhookNotifier
from app.security import RateLimiter, key_is_valid, load_api_keys
from app.service import FindingService
from app.sla import sla_info
from app.sqs_worker import poll_once
from app.storage import FindingStore

PROD = Asset(resource_id="s3://prod-data", environment="prod", owner="alice",
             data_classification="restricted", internet_facing=True)


class Clock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now


class FakeConfig:
    def __init__(self, rows=None, error=None):
        self.rows, self.error, self.queries = rows or [], error, []

    def select_resource_config(self, Expression, Limit):
        self.queries.append(Expression)
        if self.error:
            raise self.error
        return {"Results": [json.dumps(r) for r in self.rows]}


BUCKET_ROW = {"resourceType": "AWS::S3::Bucket", "accountId": "1111",
              "tags": [{"key": "Owner", "value": "priya"}, {"key": "Environment", "value": "Production"},
                       {"key": "DataClassification", "value": "Restricted"},
                       {"key": "InternetFacing", "value": "true"}]}


class CacheTests(unittest.TestCase):
    def test_entries_expire(self):
        clock = Clock()
        cache = TTLCache(ttl=10, clock=clock)
        cache.set("a", 1)
        clock.now = 9
        self.assertEqual(cache.get("a"), 1)
        clock.now = 10
        self.assertIs(cache.get("a"), MISSING)


class AwsInventoryTests(unittest.TestCase):
    def test_tags_become_asset_fields(self):
        asset = AwsInventory(FakeConfig([BUCKET_ROW])).lookup("s3://prod-data")
        self.assertEqual((asset.owner, asset.environment, asset.data_classification, asset.internet_facing),
                         ("priya", "prod", "restricted", True))

    def test_query_uses_resource_name_for_buckets(self):
        client = FakeConfig([BUCKET_ROW])
        AwsInventory(client).lookup("s3://prod-data")
        self.assertIn("resourceName = 'prod-data'", client.queries[0])

    def test_unsafe_ids_never_reach_the_query(self):
        client = FakeConfig([BUCKET_ROW])
        self.assertIsNone(AwsInventory(client).lookup("s3://x' OR resourceType != '"))
        self.assertEqual(client.queries, [])

    def test_unmapped_and_empty_results_return_none(self):
        self.assertIsNone(parse_resource_id("kms:key/payments"))
        self.assertIsNone(AwsInventory(FakeConfig([])).lookup("s3://nothing"))

    def test_client_errors_become_inventory_error(self):
        with self.assertRaises(InventoryError):
            AwsInventory(FakeConfig(error=RuntimeError("throttled"))).lookup("s3://b")


class CachedInventoryTests(unittest.TestCase):
    def test_hits_are_cached(self):
        client = FakeConfig([BUCKET_ROW])
        inv = CachedInventory(AwsInventory(client))
        inv.lookup("s3://b"), inv.lookup("s3://b")
        self.assertEqual(len(client.queries), 1)

    def test_misses_are_cached_briefly(self):
        clock, client = Clock(), FakeConfig([])
        inv = CachedInventory(AwsInventory(client), ttl=300, miss_ttl=60, clock=clock)
        inv.lookup("s3://b"), inv.lookup("s3://b")
        self.assertEqual(len(client.queries), 1)
        clock.now = 61
        inv.lookup("s3://b")
        self.assertEqual(len(client.queries), 2)

    def test_outages_are_not_cached(self):
        client = FakeConfig(error=RuntimeError("down"))
        inv = CachedInventory(AwsInventory(client))
        self.assertIsNone(inv.lookup("s3://b"))
        inv.lookup("s3://b")
        self.assertEqual(len(client.queries), 2)


class FakeSqs:
    def __init__(self, bodies):
        self.messages = [{"MessageId": str(i), "ReceiptHandle": f"r{i}", "Body": b}
                         for i, b in enumerate(bodies)]
        self.deleted = []

    def receive_message(self, **kwargs):
        return {"Messages": self.messages}

    def delete_message(self, QueueUrl, ReceiptHandle):
        self.deleted.append(ReceiptHandle)


class SqsTests(unittest.TestCase):
    def test_good_messages_are_ingested_and_deleted_bad_ones_kept(self):
        service = FindingService(Inventory([PROD]), FindingStore())
        good = json.dumps({"finding_type": "s3_public_access", "resource_id": "s3://prod-data"})
        batch = json.dumps([{"finding_type": "sg_open_ssh", "resource_id": "sg-1"},
                            {"finding_type": "sg_open_ssh", "resource_id": "sg-2"}])
        sqs = FakeSqs([good, "not json", batch, json.dumps({"surprise": 1}),
                       json.dumps({"finding_type": "x", "resource_id": "y", "detected_at": "yesterday"})])
        self.assertEqual(poll_once(service, sqs, "q"), 2)
        self.assertEqual(sqs.deleted, ["r0", "r2"])
        self.assertEqual(len(service.store.list()), 3)


class SecurityTests(unittest.TestCase):
    def test_api_keys(self):
        keys = load_api_keys(" key-one , key-two ,")
        self.assertEqual(keys, ["key-one", "key-two"])
        self.assertTrue(key_is_valid("key-two", keys))
        self.assertFalse(key_is_valid("key", keys))
        self.assertFalse(key_is_valid(None, keys))

    def test_rate_limiter_blocks_then_recovers(self):
        clock = Clock()
        limiter = RateLimiter(limit=2, window=60, clock=clock)
        self.assertEqual((limiter.check("a"), limiter.check("a")), (0, 0))
        self.assertEqual(limiter.check("a"), 60)
        self.assertEqual(limiter.check("b"), 0)
        clock.now = 61
        self.assertEqual(limiter.check("a"), 0)


class SlaTests(unittest.TestCase):
    def ingest_at(self, hours_ago, **kw):
        service = FindingService(Inventory([PROD]), FindingStore())
        when = (datetime.now(timezone.utc) - timedelta(hours=hours_ago)).isoformat()
        return service, service.ingest(RawFinding("s3_public_access", "s3://prod-data",
                                                  detected_at=when, **kw))

    def test_p1_past_four_hours_is_overdue(self):
        service, f = self.ingest_at(10)
        self.assertTrue(f["overdue"])
        self.assertEqual(service.store.summary()["overdue"], 1)
        self.assertEqual(len(service.store.list(overdue=True)), 1)

    def test_recent_finding_is_on_track(self):
        _, f = self.ingest_at(1)
        self.assertFalse(f["overdue"])
        self.assertGreater(f["hours_left"], 2)

    def test_resolving_stops_the_clock(self):
        service, f = self.ingest_at(10)
        service.store.set_status(f["id"], "resolved")
        self.assertFalse(service.store.get(f["id"])["overdue"])

    def test_naive_and_z_timestamps_parse(self):
        self.assertIsNotNone(sla_info("P2", "2026-01-01T00:00:00", "open")["sla_due"])
        self.assertIsNotNone(sla_info("P2", "2026-01-01T00:00:00Z", "open")["sla_due"])

    def test_bad_timestamp_is_rejected_on_ingest(self):
        service = FindingService(Inventory([PROD]), FindingStore())
        with self.assertRaises(ValueError):
            service.ingest(RawFinding("s3_public_access", "s3://prod-data", detected_at="yesterday"))


class Recorder:
    def __init__(self, fail=False):
        self.sent, self.fail = [], fail

    def send(self, finding):
        if self.fail:
            raise RuntimeError("slack is down")
        self.sent.append(finding["id"])


class NotifyTests(unittest.TestCase):
    def make(self, notifier):
        return FindingService(Inventory([PROD, Asset(resource_id="s3://dev", environment="dev")]),
                              FindingStore(), [notifier])

    def test_new_p1_alerts_once_and_duplicates_do_not(self):
        rec = Recorder()
        service = self.make(rec)
        for _ in range(3):
            service.ingest(RawFinding("s3_public_access", "s3://prod-data"))
        self.assertEqual(len(rec.sent), 1)

    def test_low_priority_does_not_alert(self):
        rec = Recorder()
        self.make(rec).ingest(RawFinding("s3_public_access", "s3://dev"))
        self.assertEqual(rec.sent, [])

    def test_notifier_failure_does_not_lose_the_finding(self):
        service = self.make(Recorder(fail=True))
        with self.assertLogs("app.service", level="ERROR"):
            f = service.ingest(RawFinding("s3_public_access", "s3://prod-data"))
        self.assertEqual(len(service.store.list()), 1)
        self.assertEqual(f["priority"], "P1")

    def test_slack_payload_is_escaped_and_webhook_posts_json(self):
        class Resp:
            def close(self): pass

        seen = {}

        def fake_open(req, timeout):
            seen["body"] = json.loads(req.data)
            seen["timeout"] = timeout
            return Resp()

        finding = {"title": "<!channel> bad", "resource_id": "a&b", "environment": "prod",
                   "owner": "x", "score": 91}
        SlackNotifier("https://hooks.example/x", opener=fake_open).send(finding)
        self.assertNotIn("<!channel>", seen["body"]["text"])
        self.assertIn("&lt;!channel&gt;", seen["body"]["text"])
        WebhookNotifier("https://tickets.example/x", opener=fake_open).send({"id": 7})
        self.assertEqual(seen["body"], {"id": 7})


if __name__ == "__main__":
    unittest.main()
