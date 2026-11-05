import unittest

from app.dedup import fingerprint
from app.inventory import Inventory
from app.models import Asset, RawFinding
from app.scoring import score_finding, to_priority
from app.service import FindingService
from app.storage import FindingStore

PROD_BUCKET = Asset(
    resource_id="s3://prod-data", resource_type="s3_bucket", owner="alice",
    team="data", environment="prod", data_classification="restricted",
    internet_facing=True,
)
DEV_BUCKET = Asset(
    resource_id="s3://dev-data", resource_type="s3_bucket", owner="bob",
    team="data", environment="dev", data_classification="internal",
)


def make_service():
    return FindingService(Inventory([PROD_BUCKET, DEV_BUCKET]), FindingStore())


class FingerprintTests(unittest.TestCase):
    def test_type_and_region_are_normalised(self):
        a = fingerprint("S3_Public_Access", "s3://x", "US-EAST-1")
        b = fingerprint("s3_public_access", "s3://x", "us-east-1")
        self.assertEqual(a, b)

    def test_resource_id_is_case_sensitive(self):
        self.assertNotEqual(
            fingerprint("t", "s3://Bucket", "us-east-1"),
            fingerprint("t", "s3://bucket", "us-east-1"),
        )


class ScoringTests(unittest.TestCase):
    def test_prod_restricted_public_bucket_is_p1(self):
        score, _ = score_finding("high", PROD_BUCKET)
        self.assertEqual(score, 91)
        self.assertEqual(to_priority(score), "P1")

    def test_same_finding_in_dev_ranks_lower(self):
        prod, _ = score_finding("high", PROD_BUCKET)
        dev, _ = score_finding("high", DEV_BUCKET)
        self.assertLess(dev, prod)
        self.assertEqual(to_priority(dev), "P4")

    def test_score_is_capped_at_100(self):
        score, _ = score_finding("critical", PROD_BUCKET)
        self.assertEqual(score, 100)

    def test_reasons_explain_the_score(self):
        _, reasons = score_finding("high", PROD_BUCKET)
        self.assertEqual(len(reasons), 4)

    def test_priority_boundaries(self):
        self.assertEqual(to_priority(80), "P1")
        self.assertEqual(to_priority(79), "P2")
        self.assertEqual(to_priority(60), "P2")
        self.assertEqual(to_priority(59), "P3")
        self.assertEqual(to_priority(35), "P3")
        self.assertEqual(to_priority(34), "P4")


class IngestTests(unittest.TestCase):
    def setUp(self):
        self.service = make_service()

    def test_enrichment_pulls_owner_and_environment(self):
        f = self.service.ingest(RawFinding("s3_public_access", "s3://prod-data"))
        self.assertEqual(f["owner"], "alice")
        self.assertEqual(f["environment"], "prod")
        self.assertEqual(f["priority"], "P1")
        self.assertFalse(f["duplicate"])
        self.assertTrue(f["remediation"])

    def test_unknown_resource_is_flagged_not_dropped(self):
        f = self.service.ingest(RawFinding("s3_public_access", "s3://mystery"))
        self.assertEqual(f["owner"], "unassigned")
        self.assertEqual(f["environment"], "unknown")
        self.assertIn("not in inventory", f["reasons"][-1])

    def test_duplicate_is_merged_and_counted(self):
        first = self.service.ingest(RawFinding("s3_public_access", "s3://prod-data"))
        second = self.service.ingest(RawFinding("S3_PUBLIC_ACCESS", "s3://prod-data"))
        self.assertEqual(first["id"], second["id"])
        self.assertTrue(second["duplicate"])
        self.assertEqual(second["occurrences"], 2)
        self.assertEqual(len(self.service.store.list()), 1)

    def test_different_region_is_a_separate_finding(self):
        self.service.ingest(RawFinding("s3_public_access", "s3://prod-data"))
        self.service.ingest(RawFinding("s3_public_access", "s3://prod-data", region="eu-west-1"))
        self.assertEqual(len(self.service.store.list()), 2)

    def test_resolved_finding_reopens_when_it_comes_back(self):
        f = self.service.ingest(RawFinding("s3_public_access", "s3://prod-data"))
        self.service.store.set_status(f["id"], "resolved")
        again = self.service.ingest(RawFinding("s3_public_access", "s3://prod-data"))
        self.assertEqual(again["status"], "open")

    def test_acknowledged_finding_stays_acknowledged(self):
        f = self.service.ingest(RawFinding("s3_public_access", "s3://prod-data"))
        self.service.store.set_status(f["id"], "acknowledged")
        again = self.service.ingest(RawFinding("s3_public_access", "s3://prod-data"))
        self.assertEqual(again["status"], "acknowledged")

    def test_severity_override_wins_over_default(self):
        f = self.service.ingest(
            RawFinding("s3_public_access", "s3://dev-data", severity="Critical")
        )
        self.assertEqual(f["severity"], "critical")

    def test_invalid_severity_is_rejected(self):
        with self.assertRaises(ValueError):
            self.service.ingest(RawFinding("s3_public_access", "s3://dev-data", severity="urgent"))

    def test_unknown_finding_type_gets_generic_guidance(self):
        f = self.service.ingest(RawFinding("something_new", "s3://dev-data"))
        self.assertEqual(f["severity"], "medium")
        self.assertEqual(f["title"], "Security configuration finding")


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.service = make_service()
        self.service.ingest(RawFinding("s3_public_access", "s3://prod-data"))
        self.service.ingest(RawFinding("s3_public_access", "s3://dev-data"))

    def test_list_is_sorted_by_score(self):
        scores = [f["score"] for f in self.service.store.list()]
        self.assertEqual(scores, sorted(scores, reverse=True))

    def test_filters(self):
        self.assertEqual(len(self.service.store.list(priority="P1")), 1)
        self.assertEqual(len(self.service.store.list(environment="dev")), 1)
        self.assertEqual(self.service.store.list(status="resolved"), [])

    def test_summary_excludes_resolved_and_counts_duplicates(self):
        f = self.service.ingest(RawFinding("s3_public_access", "s3://prod-data"))
        summary = self.service.store.summary()
        self.assertEqual(summary["duplicates_merged"], 1)
        self.assertEqual(summary["open_by_priority"], {"P1": 1, "P4": 1})
        self.service.store.set_status(f["id"], "resolved")
        self.assertEqual(self.service.store.summary()["open_by_priority"], {"P4": 1})

    def test_set_status_validation(self):
        with self.assertRaises(ValueError):
            self.service.store.set_status(1, "closed")
        self.assertFalse(self.service.store.set_status(999, "resolved"))


if __name__ == "__main__":
    unittest.main()
