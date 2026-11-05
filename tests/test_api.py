"""API tests. Needs fastapi and httpx installed (see requirements.txt)."""
import os
import tempfile
import unittest
from unittest import mock

os.environ["FINDINGS_DB"] = os.path.join(tempfile.mkdtemp(), "test.db")
os.environ["API_KEYS"] = "test-key"

from fastapi.testclient import TestClient  # noqa: E402

from app import main  # noqa: E402
from app.security import RateLimiter  # noqa: E402

client = TestClient(main.app)
AUTH = {"X-API-Key": "test-key"}


class ApiTests(unittest.TestCase):
    def test_create_then_duplicate(self):
        body = {"finding_type": "sg_open_ssh", "resource_id": "sg-0a12bc34de56"}
        first = client.post("/findings", json=body, headers=AUTH)
        second = client.post("/findings", json=body, headers=AUTH)
        self.assertEqual(first.status_code, 201)
        self.assertEqual(second.status_code, 200)
        self.assertTrue(second.json()["duplicate"])

    def test_ingest_requires_a_valid_key(self):
        body = {"finding_type": "sg_open_ssh", "resource_id": "sg-1"}
        self.assertEqual(client.post("/findings", json=body).status_code, 401)
        self.assertEqual(client.post("/findings", json=body, headers={"X-API-Key": "nope"}).status_code, 401)

    def test_reads_do_not_need_a_key(self):
        self.assertEqual(client.get("/summary").status_code, 200)

    def test_rate_limit_returns_429_with_retry_after(self):
        body = {"finding_type": "sg_open_ssh", "resource_id": "sg-1"}
        with mock.patch.object(main, "limiter", RateLimiter(limit=1, window=60)):
            self.assertEqual(client.post("/findings", json=body, headers=AUTH).status_code, 201)
            res = client.post("/findings", json=body, headers=AUTH)
        self.assertEqual(res.status_code, 429)
        self.assertIn("retry-after", res.headers)

    def test_bad_severity_and_bad_timestamp_are_422(self):
        base = {"finding_type": "sg_open_ssh", "resource_id": "sg-1"}
        self.assertEqual(client.post("/findings", json={**base, "severity": "urgent"}, headers=AUTH).status_code, 422)
        self.assertEqual(client.post("/findings", json={**base, "detected_at": "soon"}, headers=AUTH).status_code, 422)

    def test_overdue_filter_and_summary(self):
        client.post("/findings", headers=AUTH, json={
            "finding_type": "cloudtrail_disabled", "resource_id": "cloudtrail:org-trail",
            "detected_at": "2020-01-01T00:00:00Z"})
        overdue = client.get("/findings", params={"overdue": "true"}).json()
        self.assertTrue(overdue and all(f["overdue"] for f in overdue))
        self.assertGreaterEqual(client.get("/summary").json()["overdue"], 1)

    def test_missing_finding_is_404(self):
        self.assertEqual(client.get("/findings/99999").status_code, 404)

    def test_status_update(self):
        created = client.post("/findings", headers=AUTH, json={
            "finding_type": "iam_user_no_mfa", "resource_id": "iam:user/jlee"}).json()
        res = client.patch(f"/findings/{created['id']}/status", json={"status": "acknowledged"})
        self.assertEqual(res.json()["status"], "acknowledged")

    def test_dashboard_is_served(self):
        self.assertIn("Security findings", client.get("/").text)


if __name__ == "__main__":
    unittest.main()
