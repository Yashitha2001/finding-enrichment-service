"""API tests. Needs fastapi and httpx installed (see requirements.txt)."""
import os
import tempfile
import unittest

os.environ["FINDINGS_DB"] = os.path.join(tempfile.mkdtemp(), "test.db")

from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402

client = TestClient(app)


class ApiTests(unittest.TestCase):
    def test_create_then_duplicate(self):
        body = {"finding_type": "sg_open_ssh", "resource_id": "sg-0a12bc34de56"}
        first = client.post("/findings", json=body)
        second = client.post("/findings", json=body)
        self.assertEqual(first.status_code, 201)
        self.assertEqual(second.status_code, 200)
        self.assertTrue(second.json()["duplicate"])

    def test_bad_severity_is_422(self):
        res = client.post("/findings", json={
            "finding_type": "sg_open_ssh", "resource_id": "sg-1", "severity": "urgent",
        })
        self.assertEqual(res.status_code, 422)

    def test_missing_finding_is_404(self):
        self.assertEqual(client.get("/findings/99999").status_code, 404)

    def test_status_update(self):
        created = client.post("/findings", json={
            "finding_type": "iam_user_no_mfa", "resource_id": "iam:user/jlee",
        }).json()
        res = client.patch(f"/findings/{created['id']}/status", json={"status": "acknowledged"})
        self.assertEqual(res.json()["status"], "acknowledged")

    def test_dashboard_is_served(self):
        self.assertIn("Security findings", client.get("/").text)


if __name__ == "__main__":
    unittest.main()
