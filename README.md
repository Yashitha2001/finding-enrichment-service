# Finding enrichment service

Takes raw security configuration findings (the kind a scanner or AWS Config
produces), looks up the affected resource in an inventory, works out who owns
it and how much it matters, merges duplicates, and serves a prioritised list
with remediation steps through a REST API and a small dashboard.

The AWS inventory is mocked in `data/mock_inventory.json`. `Inventory.lookup()`
is the only thing that would need to change to call real AWS APIs.

## Run it

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

python -m app.seed          # loads data/sample_findings.json into findings.db
uvicorn app.main:app --reload
```

Dashboard: http://127.0.0.1:8000/  
API docs: http://127.0.0.1:8000/docs

## Tests

```bash
python -m unittest discover -s tests -t . -v   # or: pytest
```

`tests/test_core.py` needs nothing installed. `tests/test_api.py` needs the
packages from `requirements.txt`.

## API

| Method | Path | What it does |
|--------|------|--------------|
| POST | `/findings` | Ingest one finding. 201 if new, 200 if merged into an existing one |
| POST | `/findings/bulk` | Ingest a list of findings |
| GET | `/findings` | List, sorted by score. Filters: `priority`, `environment`, `status` |
| GET | `/findings/{id}` | One finding |
| PATCH | `/findings/{id}/status` | `open`, `acknowledged` or `resolved` |
| GET | `/summary` | Open counts by priority, duplicates merged |

Example:

```bash
curl -X POST localhost:8000/findings -H "Content-Type: application/json" \
  -d '{"finding_type": "s3_public_access", "resource_id": "s3://acme-customer-exports"}'
```

## How it works

1. **Ingest** - `FindingService.ingest()` is the single entry point.
2. **Enrich** - the resource is looked up in the inventory for owner, team,
   environment, data classification and exposure. If it isn't there, the
   finding is still kept and flagged instead of being dropped.
3. **Score** - severity (from the scanner, or the default for that finding
   type) plus data classification and internet exposure, multiplied by an
   environment factor, capped at 100. `reasons` records each step so analysts
   can see why something ranks where it does. P1 >= 80, P2 >= 60, P3 >= 35.
4. **Deduplicate** - finding type + resource + region is hashed into a
   fingerprint. A repeat report increments `occurrences` instead of creating
   a new row. If a resolved finding comes back, it is reopened.
5. **Remediate** - steps come from `app/remediation.py`, which is plain data.

## Ideas for next steps

- Replace the mock inventory with boto3 / AWS Config calls and cache results
- Ingest from SQS or an S3 drop instead of only HTTP
- Add API key auth and rate limiting on the ingest endpoints
- Track SLA deadlines per priority and flag overdue findings
- Send P1 findings to Slack or a ticketing system
