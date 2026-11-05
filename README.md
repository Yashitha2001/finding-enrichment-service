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

## Configuration

Everything is set with environment variables. With none set, the app runs
against the mock inventory with auth off, which is fine for local use.

| Variable | Default | Purpose |
|----------|---------|---------|
| `INVENTORY_BACKEND` | `mock` | `aws` reads resources from AWS Config |
| `AWS_REGION` | boto3 default | Region for Config and SQS |
| `INVENTORY_CACHE_TTL` | `300` | Seconds to cache inventory lookups (misses are cached for 60) |
| `API_KEYS` | empty | Comma-separated keys. When set, POST endpoints need an `X-API-Key` header |
| `RATE_LIMIT_PER_MINUTE` | `60` | Per API key (or per client IP when auth is off) on POST endpoints |
| `SLACK_WEBHOOK_URL` | empty | New P1 findings are posted here |
| `TICKET_WEBHOOK_URL` | empty | New P1 findings are POSTed as JSON (for Jira automation, ServiceNow, etc.) |
| `SQS_QUEUE_URL` | none | Queue for `python -m app.sqs_worker` |
| `FINDINGS_DB` | `findings.db` | SQLite file |

### AWS inventory

`INVENTORY_BACKEND=aws` runs an AWS Config advanced query per resource
(`config:SelectResourceConfig`) and reads ownership from resource tags:
`Owner`, `Team`, `Environment`, `DataClassification`, `InternetFacing`.
Untagged resources come back as "unassigned"/"unknown" rather than failing.
Supported ids: `s3://bucket`, `sg-...`, `iam:user/name`, `rds:identifier`.
Add a prefix in `app/aws_inventory.py` (`RESOURCE_MAP`) to support more.
If AWS is unreachable the finding is still stored, flagged as unknown, and the
failure is not cached.

### SQS ingestion

```bash
SQS_QUEUE_URL=https://sqs.us-east-1.amazonaws.com/123456789012/findings python -m app.sqs_worker
```

A message body is one finding (same JSON as `POST /findings`) or a list.
Processed messages are deleted. Malformed ones stay on the queue, so give the
queue a dead-letter queue (redrive policy) to catch them.

### SLA

Time to resolve, counted from first detection: P1 4h, P2 24h, P3 72h, P4 7d
(`app/sla.py`). Acknowledging does not stop the clock, resolving does.
Findings carry `sla_due`, `hours_left` and `overdue`; filter with
`GET /findings?overdue=true`.

### Alerts

A *new* P1 finding is sent to Slack and/or the ticket webhook. Repeats of the
same finding do not re-alert. Alert failures are logged and never block ingest.

## Limits worth knowing

- The rate limiter is in memory, so the limit applies per server process.
  Behind several workers, move it to Redis or the API gateway.
- Alerts are sent inside the request with a 3 second timeout. At higher volume,
  move them onto a queue.
- Only the POST endpoints require a key. The dashboard's status buttons and the
  read endpoints are open, so put the service behind SSO or a VPN before real use.
