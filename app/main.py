import os
from pathlib import Path
from typing import List, Literal, Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from .bootstrap import build_service
from .models import RawFinding
from .security import RateLimiter, key_is_valid, load_api_keys

BASE_DIR = Path(__file__).resolve().parent
MAX_BULK = 500

app = FastAPI(title="Finding Enrichment Service")

service = build_service()
store = service.store
API_KEYS = load_api_keys()  # empty means auth is off (local development)
limiter = RateLimiter(limit=int(os.getenv("RATE_LIMIT_PER_MINUTE", "60")), window=60)


class FindingIn(BaseModel):
    finding_type: str = Field(min_length=1)
    resource_id: str = Field(min_length=1)
    region: str = "us-east-1"
    title: str = ""
    severity: Optional[Literal["low", "medium", "high", "critical"]] = None
    source: str = "manual"
    detected_at: Optional[str] = None


class StatusUpdate(BaseModel):
    status: Literal["open", "acknowledged", "resolved"]


def guard_ingest(request: Request, x_api_key: Optional[str] = Header(default=None)):
    if API_KEYS and not key_is_valid(x_api_key, API_KEYS):
        raise HTTPException(401, "missing or invalid API key", headers={"WWW-Authenticate": "ApiKey"})
    caller = x_api_key if API_KEYS else (request.client.host if request.client else "unknown")
    wait = limiter.check(caller)
    if wait:
        raise HTTPException(429, "rate limit exceeded", headers={"Retry-After": str(wait)})


def _ingest(body: FindingIn):
    try:
        return service.ingest(RawFinding(**body.model_dump()))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@app.post("/findings", status_code=201, dependencies=[Depends(guard_ingest)])
def create_finding(body: FindingIn, response: Response):
    finding = _ingest(body)
    if finding["duplicate"]:
        response.status_code = 200
    return finding


@app.post("/findings/bulk", dependencies=[Depends(guard_ingest)])
def create_findings(bodies: List[FindingIn]):
    if len(bodies) > MAX_BULK:
        raise HTTPException(413, f"send at most {MAX_BULK} findings per request")
    results = [_ingest(b) for b in bodies]
    merged = sum(1 for r in results if r["duplicate"])
    return {"received": len(results), "created": len(results) - merged,
            "merged": merged, "findings": results}


@app.get("/findings")
def list_findings(
    priority: Optional[str] = None,
    environment: Optional[str] = None,
    status: Optional[str] = None,
    overdue: Optional[bool] = None,
):
    return store.list(priority=priority, environment=environment, status=status, overdue=overdue)


@app.get("/findings/{finding_id}")
def get_finding(finding_id: int):
    finding = store.get(finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="finding not found")
    return finding


@app.patch("/findings/{finding_id}/status")
def update_status(finding_id: int, body: StatusUpdate):
    if not store.set_status(finding_id, body.status):
        raise HTTPException(status_code=404, detail="finding not found")
    return store.get(finding_id)


@app.get("/summary")
def summary():
    return store.summary()


@app.get("/", include_in_schema=False)
def dashboard():
    return FileResponse(BASE_DIR / "static" / "dashboard.html")
