import os
from pathlib import Path
from typing import List, Literal, Optional

from fastapi import FastAPI, HTTPException, Response
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from .inventory import Inventory
from .models import RawFinding
from .service import FindingService
from .storage import FindingStore

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR.parent / "data"

app = FastAPI(title="Finding Enrichment Service")

inventory = Inventory.from_file(DATA_DIR / "mock_inventory.json")
store = FindingStore(os.getenv("FINDINGS_DB", "findings.db"))
service = FindingService(inventory, store)


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


def _ingest(body: FindingIn):
    try:
        return service.ingest(RawFinding(**body.model_dump()))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@app.post("/findings", status_code=201)
def create_finding(body: FindingIn, response: Response):
    finding = _ingest(body)
    if finding["duplicate"]:
        # Not a new resource, so don't claim we created one.
        response.status_code = 200
    return finding


@app.post("/findings/bulk")
def create_findings(bodies: List[FindingIn]):
    results = [_ingest(b) for b in bodies]
    merged = sum(1 for r in results if r["duplicate"])
    return {
        "received": len(results),
        "created": len(results) - merged,
        "merged": merged,
        "findings": results,
    }


@app.get("/findings")
def list_findings(
    priority: Optional[str] = None,
    environment: Optional[str] = None,
    status: Optional[str] = None,
):
    return store.list(priority=priority, environment=environment, status=status)


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
