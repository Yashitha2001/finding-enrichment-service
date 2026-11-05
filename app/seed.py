"""Load the sample findings straight into the database (no server needed).

    python -m app.seed [path/to/findings.db]
"""
import json
import sys
from pathlib import Path

from .inventory import Inventory
from .models import RawFinding
from .service import FindingService
from .storage import FindingStore

DATA_DIR = Path(__file__).resolve().parent.parent / "data"


def main():
    db_path = sys.argv[1] if len(sys.argv) > 1 else "findings.db"
    service = FindingService(
        Inventory.from_file(DATA_DIR / "mock_inventory.json"),
        FindingStore(db_path),
    )

    with open(DATA_DIR / "sample_findings.json", encoding="utf-8") as f:
        samples = json.load(f)

    new = dupes = 0
    for item in samples:
        result = service.ingest(RawFinding(**item))
        if result["duplicate"]:
            dupes += 1
        else:
            new += 1
        print(f"{result['priority']}  {result['score']:>3}  {result['title']}  ({result['resource_id']})")

    print(f"\n{new} new, {dupes} merged into existing findings -> {db_path}")


if __name__ == "__main__":
    main()
