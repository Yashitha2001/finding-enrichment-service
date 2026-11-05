import json

from .models import Asset


class Inventory:
    """Stand-in for an AWS asset inventory (Config, Resource Explorer, a CMDB...).

    Swapping this for real boto3 calls later only means changing lookup().
    """

    def __init__(self, assets):
        self._by_id = {a.resource_id: a for a in assets}

    @classmethod
    def from_file(cls, path):
        with open(path, encoding="utf-8") as f:
            rows = json.load(f)
        return cls([Asset(**row) for row in rows])

    def lookup(self, resource_id):
        return self._by_id.get(resource_id)

    def __len__(self):
        return len(self._by_id)
