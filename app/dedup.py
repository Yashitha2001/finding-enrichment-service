import hashlib


def fingerprint(finding_type, resource_id, region):
    """Two reports of the same problem on the same resource share a fingerprint.

    Type and region are normalised; resource ids are left alone because
    things like ARNs and S3 keys are case sensitive.
    """
    key = "|".join([
        finding_type.strip().lower(),
        resource_id.strip(),
        region.strip().lower(),
    ])
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]
