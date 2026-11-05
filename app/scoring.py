BASE_POINTS = {"low": 10, "medium": 20, "high": 35, "critical": 65}
DATA_POINTS = {"restricted": 20, "confidential": 10}
EXPOSURE_POINTS = 15
ENV_FACTOR = {"prod": 1.3, "staging": 1.0, "dev": 0.7}


def score_finding(severity, asset):
    """Return (score, reasons). Reasons are kept so analysts can see why."""
    points = BASE_POINTS[severity]
    reasons = [f"{severity} severity (+{points})"]

    extra = DATA_POINTS.get(asset.data_classification, 0)
    if extra:
        points += extra
        reasons.append(f"{asset.data_classification} data (+{extra})")

    if asset.internet_facing:
        points += EXPOSURE_POINTS
        reasons.append(f"internet facing (+{EXPOSURE_POINTS})")

    factor = ENV_FACTOR.get(asset.environment, 1.0)
    if factor != 1.0:
        points *= factor
        reasons.append(f"{asset.environment} environment (x{factor})")

    return min(round(points), 100), reasons


def to_priority(score):
    if score >= 80:
        return "P1"
    if score >= 60:
        return "P2"
    if score >= 35:
        return "P3"
    return "P4"
