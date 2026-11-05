# Remediation guidance per finding type. Kept as plain data so a security
# engineer can edit it without touching any logic.

CATALOG = {
    "s3_public_access": {
        "default_severity": "high",
        "summary": "S3 bucket allows public access",
        "steps": [
            "Turn on S3 Block Public Access for the bucket and the account",
            "Remove bucket policy statements and ACLs that grant access to everyone",
            "Check access logs for reads from outside the organisation",
            "Tell the resource owner and record the outcome on the ticket",
        ],
    },
    "sg_open_ssh": {
        "default_severity": "high",
        "summary": "Security group allows SSH (port 22) from 0.0.0.0/0",
        "steps": [
            "Replace the open rule with a specific CIDR or a bastion/SSM Session Manager",
            "Check VPC flow logs for unexpected inbound SSH sessions",
            "Confirm with the owner that no automation depends on the open rule",
        ],
    },
    "iam_user_no_mfa": {
        "default_severity": "medium",
        "summary": "IAM user with console access has no MFA device",
        "steps": [
            "Ask the user to register an MFA device",
            "Add a policy that denies actions unless MFA is present",
            "Disable console access if the user no longer needs it",
        ],
    },
    "rds_unencrypted": {
        "default_severity": "high",
        "summary": "RDS instance is not encrypted at rest",
        "steps": [
            "Take a snapshot and copy it with encryption enabled",
            "Restore a new instance from the encrypted snapshot",
            "Cut the application over and delete the unencrypted instance",
        ],
    },
    "cloudtrail_disabled": {
        "default_severity": "critical",
        "summary": "CloudTrail logging is disabled",
        "steps": [
            "Re-enable the trail and confirm logs are reaching the log bucket",
            "Review who stopped logging and when, using the last events available",
            "Add an alarm on StopLogging and DeleteTrail API calls",
        ],
    },
}

GENERIC = {
    "default_severity": "medium",
    "summary": "Security configuration finding",
    "steps": [
        "Review the finding with the resource owner",
        "Decide whether to fix, accept the risk or mark it as a false positive",
    ],
}


def get_guidance(finding_type):
    return CATALOG.get(finding_type.strip().lower(), GENERIC)
