"""Pulls findings from an SQS queue and ingests them.

    SQS_QUEUE_URL=https://sqs.<region>.amazonaws.com/<acct>/<queue> python -m app.sqs_worker

Each message body is one finding as JSON, or a JSON list of findings.
"""
import json
import logging
import os

from .models import RawFinding

log = logging.getLogger(__name__)


def handle_body(service, body):
    data = json.loads(body)
    items = data if isinstance(data, list) else [data]
    return [service.ingest(RawFinding(**item)) for item in items]


def poll_once(service, client, queue_url, wait=20):
    """Receive one batch. Returns how many messages were processed and deleted."""
    response = client.receive_message(
        QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=wait
    )
    done = 0
    for message in response.get("Messages", []):
        try:
            handle_body(service, message["Body"])
        except (ValueError, TypeError) as exc:
            # Leave it on the queue. After maxReceiveCount the queue's redrive
            # policy moves it to the dead-letter queue for inspection.
            log.warning("skipping message %s: %s", message.get("MessageId"), exc)
            continue
        client.delete_message(QueueUrl=queue_url, ReceiptHandle=message["ReceiptHandle"])
        done += 1
    return done


def main():
    import boto3
    from .bootstrap import build_service

    logging.basicConfig(level=logging.INFO)
    queue_url = os.environ["SQS_QUEUE_URL"]
    client = boto3.client("sqs", region_name=os.getenv("AWS_REGION"))
    service = build_service()
    log.info("polling %s", queue_url)
    while True:
        poll_once(service, client, queue_url)


if __name__ == "__main__":
    main()
