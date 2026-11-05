import json
import logging
import urllib.request

log = logging.getLogger(__name__)


class WebhookNotifier:
    """POSTs the full finding as JSON. Point it at a ticketing system's webhook."""

    def __init__(self, url, timeout=3, opener=urllib.request.urlopen):
        self.url = url
        self.timeout = timeout
        self._open = opener

    def payload(self, finding):
        return finding

    def send(self, finding):
        req = urllib.request.Request(
            self.url,
            data=json.dumps(self.payload(finding)).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        self._open(req, timeout=self.timeout).close()


def _slack_escape(text):
    # Stops scanner-supplied text from triggering @channel or fake links.
    return str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


class SlackNotifier(WebhookNotifier):
    def payload(self, f):
        return {"text": (
            f":rotating_light: *P1 finding:* {_slack_escape(f['title'])}\n"
            f"`{_slack_escape(f['resource_id'])}` | {_slack_escape(f['environment'])} | "
            f"owner {_slack_escape(f['owner'])} | score {f['score']} | "
            f"SLA due {f.get('sla_due') or 'n/a'}"
        )}
