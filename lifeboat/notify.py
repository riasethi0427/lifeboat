"""Slack incoming-webhook posting. Falls back to certifi's CA bundle if the system Python
has no certificates installed (common with python.org builds on macOS)."""
import json
import os
import ssl
import urllib.request


def post_slack(text: str) -> tuple[bool, str]:
    if os.environ.get("PUBLIC_DEMO") == "1":
        return False, "Slack posting is turned off in the public demo. This is the message it would send."
    hook = os.environ.get("SLACK_WEBHOOK_URL")
    if not hook:
        return False, "Set SLACK_WEBHOOK_URL to post to your #incident channel."
    req = urllib.request.Request(hook, data=json.dumps({"text": text}).encode(),
                                 headers={"Content-Type": "application/json"})
    try:
        urllib.request.urlopen(req, timeout=10)
        return True, "sent"
    except Exception as first:
        if "CERTIFICATE_VERIFY_FAILED" not in str(first):
            return False, f"Slack error: {first}"
        try:
            import certifi
            ctx = ssl.create_default_context(cafile=certifi.where())
            urllib.request.urlopen(req, timeout=10, context=ctx)
            return True, "sent"
        except Exception as second:
            return False, f"Slack error: {second}"
