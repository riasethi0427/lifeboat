"""Enforced redaction. Runs in code (not by asking a model nicely) on EVERYTHING
before it is allowed to leave the machine."""
from __future__ import annotations

import hashlib
import json
import re
from collections import Counter

PATTERNS = [
    ("aws_secret_key", re.compile(r"(AWS_SECRET_ACCESS_KEY\s*[=:]\s*)[A-Za-z0-9/+=]{20,}")),
    ("aws_access_key_id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("hf_token", re.compile(r"\bhf_[A-Za-z0-9]{20,}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}")),
    ("secret_assignment", re.compile(r"\b([A-Z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD)[A-Z0-9_]*\s*[=:]\s*)(?!\[REDACTED)\S+")),
    ("private_key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]+?-----END [A-Z ]*PRIVATE KEY-----")),
    ("base64_blob", re.compile(r"\b[A-Za-z0-9+/]{40,}={0,2}")),
]
EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")


class Redactor:
    def __init__(self, directory: dict | None = None):
        self.directory = {k: v for k, v in (directory or {}).items() if not k.startswith("_")}
        self.counts: Counter = Counter()

    def _email(self, m: re.Match) -> str:
        addr = m.group(0)
        known = self.directory.get(addr)
        self.counts["employee_identity"] += 1
        if known:
            return known["pseudonym"]
        return "email:" + hashlib.sha256(addr.encode()).hexdigest()[:8]

    def text(self, s: str) -> str:
        if not isinstance(s, str) or not s:
            return s
        for name, pat in PATTERNS:
            def repl(m, name=name):
                self.counts[name] += 1
                if m.groups():
                    return m.group(1) + f"[REDACTED:{name}]"
                return f"[REDACTED:{name}]"
            s = pat.sub(repl, s)
        s = EMAIL.sub(self._email, s)
        return s

    def obj(self, o):
        if isinstance(o, str):
            return self.text(o)
        if isinstance(o, list):
            return [self.obj(x) for x in o]
        if isinstance(o, dict):
            return {self.text(k) if isinstance(k, str) else k: self.obj(v) for k, v in o.items()}
        return o


def assert_clean(payload: str) -> None:
    """Last line of defense: refuse to send if anything secret-shaped survived."""
    for name, pat in PATTERNS[:5]:
        for m in pat.finditer(payload):
            if "[REDACTED" not in payload[m.start():m.end() + 30]:
                raise RuntimeError(f"Egress blocked: unredacted {name} detected")
    for m in EMAIL.finditer(payload):
        raise RuntimeError("Egress blocked: raw email address detected")


if __name__ == "__main__":
    r = Redactor({"lena.ortiz@tessera.ai": {"pseudonym": "employee:SRE-1"}})
    sample = ("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY "
              "HF_TOKEN=hf_FAKEdemoTOKENdoNOTuse0000000000 by lena.ortiz@tessera.ai")
    out = r.text(sample)
    print(out)
    print(dict(r.counts))
    assert_clean(json.dumps(out))
