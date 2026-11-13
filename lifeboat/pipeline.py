"""Orchestrates the four stages and keeps a live status dict for the UI."""
from __future__ import annotations

import json
import os
import threading
import time
from datetime import datetime, timezone

from . import detect, local_llm
from .claude_agent import CLAUDE_MODEL, Investigation, fallback_report
from .redact import Redactor

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _now():
    return datetime.now(timezone.utc).strftime("%H:%M:%S")


def new_status():
    return {
        "state": "idle", "error": None, "started": None, "finished": None,
        "ingest": {"done": False, "events": 0, "bytes": 0, "window": None},
        "detect": {"done": False, "bursts": [], "candidates": [], "flagged": 0},
        "local": {"done": False, "analyzer": None, "groups_total": 0, "groups_done": 0, "routine": 0},
        "redact": {"done": False, "counts": {}},
        "claude": {"done": False, "mode": None, "model": None, "tool_calls": [], "egress_bytes": 0, "egress_requests": 0},
        "report": None,
        "egress_log": [],
    }


class Run:
    def __init__(self):
        self.lock = threading.Lock()
        self.status = new_status()

    def update(self, fn):
        with self.lock:
            fn(self.status)

    def snapshot(self, include_egress=False):
        with self.lock:
            s = json.loads(json.dumps(self.status, default=str))
        if not include_egress:
            s.pop("egress_log", None)
        return s

    def start(self, log_path: str):
        with self.lock:
            if self.status["state"] == "running":
                return False
            self.status = new_status()
            self.status["state"] = "running"
            self.status["started"] = _now()
        threading.Thread(target=self._run, args=(log_path,), daemon=True).start()
        return True

    # -----------------------------------------------------------------
    def _run(self, log_path: str):
        try:
            self._pipeline(log_path)
            self.update(lambda s: s.update(state="done", finished=_now()))
        except Exception as ex:  # surface errors in the UI
            msg = f"{type(ex).__name__}: {ex}"
            self.update(lambda s: s.update(state="error", error=msg))

    def _pipeline(self, log_path: str):
        with open(os.path.join(ROOT, "data", "inventory.json")) as f:
            inventory = json.load(f)
        with open(os.path.join(ROOT, "data", "directory.json")) as f:
            directory = json.load(f)

        # 1. ingest + 2. detect (deterministic)
        size = os.path.getsize(log_path)
        det = detect.detect(log_path)
        events = detect.load_events(log_path)
        window = {"from": events[0]["ts"], "to": events[-1]["ts"]} if events else None
        self.update(lambda s: s["ingest"].update(done=True, events=det["events_total"], bytes=size, window=window))
        time.sleep(0.4)
        self.update(lambda s: s["detect"].update(
            done=True, bursts=det["bursts"], flagged=det["flagged_events"],
            candidates=[{k: c[k] for k in ("id", "severity", "start", "end", "events", "actors", "rules")}
                        | {"groups": len(c["groups"])} for c in det["candidates"]]))

        # 3. local model reads the high-risk raw evidence; routine groups are handled by rules
        groups = [g for c in det["candidates"] for g in c["groups"]]
        risky = [g for g in groups if local_llm.needs_local_read(g)]
        routine = [g for g in groups if not local_llm.needs_local_read(g)]
        use_model = local_llm.available()
        self.update(lambda s: s["local"].update(groups_total=len(risky), routine=len(routine),
                                                analyzer=(f"local model: {local_llm.LOCAL_MODEL}" if use_model
                                                          else "rules (no local model running)")))

        def prog(done, total):
            self.update(lambda s: s["local"].update(groups_done=done))
            if not use_model:
                time.sleep(0.6)
        analyses, _ = local_llm.analyze_groups(routine, False)
        risky_an, analyzer = local_llm.analyze_groups(risky, use_model, progress=prog)
        analyses.update(risky_an)
        for g in groups:
            g["analysis"] = analyses[g["id"]]
            g["analysis"]["read_by"] = "local model" if (use_model and g in risky) else "rules"
        self.update(lambda s: s["local"].update(done=True, analyzer=analyzer))

        # 4. enforced redaction before anything can leave
        red = Redactor(directory)
        findings = red.obj({
            "window": window, "events_total": det["events_total"], "analyzer": analyzer,
            "bursts": det["bursts"], "candidates": det["candidates"], "inventory": inventory,
        })
        self.update(lambda s: s["redact"].update(done=True, counts=dict(red.counts)))

        # 5. Claude investigates redacted findings
        has_key = bool(os.environ.get("ANTHROPIC_API_KEY"))
        self.update(lambda s: s["claude"].update(mode="claude" if has_key else "fallback",
                                                 model=CLAUDE_MODEL if has_key else None))
        if not has_key:
            report = fallback_report(findings)
        else:
            def on_tool(name, args):
                summary = args.get("group_id") or args.get("credential_type") or ""
                self.update(lambda s: s["claude"]["tool_calls"].append({"t": _now(), "name": name, "arg": summary}))

            def on_egress(nbytes, last_msg):
                def f(s):
                    s["claude"]["egress_bytes"] += nbytes
                    s["claude"]["egress_requests"] += 1
                    s["egress_log"].append({"t": _now(), "bytes": nbytes,
                                            "new_content": json.loads(json.dumps(last_msg, default=lambda o: o.model_dump(exclude_none=True) if hasattr(o, "model_dump") else str(o)))})
                self.update(f)
            report = Investigation(findings, red, on_tool=on_tool, on_egress=on_egress).run()
        self.update(lambda s: s["claude"].update(done=True))
        self.update(lambda s: s.update(report=report))
