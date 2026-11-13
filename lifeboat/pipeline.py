"""Orchestrates the four stages and keeps a live status dict for the UI."""
from __future__ import annotations

import json
import os
import threading
import time
from datetime import datetime, timezone

from datetime import timedelta

from . import detect, local_llm, scenario
from .claude_agent import CLAUDE_MODEL, Investigation, fallback_report
from .notify import post_slack
from .redact import Redactor

LIVE_SPEED = float(os.environ.get("LIVE_SPEED", "4"))       # simulated seconds per real second
LIVE_MAX_GAP = float(os.environ.get("LIVE_MAX_GAP", "0.3"))  # cap idle time between events (real seconds)
WINDOW = ("2026-11-07T01:56:00", "2026-11-07T02:20:30")

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
        "live": None,
        "approvals": [],
    }


class Run:
    def __init__(self):
        self.lock = threading.Lock()
        self.status = new_status()
        self._tl = threading.local()  # each run's threads write only to their own status dict

    def _bind(self, status):
        self._tl.status = status

    def cancelled(self) -> bool:
        st = getattr(self._tl, "status", None)
        return st is not None and st is not self.status

    def update(self, fn):
        with self.lock:
            fn(getattr(self._tl, "status", None) or self.status)

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

    def start_live(self, protect: bool):
        with self.lock:  # a new replay replaces (cancels) any run in progress
            self.status = new_status()
            self.status["state"] = "running"
            self.status["started"] = _now()
            self.status["live"] = {"protect": protect, "done": False, "clock": None, "events": 0,
                                   "tripwires": scenario.TRIPWIRES if protect else [], "fired": [],
                                   "feed": [], "actions": [], "slack": None,
                                   "outcome": {"files": 0, "models": 0, "secrets": 0, "denied": 0}}
        st = self.status
        threading.Thread(target=self._run_live, args=(protect, st), daemon=True).start()
        return True

    def approve(self, item_id: str):
        def f(s):
            for a in s["approvals"]:
                if a["id"] == item_id and a["status"] == "pending":
                    a["status"] = "approved"
                    a["approved_at"] = _now()
        self.update(f)

    def _run_live(self, protect: bool, st: dict):
        self._bind(st)
        try:
            path, extra = self._replay(protect)
            if path is None:
                return
            if self.cancelled():
                return
            self._pipeline(path, extra=extra)
            self.update(lambda s: s.update(state="done", finished=_now()))
        except Exception as ex:
            if self.cancelled():
                return
            msg = f"{type(ex).__name__}: {ex}"
            self.update(lambda s: s.update(state="error", error=msg))

    # ----------------------------------------------------------------- live replay
    def _feed(self, key, kind, text, ts):
        def f(s):
            feed = s["live"]["feed"]
            if feed and feed[-1]["key"] == key:
                feed[-1]["count"] += 1
                feed[-1]["ts_last"] = ts
            else:
                feed.append({"key": key, "kind": kind, "text": text, "ts": ts, "ts_last": ts, "count": 1})
                del feed[:-60]
        self.update(f)

    def _classify(self, e):
        a, st, raw, res = e["action"], e["status"], e.get("raw", ""), e["resource"]
        if st == 403 and "Lifeboat" in raw:
            if a == "net.connect":
                return ("blocked:net", "denied", "Exfiltration attempt blocked")
            return (f"denied:{a}", "denied", f"Denied by Lifeboat: {a}")
        if scenario.is_tripwire(e):
            if a.startswith("tripwire."):
                return ("trip1", "alert", "Tripwire fired: the attacker's agent obeyed the planted note and called the lure URL")
            return ("trip2", "alert", f"Tripwire fired: canary AWS key used from {e['src_ip']}")
        table = {
            "dataset.upload": "Trial account northwind-trial uploaded a dataset with a template-injection payload",
            "dataset.load": "ds-worker-3 loaded the dataset with remote code enabled",
            "pods/exec.create": "Attacker opened a shell inside training-scheduler",
            "process.output": "AWS, HF and W&B keys dumped from the environment",
            "s3:GetObject": "Customer files read with the stolen AWS key",
            "model.download": "Private models downloaded with the stolen HF token",
            "clusterrolebindings.create": "Backdoor cluster-admin binding attempted",
        }
        if a == "process.spawn":
            return (f"spawn:{res}", "attack", f"Shell command running inside {res}")
        if a == "file.read":
            if "AGENTS.md" in res:
                return ("lure", "attack", "Attacker's agent read the planted AGENTS.md note")
            if "kube/config" in res:
                return ("kubeconfig", "attack", "Kubeconfig for the inference cluster read")
            return ("token", "attack", "Kubernetes service-account token read")
        if a == "secrets.get" and st == 200:
            return (f"secret:{res}", "attack", f"Inference secret read: {res}")
        if a in table:
            return (a, "attack", table[a])
        if e["source"] == "cloudtrail" or e["cluster"] == "inference-prod":
            return ("recon:stolen", "attack", "Reconnaissance with stolen credentials")
        return ("recon:cluster", "attack", "Permission probing inside the cluster")

    def _replay(self, protect: bool):
        bg_all = detect.load_events(os.path.join(ROOT, "data", "background.jsonl"))
        lo = datetime.fromisoformat(WINDOW[0] + "+00:00")
        hi = datetime.fromisoformat(WINDOW[1] + "+00:00")
        bg = [e for e in bg_all if lo <= e["_t"] <= hi]
        sim = scenario.CloudSim()
        ctx = {"last_dataset_on": {}, "uploader_of": {}}
        atk = scenario.attacker(sim, lures=protect)
        emitted, bi, pending, done_atk, prev_t = [], 0, None, False, None
        outcome = {"files": 0, "models": 0, "secrets": 0, "denied": 0}
        while True:
            if self.cancelled():
                return None, None
            if pending is None and not done_atk:
                try:
                    pending = next(atk)
                    pending["_t"] = scenario.parse(pending["ts"])
                except StopIteration:
                    done_atk = True
            nb = bg[bi] if bi < len(bg) else None
            if pending is None and nb is None:
                break
            if nb is not None and (pending is None or nb["_t"] <= pending["_t"]):
                e, bi, is_atk = nb, bi + 1, False
            else:
                e, pending, is_atk = pending, None, True
            if prev_t is not None:
                time.sleep(min(max((e["_t"] - prev_t).total_seconds(), 0) / LIVE_SPEED, LIVE_MAX_GAP))
            prev_t = e["_t"]
            self.update(lambda s: s["live"].update(clock=e["ts"], events=s["live"]["events"] + 1))
            if not is_atk:
                continue
            emitted.append(e)
            if e["action"] == "dataset.upload":
                ctx["uploader_of"][e["resource"]] = e["actor"]
            if e["action"] == "dataset.load":
                ctx["last_dataset_on"][e.get("node")] = e["resource"]
            if e["status"] == 403 and "Lifeboat" in e.get("raw", ""):
                outcome["denied"] += 1
            elif e["action"] == "s3:GetObject" and e["status"] == 200:
                outcome["files"] += 1
            elif e["action"] == "model.download" and e["status"] == 200:
                outcome["models"] += 1
            elif e["action"] == "process.output":
                outcome["secrets"] += 4
            elif e["action"] == "secrets.get" and e["status"] == 200:
                outcome["secrets"] += 1
            self.update(lambda s: s["live"].update(outcome=dict(outcome)))
            key, kind, text = self._classify(e)
            self._feed(key, kind, text, e["ts"])
            if protect and scenario.is_tripwire(e):
                acts = scenario.reflex(sim, e, ctx)
                fired = {"ts": e["ts"], "tripwire": "TW1" if e["action"].startswith("tripwire.") else "TW2"}
                self.update(lambda s: s["live"]["fired"].append(fired))
                for a in acts:
                    self.update(lambda s, a=a: s["live"]["actions"].append(a))
                    self._feed(f"act:{a['id']}", "lifeboat", f"Lifeboat: {a['label']}", a["ts"])
                if acts:
                    st_ref = self._tl.status
                    threading.Thread(target=lambda e=e, acts=acts: (self._bind(st_ref), self._slack_alert(e, acts)),
                                     daemon=True).start()
        self.update(lambda s: s["live"].update(done=True))

        # Write the combined log (normal weekend + what the attacker actually did) for the investigation.
        out = os.path.join(ROOT, "data", "live_run.jsonl")
        rows = [{k: v for k, v in e.items() if not k.startswith("_")} for e in bg_all + emitted]
        rows.sort(key=lambda r: r["ts"])
        with open(out, "w") as f:
            for r in rows:
                f.write(json.dumps(r) + "\n")

        def status_fn():
            snap = self.snapshot()["live"]
            return {"mode": "protection on" if protect else "protection off",
                    "tripwires_armed": snap["tripwires"], "tripwires_fired": snap["fired"],
                    "actions_taken": snap["actions"], "attacker_outcome": snap["outcome"]}

        def act_fn(kind, target, reason):
            try:
                a = sim.apply(datetime.now(timezone.utc), kind, target, reason, "Claude")
            except ValueError as ex:
                return {"error": str(ex)}
            if not a:
                return {"ok": True, "note": "already in place"}
            self.update(lambda s: s["live"]["actions"].append(a))
            self._feed(f"act:{a['id']}", "lifeboat", f"Claude: {a['label']}", a["ts"])
            return {"ok": True, "action": a}

        def approve_fn(action, reason, command):
            def f(s):
                item = {"id": f"P{len(s['approvals']) + 1}", "action": action, "reason": reason,
                        "command": command, "status": "pending"}
                s["approvals"].append(item)
            self.update(f)
            return {"ok": True, "queued_for_human": action}

        extra = {"live": {"status": status_fn, "act": act_fn, "approve": approve_fn, "cancelled": self.cancelled},
                 "summary": status_fn()}
        return out, extra

    def _slack_alert(self, e, acts):
        first = scenario.parse(e["ts"])
        lines = [f":rotating_light: *Tripwire fired at {first.strftime('%H:%M:%S')} UTC: automated attacker inside Tessera AI*",
                 "Lifeboat contained it automatically (all reversible):"]
        for a in acts:
            delay = (scenario.parse(a["ts"]) - first).total_seconds()
            lines.append(f"- {a['label']}  _(+{delay:.1f}s; undo: {a['undo']})_")
        lines.append("Claude is investigating now. Full report and approvals to follow.")
        ok, note = post_slack("\n".join(lines))
        self.update(lambda s: s["live"].update(slack="sent" if ok else note))

    # -----------------------------------------------------------------
    def _run(self, log_path: str):
        try:
            self._pipeline(log_path)
            self.update(lambda s: s.update(state="done", finished=_now()))
        except Exception as ex:  # surface errors in the UI
            msg = f"{type(ex).__name__}: {ex}"
            self.update(lambda s: s.update(state="error", error=msg))

    def _pipeline(self, log_path: str, extra: dict | None = None):
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
            "live_summary": (extra or {}).get("summary"),
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
                summary = (args.get("group_id") or args.get("credential_type") or
                           (f"{args.get('kind', '')} {args.get('target', '')}".strip() if name == "take_reversible_action" else "") or
                           args.get("action") or "")
                self.update(lambda s: s["claude"]["tool_calls"].append({"t": _now(), "name": name, "arg": summary}))

            def on_egress(nbytes, last_msg):
                def f(s):
                    s["claude"]["egress_bytes"] += nbytes
                    s["claude"]["egress_requests"] += 1
                    s["egress_log"].append({"t": _now(), "bytes": nbytes,
                                            "new_content": json.loads(json.dumps(last_msg, default=lambda o: o.model_dump(exclude_none=True) if hasattr(o, "model_dump") else str(o)))})
                self.update(f)
            report = Investigation(findings, red, on_tool=on_tool, on_egress=on_egress,
                                   live=(extra or {}).get("live")).run()
        self.update(lambda s: s["claude"].update(done=True))
        self.update(lambda s: s.update(report=report))
