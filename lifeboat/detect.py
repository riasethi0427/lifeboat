"""Deterministic detection. No model involved: every flag here is reproducible and explainable.

1. Baseline: learn each actor's normal behavior from the first BASELINE_HOURS of logs
   (actions, source IPs, peak events/minute).
2. Machine-speed detector: bursts far above an actor's own baseline rate. This is the
   "AI agent as attacker" tell (thousands of actions, no human pauses).
3. Rules: known-bad patterns for ML pipelines (remote-code loaders, template injection,
   shells from workers, token reads, RBAC enumeration, exec by service accounts, ...).
4. Candidates: flagged events clustered in time; behavior groups for the analyst step.
"""
from __future__ import annotations

import base64
import json
import re
import statistics
from collections import defaultdict
from datetime import datetime, timedelta

BASELINE_HOURS = 6
BURST_WINDOW_S = 60
BURST_MIN_EVENTS = 25
BURST_BASELINE_MULT = 3.0
CANDIDATE_GAP = timedelta(minutes=20)

SEV_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def parse_ts(s: str) -> datetime:
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def load_events(path: str) -> list[dict]:
    events = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            e = json.loads(line)
            e["_t"] = parse_ts(e["ts"])
            events.append(e)
    events.sort(key=lambda e: e["_t"])
    for i, e in enumerate(events):
        e["_i"] = i
    return events


# ------------------------------------------------------------------ baseline
def peak_per_window(times: list[datetime], window_s: int = BURST_WINDOW_S) -> int:
    best, lo = 0, 0
    for hi in range(len(times)):
        while (times[hi] - times[lo]).total_seconds() > window_s:
            lo += 1
        best = max(best, hi - lo + 1)
    return best


def build_baseline(events: list[dict]) -> dict:
    if not events:
        return {}
    cutoff = events[0]["_t"] + timedelta(hours=BASELINE_HOURS)
    per_actor: dict[str, dict] = defaultdict(lambda: {"actions": set(), "ips": set(), "times": []})
    for e in events:
        if e["_t"] >= cutoff:
            break
        b = per_actor[e["actor"]]
        b["actions"].add(e["action"])
        b["ips"].add(e["src_ip"])
        b["times"].append(e["_t"])
    out = {}
    for actor, b in per_actor.items():
        out[actor] = {"actions": b["actions"], "ips": b["ips"], "peak": peak_per_window(b["times"])}
    out["_cutoff"] = cutoff
    return out


# ------------------------------------------------------------------ machine speed
def machine_speed_bursts(events: list[dict], baseline: dict) -> list[dict]:
    by_actor: dict[str, list[dict]] = defaultdict(list)
    for e in events:
        by_actor[e["actor"]].append(e)
    bursts = []
    for actor, evs in by_actor.items():
        times = [e["_t"] for e in evs]
        # mark every event that sits in a dense window
        dense = [False] * len(evs)
        lo = 0
        for hi in range(len(evs)):
            while (times[hi] - times[lo]).total_seconds() > BURST_WINDOW_S:
                lo += 1
            if hi - lo + 1 >= BURST_MIN_EVENTS:
                for k in range(lo, hi + 1):
                    dense[k] = True
        # merge dense runs into bursts
        k = 0
        while k < len(evs):
            if not dense[k]:
                k += 1
                continue
            j = k
            while j + 1 < len(evs) and dense[j + 1] and (times[j + 1] - times[j]).total_seconds() <= BURST_WINDOW_S:
                j += 1
            run = evs[k:j + 1]
            peak = peak_per_window([e["_t"] for e in run])
            base_peak = baseline.get(actor, {}).get("peak", 0)
            gaps = [(run[x + 1]["_t"] - run[x]["_t"]).total_seconds() for x in range(len(run) - 1)]
            median_gap_ms = int(statistics.median(gaps) * 1000) if gaps else 0
            threshold = max(BURST_MIN_EVENTS, BURST_BASELINE_MULT * base_peak)
            if peak >= threshold:
                bursts.append({
                    "actor": actor,
                    "start": run[0]["ts"], "end": run[-1]["ts"],
                    "events": len(run),
                    "peak_per_min": peak,
                    "baseline_peak_per_min": base_peak,
                    "median_gap_ms": median_gap_ms,
                    "distinct_actions": len({e["action"] for e in run}),
                    "event_ids": [e["_i"] for e in run],
                    "why": (f"{peak} actions/min vs. its normal peak of {base_peak}/min"
                            if base_peak else f"{peak} actions/min from an actor with no baseline"),
                })
            k = j + 1
    return bursts


# ------------------------------------------------------------------ rules
TEMPLATE_INJECTION = re.compile(r"__(globals|class|mro|subclasses|builtins|init)__|os\.popen|subprocess")
B64_PIPE_SH = re.compile(r"echo\s+([A-Za-z0-9+/=]{16,})\s*\|\s*base64\s+-d\s*\|\s*(ba)?sh")
SECRET_ASSIGN = re.compile(r"\b[A-Z0-9_]*(KEY|TOKEN|SECRET|PASSWORD)[A-Z0-9_]*=", re.I)


def _rule(rule_id, severity, title, why):
    return {"id": rule_id, "severity": severity, "title": title, "why": why}


RULES = {
    "R1": _rule("R1", "high", "Untrusted dataset with remote-code loader",
                "dataset loaded with trust_remote_code=True runs the uploader's Python on your worker"),
    "R2": _rule("R2", "high", "Template injection in dataset config",
                "Python object-traversal syntax in a prompt template (server-side template injection)"),
    "R3": _rule("R3", "critical", "Shell spawned by a data-processing worker",
                "workers should load data, not start shells"),
    "R4": _rule("R4", "high", "Encoded command piped to shell", "base64 | sh hides the real command"),
    "R5": _rule("R5", "critical", "Service-account token read by a non-system process",
                "the token is the pod's Kubernetes identity"),
    "R6": _rule("R6", "high", "Permission enumeration (burst of 403s)", "10+ denied requests in 60s = probing for access"),
    "R7": _rule("R7", "critical", "Service account exec'd into another workload", "pods/exec by a workload identity = lateral movement"),
    "R8": _rule("R8", "critical", "Secrets dumped from environment", "env output containing keys/tokens"),
    "R9": _rule("R9", "critical", "Kubeconfig read inside a container", "credentials for another cluster"),
    "R10": _rule("R10", "high", "Identity used from a new IP", "source IP never seen for this identity in the baseline"),
    "R11": _rule("R11", "high", "Bulk object reads (S3 fan-out)", "50+ distinct objects read by one identity within 5 minutes"),
    "R12": _rule("R12", "high", "Private model download from a CI token", "CI token normally uploads; downloads from outside = weight theft"),
    "R13": _rule("R13", "medium", "Human exec into a production pod", "interactive shell in prod; usually debugging, sometimes not"),
    "R14": _rule("R14", "high", "Privilege-escalation attempt", "attempt to create keys or cluster-admin bindings"),
    "R15": _rule("R15", "medium", "Service identity performing a never-seen action", "outside the actor's baseline behavior"),
    "R17": _rule("R17", "critical", "Tripwire triggered",
                 "a planted lure or canary credential was used; nothing legitimate ever touches these"),
    "R16": _rule("R16", "high", "First-seen credential used from outside the network",
                 "a service credential with no history suddenly active from an external IP"),
}


def apply_rules(events: list[dict], baseline: dict) -> dict[int, list[str]]:
    hits: dict[int, list[str]] = defaultdict(list)
    cutoff = baseline.get("_cutoff")

    def hit(e, rid):
        if rid not in hits[e["_i"]]:
            hits[e["_i"]].append(rid)

    denied: dict[str, list[dict]] = defaultdict(list)
    s3reads: dict[str, list[dict]] = defaultdict(list)
    for e in events:
        raw, action, actor = e.get("raw", ""), e["action"], e["actor"]
        if action == "dataset.load" and "trust_remote_code=True" in raw:
            hit(e, "R1")
        if action == "dataset.upload" and TEMPLATE_INJECTION.search(raw):
            hit(e, "R2")
        if action == "process.spawn" and e["actor_type"] == "service" and re.search(r"\b(sh|bash)\b", raw):
            hit(e, "R3")
        if B64_PIPE_SH.search(raw):
            hit(e, "R4")
        if action == "file.read" and "serviceaccount/token" in e["resource"]:
            hit(e, "R5")
        if e["status"] == 403:
            denied[actor].append(e)
        if action == "pods/exec.create":
            hit(e, "R7" if e["actor_type"] == "service" else "R13")
        if action == "process.output" and len(SECRET_ASSIGN.findall(raw)) >= 2:
            hit(e, "R8")
        if action == "file.read" and "kube/config" in e["resource"]:
            hit(e, "R9")
        b = baseline.get(actor)
        if b and cutoff and e["_t"] >= cutoff and e["actor_type"] == "service":
            # customers legitimately come from changing IPs; service identities should not
            if e["src_ip"] not in b["ips"]:
                hit(e, "R10")
            if action not in b["actions"]:
                hit(e, "R15")
        if (not b and cutoff and e["_t"] >= cutoff and e["actor_type"] == "service"
                and not e["src_ip"].startswith("10.")):
            hit(e, "R16")
        if action == "s3:GetObject":
            s3reads[actor].append(e)
        if action == "model.download" and actor.startswith("hf-token:") and not e["src_ip"].startswith("10."):
            hit(e, "R12")
        if action in ("iam:CreateAccessKey", "clusterrolebindings.create"):
            hit(e, "R14")
        if action.startswith("tripwire.") or actor == "iam:svc-backup":
            hit(e, "R17")

    for actor, evs in denied.items():
        lo = 0
        for hi in range(len(evs)):
            while (evs[hi]["_t"] - evs[lo]["_t"]).total_seconds() > 60:
                lo += 1
            if hi - lo + 1 >= 10:
                for k in range(lo, hi + 1):
                    hit(evs[k], "R6")
    for actor, evs in s3reads.items():
        lo = 0
        for hi in range(len(evs)):
            while (evs[hi]["_t"] - evs[lo]["_t"]).total_seconds() > 300:
                lo += 1
            window = evs[lo:hi + 1]
            if len({x["resource"] for x in window}) >= 50:
                for x in window:
                    hit(x, "R11")
    return hits


# ------------------------------------------------------------------ candidates & groups
def decode_commands(raw: str) -> list[str]:
    out = []
    for m in B64_PIPE_SH.finditer(raw or ""):
        try:
            out.append(base64.b64decode(m.group(1)).decode("utf-8", "replace"))
        except Exception:
            pass
    return out


def build_candidates(events, rule_hits, bursts):
    first_seen: dict[str, str] = {}
    for e in events:
        first_seen.setdefault(e["actor"], e["ts"])
    flagged = set(rule_hits)
    burst_of: dict[int, int] = {}
    for bi, b in enumerate(bursts):
        for i in b["event_ids"]:
            flagged.add(i)
            burst_of[i] = bi
    ordered = sorted(flagged)
    clusters: list[list[int]] = []
    for i in ordered:
        if clusters and events[i]["_t"] - events[clusters[-1][-1]]["_t"] <= CANDIDATE_GAP:
            clusters[-1].append(i)
        else:
            clusters.append([i])
    # pull in context: earlier events by the same actors are linked only if flagged; keep it simple.
    candidates = []
    for ci, idxs in enumerate(clusters, 1):
        rids = sorted({r for i in idxs for r in rule_hits.get(i, [])}, key=lambda r: int(r[1:]))
        sev = max([SEV_RANK[RULES[r]["severity"]] for r in rids] + [3 if any(i in burst_of for i in idxs) else 1])
        sev_name = {v: k for k, v in SEV_RANK.items()}[sev]
        cand_bursts = sorted({burst_of[i] for i in idxs if i in burst_of})
        groups = build_groups(events, idxs, rule_hits, burst_of, prefix=f"C{ci}-G")
        for g in groups:
            g["actor_first_seen"] = first_seen.get(g["actor"])
        candidates.append({
            "id": f"C{ci}",
            "start": events[idxs[0]]["ts"], "end": events[idxs[-1]]["ts"],
            "events": len(idxs),
            "severity": sev_name,
            "actors": sorted({events[i]["actor"] for i in idxs}),
            "rules": [{**RULES[r], "count": sum(1 for i in idxs if r in rule_hits.get(i, []))} for r in rids],
            "burst_ids": cand_bursts,
            "groups": groups,
        })
    # Attach the foothold: a rule hit that is far earlier (e.g. the malicious upload) forms its own
    # candidate; merge single-event candidates that share a resource with a later candidate.
    merged = []
    for c in candidates:
        if merged and c["groups"] and any(
                g["resources_sample"] and any(r in json.dumps(c["groups"]) for r in g["resources_sample"])
                for g in merged[-1]["groups"]) and merged[-1]["events"] <= 3:
            prev = merged.pop()
            c = _merge(prev, c)
        merged.append(c)
    for k, c in enumerate(merged, 1):
        c["id"] = f"C{k}"
        for gi, g in enumerate(c["groups"], 1):
            g["id"] = f"C{k}-G{gi}"
    return merged


def _merge(a, b):
    out = dict(b)
    out["start"] = a["start"]
    out["events"] = a["events"] + b["events"]
    out["actors"] = sorted(set(a["actors"]) | set(b["actors"]))
    rules = {r["id"]: dict(r) for r in a["rules"]}
    for r in b["rules"]:
        if r["id"] in rules:
            rules[r["id"]]["count"] += r["count"]
        else:
            rules[r["id"]] = dict(r)
    out["rules"] = sorted(rules.values(), key=lambda r: int(r["id"][1:]))
    out["severity"] = max(a["severity"], b["severity"], key=lambda s: SEV_RANK[s])
    out["groups"] = a["groups"] + b["groups"]
    out["burst_ids"] = sorted(set(a["burst_ids"]) | set(b["burst_ids"]))
    return out


def build_groups(events, idxs, rule_hits, burst_of, prefix):
    groups: dict[tuple, dict] = {}
    for i in idxs:
        e = events[i]
        key = (e["actor"], e["action"], e["status"], e.get("cluster"))
        g = groups.get(key)
        if not g:
            g = groups[key] = {
                "actor": e["actor"], "actor_type": e["actor_type"], "action": e["action"],
                "status": e["status"], "cluster": e.get("cluster"), "source": e["source"],
                "count": 0, "first": e["ts"], "last": e["ts"], "_resources": [], "_raws": [],
                "src_ips": set(), "rules": set(), "machine_speed": False, "decoded_commands": [],
            }
        g["count"] += 1
        g["last"] = e["ts"]
        if e["resource"] not in g["_resources"]:
            g["_resources"].append(e["resource"])
        if e.get("raw") and e["raw"] not in g["_raws"] and len(g["_raws"]) < 2:
            g["_raws"].append(e["raw"])
        g["src_ips"].add(e["src_ip"])
        g["rules"].update(rule_hits.get(i, []))
        if i in burst_of:
            g["machine_speed"] = True
        for d in decode_commands(e.get("raw", "")):
            if d not in g["decoded_commands"]:
                g["decoded_commands"].append(d)
    out = []
    for n, g in enumerate(sorted(groups.values(), key=lambda g: g["first"]), 1):
        breakdown = {}
        if len(g["_resources"]) > 6:  # summarize big fan-outs by prefix (e.g. bucket/customer)
            for r in g["_resources"]:
                parts = r.replace("s3://", "").split("/")
                key = "/".join(parts[:-1]) if len(parts) > 1 else parts[0]
                breakdown[key] = breakdown.get(key, 0) + 1
        out.append({
            "resource_breakdown": dict(sorted(breakdown.items(), key=lambda kv: -kv[1])[:15]),
            "id": f"{prefix}{n}",
            "actor": g["actor"], "actor_type": g["actor_type"], "action": g["action"], "status": g["status"],
            "cluster": g["cluster"], "source": g["source"], "count": g["count"], "first": g["first"], "last": g["last"],
            "distinct_resources": len(g["_resources"]), "resources_sample": g["_resources"][:6],
            "raw_samples": g["_raws"], "src_ips": sorted(g["src_ips"]),
            "rules": sorted(g["rules"], key=lambda r: int(r[1:])), "machine_speed": g["machine_speed"],
            "decoded_commands": g["decoded_commands"],
        })
    return out


def detect(path: str) -> dict:
    events = load_events(path)
    baseline = build_baseline(events)
    bursts = machine_speed_bursts(events, baseline)
    rule_hits = apply_rules(events, baseline)
    candidates = build_candidates(events, rule_hits, bursts)
    for b in bursts:
        b.pop("event_ids", None)
    return {
        "events_total": len(events),
        "baseline_until": baseline.get("_cutoff").isoformat() if baseline.get("_cutoff") else None,
        "baseline_actors": len([k for k in baseline if not k.startswith("_")]),
        "bursts": bursts,
        "flagged_events": sum(c["events"] for c in candidates),
        "candidates": candidates,
    }


if __name__ == "__main__":
    import sys
    r = detect(sys.argv[1] if len(sys.argv) > 1 else "data/logs.jsonl")
    print(json.dumps({k: v for k, v in r.items() if k != "candidates"}, indent=2, default=str))
    for c in r["candidates"]:
        print(f"\n{c['id']} {c['severity']} {c['start']} -> {c['end']} events={c['events']} actors={c['actors']}")
        for rr in c["rules"]:
            print(f"   {rr['id']} x{rr['count']} {rr['title']}")
        for g in c["groups"]:
            print(f"   {g['id']} {g['actor']} {g['action']} {g['status']} x{g['count']} ms={g['machine_speed']} rules={g['rules']}")
