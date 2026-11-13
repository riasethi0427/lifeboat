"""Step 4: Claude investigates the REDACTED findings with tools and files a structured
incident report. Every byte sent to the API passes redact.assert_clean() first and is
logged for the egress meter."""
from __future__ import annotations

import json
import os
import time

CLAUDE_MODEL = os.environ.get("CLAUDE_MODEL", "claude-sonnet-5-5")
MAX_TURNS = 14

SYSTEM = """You are Lifeboat's incident responder for a small AI startup that has no security team.
You never see raw logs. A local model on the company's hardware already read the raw evidence;
you receive redacted, pre-analyzed behavior groups, deterministic detector output, and an
inventory of the company's credentials and data assets.

Your job:
1. Investigate every candidate. Use get_group to read evidence before concluding; use
   get_on_call_roster before judging human activity; use get_credential_inventory and
   get_rotation_playbook to work out the blast radius precisely.
2. Decide per candidate: malicious, benign, or needs_review, with the evidence.
3. Reconstruct the attack as an ordered timeline (cite group ids).
4. Blast radius: every credential that was exposed (and why you think so), every data asset
   touched and which customers are affected.
5. Containment: ordered, concrete steps a non-security engineer can run tonight, with commands
   from the playbooks. Rotation order matters: the credential still being used goes first.
6. Draft a short, honest customer notification.
Be precise and calm. Do not invent facts that the evidence does not show; list unknowns as
open_questions. When done, call submit_incident_report exactly once."""

REPORT_SCHEMA = {
    "type": "object",
    "properties": {
        "severity": {"type": "string", "enum": ["critical", "high", "medium", "low"]},
        "headline": {"type": "string", "description": "One sentence a CEO understands."},
        "executive_summary": {"type": "string", "description": "3-5 sentences."},
        "attacker_profile": {"type": "string", "description": "Human or automated agent, and the evidence."},
        "verdicts": {"type": "array", "items": {"type": "object", "properties": {
            "candidate_id": {"type": "string"},
            "verdict": {"type": "string", "enum": ["malicious", "benign", "needs_review"]},
            "reason": {"type": "string"}}, "required": ["candidate_id", "verdict", "reason"]}},
        "timeline": {"type": "array", "items": {"type": "object", "properties": {
            "time": {"type": "string"}, "stage": {"type": "string"}, "what": {"type": "string"},
            "groups": {"type": "array", "items": {"type": "string"}}}, "required": ["time", "stage", "what"]}},
        "credentials_to_rotate": {"type": "array", "items": {"type": "object", "properties": {
            "credential_id": {"type": "string"}, "priority": {"type": "integer"},
            "why_exposed": {"type": "string"}, "evidence_of_use": {"type": "string"}},
            "required": ["credential_id", "priority", "why_exposed"]}},
        "data_impact": {"type": "array", "items": {"type": "object", "properties": {
            "asset": {"type": "string"}, "what_happened": {"type": "string"},
            "customers_affected": {"type": "array", "items": {"type": "string"}}},
            "required": ["asset", "what_happened"]}},
        "containment_steps": {"type": "array", "items": {"type": "object", "properties": {
            "order": {"type": "integer"}, "step": {"type": "string"}, "command": {"type": "string"},
            "owner": {"type": "string"}}, "required": ["order", "step"]}},
        "root_causes": {"type": "array", "items": {"type": "string"}},
        "customer_notification_draft": {"type": "string"},
        "open_questions": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["severity", "headline", "executive_summary", "verdicts", "timeline",
                 "credentials_to_rotate", "containment_steps", "customer_notification_draft"],
}

TOOLS = [
    {"name": "get_group", "description": "Full redacted evidence for one behavior group: counts, timing, sample "
     "resources, redacted raw samples, decoded commands, local-model analysis, detector rules hit.",
     "input_schema": {"type": "object", "properties": {"group_id": {"type": "string"}}, "required": ["group_id"]}},
    {"name": "get_machine_speed_bursts", "description": "Actors whose activity rate far exceeded their own "
     "baseline (the signature of an automated/AI attacker).", "input_schema": {"type": "object", "properties": {}}},
    {"name": "get_credential_inventory", "description": "The company's credentials (masked) with scope and where "
     "each is stored, plus data assets.", "input_schema": {"type": "object", "properties": {}}},
    {"name": "get_rotation_playbook", "description": "Exact rotation/containment steps for a credential type.",
     "input_schema": {"type": "object", "properties": {"credential_type": {"type": "string", "enum": [
         "aws_access_key", "hf_token", "wandb_api_key", "k8s_service_account_token", "kubeconfig_token",
         "third_party_api_key", "malicious_dataset"]}}, "required": ["credential_type"]}},
    {"name": "get_on_call_roster", "description": "Who was on call during the window (pseudonymized).",
     "input_schema": {"type": "object", "properties": {}}},
    {"name": "submit_incident_report", "description": "File the final incident report. Call exactly once.",
     "input_schema": REPORT_SCHEMA},
]

PLAYBOOKS = {
    "aws_access_key": [
        {"step": "Deactivate the exposed key immediately", "command": "aws iam update-access-key --user-name svc-training --access-key-id <KEY_ID> --status Inactive"},
        {"step": "Create a replacement and store it in your secret manager (not pod env)", "command": "aws iam create-access-key --user-name svc-training"},
        {"step": "Restrict the role to internal source IPs", "command": "add aws:SourceIp / aws:SourceVpc condition to the svc-training policy"},
        {"step": "Delete the old key after the deploy picks up the new one", "command": "aws iam delete-access-key --user-name svc-training --access-key-id <KEY_ID>"},
    ],
    "hf_token": [
        {"step": "Revoke the token", "command": "huggingface.co → Settings → Access Tokens → Invalidate (or org token admin)"},
        {"step": "Issue a fine-grained token scoped only to the repos the job needs, write-only for uploads", "command": "huggingface.co → New fine-grained token"},
        {"step": "Review the org audit log for downloads, new tokens, and repo setting changes", "command": "huggingface.co/organizations/<org>/settings/audit-log"},
    ],
    "wandb_api_key": [
        {"step": "Regenerate the API key", "command": "wandb.ai → User settings → API keys → Revoke / New key"},
        {"step": "Check for runs or artifacts accessed from unknown IPs", "command": "W&B audit logs (team admin)"},
    ],
    "k8s_service_account_token": [
        {"step": "Remove the RBAC binding that let the worker exec into training pods", "command": "kubectl -n training delete rolebinding legacy-debug-ds-worker"},
        {"step": "Verify the worker can no longer exec", "command": "kubectl auth can-i create pods/exec -n training --as=system:serviceaccount:data-pipeline:ds-worker"},
        {"step": "Restart workers so projected tokens rotate; quarantine the compromised node first", "command": "kubectl cordon <node> && kubectl -n data-pipeline rollout restart deploy/ds-worker"},
        {"step": "Stop mounting the token where it is not needed", "command": "set automountServiceAccountToken: false on the ds-worker pod spec"},
    ],
    "kubeconfig_token": [
        {"step": "Revoke the token behind the kubeconfig (delete its secret / service account) on the target cluster", "command": "kubectl --context inference-prod -n kube-system delete secret training-admin-token"},
        {"step": "Remove the kubeconfig from the training-scheduler image and rebuild", "command": "rebuild image without /root/.kube/config"},
        {"step": "Rotate every secret that identity could read in that namespace", "command": "kubectl --context inference-prod -n inference get secrets"},
    ],
    "third_party_api_key": [
        {"step": "Rotate the key in the provider dashboard and update the k8s secret", "command": "kubectl -n inference create secret generic <name> --from-literal=key=<new> --dry-run=client -o yaml | kubectl apply -f -"},
        {"step": "Set a spending cap/alert while you investigate", "command": "provider billing settings"},
    ],
    "malicious_dataset": [
        {"step": "Quarantine the dataset and suspend the uploading account", "command": "move datasets/<name> to quarantine bucket; disable org"},
        {"step": "Disable remote-code loaders for customer uploads", "command": "load_dataset(..., trust_remote_code=False) everywhere; reject uploads with loader scripts"},
        {"step": "Render prompt templates in a sandbox (no object traversal)", "command": "use jinja2.sandbox.SandboxedEnvironment or plain str.format"},
    ],
}


def _ser(o):
    if hasattr(o, "model_dump"):
        return o.model_dump(exclude_none=True)
    return str(o)


class Investigation:
    def __init__(self, findings: dict, redactor, on_tool=None, on_egress=None):
        self.f = findings  # already redacted
        self.redactor = redactor
        self.on_tool = on_tool or (lambda *a: None)
        self.on_egress = on_egress or (lambda *a: None)
        self.groups = {g["id"]: g for c in findings["candidates"] for g in c["groups"]}
        self.report = None

    # -------------------------------------------------- tools (all return redacted data)
    def run_tool(self, name: str, args: dict):
        if name == "get_group":
            g = self.groups.get(args.get("group_id"))
            return g or {"error": "unknown group id", "valid_ids": list(self.groups)[:40]}
        if name == "get_machine_speed_bursts":
            return self.f["bursts"]
        if name == "get_credential_inventory":
            return {"credentials": self.f["inventory"]["credentials"], "data_assets": self.f["inventory"]["data_assets"]}
        if name == "get_rotation_playbook":
            return PLAYBOOKS.get(args.get("credential_type"), {"error": "unknown type"})
        if name == "get_on_call_roster":
            return self.f["inventory"].get("on_call", [])
        if name == "submit_incident_report":
            self.report = args
            return {"ok": True}
        return {"error": f"unknown tool {name}"}

    def overview(self) -> str:
        cands = []
        for c in self.f["candidates"]:
            cands.append({
                "id": c["id"], "severity_by_rules": c["severity"], "start": c["start"], "end": c["end"],
                "events": c["events"], "actors": c["actors"],
                "rules": [f"{r['id']} x{r['count']}: {r['title']}" for r in c["rules"]],
                "groups": [{"id": g["id"], "actor": g["actor"], "action": g["action"], "status": g["status"],
                            "count": g["count"], "machine_speed": g["machine_speed"],
                            "stage": g["analysis"]["stage"], "summary": g["analysis"]["what_happened"]}
                           for g in c["groups"]],
            })
        return json.dumps({
            "company": self.f["inventory"].get("company"),
            "log_window": self.f["window"], "events_scanned": self.f["events_total"],
            "local_analyzer": self.f["analyzer"],
            "machine_speed_actors": [{k: b[k] for k in ("actor", "start", "end", "events", "peak_per_min", "baseline_peak_per_min", "median_gap_ms")}
                                     for b in self.f["bursts"]],
            "candidates": cands,
        }, indent=1)

    # -------------------------------------------------- agent loop
    def run(self) -> dict:
        from .redact import assert_clean
        import anthropic

        client = anthropic.Anthropic()
        messages = [{"role": "user", "content": "Investigate this weekend's detections and file the incident report.\n\n"
                                                + self.overview()}]
        for turn in range(MAX_TURNS):
            ser = json.dumps(messages, default=_ser)
            body = json.dumps({"system": SYSTEM, "messages": json.loads(ser), "tools": TOOLS})
            assert_clean(ser)
            self.on_egress(len(body.encode()), messages[-1])
            force = turn >= MAX_TURNS - 2
            resp = client.messages.create(
                model=CLAUDE_MODEL, max_tokens=8000, system=SYSTEM, tools=TOOLS, messages=messages,
                tool_choice={"type": "tool", "name": "submit_incident_report"} if force else {"type": "auto"},
            )
            messages.append({"role": "assistant", "content": resp.content})
            tool_uses = [b for b in resp.content if b.type == "tool_use"]
            if not tool_uses:
                messages.append({"role": "user", "content": "Please call submit_incident_report now."})
                continue
            results = []
            for tu in tool_uses:
                self.on_tool(tu.name, tu.input)
                out = self.run_tool(tu.name, tu.input)
                results.append({"type": "tool_result", "tool_use_id": tu.id,
                                "content": json.dumps(self.redactor.obj(out))})
            messages.append({"role": "user", "content": results})
            if self.report:
                return self.report
            time.sleep(0.05)
        raise RuntimeError("Claude did not submit a report")


def fallback_report(findings: dict) -> dict:
    """Deterministic report used only when no ANTHROPIC_API_KEY is set (keeps the UI demoable)."""
    stage_order = ["initial_access", "execution", "credential_access", "discovery", "lateral_movement",
                   "privilege_escalation", "persistence", "collection", "exfiltration", "admin_activity", "unknown"]
    verdicts, timeline, creds = [], [], []
    inv = {c["identity"]: c for c in findings["inventory"]["credentials"]}
    for c in findings["candidates"]:
        crit = c["severity"] in ("critical", "high")
        verdicts.append({"candidate_id": c["id"], "verdict": "malicious" if crit else "needs_review",
                         "reason": "; ".join(r["title"] for r in c["rules"][:4])})
        if crit:
            for g in sorted(c["groups"], key=lambda g: g["first"]):
                timeline.append({"time": g["first"], "stage": g["analysis"]["stage"],
                                 "what": g["analysis"]["what_happened"], "groups": [g["id"]]})
                if g["actor"] in inv and inv[g["actor"]]["id"] not in [x["credential_id"] for x in creds]:
                    creds.append({"credential_id": inv[g["actor"]]["id"], "priority": len(creds) + 1,
                                  "why_exposed": f"used by {g['actor']} from {', '.join(g['src_ips'])}"})
    steps = [{"order": i + 1, "step": s["step"], "command": s["command"]}
             for i, s in enumerate(PLAYBOOKS["malicious_dataset"][:1] + PLAYBOOKS["aws_access_key"][:1]
                                   + PLAYBOOKS["hf_token"][:1] + PLAYBOOKS["k8s_service_account_token"][:1])]
    return {
        "severity": "critical", "headline": "Rule-based summary (connect Claude for the full investigation)",
        "executive_summary": "Set ANTHROPIC_API_KEY to have Claude investigate, judge each candidate, and write the report.",
        "attacker_profile": "", "verdicts": verdicts, "timeline": timeline[:25], "credentials_to_rotate": creds,
        "data_impact": [], "containment_steps": steps, "root_causes": [], "customer_notification_draft": "",
        "open_questions": [], "_fallback": True,
    }
