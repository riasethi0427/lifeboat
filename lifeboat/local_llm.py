"""Step 2: the local open-weight model reads the RAW evidence (payloads, env dumps,
commands) on your own hardware. Nothing here touches the network except localhost.

Works with Ollama (default) or any OpenAI-compatible local server (llama.cpp, LM Studio, vLLM):
  LOCAL_LLM_URL=http://localhost:11434   LOCAL_LLM_API=ollama|openai   LOCAL_MODEL=qwen3:8b

If no local model is reachable, a deterministic rule-based analyzer is used so the demo never breaks.
"""
from __future__ import annotations

import json
import os
import re
import urllib.request

LOCAL_LLM_URL = os.environ.get("LOCAL_LLM_URL", "http://localhost:11434").rstrip("/")
LOCAL_LLM_API = os.environ.get("LOCAL_LLM_API", "ollama")
LOCAL_MODEL = os.environ.get("LOCAL_MODEL", "qwen3:8b")
BATCH = int(os.environ.get("LOCAL_BATCH", "3"))

STAGES = ["initial_access", "execution", "discovery", "credential_access", "privilege_escalation",
          "lateral_movement", "collection", "exfiltration", "persistence", "admin_activity", "unknown"]

SYSTEM = (
    "You are a security log analyst running locally on the company's own hardware. You receive behavior "
    "groups extracted from infrastructure logs (Kubernetes audit, worker process logs, CloudTrail, model hub). "
    "For EACH group return: what_happened (one plain-English sentence under 25 words, mention counts and "
    "status codes), stage (one of: " + ", ".join(STAGES) + "; a dataset upload from an outside account is "
    "initial_access), and secret_types (types of credentials visible in the evidence, e.g. aws_access_key, "
    "aws_secret_key, hf_token, wandb_api_key, kube_token; types only). "
    "NEVER copy secret values into your answer. Respond with compact single-line JSON only, no indentation: "
    '{"groups":[{"id":"...","what_happened":"...","stage":"...","secret_types":[]}]}'
)


def _post(url: str, body: dict, timeout: float) -> dict:
    req = urllib.request.Request(url, data=json.dumps(body).encode(), headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode())


def available() -> bool:
    path = "/api/tags" if LOCAL_LLM_API == "ollama" else "/v1/models"
    try:
        with urllib.request.urlopen(LOCAL_LLM_URL + path, timeout=1.5) as r:
            return r.status == 200
    except Exception:
        return False


def warmup() -> None:
    """Load the model into memory ahead of time so the first demo batch isn't slow."""
    if LOCAL_LLM_API != "ollama" or not available():
        return
    try:
        _post(LOCAL_LLM_URL + "/api/generate", {"model": LOCAL_MODEL, "prompt": "ok", "stream": False,
                                                "think": False, "keep_alive": "60m",
                                                "options": {"num_predict": 1}}, timeout=300)
    except Exception:
        pass


# Only these behaviors carry raw evidence worth a model's read (payloads, commands, env dumps).
LOCAL_RULES = {"R1", "R2", "R3", "R4", "R5", "R7", "R8", "R9", "R12", "R13"}


def needs_local_read(g: dict) -> bool:
    return bool(set(g.get("rules", [])) & LOCAL_RULES or g.get("decoded_commands"))


def _chat(user: str) -> str:
    msgs = [{"role": "system", "content": SYSTEM}, {"role": "user", "content": user}]
    if LOCAL_LLM_API == "ollama":
        r = _post(LOCAL_LLM_URL + "/api/chat", {"model": LOCAL_MODEL, "messages": msgs, "stream": False,
                                                "format": "json", "think": False, "keep_alive": "60m",
                                                "options": {"temperature": 0}}, timeout=180)
        return r["message"]["content"]
    r = _post(LOCAL_LLM_URL + "/v1/chat/completions", {"model": LOCAL_MODEL, "messages": msgs, "temperature": 0,
                                                       "response_format": {"type": "json_object"}}, timeout=180)
    return r["choices"][0]["message"]["content"]


def _parse(text: str) -> dict:
    text = re.sub(r"<think>[\s\S]*?</think>", "", text or "").strip()
    m = re.search(r"\{[\s\S]*\}", text)
    return json.loads(m.group(0)) if m else {}


# ------------------------------------------------------------------ deterministic fallback
STAGE_BY_ACTION = {
    "dataset.upload": "initial_access", "dataset.load": "execution", "process.spawn": "execution",
    "selfsubjectrulesreviews.create": "discovery", "secrets.list": "discovery", "rolebindings.list": "discovery",
    "pods.list": "discovery", "namespaces.list": "discovery", "deployments.list": "discovery",
    "configmaps.list": "discovery", "sts:GetCallerIdentity": "discovery", "s3:ListBuckets": "discovery",
    "s3:ListObjectsV2": "discovery", "iam:ListUsers": "discovery", "pods/exec.create": "lateral_movement",
    "process.output": "credential_access", "secrets.get": "credential_access", "s3:GetObject": "collection",
    "model.download": "exfiltration", "iam:CreateAccessKey": "persistence",
    "clusterrolebindings.create": "privilege_escalation",
}
SECRET_HINTS = [("aws_access_key", r"AKIA|AWS_ACCESS_KEY_ID"), ("aws_secret_key", r"AWS_SECRET_ACCESS_KEY"),
                ("hf_token", r"hf_|HF_TOKEN"), ("wandb_api_key", r"WANDB_API_KEY"),
                ("kube_token", r"token: eyJ|serviceaccount/token")]
IOC = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b|/[\w./-]+(?:token|config)\b|[\w-]+/[\w.-]+-v\d+")


def rule_analyze(g: dict) -> dict:
    action = g["action"]
    stage = STAGE_BY_ACTION.get(action, "unknown")
    if action == "file.read":
        stage = "credential_access"
    if g["actor_type"] == "human" and action == "pods/exec.create":
        stage = "admin_activity"
    blob = " ".join(g.get("raw_samples", []) + g.get("resources_sample", []) + g.get("decoded_commands", []))
    secret_types = [name for name, pat in SECRET_HINTS if re.search(pat, blob)]
    short = g["actor"].split(":")[-1]
    res = g["resources_sample"][0] if g["resources_sample"] else ""
    what = (f"{short} ran {action} {g['count']}x (status {g['status']}) across {g['distinct_resources']} "
            f"resource(s), e.g. {res}")
    if g.get("decoded_commands"):
        what += f"; decoded command: {g['decoded_commands'][0]}"
    iocs = sorted(set(IOC.findall(blob)) | {ip for ip in g.get("src_ips", []) if not ip.startswith("10.")})[:8]
    return {"what_happened": what, "stage": stage, "secret_types": secret_types, "iocs": iocs}


def analyze_groups(groups: list[dict], use_model: bool, progress=None) -> tuple[dict, str]:
    """Returns ({group_id: analysis}, analyzer_label)."""
    results = {g["id"]: rule_analyze(g) for g in groups}
    if not use_model:
        if progress:
            progress(len(groups), len(groups))
        return results, "rules (no local model running)"
    done = 0
    for k in range(0, len(groups), BATCH):
        batch = groups[k:k + BATCH]
        payload = [{key: g[key] for key in ("id", "actor", "actor_type", "action", "status", "count",
                                            "distinct_resources", "resources_sample", "raw_samples",
                                            "decoded_commands", "src_ips", "machine_speed", "first", "last")}
                   for g in batch]
        try:
            out = _parse(_chat(json.dumps(payload, indent=1)))
            for item in out.get("groups", []):
                gid = item.get("id")
                if gid in results and item.get("what_happened"):
                    stage = item.get("stage") if item.get("stage") in STAGES else results[gid]["stage"]
                    results[gid] = {
                        "what_happened": str(item["what_happened"])[:400],
                        "stage": stage,
                        "secret_types": sorted(set(results[gid]["secret_types"]) | set(item.get("secret_types") or [])),
                        "iocs": [str(x) for x in (item.get("iocs") or [])][:8] or results[gid]["iocs"],
                    }
        except Exception as ex:  # keep the rule-based answer for this batch
            for g in batch:
                results[g["id"]]["note"] = f"local model error, rule fallback: {type(ex).__name__}"
        done += len(batch)
        if progress:
            progress(done, len(groups))
    return results, f"local model: {LOCAL_MODEL}"
