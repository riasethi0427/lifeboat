# 🛟 Lifeboat: local-first incident response for AI startups

> In July 2026, Hugging Face was breached by an autonomous AI agent: 17,000+ actions over one weekend,
> starting from a malicious dataset. Its responders ran forensics on an open-weight model on their own
> hardware. Hugging Face has an ML team to do that. The 30-person AI startup next door doesn't.
> **Lifeboat gives them the same setup in one command.**

## How it works (4 stages, 3 of them never leave your machine)

| # | Stage | Where | What |
|---|-------|-------|------|
| 1 | **Detect** | local, deterministic | Learns each identity's baseline (first 6h), then flags **machine-speed bursts** (the AI-attacker tell) + 16 ML-pipeline rules: remote-code dataset loaders, template injection, shells from workers, SA-token reads, 403 enumeration, exec by service accounts, env/kubeconfig dumps, new-IP credential use, S3 fan-out, private-model downloads… |
| 2 | **Read raw evidence** | local open-weight model (Ollama / llama.cpp / LM Studio) | Reads payloads, decoded commands, env dumps. Can't refuse, can't leak. Falls back to a rule-based analyzer if no model is running. |
| 3 | **Redact** | local, enforced in code | Keys, tokens, JWTs, secrets, blobs, employee emails→pseudonyms. `assert_clean()` blocks any request that still contains a secret-shaped string. |
| 4 | **Investigate** | Claude (tool use) | Gets only redacted findings. Calls tools (`get_group`, `get_credential_inventory`, `get_rotation_playbook`, `get_on_call_roster`, …) to judge each candidate, rebuild the timeline, compute blast radius, order key rotation, write containment steps + a customer notification. Then posts to Slack with one click. |

The egress meter in the UI shows bytes kept local vs. bytes sent to Claude, and **"inspect what left"** shows every request's new content.

## Run it (5 minutes)

```bash
pip install anthropic                       # only dependency
python gen_logs.py                          # writes data/logs.jsonl (12,460 events, 4.6 MB)

# optional but the point of the product: a local model
ollama pull qwen3:8b                        # ~5 GB. On bad wifi: qwen3:4b, then LOCAL_MODEL=qwen3:4b
ollama serve                                # if not already running

export ANTHROPIC_API_KEY=...                # Claude step
export SLACK_WEBHOOK_URL=...                # optional: "Send to #incident" posts for real
python server.py                            # http://localhost:8000
```

Env knobs: `CLAUDE_MODEL` (default `claude-sonnet-5-5`), `LOCAL_MODEL`, `LOCAL_LLM_URL`,
`LOCAL_LLM_API=ollama|openai` (for llama.cpp / LM Studio / vLLM), `LOG_PATH` (your own JSONL), `PORT`.

Without a local model → rule-based analyzer. Without an API key → rule-based report. The demo never hard-fails.

## The synthetic incident (what judges will see)

Fictional "Tessera AI", a fine-tuning-as-a-service startup. Fri 18:00 → Mon 08:00 UTC.
Hidden in normal noise (incl. an inference gateway that *legitimately* does 70 req/min, which is correctly NOT flagged):

1. Trial account signs up Fri night, uploads `northwind/eval-mix-v2` with a loader script + template injection
2. Worker loads it with `trust_remote_code=True` → base64-encoded shell → reads its service-account token
3. 18 permission probes in 4 seconds (403s) → finds a legacy RBAC binding → `exec` into the training scheduler
4. Dumps env (AWS key, HF token, W&B key) and a kubeconfig for the inference cluster
5. AWS key used from outside: 246 customer-dataset objects read in ~80s (192 actions/min vs. 4 normal)
6. Kubeconfig used on inference-prod: reads `hf-registry-token`, `openai-fallback-key`; cluster-admin attempt denied
7. HF token downloads 12 private customer fine-tunes

Plus a decoy: the on-call SRE's legitimate `kubectl exec` on Saturday. Claude should check the on-call roster and clear it.

## 3-minute demo script

1. **(20s) Hook.** "In July, Hugging Face got breached by an AI agent over one weekend. They fought back with a model running on their own hardware. Your AI startup has the same pipeline, and no security team."
2. **(15s)** "This is a weekend of logs from an AI startup: 12,000 events, 4.6 MB." Click **Investigate**.
3. **(30s) Point at the machine-speed panel.** "192 actions a minute from a key that normally does 4. That's not a person." Point at the LOCAL tags: the local model is reading the raw payloads right now.
4. **(30s) Point at the Redact card and the egress meter.** "It found AWS keys, HF tokens and JWTs in the logs. Every one was stripped in code before anything left. Here's exactly what Claude saw." Open **inspect what left**.
5. **(45s) The report.** Read the headline. Show verdicts: the SRE's exec cleared as on-call, the attack marked malicious. Show **rotate now, in this order**: which key is still in use goes first. Show a copyable command.
6. **(20s)** Click **Send to #incident**, and it lands in Slack.
7. **(20s) Honest limits + why us.** Synthetic data; detection rules are tuned to ML pipelines on Kubernetes + AWS; v1 reads logs, it doesn't auto-remediate (a human approves every action).

## Team split (4 people, ~3.5h)

- **Claude loop + prompts** (`lifeboat/claude_agent.py`): tune the system prompt and report quality on real runs
- **Local model** (`lifeboat/local_llm.py`): get Ollama running on the demo laptop FIRST; tune batch size for speed
- **UI + Slack** (`static/index.html`, `server.py`): set up a Slack incoming webhook in a test workspace
- **Story + data** (`gen_logs.py`, pitch): rehearse twice, record a backup video before 4:15

## Files

```
gen_logs.py              synthetic logs (deterministic seed)
data/inventory.json      credentials (masked), data assets, on-call roster
data/directory.json      local-only email → pseudonym map
lifeboat/detect.py       baselines, machine-speed bursts, rules, candidates, behavior groups
lifeboat/local_llm.py    local model analysis (Ollama/OpenAI-compatible) + rule fallback
lifeboat/redact.py       enforced redaction + egress guard
lifeboat/claude_agent.py Claude tool-use investigation + playbooks + fallback report
lifeboat/pipeline.py     orchestration + live status
server.py                stdlib web server (UI, /api/run, /api/status, /api/egress, /api/notify)
static/index.html        UI
```
