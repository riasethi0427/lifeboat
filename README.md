# Lifeboat: local-first incident response for AI startups

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

The bar at the top of the UI shows bytes kept on the laptop vs. bytes sent to Claude. **View** shows exactly what each request to Claude contained.

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

Start the run while you give the hook. The report lands about 90 seconds later.

1. **(20s) Hook.** "In July, Hugging Face got breached by an AI agent over one weekend. They fought back with a model running on their own hardware. Your AI startup has the same pipeline and no security team." Click **Run investigation** now.
2. **(15s)** "This is a weekend of logs from an AI startup: 12,000 events, 4.6 MB."
3. **(30s) "Activity faster than any person" chart.** "192 actions a minute from a key that normally does 4. That's not a person." Point at the sidebar: **Read raw evidence, on this laptop, qwen3:8b**. The local model is reading the raw payloads right now.
4. **(30s) Data boundary.** Sidebar: **Redact secrets, 9 removed**. Top bar: **4.6 MB kept on this laptop** vs. the **KB sent to Claude** (read the live number off the bar; it counts every request, so it varies by run). Click **View** to show exactly what Claude saw.
5. **(45s) The report.** Read the headline. **Verdicts:** the on-call engineer's exec cleared as benign (Claude checked the roster), the attack marked malicious. **Rotate these credentials first:** point at #1 and read Claude's reason out loud (the order can differ between runs; each order is reasoned from the evidence). Copy one command.
6. **(20s)** Click **Send to #incident**, and it lands in Slack.
7. **(20s) Honest limits and why us.** Synthetic data in our own log format. Rules are tuned to ML pipelines on Kubernetes and AWS. Next: CloudTrail and Kubernetes audit importers plus a runtime sensor (Falco). v1 reads logs and does not auto-remediate; a human approves every action.

### Likely judge questions

- **Why not paste the logs into Claude?** 4.6 MB full of live secrets can't leave the company, and wouldn't fit anyway. The local model reads raw data; Claude only gets redacted findings, a small fraction of the raw size (the bar shows the exact figure).
- **Does it work on real data?** Not yet: synthetic data in our own format. Next step is CloudTrail and Kubernetes audit importers.
- **Who pays?** AI startups with 10 to 200 people, customer data, and no security team. Enterprise tools are priced and built for large security teams.

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
