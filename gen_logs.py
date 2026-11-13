#!/usr/bin/env python3
"""Generate a synthetic weekend of logs for a fictional AI startup ("Tessera AI"),
with one AI-agent-driven intrusion hidden inside ~15k normal events.

Everything is fake: AWS keys are AWS's documented example keys, tokens are obviously
fake, IPs are from documentation ranges (203.0.113.0/24, 10.0.0.0/8).

Attack path mirrors the public write-ups of the July 2026 Hugging Face incident:
malicious dataset -> remote-code loader -> shell on a processing worker -> service
account token -> RBAC misconfig -> exec into another pod -> env/kubeconfig secrets ->
cloud data collection + private model download, all at machine speed.

Usage: python gen_logs.py [out_path]   (default: data/logs.jsonl)
"""
import base64
import json
import random
import sys
from datetime import datetime, timedelta, timezone

random.seed(7)
UTC = timezone.utc
START = datetime(2026, 11, 6, 18, 0, tzinfo=UTC)   # Fri 18:00 UTC
END = datetime(2026, 11, 9, 8, 0, tzinfo=UTC)      # Mon 08:00 UTC
events = []

DS_WORKER = "system:serviceaccount:data-pipeline:ds-worker"
SCHEDULER = "system:serviceaccount:training:training-scheduler"
GATEWAY = "system:serviceaccount:inference:inference-gateway"
SVC_TRAINING = "iam:svc-training"
HF_CI = "hf-token:tessera-ci"
KUBECONFIG_ADMIN = "kubeconfig:training-admin"
ATTACKER_IP = "203.0.113.50"
CUSTOMERS = ["acme", "globex", "initech", "umbrella", "hooli"]


def iso(t):
    return t.strftime("%Y-%m-%dT%H:%M:%S.") + f"{t.microsecond // 1000:03d}Z"


def ev(t, source, actor, actor_type, action, resource, status=200,
       cluster="train-prod", node=None, src_ip="10.0.4.12", raw=""):
    events.append(dict(ts=iso(t), source=source, actor=actor, actor_type=actor_type,
                       action=action, resource=resource, status=status,
                       cluster=cluster, node=node, src_ip=src_ip, raw=raw))


def jitter(t, max_s):
    return t + timedelta(seconds=random.uniform(0, max_s))


# ---------------------------------------------------------------- normal activity
# Inference gateway: legit machine-speed bursts all weekend (should NOT be flagged:
# it matches its own baseline).
t = START
while t < END:
    burst_start = jitter(t, 300)
    n = random.randint(40, 70)
    for i in range(n):
        bt = burst_start + timedelta(seconds=random.uniform(0, 58))
        model = random.choice(["tessera/ft-acme-legal-v3", "tessera/ft-globex-support-v7",
                               "tessera/base-8b-instruct"])
        ev(bt, "app", GATEWAY, "service", "model.invoke", model, cluster="inference-prod",
           node=f"inf-node-{random.randint(1, 4)}", src_ip="10.0.8.21",
           raw=f"POST /v1/generate model={model} tokens={random.randint(80, 900)} 200")
    t += timedelta(minutes=20)

# Training scheduler: polls every 5 min; launches a job every ~2h.
t = START
job = 0
while t < END:
    ev(jitter(t, 3), "k8s_audit", SCHEDULER, "service", "jobs.list", "training/jobs",
       node="train-node-2", src_ip="10.0.4.12", raw="GET /apis/batch/v1/namespaces/training/jobs 200")
    ev(jitter(t, 3), "k8s_audit", SCHEDULER, "service", "pods.list", "training/pods",
       node="train-node-2", src_ip="10.0.4.12", raw="GET /api/v1/namespaces/training/pods 200")
    if t.minute == 0 and t.hour % 2 == 0:
        job += 1
        cust = random.choice(CUSTOMERS)
        jt = jitter(t, 20)
        ev(jt, "k8s_audit", SCHEDULER, "service", "jobs.create", f"training/ft-{cust}-{job}",
           node="train-node-2", raw=f"POST jobs ft-{cust}-{job} 201", status=201)
        ev(jt + timedelta(seconds=40), "cloudtrail", SVC_TRAINING, "service", "sts:GetCallerIdentity",
           "sts", cluster=None, raw="sts:GetCallerIdentity from 10.0.4.12")
        for k in range(random.randint(2, 4)):
            ev(jt + timedelta(seconds=45 + k * 7), "cloudtrail", SVC_TRAINING, "service", "s3:GetObject",
               f"s3://tessera-customer-datasets/{cust}/train-00{k}.parquet", cluster=None,
               raw=f"s3:GetObject tessera-customer-datasets/{cust}/train-00{k}.parquet 200")
        ev(jt + timedelta(minutes=95), "app", HF_CI, "service", "model.upload",
           f"tessera/ft-{cust}-v{job}", cluster=None,
           raw=f"POST /api/repos/tessera/ft-{cust}-v{job}/upload (private) 200")
    t += timedelta(minutes=5)

# Legit customer dataset uploads + worker loads (trust_remote_code=False).
t = START + timedelta(minutes=17)
while t < END:
    cust = random.choice(CUSTOMERS)
    name = f"{cust}/{random.choice(['support-logs', 'contracts', 'faq', 'tickets'])}-v{random.randint(2, 9)}"
    ut = jitter(t, 600)
    ev(ut, "app", f"org:{cust}", "customer", "dataset.upload", f"datasets/{name}", cluster=None,
       src_ip=f"198.51.100.{random.randint(10, 200)}",
       raw=json.dumps({"name": name, "loader": None, "config": {"prompt_template": "### Q: {question}\n### A:"}}))
    lt = ut + timedelta(minutes=random.randint(2, 15))
    ev(lt, "worker", DS_WORKER, "service", "dataset.load", f"datasets/{name}", node="ds-worker-1",
       src_ip="10.0.5.3", raw=f"load_dataset('{name}', trust_remote_code=False)")
    ev(lt + timedelta(seconds=2), "k8s_audit", DS_WORKER, "service", "configmaps.get",
       "data-pipeline/loader-config", node="ds-worker-1", src_ip="10.0.5.3", raw="GET configmap loader-config 200")
    for k in range(random.randint(1, 3)):
        ev(lt + timedelta(seconds=4 + k * 3), "cloudtrail", "iam:svc-dataworker", "service", "s3:GetObject",
           f"s3://tessera-uploads/{name}/part-{k}.jsonl", cluster=None, src_ip="10.0.5.3",
           raw=f"s3:GetObject tessera-uploads/{name}/part-{k}.jsonl 200")
    ev(lt + timedelta(seconds=30), "cloudtrail", "iam:svc-dataworker", "service", "s3:PutObject",
       f"s3://tessera-customer-datasets/{name}.parquet", cluster=None, src_ip="10.0.5.3",
       raw=f"s3:PutObject tessera-customer-datasets/{name}.parquet 200")
    t += timedelta(minutes=random.randint(60, 140))

# Humans: Friday evening engineering, Saturday on-call check (incl. a legit exec).
for who, n in [("maya.chen@tessera.ai", 25), ("rahul.d@tessera.ai", 18)]:
    for _ in range(n):
        ht = START + timedelta(seconds=random.uniform(0, 3 * 3600))
        act = random.choice(["pods.list", "pods/log.get", "deployments.get"])
        ev(ht, "k8s_audit", who, "human", act, f"training/{random.choice(['pods', 'ft-acme-3', 'scheduler'])}",
           src_ip="10.0.1.40", raw=f"kubectl {act.split('.')[0]} 200")
lena = "lena.ortiz@tessera.ai"
for i, (act, res, raw) in enumerate([
    ("pods.list", "inference/pods", "kubectl get pods -n inference 200"),
    ("pods/log.get", "inference/inference-gateway-5c8d", "kubectl logs inference-gateway-5c8d 200"),
    ("pods/exec.create", "inference/inference-gateway-5c8d", "kubectl exec inference-gateway-5c8d -- curl -s localhost:8080/healthz 200"),
    ("pods/log.get", "inference/inference-gateway-5c8d", "kubectl logs inference-gateway-5c8d --since=10m 200"),
]):
    ev(datetime(2026, 11, 7, 18, 6, tzinfo=UTC) + timedelta(minutes=i * 3 + random.uniform(0, 1)),
       "k8s_audit", lena, "human", act, res, cluster="inference-prod", src_ip="10.0.1.52", raw=raw)

# New trial account created Friday night (the attacker's foothold).
ev(datetime(2026, 11, 6, 23, 40, 9, tzinfo=UTC), "app", "org:northwind-trial", "customer", "account.create",
   "orgs/northwind-trial", cluster=None, src_ip="203.0.113.77", raw="signup plan=trial email_domain=northwind-ml.io")

# ---------------------------------------------------------------- the intrusion
BACKGROUND_ONLY = "--background" in sys.argv
if BACKGROUND_ONLY:  # v5 live replay generates the attacker reactively; write normal activity only
    events.sort(key=lambda e: e["ts"])
    with open("data/background.jsonl", "w") as f:
        for e in events:
            f.write(json.dumps(e) + "\n")
    print(f"wrote {len(events)} background events to data/background.jsonl")
    sys.exit(0)
t = datetime(2026, 11, 7, 1, 58, 12, tzinfo=UTC)
ev(t, "app", "org:northwind-trial", "customer", "dataset.upload", "datasets/northwind/eval-mix-v2", cluster=None,
   src_ip="203.0.113.77",
   raw=json.dumps({"name": "northwind/eval-mix-v2", "loader": "eval_mix.py",
                   "config": {"prompt_template": "{{ self.__init__.__globals__.__builtins__ ... [payload truncated in demo data] }}"}}))

t = datetime(2026, 11, 7, 2, 13, 4, 120000, tzinfo=UTC)


def step(seconds):
    global t
    t = t + timedelta(seconds=seconds)
    return t


ev(t, "worker", DS_WORKER, "service", "dataset.load", "datasets/northwind/eval-mix-v2", node="ds-worker-3",
   src_ip="10.0.5.7", raw="load_dataset('northwind/eval-mix-v2', trust_remote_code=True) loader=eval_mix.py")
cmd = base64.b64encode(b"id; uname -a; cat /var/run/secrets/kubernetes.io/serviceaccount/token").decode()
ev(step(0.8), "worker", DS_WORKER, "service", "process.spawn", "ds-worker-3", node="ds-worker-3", src_ip="10.0.5.7",
   raw=f"sh -c 'echo {cmd} | base64 -d | sh' ppid=python3(eval_mix.py)")
ev(step(0.3), "worker", DS_WORKER, "service", "file.read", "/var/run/secrets/kubernetes.io/serviceaccount/token",
   node="ds-worker-3", src_ip="10.0.5.7", raw="open(/var/run/secrets/kubernetes.io/serviceaccount/token) pid=4127")

ev(step(0.9), "k8s_audit", DS_WORKER, "service", "selfsubjectrulesreviews.create", "authorization",
   node="ds-worker-3", src_ip="10.0.5.7", status=201, raw="POST selfsubjectrulesreviews 201")
for ns in ["default", "kube-system", "training", "inference", "data-pipeline", "monitoring", "billing",
           "auth", "registry", "ci", "argo", "vault", "ingress", "cert-manager"]:
    ev(step(random.uniform(0.03, 0.09)), "k8s_audit", DS_WORKER, "service", "secrets.list", f"{ns}/secrets",
       node="ds-worker-3", src_ip="10.0.5.7", status=403, raw=f"GET /api/v1/namespaces/{ns}/secrets 403 Forbidden")
for ns in ["default", "kube-system", "training", "inference"]:
    ev(step(random.uniform(0.03, 0.09)), "k8s_audit", DS_WORKER, "service", "rolebindings.list", f"{ns}/rolebindings",
       node="ds-worker-3", src_ip="10.0.5.7", status=403, raw=f"GET rolebindings -n {ns} 403 Forbidden")
for ns in ["data-pipeline", "training", "inference"]:
    st = 403 if ns == "inference" else 200
    ev(step(random.uniform(0.05, 0.12)), "k8s_audit", DS_WORKER, "service", "pods.list", f"{ns}/pods",
       node="ds-worker-3", src_ip="10.0.5.7", status=st, raw=f"GET /api/v1/namespaces/{ns}/pods {st}")
ev(step(0.4), "k8s_audit", DS_WORKER, "service", "pods/exec.create", "training/training-scheduler-7d9f4",
   node="train-node-2", src_ip="10.0.5.7", status=101,
   raw="POST pods/training-scheduler-7d9f4/exec?command=sh 101 Switching Protocols (RBAC: role/legacy-debug grants pods/exec)")
ev(step(0.2), "worker", DS_WORKER, "service", "process.spawn", "training-scheduler-7d9f4", node="train-node-2",
   src_ip="10.0.5.7", raw="sh -c 'env; cat /root/.kube/config' (exec session)")
ev(step(0.1), "worker", DS_WORKER, "service", "process.output", "training-scheduler-7d9f4", node="train-node-2",
   src_ip="10.0.5.7",
   raw=("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY "
        "HF_TOKEN=hf_FAKEdemoTOKENdoNOTuse0000000000 WANDB_API_KEY=0000fakefakefakefake1111222233334444 "
        "TRAINING_BUCKET=tessera-customer-datasets"))
ev(step(0.2), "worker", DS_WORKER, "service", "file.read", "/root/.kube/config", node="train-node-2", src_ip="10.0.5.7",
   raw=("clusters: [{server: https://inference-prod.k8s.tessera.internal}] users: [{name: training-admin, "
        "token: eyJhbGciOiJSUzI1NiIsImtpZCI6ImRlbW8ifQ.eyJzdWIiOiJ0cmFpbmluZy1hZG1pbiJ9.ZmFrZXNpZ25hdHVyZQ}]"))

# Cloud: stolen svc-training key used from outside.
t = datetime(2026, 11, 7, 2, 13, 41, tzinfo=UTC)
ev(t, "cloudtrail", SVC_TRAINING, "service", "sts:GetCallerIdentity", "sts", cluster=None, src_ip=ATTACKER_IP,
   raw=f"sts:GetCallerIdentity from {ATTACKER_IP} ua=boto3/1.40")
ev(step(0.4), "cloudtrail", SVC_TRAINING, "service", "s3:ListBuckets", "s3", cluster=None, src_ip=ATTACKER_IP,
   raw="s3:ListBuckets 200")
ev(step(0.3), "cloudtrail", SVC_TRAINING, "service", "iam:ListUsers", "iam", cluster=None, src_ip=ATTACKER_IP,
   status=403, raw="iam:ListUsers AccessDenied")
ev(step(0.3), "cloudtrail", SVC_TRAINING, "service", "iam:CreateAccessKey", "iam/svc-training", cluster=None,
   src_ip=ATTACKER_IP, status=403, raw="iam:CreateAccessKey AccessDenied")
for cust in CUSTOMERS + ["northwind"]:
    ev(step(0.25), "cloudtrail", SVC_TRAINING, "service", "s3:ListObjectsV2",
       f"s3://tessera-customer-datasets/{cust}/", cluster=None, src_ip=ATTACKER_IP,
       raw=f"s3:ListObjectsV2 tessera-customer-datasets prefix={cust}/ 200")
for cust in CUSTOMERS:
    for k in range(random.randint(38, 60)):
        ev(step(random.uniform(0.15, 0.5)), "cloudtrail", SVC_TRAINING, "service", "s3:GetObject",
           f"s3://tessera-customer-datasets/{cust}/train-{k:03d}.parquet", cluster=None, src_ip=ATTACKER_IP,
           raw=f"s3:GetObject tessera-customer-datasets/{cust}/train-{k:03d}.parquet 200 bytes={random.randint(2, 40)}MB")

# Inference cluster via stolen kubeconfig.
t = datetime(2026, 11, 7, 2, 17, 2, tzinfo=UTC)
for act, res, st in [("namespaces.list", "namespaces", 200), ("pods.list", "inference/pods", 200),
                     ("deployments.list", "inference/deployments", 200), ("configmaps.list", "inference/configmaps", 200),
                     ("secrets.list", "inference/secrets", 200), ("secrets.get", "inference/hf-registry-token", 200),
                     ("secrets.get", "inference/openai-fallback-key", 200), ("secrets.get", "billing/stripe-webhook", 403),
                     ("clusterrolebindings.create", "cluster/backdoor-admin", 403)]:
    ev(step(random.uniform(0.2, 0.6)), "k8s_audit", KUBECONFIG_ADMIN, "service", act, res, cluster="inference-prod",
       src_ip=ATTACKER_IP, status=st, raw=f"kubectl {act} {res} {st} ua=kubectl/1.34 (python-requests)")

# Private model weights downloaded with the stolen HF token.
t = datetime(2026, 11, 7, 2, 18, 30, tzinfo=UTC)
for m in ["ft-acme-legal-v3", "ft-globex-support-v7", "ft-initech-claims-v2", "ft-umbrella-pharma-v5",
          "ft-hooli-search-v4", "base-8b-instruct-tessera", "ft-acme-legal-v2", "ft-globex-support-v6",
          "reward-model-v9", "ft-initech-claims-v1", "ft-umbrella-pharma-v4", "distill-3b-v2"]:
    ev(step(random.uniform(1.5, 3.5)), "app", HF_CI, "service", "model.download", f"tessera/{m}", cluster=None,
       src_ip=ATTACKER_IP, raw=f"GET /api/models/tessera/{m}/resolve/main/model.safetensors (private) 200")

# ---------------------------------------------------------------- write
events.sort(key=lambda e: e["ts"])
out = next((a for a in sys.argv[1:] if not a.startswith("--")), "data/logs.jsonl")
with open(out, "w") as f:
    for e in events:
        f.write(json.dumps(e) + "\n")
print(f"wrote {len(events)} events to {out}")
