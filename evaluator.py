import csv, json, subprocess
from collections import defaultdict

EXEC   = "./egl"
POLICY = "examples/eval_policy.egl"
FLAGS  = ["--json"]

MAP = {
    "email": "EMAIL",
    "phone": "PHONE",
    "ip": "IPV4",
    "device_id": "MAC",
    "self_harm": "ENCOURAGEMENT_TO_SELF_HARM",
    "handle": "SOCIAL_HANDLE",
}

ALL = list(MAP.values())
counts = {cat: {"tp":0, "fp":0, "fn":0, "tn":0} for cat in ALL}

with open("test_datasets/egl_eval.csv") as f:
    reader = csv.DictReader(f)
    for row in reader:
        text = row["text"]
        expected = set(row["expected_categories"].split("|")) if row["expected_categories"] else set()

        cmd = [EXEC, POLICY] + FLAGS + [text]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        out = proc.stdout.strip()
        if out.startswith("{"):
            js = json.loads(out)
            got = {MAP[a["evaluated"]] for a in js["actions_applied"] if a["evaluated"] in MAP}

            for cat in ALL:
                if cat in expected and cat in got:
                    counts[cat]["tp"] += 1
                elif cat in expected and cat not in got:
                    if cat == "ENCOURAGEMENT_TO_SELF_HARM":
                          print(expected, ": ", out)
                    counts[cat]["fn"] += 1
                elif cat not in expected and cat in got:
                    counts[cat]["fp"] += 1
                else:
                    counts[cat]["tn"] += 1

print(f"{'CATEGORY':30} TP  FP  FN  TN  PREC   REC    F1")
for cat in ALL:
    c = counts[cat]
    tp, fp, fn = c["tp"], c["fp"], c["fn"]
    p = tp/(tp+fp) if (tp+fp) else 1
    r = tp/(tp+fn) if (tp+fn) else 1
    f1 = 2*p*r/(p+r) if (p+r) else 1
    print(f"{cat:30} {tp:2d}  {fp:2d}  {fn:2d}  {c['tn']:3d}  {p:5.2f}  {r:5.2f}  {f1:5.2f}")


