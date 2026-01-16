#!/usr/bin/env python3
import argparse
import os
import sys
from typing import Optional, List, Dict, Any
import logging
from transformers.utils import logging as hf_logging
import re
logging.getLogger("transformers").setLevel(logging.ERROR)
hf_logging.set_verbosity_error()


EUPHEMISMS = [
    r"\bunalive\b",
    r"\bkys\b",
    r"\bkill\s*(yourself|urself)\b",
    r"\bend\s*(your\s*)?life\b",
    r"\boff\s*yourself\b",
    r"\bdo\s*it\b",
    r"\bcommit\s*suicide\b",
]

ENCOURAGE_CUES = [
    r"\byou\s+should\b",
    r"\bjust\b",
    r"\bthe\s+best\s+way\b",
    r"\bhere(\'s| is)\s+how\b",
    r"\bi\s+recommend\b",
    r"\bgo\s+(and\s+)?\b",
]

DEFAULT_MODEL = "sentinet/suicidality" 

def encourage_score(text: str) -> float:
    t = text.lower()
    eup = any(re.search(p, t) for p in EUPHEMISMS)
    cue = any(re.search(p, t) for p in ENCOURAGE_CUES)

    if eup and cue:
        return 0.95
    if eup:
        return 0.75
    if cue and ("yourself" in t or "life" in t or "suicide" in t):
        return 0.70
    return 0.0


def pick_positive_score(scores: List[Dict[str, Any]], pos_label: Optional[str]) -> float:
    if not scores:
        return 0.0

    if pos_label:
        for e in scores:
            if str(e.get("label")) == pos_label:
                return float(e.get("score", 0.0))

    for e in scores:
        if str(e.get("label", "")).upper() == "LABEL_1":
            return float(e.get("score", 0.0))

    POS_KEYS = ("suicid", "self", "harm", "risk", "positive", "yes", "unsafe")
    NEG_KEYS = ("safe", "negative", "no", "neutral")
    for e in scores:
        lab = str(e.get("label", "")).lower()
        if any(k in lab for k in POS_KEYS) and not any(k in lab for k in NEG_KEYS):
            return float(e.get("score", 0.0))

    best = max(scores, key=lambda x: float(x.get("score", 0.0)))
    return float(best.get("score", 0.0))

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="infile", required=True)
    ap.add_argument("--model", default=DEFAULT_MODEL)
    ap.add_argument("--pos-label", default=None)
    ap.add_argument("--max-length", type=int, default=256)
    args = ap.parse_args()

    try:
        text = open(args.infile, "r", encoding="utf-8", errors="ignore").read().strip()
    except Exception as e:
        if args.debug:
            print(f"[py] failed to read file: {e}", file=sys.stderr)
        print("0.0")   
        return 0


    if not text:
        print("0.0")
        return 0

    os.environ.setdefault("HF_HUB_DISABLE_TELEMETRY", "1")
    os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")

    try:
        from transformers import pipeline  
    except Exception as e:
        print(f"[py] transformers import failed: {e}", file=sys.stderr)
        print("0.0")
        return 0

    try:
        clf = pipeline(
            "text-classification",
            model=args.model,
            tokenizer=args.model,
            top_k=None,
            truncation=True,
            max_length=args.max_length,
            device=-1,  # CPU
        )

        out = clf(text)

        if isinstance(out, list) and out and isinstance(out[0], list):
            scores = out[0]
        elif isinstance(out, list):
            scores = out
        else:
            scores = []

        topic_score = pick_positive_score(scores, args.pos_label)
        e_score = encourage_score(text)
        score = max(topic_score, e_score)
        print(f"{score:.6f}")
        return 0

    except Exception as e:
        print(f"[py] inference failed: {e}", file=sys.stderr)
        print("0.0")
        return 0

if __name__ == "__main__":
    raise SystemExit(main())

