#!/usr/bin/env python3
import argparse
import os
import re
import sys
from typing import Any, Dict, List, Optional

DEFAULT_MODEL = "SalKhan12/prompt-safety-model"

INSTRUCTION_CUES = [
    r"\bhow\s+to\b",
    r"\bsteps?\b",
    r"\bstep\s*-\s*by\s*-\s*step\b",
    r"\btutorial\b",
    r"\bguide\b",
    r"\binstructions?\b",
    r"\brecipe\b",
    r"\bwalk\s*me\s*through\b",
    r"\bexplain\s+how\b",
    r"\bwhat\s+is\s+the\s+best\s+way\b",
]

DANGER_INTENT = [
    r"\bmake\b",
    r"\bbuild\b",
    r"\bcreate\b",
    r"\bmanufacture\b",
    r"\bconvert\b",
    r"\bweapon\b",
    r"\bexplosive\b",
    r"\bpoison\b",
    r"\bhack\b",
    r"\bsteal\b",
    r"\bkill\b",
]

def _safe_float(x: Any, default: float = 0.0) -> float:
    try:
        return float(x)
    except Exception:
        return default

def pick_positive_score(scores: List[Dict[str, Any]], pos_label: Optional[str]) -> float:
    if not scores:
        return 0.0

    if pos_label:
        for e in scores:
            if str(e.get("label")) == pos_label:
                return _safe_float(e.get("score"), 0.0)

    for e in scores:
        lab = str(e.get("label", "")).lower()
        if lab in ("unsafe", "harmful", "bad", "toxic", "violation"):
            return _safe_float(e.get("score"), 0.0)

    for e in scores:
        if str(e.get("label", "")).upper() == "LABEL_1":
            return _safe_float(e.get("score"), 0.0)

    best = max(scores, key=lambda x: _safe_float(x.get("score"), 0.0))
    return _safe_float(best.get("score"), 0.0)

def heuristic_instruction_score(text: str) -> float:
    t = text.lower()
    has_instr = any(re.search(p, t) for p in INSTRUCTION_CUES)
    has_intent = any(re.search(p, t) for p in DANGER_INTENT)

    if has_instr and has_intent:
        return 0.85
    if has_instr:
        return 0.25
    return 0.0

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="infile", required=True)
    ap.add_argument("--model", default=DEFAULT_MODEL)
    ap.add_argument("--pos-label", default=None)
    ap.add_argument("--max-length", type=int, default=256)
    ap.add_argument("--debug", action="store_true")
    ap.add_argument("--hybrid", action="store_true",
                    help="max(model_score, heuristic_instruction_score)")
    args = ap.parse_args()

    try:
        text = open(args.infile, "r", encoding="utf-8", errors="ignore").read().strip()
    except Exception as e:
        if args.debug:
            print(f"[py] read failed: {e}", file=sys.stderr)
        print("0.0")
        return 0

    if not text:
        print("0.0")
        return 0

    os.environ.setdefault("HF_HUB_DISABLE_TELEMETRY", "1")
    os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")

    try:
        from transformers import pipeline
        from transformers.utils import logging as hf_logging
        hf_logging.set_verbosity_error()
    except Exception as e:
        if args.debug:
            print(f"[py] transformers import failed: {e}", file=sys.stderr)
        if args.hybrid:
            score = heuristic_instruction_score(text)
            print(f"{score:.6f}")
            return 0
        print("0.0")
        return 0

    model_score = 0.0
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

        model_score = pick_positive_score(scores, args.pos_label)

    except Exception as e:
        if args.debug:
            print(f"[py] inference failed: {e}", file=sys.stderr)
        model_score = 0.0

    if args.hybrid:
        h = heuristic_instruction_score(text)
        score = max(model_score, h)
        return 0

    print(f"{model_score:.6f}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())

