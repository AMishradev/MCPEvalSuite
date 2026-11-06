"""Turn Inspect AI eval logs into cost rows in the mcpeval ledger (same price table, same JSONL file).

  python evals/inspect_cost.py out/inspect            # all logs in a directory
  python evals/inspect_cost.py out/inspect/<log>.eval # one log
Writes to $MCPEVAL_HOME/llm_costs.jsonl (default .mcpeval/llm_costs.jsonl) and prints a summary.
"""
from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

from inspect_ai.log import read_eval_log

PRICES = {  # USD per 1M tokens: input, output, cache_read, cache_write (override via MCPEVAL_PRICES_JSON)
    "claude-opus-5-5": (4.00, 20.00, 0.20, 5.00),
    "claude-sonnet-5-5": (2.00, 10.00, 0.20, 2.50),
    "claude-haiku-5-5": (0.10, 0.50, 0.01, 0.125),
}
PRICES.update({k: tuple(v) for k, v in json.loads(os.environ.get("MCPEVAL_PRICES_JSON", "{}")).items()})


def usd(model: str, u) -> float:
    key = model.split("/")[-1]
    if model.startswith("mockllm/"):
        return 0.0
    p = PRICES.get(key)
    if p is None:
        print(f"warning: no price for {model}; using a conservative fallback (set MCPEVAL_PRICES_JSON)", file=sys.stderr)
        p = (10.0, 50.0, 1.0, 12.5)
    return (u.input_tokens * p[0] + u.output_tokens * p[1] + (u.input_tokens_cache_read or 0) * p[2] + (u.input_tokens_cache_write or 0) * p[3]) / 1_000_000


def main(paths: list[str]) -> None:
    ledger = Path(os.environ.get("MCPEVAL_HOME", ".mcpeval")) / "llm_costs.jsonl"
    ledger.parent.mkdir(parents=True, exist_ok=True)
    logs = []
    for p in paths:
        pp = Path(p)
        logs += sorted(pp.glob("*.eval")) + sorted(pp.glob("*.json")) if pp.is_dir() else [pp]
    total = 0.0
    with ledger.open("a") as fh:
        for lp in logs:
            log = read_eval_log(str(lp), header_only=True)
            for model, u in (log.stats.model_usage or {}).items():
                cost = usd(model, u)
                total += cost
                row = {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "scan_id": f"inspect:{lp.stem[:24]}", "model": model.split("/")[-1],
                       "purpose": "inspect-eval", "subject": log.eval.task, "cached": False, "request_id": None,
                       "input_tokens": u.input_tokens, "output_tokens": u.output_tokens,
                       "cache_read_input_tokens": u.input_tokens_cache_read or 0, "cache_creation_input_tokens": u.input_tokens_cache_write or 0, "usd": round(cost, 6)}
                fh.write(json.dumps(row) + "\n")
                print(f"{lp.name}: {model} in={u.input_tokens} out={u.output_tokens} ${cost:.4f}")
    print(f"total ${total:.4f} appended to {ledger}")


if __name__ == "__main__":
    main(sys.argv[1:] or ["out/inspect"])
