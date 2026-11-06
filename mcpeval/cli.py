"""mcpeval command line.

  mcpeval scan TARGET            probe a server, run checks, write reports, exit non-zero if the gate fails
  mcpeval baseline approve TARGET  store the current manifest as the approved baseline (rug-pull diff)
  mcpeval static PATH            static checks on a server's source tree / Dockerfile / configs
  mcpeval discover               find MCP servers on this machine, in a repo, or in AWS (shadow MCP)
  mcpeval costs                  summarize LLM spend from the ledger
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from .models import Lane, ScanResult, Severity

app = typer.Typer(add_completion=False, no_args_is_help=True, help=__doc__)
baseline_app = typer.Typer(help="Approved-manifest baselines")
app.add_typer(baseline_app, name="baseline")
con = Console(stderr=True)


def _home() -> Path:
    return Path(os.environ.get("MCPEVAL_HOME", ".mcpeval"))


def _write_reports(result: ScanResult, out: Path, formats: list[str]) -> list[Path]:
    from .report.writers import to_asff, to_json, to_markdown, to_sarif

    out.mkdir(parents=True, exist_ok=True)
    stem = "mcpeval"
    written = []
    for f in formats:
        if f == "json":
            p = out / f"{stem}.json"; p.write_text(to_json(result))
        elif f == "sarif":
            p = out / f"{stem}.sarif"; p.write_text(to_sarif(result))
        elif f == "md":
            p = out / f"{stem}.md"; p.write_text(to_markdown(result))
        elif f == "asff":
            p = out / f"{stem}.asff.json"
            p.write_text(to_asff(result, aws_account_id=os.environ.get("AWS_ACCOUNT_ID", "000000000000"), region=os.environ.get("AWS_REGION", "us-east-1")))
        else:
            raise typer.BadParameter(f"unknown format {f}")
        written.append(p)
    return written


def _print_summary(result: ScanResult) -> None:
    s = result.summary()
    t = Table(title=f"mcpeval: {result.target}", show_lines=False)
    for col in ("critical", "high", "medium", "low", "info"):
        t.add_column(col, justify="right")
    t.add_row(*[str(s[c]) for c in ("critical", "high", "medium", "low", "info")])
    con.print(t)
    for f in sorted(result.findings, key=lambda f: -f.severity.rank):
        if f.severity in (Severity.CRITICAL, Severity.HIGH):
            con.print(f"[red]{f.severity.value.upper():8}[/red] {f.check_id:10} {f.subject[:28]:28} {f.message[:120]}")
    g = result.gate
    con.print(("[green]GATE PASS[/green] " if g.get("passed") else "[red]GATE FAIL[/red] ") + g.get("reason", ""))
    llm = result.metadata.get("llm")
    if llm:
        con.print(f"LLM lane: {llm['llm_calls']} calls, {llm['cache_hits']} cache hits, {llm['input_tokens']} in / {llm['output_tokens']} out tokens, ${llm['usd']:.4f}")


@app.command()
def scan(
    target: str = typer.Argument(..., help='URL, "stdio:cmd args", config:/path.json#name, or inline JSON'),
    policy: str | None = typer.Option(None, "--policy", "-p", help="policy YAML (default: .mcpeval/policy.yaml or built-in)"),
    out: Path = typer.Option(Path("out"), "--out", "-o", help="report directory"),
    formats: str = typer.Option("json,sarif,md", "--format", "-f", help="comma list: json,sarif,md,asff"),
    llm: str = typer.Option("auto", "--llm", help="auto (escalate low-confidence tools), all, off"),
    llm_model: str | None = typer.Option(None, "--llm-model", help="override policy.classifier.llm_model"),
    budget_usd: float | None = typer.Option(None, "--budget-usd", help="hard cap on LLM spend for this scan"),
    behavior: bool = typer.Option(False, "--behavior", help="opt-in: invoke tools (sandbox / non-prod only)"),
    timeout: float = typer.Option(30.0, "--timeout"),
    no_gate: bool = typer.Option(False, "--no-gate", help="always exit 0"),
) -> None:
    """Probe an MCP server and evaluate it against the policy."""
    from .checks import load_all_checks
    from .checks.base import CheckContext, all_checks, run_checks
    from .classify.lexicon import classify_tool
    from .policy.loader import BaselineStore, evaluate_gate, load_policy
    from .probe.connect import capture_manifest, parse_target

    load_all_checks()
    pol = load_policy(policy)
    spec = parse_target(target)
    con.print(f"[bold]probe[/bold] {spec} ({spec.kind})")
    manifest = asyncio.run(capture_manifest(spec, timeout=timeout))
    if manifest.errors:
        con.print(f"[yellow]probe errors:[/yellow] {manifest.errors}")
    if spec.kind in ("http", "sse"):
        from .probe.auth import probe_http_auth
        manifest.http.update(asyncio.run(probe_http_auth(spec.url, headers=spec.headers, timeout=timeout)))
    for t in manifest.tools:
        classify_tool(t)

    result = ScanResult(target=manifest.target, manifest=manifest)
    result.metadata["policy_file"] = pol.get("_policy_file")
    result.metadata["scan_id"] = uuid.uuid4().hex[:12]

    # LLM lane
    cls_pol = pol.get("classifier", {})
    mode = llm if llm != "auto" else ("escalate" if cls_pol.get("llm_enabled", True) else "off")
    if mode != "off" and manifest.tools:
        if not (os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("ANTHROPIC_AUTH_TOKEN")):
            con.print("[yellow]LLM lane skipped: no ANTHROPIC_API_KEY / ANTHROPIC_AUTH_TOKEN (and no `ant auth login` profile detected via env)[/yellow]")
            result.metadata["llm"] = {"skipped": "no credentials"}
        else:
            from .classify.llm import CostLedger, LLMClassifier, apply_llm_result

            ledger = CostLedger(path=_home() / "llm_costs.jsonl", scan_id=result.metadata["scan_id"])
            ledger.prices.update({k: tuple(v) for k, v in (cls_pol.get("prices") or {}).items()})
            clf = LLMClassifier(model=llm_model or cls_pol.get("llm_model", "claude-opus-5-5"),
                                max_usd=budget_usd if budget_usd is not None else float(cls_pol.get("max_usd_per_scan", 1.0)),
                                ledger=ledger, cache_dir=_home() / "llm_cache")
            floor = float(cls_pol.get("escalate_below_confidence", 0.6))
            targets = [t for t in manifest.tools if mode == "all" or t.category_confidence < floor]
            con.print(f"[bold]llm[/bold] {clf.model}: {len(targets)} tool(s), cap ${clf.max_usd:.2f}")
            for t in targets:
                data = clf.classify(t)
                if data:
                    apply_llm_result(t, data)
            summary = ledger.summary()
            summary["skipped_for_budget"] = clf.skipped_for_budget
            summary["errors"] = clf.errors
            result.metadata["llm"] = summary

    if behavior:
        from .probe.behavior import run_behavior_probes
        result.metadata["behavior"] = asyncio.run(run_behavior_probes(spec, manifest, timeout=timeout))

    store = BaselineStore(str(_home()))
    ctx = CheckContext(manifest=manifest, policy=pol, baseline=store.load(manifest.target),
                       options={"elicited_tools": (result.metadata.get("behavior") or {}).get("elicited_tools", [])})
    lanes = {Lane.MANIFEST, Lane.AUTH, Lane.BEHAVIOR}
    findings, ran = run_checks(ctx, all_checks(lanes), on_error=lambda cid, tb: con.print(f"[red]{cid} crashed[/red]\n{tb}"))
    result.findings = findings
    result.checks_run = ran
    result.finished_at = datetime.now(timezone.utc)
    result.gate = evaluate_gate(result, pol)

    written = _write_reports(result, out, [f.strip() for f in formats.split(",") if f.strip()])
    _print_summary(result)
    con.print("reports: " + ", ".join(str(p) for p in written))
    if not no_gate and not result.gate["passed"]:
        raise typer.Exit(code=1)


@baseline_app.command("approve")
def baseline_approve(target: str, approved_by: str = typer.Option("", "--by"), timeout: float = 30.0) -> None:
    """Capture the server's current manifest and store it as the approved baseline."""
    from .policy.loader import BaselineStore
    from .probe.connect import capture_manifest, parse_target

    spec = parse_target(target)
    m = asyncio.run(capture_manifest(spec, timeout=timeout))
    if m.errors and not m.tools:
        con.print(f"[red]could not capture manifest:[/red] {m.errors}")
        raise typer.Exit(2)
    p = BaselineStore(str(_home())).save(m, approved_by=approved_by)
    con.print(f"baseline saved: {p} ({len(m.tools)} tools, hash {m.manifest_hash[:16]})")


@baseline_app.command("show")
def baseline_show(target: str) -> None:
    from .policy.loader import BaselineStore
    from .probe.connect import parse_target

    m = BaselineStore(str(_home())).load(str(parse_target(target)))
    if not m:
        con.print("no baseline"); raise typer.Exit(1)
    print(json.dumps({"captured_at": str(m.captured_at), "hash": m.manifest_hash, "tools": [t.name for t in m.tools]}, indent=2))


@app.command()
def static(
    path: Path = typer.Argument(Path("."), help="source tree of an MCP server (or a client config file)"),
    policy: str | None = typer.Option(None, "--policy", "-p"),
    out: Path = typer.Option(Path("out"), "--out", "-o"),
    formats: str = typer.Option("json,sarif,md", "--format", "-f"),
    semgrep: bool = typer.Option(True, "--semgrep/--no-semgrep", help="run bundled Semgrep rules if semgrep is installed"),
    no_gate: bool = typer.Option(False, "--no-gate"),
) -> None:
    """Static checks: Dockerfile root user, secrets in configs, SDK auth defaults, pinned deps, signatures."""
    from .checks import load_all_checks
    from .checks.base import CheckContext, all_checks, run_checks
    from .policy.loader import evaluate_gate, load_policy

    load_all_checks()
    pol = load_policy(policy, search_from=str(path))
    ctx = CheckContext(manifest=None, policy=pol, source_dir=str(path), options={"semgrep": semgrep})
    result = ScanResult(target=str(path))
    result.findings, result.checks_run = run_checks(ctx, all_checks({Lane.STATIC, Lane.SUPPLY_CHAIN}), on_error=lambda cid, tb: con.print(f"[red]{cid} crashed[/red]\n{tb}"))
    result.finished_at = datetime.now(timezone.utc)
    result.gate = evaluate_gate(result, pol)
    written = _write_reports(result, out, [f.strip() for f in formats.split(",") if f.strip()])
    _print_summary(result)
    con.print("reports: " + ", ".join(str(p) for p in written))
    if not no_gate and not result.gate["passed"]:
        raise typer.Exit(code=1)


@app.command()
def discover(
    endpoint: bool = typer.Option(True, "--endpoint/--no-endpoint", help="scan this machine's MCP client configs"),
    repo: Path | None = typer.Option(None, "--repo", help="scan a source tree for MCP servers/clients"),
    aws: bool = typer.Option(False, "--aws", help="query AWS (Inspector SBOM, ECS, Lambda, CloudTrail) with boto3"),
    policy: str | None = typer.Option(None, "--policy", "-p"),
    out: Path = typer.Option(Path("out"), "--out", "-o"),
    formats: str = typer.Option("json,md", "--format", "-f"),
) -> None:
    """Inventory MCP servers in use and compare against the policy allowlist (shadow MCP)."""
    from .discover.inventory import run_discovery
    from .policy.loader import load_policy

    pol = load_policy(policy)
    result = run_discovery(pol, endpoint=endpoint, repo=repo, aws=aws)
    written = _write_reports(result, out, [f.strip() for f in formats.split(",") if f.strip()])
    _print_summary(result)
    inv = result.metadata.get("inventory") or []
    t = Table(title=f"{len(inv)} MCP server definitions found")
    t.add_column("source"); t.add_column("name"); t.add_column("launch"); t.add_column("sanctioned")
    for i in inv[:60]:
        t.add_row(i["source"][-48:], i["name"][:28], i["launch"][:60], "yes" if i["sanctioned"] else "[red]NO[/red]")
    con.print(t)
    con.print("reports: " + ", ".join(str(p) for p in written))


@app.command()
def costs(ledger: Path | None = typer.Option(None, "--ledger")) -> None:
    """Summarize LLM spend recorded by the classifier."""
    p = ledger or (_home() / "llm_costs.jsonl")
    if not p.exists():
        con.print(f"no ledger at {p}"); raise typer.Exit(1)
    rows = [json.loads(line) for line in p.read_text().splitlines() if line.strip()]
    by_scan: dict[str, dict] = {}
    for r in rows:
        d = by_scan.setdefault(r.get("scan_id") or "-", {"calls": 0, "cached": 0, "in": 0, "out": 0, "usd": 0.0, "model": r["model"], "first": r["ts"]})
        d["cached" if r["cached"] else "calls"] += 1
        d["in"] += r["input_tokens"]; d["out"] += r["output_tokens"]; d["usd"] += r["usd"]
    t = Table(title=f"LLM costs ({p})")
    for c in ("scan", "first call", "model", "calls", "cache hits", "input tok", "output tok", "USD"):
        t.add_column(c, justify="right" if c not in ("scan", "first call", "model") else "left")
    for sid, d in by_scan.items():
        t.add_row(sid, d["first"], d["model"], str(d["calls"]), str(d["cached"]), str(d["in"]), str(d["out"]), f"{d['usd']:.4f}")
    t.add_row("TOTAL", "", "", str(sum(d["calls"] for d in by_scan.values())), str(sum(d["cached"] for d in by_scan.values())),
              str(sum(d["in"] for d in by_scan.values())), str(sum(d["out"] for d in by_scan.values())), f"{sum(d['usd'] for d in by_scan.values()):.4f}")
    con.print(t)


if __name__ == "__main__":
    app()
