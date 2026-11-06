"""LLM lane tests with a fake Anthropic client: ledger, cache, budget cap, refusal handling. No network."""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from mcpeval.classify import llm as llm_mod
from mcpeval.classify.lexicon import classify_tool
from mcpeval.models import Category, ToolRecord


class FakeUsage:
    def __init__(self, i=1200, o=80, cr=0, cw=0):
        self.input_tokens, self.output_tokens, self.cache_read_input_tokens, self.cache_creation_input_tokens = i, o, cr, cw


class FakeMessages:
    def __init__(self, payloads):
        self.payloads, self.calls = list(payloads), 0

    def create(self, **kw):
        self.calls += 1
        p = self.payloads.pop(0)
        if p == "refusal":
            return SimpleNamespace(stop_reason="refusal", stop_details=SimpleNamespace(category="cyber"), content=[], usage=FakeUsage(), _request_id="req_r")
        return SimpleNamespace(stop_reason="end_turn", content=[SimpleNamespace(type="text", text=json.dumps(p))], usage=FakeUsage(), _request_id="req_1")


@pytest.fixture
def fake_client(monkeypatch):
    holder = {}

    class FakeAnthropic:
        def __init__(self, *a, **k):
            self.messages = holder["messages"]

    import anthropic
    monkeypatch.setattr(anthropic, "Anthropic", FakeAnthropic)
    return holder


def _tool(name="snow_update_ticket"):
    return classify_tool(ToolRecord(name=name, description="x", input_schema={"type": "object", "properties": {}}))


def test_ledger_cache_and_budget(tmp_path: Path, fake_client):
    verdict = {"category": "dml", "confidence": 0.9, "rationale": "updates", "side_effects": ["update"], "requires_hitl": True,
               "injection_suspected": False, "injection_rationale": ""}
    fake_client["messages"] = FakeMessages([verdict, verdict])
    ledger = llm_mod.CostLedger(path=tmp_path / "costs.jsonl", scan_id="t1")
    clf = llm_mod.LLMClassifier(model="claude-opus-5-5", max_usd=1.0, ledger=ledger, cache_dir=tmp_path / "cache")
    t = _tool()
    d1 = clf.classify(t)
    assert d1["category"] == "dml"
    # price: 1200 * 4.00 + 80 * 20.00 per 1M = 0.0048 + 0.0016
    assert abs(ledger.total_usd - 0.0064) < 1e-6
    assert (tmp_path / "costs.jsonl").read_text().count("\n") == 1
    d2 = clf.classify(_tool())  # same content hash -> cache hit, no API call
    assert d2 == d1 and fake_client["messages"].calls == 1
    assert ledger.summary()["cache_hits"] == 1 and ledger.summary()["usd"] == ledger.total_usd
    # budget cap
    clf.max_usd = 0.001
    assert clf.classify(_tool("jira_update_issue")) is None and clf.skipped_for_budget == 1


def test_refusal_fails_closed(tmp_path: Path, fake_client):
    fake_client["messages"] = FakeMessages(["refusal"])
    ledger = llm_mod.CostLedger(path=tmp_path / "c.jsonl")
    clf = llm_mod.LLMClassifier(model="claude-opus-5-5", max_usd=1.0, ledger=ledger, cache_dir=tmp_path / "cache")
    t = _tool("helper_tool_7")
    d = clf.classify(t)
    assert d["category"] == "ddl" and d["injection_suspected"] is True
    llm_mod.apply_llm_result(t, d)
    assert t.category is Category.DDL and t.meta["mcpeval/llm"]["injection_suspected"] is True


def test_apply_result_takes_riskier_category():
    t = _tool("snow_get_ticket")
    assert t.category is Category.READ
    llm_mod.apply_llm_result(t, {"category": "dml", "confidence": 0.8, "rationale": "writes audit rows", "side_effects": ["update"],
                                 "requires_hitl": True, "injection_suspected": False, "injection_rationale": ""})
    assert t.category is Category.DML and t.category_sources["llm"] == "dml"
