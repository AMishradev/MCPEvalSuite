"""AWS discovery for shadow MCP (`mcpeval discover --aws`). Needs boto3 and read-only credentials.

What it looks at (all read-only API calls):
  * Bedrock AgentCore gateways + targets (control plane): the sanctioned MCP surface. Flags gateways
    with no inbound authorizer (matches Security Hub control BedrockAgentCore.2).
  * CloudTrail LookupEvents for CreateGateway / CreateGatewayTarget / CreateAgentRuntime in the last 90 days:
    who stood up agent infrastructure, from where.
  * ECS task definitions (ACTIVE): images, commands or env that mention mcp/fastmcp/modelcontextprotocol;
    also user/privileged for the non-root control.
  * Lambda functions: names, env var keys, layers mentioning mcp.
  * AWS Config advanced query (if Config is on): AgentCore resource types and ECS task definitions.

Package-level discovery (which images actually contain `mcp` / `fastmcp` / `@modelcontextprotocol/sdk`)
needs Amazon Inspector SBOM export or Security Hub software inventory; see docs/AWS.md for the Athena query.
"""
from __future__ import annotations

import datetime as dt
import json
import re
from typing import Any

MCP_HINT = re.compile(r"mcp|fastmcp|modelcontextprotocol|model-context-protocol", re.I)


def _client(session, name: str, region: str | None):
    return session.client(name, region_name=region) if region else session.client(name)


def _safe(fn, errors: list[str], label: str, default=None):
    try:
        return fn()
    except Exception as e:  # noqa: BLE001 - boto errors vary; report and continue
        errors.append(f"{label}: {type(e).__name__}: {str(e)[:160]}")
        return default


def discover_aws(*, region: str | None = None, profile: str | None = None) -> dict[str, Any]:
    out: dict[str, Any] = {"inventory": [], "issues": [], "errors": [], "skipped": []}
    try:
        import boto3
    except ImportError:
        out["errors"].append("boto3 not installed (pip install 'mcpeval[aws]')")
        return out
    session = boto3.Session(profile_name=profile) if profile else boto3.Session()
    region = region or session.region_name
    inv, issues, errors = out["inventory"], out["issues"], out["errors"]

    # --- AgentCore gateways -------------------------------------------------------------------
    ac = _safe(lambda: _client(session, "bedrock-agentcore-control", region), errors, "agentcore client")
    if ac:
        gws = _safe(lambda: ac.list_gateways().get("items", []), errors, "agentcore list_gateways", [])
        for g in gws or []:
            gid = g.get("gatewayId") or g.get("gatewayIdentifier") or g.get("name")
            detail = _safe(lambda: ac.get_gateway(gatewayIdentifier=gid), errors, f"agentcore get_gateway {gid}", {}) or {}
            auth = detail.get("authorizerType") or g.get("authorizerType")
            url = detail.get("gatewayUrl") or g.get("gatewayUrl", "")
            targets = _safe(lambda: ac.list_gateway_targets(gatewayIdentifier=gid).get("items", []), errors, f"agentcore list_gateway_targets {gid}", []) or []
            inv.append({"source": f"aws:agentcore:{region}", "name": g.get("name", gid), "launch": url, "kind": "agentcore-gateway",
                        "authorizer": auth, "targets": [t.get("name") for t in targets], "status": detail.get("status")})
            if auth in (None, "NONE"):
                issues.append({"severity": "high", "title": "AgentCore gateway without inbound authorizer", "subject": url or gid,
                               "message": f"Gateway {g.get('name')} has authorizerType={auth}; any caller can invoke its MCP tools. (Security Hub BedrockAgentCore.2)"})

    # --- CloudTrail: who created agent infrastructure ----------------------------------------
    ct = _safe(lambda: _client(session, "cloudtrail", region), errors, "cloudtrail client")
    if ct:
        start = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=90)
        for ev in ("CreateGateway", "CreateGatewayTarget", "CreateAgentRuntime", "CreateAgent"):
            res = _safe(lambda: ct.lookup_events(LookupAttributes=[{"AttributeKey": "EventName", "AttributeValue": ev}], StartTime=start, MaxResults=50),
                        errors, f"cloudtrail lookup {ev}", {}) or {}
            for e in res.get("Events", []):
                inv.append({"source": f"aws:cloudtrail:{region}", "name": f"{ev} by {e.get('Username')}", "kind": "cloudtrail-event",
                            "launch": f"{e.get('EventTime')} {e.get('EventSource')}", "event_id": e.get("EventId")})

    # --- ECS task definitions ------------------------------------------------------------------
    ecs = _safe(lambda: _client(session, "ecs", region), errors, "ecs client")
    if ecs:
        arns = []
        paginator = _safe(lambda: ecs.get_paginator("list_task_definitions"), errors, "ecs paginator")
        if paginator:
            for page in _safe(lambda: list(paginator.paginate(status="ACTIVE", PaginationConfig={"MaxItems": 500})), errors, "ecs list_task_definitions", []) or []:
                arns += page.get("taskDefinitionArns", [])
        # keep only the latest revision per family
        latest: dict[str, str] = {}
        for a in arns:
            fam, _, rev = a.rpartition(":")
            if fam not in latest or int(rev) > int(latest[fam].rpartition(":")[2]):
                latest[fam] = a
        for a in list(latest.values())[:200]:
            td = _safe(lambda: ecs.describe_task_definition(taskDefinition=a).get("taskDefinition", {}), errors, f"ecs describe {a}", {}) or {}
            for cd in td.get("containerDefinitions", []):
                blob = " ".join([cd.get("image", ""), " ".join(cd.get("command") or []), " ".join(cd.get("entryPoint") or []),
                                 " ".join(e.get("name", "") for e in cd.get("environment") or [])])
                if MCP_HINT.search(blob):
                    user = cd.get("user")
                    inv.append({"source": f"aws:ecs:{region}", "name": f"{td.get('family')}/{cd.get('name')}", "kind": "ecs-container",
                                "launch": cd.get("image", ""), "user": user, "privileged": cd.get("privileged"), "arn": a})
                    if not user or str(user).split(":")[0] in ("root", "0") or cd.get("privileged"):
                        issues.append({"severity": "high", "title": "MCP container runs as root / privileged", "subject": f"{td.get('family')}/{cd.get('name')}",
                                       "message": f"ECS container user={user!r} privileged={cd.get('privileged')} (Config rule ecs-task-definition-nonroot-user)."})
                    if any(re.search(r"KEY|TOKEN|SECRET|PASSWORD", e.get("name", ""), re.I) and e.get("value") for e in cd.get("environment") or []):
                        issues.append({"severity": "high", "title": "MCP container has literal secret in environment", "subject": f"{td.get('family')}/{cd.get('name')}",
                                       "message": "Use secrets (valueFrom Secrets Manager / SSM) instead of plaintext environment values."})

        # environment isolation: prod and non-prod MCP tasks in one cluster (BP-ENV-ISOLATION)
        env_re = {"prod": re.compile(r"\b(prod|production|prd)\b", re.I), "nonprod": re.compile(r"\b(dev|test|qa|stage|staging|sandbox|uat|nonprod|non-prod)\b", re.I)}
        clusters = _safe(lambda: ecs.list_clusters().get("clusterArns", []), errors, "ecs list_clusters", []) or []
        mcp_families = {i["arn"].rpartition("/")[2].rpartition(":")[0] for i in inv if i.get("kind") == "ecs-container"}
        for cl in clusters[:50]:
            svcs = _safe(lambda: ecs.list_services(cluster=cl, maxResults=100).get("serviceArns", []), errors, f"ecs list_services {cl}", []) or []
            if not svcs:
                continue
            desc = _safe(lambda: ecs.describe_services(cluster=cl, services=svcs[:10]).get("services", []), errors, f"ecs describe_services {cl}", []) or []
            envs: dict[str, list[str]] = {"prod": [], "nonprod": []}
            for sv in desc:
                fam = (sv.get("taskDefinition") or "").rpartition("/")[2].rpartition(":")[0]
                if fam not in mcp_families:
                    continue
                label = " ".join([sv.get("serviceName", ""), fam, " ".join(f"{t.get('key')}={t.get('value')}" for t in sv.get("tags") or [])])
                for k, rx in env_re.items():
                    if rx.search(label):
                        envs[k].append(sv.get("serviceName", fam))
            if envs["prod"] and envs["nonprod"]:
                issues.append({"severity": "medium", "title": "Prod and non-prod MCP services share one ECS cluster", "subject": cl.rpartition("/")[2],
                               "message": f"prod={envs['prod']} nonprod={envs['nonprod']} run in the same cluster/network (BP-ENV-ISOLATION).", "control": "BP-ENV-ISOLATION"})
        # role separation: task roles of MCP containers that humans can also assume (BP-ROLE-SEPARATION)
        iam = _safe(lambda: _client(session, "iam", None), errors, "iam client")
        if iam:
            seen_roles: set[str] = set()
            for i in [x for x in inv if x.get("kind") == "ecs-container"]:
                td = _safe(lambda: ecs.describe_task_definition(taskDefinition=i["arn"]).get("taskDefinition", {}), errors, f"ecs describe {i['arn']}", {}) or {}
                role_arn = td.get("taskRoleArn")
                if not role_arn or role_arn in seen_roles:
                    continue
                seen_roles.add(role_arn)
                role = _safe(lambda: iam.get_role(RoleName=role_arn.rpartition("/")[2]).get("Role", {}), errors, f"iam get_role {role_arn}", {}) or {}
                trust = json.dumps(role.get("AssumeRolePolicyDocument") or {})
                human = re.search(r"saml-provider|:root\"|AWSReservedSSO|sso\.amazonaws\.com|:user/", trust)
                if human:
                    issues.append({"severity": "medium", "title": "MCP task role is also assumable by humans", "subject": role_arn,
                                   "message": f"Trust policy of {role_arn} allows a human/SSO principal; agent and human lanes should use separate roles (BP-ROLE-SEPARATION).",
                                   "control": "BP-ROLE-SEPARATION"})

    # --- Lambda ---------------------------------------------------------------------------------
    lam = _safe(lambda: _client(session, "lambda", region), errors, "lambda client")
    if lam:
        pag = _safe(lambda: lam.get_paginator("list_functions"), errors, "lambda paginator")
        if pag:
            for page in _safe(lambda: list(pag.paginate(PaginationConfig={"MaxItems": 1000})), errors, "lambda list_functions", []) or []:
                for f in page.get("Functions", []):
                    env_keys = " ".join((f.get("Environment") or {}).get("Variables", {}).keys())
                    layers = " ".join(l.get("Arn", "") for l in f.get("Layers") or [])
                    if MCP_HINT.search(" ".join([f.get("FunctionName", ""), f.get("Description", ""), env_keys, layers])):
                        inv.append({"source": f"aws:lambda:{region}", "name": f.get("FunctionName"), "kind": "lambda", "launch": f.get("Runtime", ""), "arn": f.get("FunctionArn")})

    # --- AWS Config advanced query --------------------------------------------------------------
    cfg = _safe(lambda: _client(session, "config", region), errors, "config client")
    if cfg:
        q = "SELECT resourceId, resourceType, resourceName, awsRegion, tags WHERE resourceType LIKE 'AWS::BedrockAgentCore::%'"
        res = _safe(lambda: cfg.select_resource_config(Expression=q, Limit=100), errors, "config select_resource_config", {}) or {}
        for row in res.get("Results", []):
            inv.append({"source": f"aws:config:{region}", "name": row[:120], "kind": "config-ci", "launch": ""})

    out["region"] = region
    return out
