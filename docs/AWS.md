# Running MCPEvalSuite in an AWS shop

Everything here was verified against AWS documentation on 2026-11-06 (see `docs/RESEARCH.md` for sources).
It covers three things: where MCP servers should live, how to wire the scanner into CI and Security Hub,
and how to find MCP servers nobody told you about.

## 1. Where MCP servers should run

| Pattern | Use it for | Why |
|---|---|---|
| **Bedrock AgentCore Gateway** in front of Lambda / OpenAPI / remote MCP targets | Any server agents call in production | Only AWS-native layer that can authorize and log **per tool call** (Policy, Cedar, GA 2026-03-03). Inbound auth is `AWS_IAM` or `CUSTOM_JWT`; 401 responses carry RFC 9728 `resource_metadata`. CloudTrail data event `InvokeGateway` records the tool name per call. |
| **AgentCore Runtime** (MCP protocol mode) | Hosting your own MCP server code | MicroVM per session, JWT or SigV4 inbound, VPC mode, PrivateLink. Containers must run non-root; MMDSv2 is required. |
| ECS Fargate / EKS behind ALB with `jwt-validation` | Legacy or non-agent callers | ALB validates bearer tokens but cannot see the JSON-RPC body, so there is no per-tool control; put a gateway in front for agents. |
| Local stdio servers on developer laptops | IDE assistants | Governed client-side only (Kiro registry URL / managed-settings.json, Claude Code managed settings). Inventory them with `mcpeval discover`. |

AgentCore Gateway names tools `<target>___<tool>` (three underscores). The scanner strips that prefix before applying the naming rule, so `SnowTarget___snow_get_ticket` passes.

Org-wide guardrails worth setting once:

- SCP: deny `bedrock-agentcore:CreateGateway` / `UpdateGateway` unless `bedrock-agentcore:GatewayAuthorizerType` is `AWS_IAM` or `CUSTOM_JWT` (blocks `NONE`), and unless `bedrock-agentcore:DiscoveryUrl` is your IdP.
- Restrict `bedrock-agentcore:UpdateGateway` so nobody flips Policy to `LOG_ONLY`.
- Security Hub control `BedrockAgentCore.2` (gateway requires inbound authorization) and Config rules `ecs-task-definition-nonroot-user`, `ecs-containers-nonprivileged`, `ecs-no-environment-secrets`.
- CodeArtifact package-group origin controls for `/npm/@modelcontextprotocol/~` and `/pypi//mcp$`, `/pypi//fastmcp$` so `uvx` / `npx` can only pull vetted versions.
- ECR managed signing (`put-signing-configuration`) for MCP images; awslabs ECR Public images are not signed, so rebuild and sign them yourself.

## 2. CI wiring

`ci/github/mcpeval.yml` runs the static lane on the repo, then a live scan of the server over stdio, and uploads SARIF to GitHub code scanning.
`ci/aws/buildspec.yml` does the same in CodeBuild and pushes ASFF findings to Security Hub CSPM with `ci/aws/securityhub_import.sh`.

Security Hub notes:

- Custom findings go through CSPM `BatchImportFindings` (ASFF). The new OCSF Security Hub has no `BatchImportFindingsV2`; CSPM findings are forwarded into it (verify with one finding before relying on it).
- `ProductArn` is `arn:aws:securityhub:<region>:<account>:product/<account>/default`. Set `AWS_ACCOUNT_ID` and `AWS_REGION` in the build.
- Findings carry `Compliance.RelatedRequirements` = `MCP-BP/<control>` so automation rules can route by control (for example page the platform team on `BP-HITL-DDL`).

Gate behaviour: `mcpeval scan` exits 1 when a finding is at or above `gate.fail_on` (default `high`) or when any `gate.fail_on_controls` control is violated. Tune in `.mcpeval/policy.yaml`.

## 3. Finding shadow MCP servers

No AWS service detects MCP servers today. Security Hub AI inventory (GA 2026-07-14) finds models, inference servers and external AI endpoints but explicitly not MCP servers; Agent Registry auto-detection (GA Aug 2026) catalogs AgentCore Runtimes and Gateways only. So the inventory is assembled from several sources:

| Source | What it finds | How |
|---|---|---|
| `mcpeval discover --aws` | AgentCore gateways (and whether they have an authorizer), ECS task definitions and Lambda functions that mention mcp, `CreateGateway*` CloudTrail events, AgentCore Config items | boto3, read-only |
| Inspector SBOM export + Athena | Images and instances that contain `mcp`, `fastmcp`, `@modelcontextprotocol/sdk`, `awslabs.*-mcp-server` | `aws inspector2 create-sbom-export --report-format CYCLONEDX_1_4 ...` then query `components[].purl` for `pkg:pypi/mcp@`, `pkg:pypi/fastmcp@`, `pkg:npm/%40modelcontextprotocol/` |
| Security Hub `GetSoftwareResourcesV2` | Same question without Athena | filter on package name |
| Agent Registry org auto-detection | Every AgentCore Runtime / Gateway in every member account, with provenance | enable Organizations trusted access; EventBridge `aws.agent-registry` state changes can trigger a scan |
| CloudTrail Lake | Who created agent infrastructure; which tools are called through gateways | queries in `docs/RESEARCH.md` |
| Route 53 Resolver query logs + DNS Firewall | Workloads talking to hosted MCP SaaS endpoints | ALERT rule on the hostname list in `mcpeval/discover/mcp_hosts.yaml`, then BLOCK |
| VPC Flow Logs (ECS v7 fields) | Unexpected listeners on 8000/3000 between tasks | `ecs-task-definition-arn`, `ecs-container-id` fields |
| SSM Inventory / Run Command | Config files on EC2 and managed workstations | `AWS:File` inventory with patterns `mcp.json`, `.mcp.json`, `claude_desktop_config.json`, or run `mcpeval discover` via Run Command and ship the JSON |

Mark sanctioned servers in `policy.allowlist.servers`; anything else shows up as `SHADOW-001`.

## 4. awslabs/mcp servers

The awslabs repo is now a legacy tier (the Agent Toolkit for AWS is the successor) and several servers are deprecated. Read-only flags are per server and inconsistent (`--readonly`, `--allow-write`, `ACCESS_MODE`, `--allow_write_query`, and so on), and AWS calls the database ones best-effort rather than a security boundary. Treat IAM as the real control: run each server under a role that only has the actions its category needs, and use the scan's category table to decide which servers an autonomous agent may have at all.

PyPI packages from awslabs carry PEP 740 / Sigstore provenance; verify it before approving a version. ECR Public images do not carry signatures.

## 5. Managed AWS MCP Server

Governed with IAM condition keys `aws:ViaAWSMCPService`, `aws:CalledViaAWSMCP`, `aws:IsMcpServiceAction`; logs to CloudTrail (`eventSource aws-mcp.amazonaws.com`). It has no VPC endpoint and no FIPS endpoint as of this writing, and its `--read-only` is a client-side filter. The managed EKS and ECS MCP servers do have server-side read-only IAM actions.
