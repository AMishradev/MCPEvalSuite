#!/usr/bin/env bash
# Import mcpeval ASFF findings into Security Hub CSPM (custom product). ≤100 findings per call.
set -euo pipefail
FILE="${1:?asff json file}"
COUNT=$(python3 -c "import json,sys; print(len(json.load(open(sys.argv[1]))['Findings']))" "$FILE")
if [ "$COUNT" = "0" ]; then echo "no findings to import"; exit 0; fi
python3 - "$FILE" <<'PY'
import json, subprocess, sys
findings = json.load(open(sys.argv[1]))["Findings"]
for i in range(0, len(findings), 100):
    batch = json.dumps(findings[i:i+100])
    subprocess.run(["aws", "securityhub", "batch-import-findings", "--findings", batch], check=True)
    print(f"imported {min(i+100, len(findings))}/{len(findings)}")
PY
