#!/usr/bin/env bash
# demo.sh — end-to-end demo of receiptchain.
#
# 1. Emits receipts for three fake cron-job runs.
# 2. Verifies the clean chain (must pass).
# 3. Tampers one receipt's payload by hand.
# 4. Verifies again (must flag exactly the tampered receipt).
#
# Everything happens in a throwaway temp dir; nothing is installed.
set -u
RC="./receiptchain.py"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

export RECEIPTCHAIN_KEY="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
export RECEIPTCHAIN_LOG="$WORK/receipts.jsonl"

echo "== 1. emitting receipts for fake jobs =="
"$RC" emit --job-id github-activity --started-at 2026-09-29T09:00:00-04:00 \
  --finished-at 2026-09-29T09:07:12-04:00 --status ok \
  --inputs "trending page snapshot" --outputs "starred 4, forked 1"
"$RC" emit --job-id wally-email-check --started-at 2026-09-29T10:00:00-04:00 \
  --finished-at 2026-09-29T10:00:41-04:00 --status ok \
  --inputs "inbox uidvalidity 1234" --outputs "0 actionable"
"$RC" emit --job-id participation-scout --started-at 2026-09-29T11:00:00-04:00 \
  --finished-at 2026-09-29T11:19:03-04:00 --status failed \
  --inputs "community index v7" --outputs "api timeout on colony" \
  --note "will retry next run"

echo
echo "== 2. verify clean chain (expect: intact, exit 0) =="
"$RC" verify
echo "verify exit code: $?"

echo
echo "== 3. tampering: flip receipt seq=2 status ok -> failed by hand =="
python3 - "$WORK/receipts.jsonl" <<'EOF'
import json, sys
path = sys.argv[1]
lines = open(path).read().splitlines()
r = json.loads(lines[1])
assert r["seq"] == 2 and r["status"] == "ok", "unexpected fixture layout"
r["status"] = "failed"          # the tamper: payload changed, hash+signature untouched
lines[1] = json.dumps(r, sort_keys=True)
open(path, "w").write("\n".join(lines) + "\n")
print("tampered receipt seq=2 in place")
EOF

echo
echo "== 4. verify tampered chain (expect: exactly one break, exit 1) =="
set +e
"$RC" verify > "$WORK/tampered.out" 2>&1
code=$?
set -e
cat "$WORK/tampered.out"
echo "verify exit code: $code"
nbreaks=$(grep -c '^  - ' "$WORK/tampered.out" || true)
if [ "$code" -eq 1 ] && [ "$nbreaks" -eq 1 ] && grep -q 'seq=2' "$WORK/tampered.out"; then
  echo "DEMO RESULT: PASS — exactly the tampered receipt (seq=2) was detected."
else
  echo "DEMO RESULT: FAIL — unexpected verification outcome."
  exit 1
fi
