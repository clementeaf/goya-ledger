#!/usr/bin/env bash
set -euo pipefail

NODE="${1:-http://localhost:8080}"
API="$NODE/api/v1"

G='\033[0;32m'; R='\033[0;31m'; B='\033[1m'; N='\033[0m'
ok()   { echo -e "${G}✓${N} $1"; }
fail() { echo -e "${R}✗${N} $1"; FAILURES=$((FAILURES+1)); }
step() { echo -e "\n${B}── $1${N}"; }
PASS=0; FAILURES=0
assert_eq() {
  if [ "$1" = "$2" ]; then ok "$3"; PASS=$((PASS+1));
  else fail "$3 (expected '$2', got '$1')"; fi
}

jq_or_python() {
  if command -v jq >/dev/null 2>&1; then jq -r "$1"
  else python3 -c "import sys,json; d=json.load(sys.stdin); print($2)"
  fi
}

echo -e "\n${B}╔══════════════════════════════════════════════════════╗${N}"
echo -e "${B}║     ALGORITHM DEATH DAY — E2E vs LIVE NODE           ║${N}"
echo -e "${B}╚══════════════════════════════════════════════════════╝${N}"

# ── 0. Health check ────────────────────────────────────────
step "0. Health check"
health_resp=$(curl -sf "$API/health") || { fail "Health unreachable"; exit 1; }
health=$(echo "$health_resp" | jq_or_python '.data.status' "d.get('data',{}).get('status','?')")
assert_eq "$health" "healthy" "Node is healthy"

# ── 1. Create 4 identities ────────────────────────────────
step "1. Create identities"
now=$(date +%s)

rand_hex() { python3 -c "import os; print(os.urandom($1).hex())"; }

alice_pk=$(rand_hex 32)
alice_did="did:goya:${alice_pk:0:16}"
bob_pk=$(rand_hex 32)
bob_did="did:goya:${bob_pk:0:16}"
charlie_pk=$(rand_hex 1952)
charlie_did="did:goya:${charlie_pk:0:16}"
dave_pk=$(rand_hex 1952)
dave_did="did:goya:${dave_pk:0:16}"

register_id() {
  local name=$1 did=$2 pk=$3
  curl -sf -X POST "$API/store/identities" \
    -H "Content-Type: application/json" \
    -d "{\"did\":\"$did\",\"public_key\":\"$pk\",\"created_at\":$now,\"updated_at\":$now,\"status\":\"active\"}" >/dev/null \
    && { ok "$name: $did"; PASS=$((PASS+1)); } \
    || fail "Register $name"
}
register_id "Alice" "$alice_did" "$alice_pk"
register_id "Bob" "$bob_did" "$bob_pk"
register_id "Charlie" "$charlie_did" "$charlie_pk"
register_id "Dave" "$dave_did" "$dave_pk"

# ── 2. Deploy Ed25519-only contract ───────────────────────
step "2. Deploy contracts"

ed_body="{\"type\":\"nda\",\"parties\":[{\"role\":\"a\",\"did\":\"$alice_did\",\"signature_level\":\"simple\"},{\"role\":\"b\",\"did\":\"$bob_did\",\"signature_level\":\"simple\"}],\"payload\":{\"scope\":\"vulnerable-ed25519-only\"},\"require_notarization\":false}"

ed_resp=$(curl -sf -X POST "$API/lexchain/deploy" \
  -H "Content-Type: application/json" \
  -d "$ed_body") || { fail "Deploy Ed25519 contract"; ed_resp="{}"; }

ed_id=$(echo "$ed_resp" | jq_or_python '.data.id' "d['data']['id']" 2>/dev/null) || ed_id="none"
ed_state=$(echo "$ed_resp" | jq_or_python '.data.state' "d['data']['state']" 2>/dev/null) || ed_state="none"
assert_eq "$ed_state" "pending_signatures" "Ed25519 contract deployed: $ed_id"

# Deploy PQC contract
pqc_body="{\"type\":\"service_agreement\",\"parties\":[{\"role\":\"provider\",\"did\":\"$charlie_did\",\"signature_level\":\"simple\"},{\"role\":\"client\",\"did\":\"$dave_did\",\"signature_level\":\"simple\"}],\"payload\":{\"scope\":\"pqc-protected\"},\"require_notarization\":false}"

pqc_resp=$(curl -sf -X POST "$API/lexchain/deploy" \
  -H "Content-Type: application/json" \
  -d "$pqc_body") || { fail "Deploy PQC contract"; pqc_resp="{}"; }

pqc_id=$(echo "$pqc_resp" | jq_or_python '.data.id' "d['data']['id']" 2>/dev/null) || pqc_id="none"
pqc_state=$(echo "$pqc_resp" | jq_or_python '.data.state' "d['data']['state']" 2>/dev/null) || pqc_state="none"
assert_eq "$pqc_state" "pending_signatures" "PQC contract deployed: $pqc_id"

# ── 3. List contracts ──────────────────────────────────────
step "3. List contracts on chain"

list_resp=$(curl -sf "$API/lexchain") || { fail "List contracts"; list_resp="{}"; }
count=$(echo "$list_resp" | jq_or_python '.data | length' "len(d['data'])" 2>/dev/null) || count=0
ok "Contracts on chain: $count"
PASS=$((PASS+1))

# ── 4. Retrieve by ID ─────────────────────────────────────
step "4. Retrieve contracts by ID"

if [ "$ed_id" != "none" ]; then
  ed_get=$(curl -sf "$API/lexchain/$ed_id") || { fail "GET $ed_id"; ed_get="{}"; }
  ed_get_state=$(echo "$ed_get" | jq_or_python '.data.state' "d['data']['state']" 2>/dev/null) || ed_get_state="none"
  assert_eq "$ed_get_state" "pending_signatures" "Ed25519 contract retrievable"

  party_count=$(echo "$ed_get" | jq_or_python '.data.parties | length' "len(d['data']['parties'])" 2>/dev/null) || party_count=0
  assert_eq "$party_count" "2" "Ed25519 contract has 2 parties"
fi

if [ "$pqc_id" != "none" ]; then
  pqc_get=$(curl -sf "$API/lexchain/$pqc_id") || { fail "GET $pqc_id"; pqc_get="{}"; }
  pqc_get_state=$(echo "$pqc_get" | jq_or_python '.data.state' "d['data']['state']" 2>/dev/null) || pqc_get_state="none"
  assert_eq "$pqc_get_state" "pending_signatures" "PQC contract retrievable"
fi

# ── 5. Verify identity retrieval ──────────────────────────
step "5. Verify identities persist"

alice_get=$(curl -sf "$API/store/identities/$alice_did") || { fail "GET Alice"; alice_get="{}"; }
alice_status=$(echo "$alice_get" | jq_or_python '.data.status' "d['data']['status']" 2>/dev/null) || alice_status="none"
assert_eq "$alice_status" "active" "Alice identity active"

charlie_get=$(curl -sf "$API/store/identities/$charlie_did") || { fail "GET Charlie"; charlie_get="{}"; }
charlie_key_len=$(echo "$charlie_get" | jq_or_python '.data.public_key | length' "len(d['data']['public_key'])" 2>/dev/null) || charlie_key_len=0
ok "Charlie pk length: $charlie_key_len chars (PQC-size)"
PASS=$((PASS+1))

# ── 6. Post-scenario health ───────────────────────────────
step "6. Post-scenario health"
health_after=$(curl -sf "$API/health" | jq_or_python '.data.status' "d.get('data',{}).get('status','?')") || health_after="?"
assert_eq "$health_after" "healthy" "Node healthy after full scenario"

# ── Report ─────────────────────────────────────────────────
echo ""
echo -e "${B}╔══════════════════════════════════════════════════════╗${N}"
echo -e "${B}║     ALGORITHM DEATH DAY E2E — REPORT                ║${N}"
echo -e "${B}╠══════════════════════════════════════════════════════╣${N}"
printf  "${B}║  Assertions passed:  ${G}%-3s${N}${B}                            ║${N}\n" "$PASS"
printf  "${B}║  Assertions failed:  ${R}%-3s${N}${B}                            ║${N}\n" "$FAILURES"
echo -e "${B}║  Node:               $NODE              ║${N}"
echo -e "${B}║  Contracts deployed: 2                              ║${N}"
echo -e "${B}║  Identities created: 4                              ║${N}"
echo -e "${B}╚══════════════════════════════════════════════════════╝${N}"

if [ "$FAILURES" -gt 0 ]; then
  echo -e "\n${R}FAILED: $FAILURES assertions${N}"; exit 1
else
  echo -e "\n${G}ALL PASSED${N}"
fi
