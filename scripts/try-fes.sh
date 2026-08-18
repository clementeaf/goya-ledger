#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
# Goya LexChain FES end-to-end demo
#
# Deploys an NDA contract, creates two DIDs, signs as both
# parties with FES (Ed25519), and retrieves the fully signed
# contract — all against a running Goya node.
#
# Usage:
#   ./scripts/try-fes.sh                    # default: localhost:8080
#   ./scripts/try-fes.sh https://goya-node.fly.dev   # remote node
# ─────────────────────────────────────────────────────────────
set -euo pipefail

NODE="${1:-http://localhost:8080}"
API="$NODE/api/v1"

command -v curl >/dev/null || { echo "curl required"; exit 1; }
command -v python3 >/dev/null || { echo "python3 required"; exit 1; }

# Colors
G='\033[0;32m'; R='\033[0;31m'; B='\033[1m'; N='\033[0m'

ok()   { echo -e "${G}✓${N} $1"; }
fail() { echo -e "${R}✗${N} $1"; exit 1; }
step() { echo -e "\n${B}── $1${N}"; }

# ── Helper: generate Ed25519 keypair + sign payload ──────────
# Uses Python with no external deps (stdlib only)
keygen_and_sign() {
  local payload="$1"
  python3 - "$payload" <<'PYEOF'
import sys, hashlib, os, json

# Minimal Ed25519 — uses hazmat but stdlib-only approach not viable,
# so we shell out to openssl if available, or use a vendored pure-python.
# Simplest: generate key with openssl and sign.
import subprocess, tempfile

payload = sys.argv[1].encode()

# Generate Ed25519 keypair
with tempfile.NamedTemporaryFile(suffix='.pem', delete=False) as kf:
    kp = kf.name
subprocess.run(['openssl', 'genpkey', '-algorithm', 'Ed25519', '-out', kp],
               check=True, capture_output=True)

# Extract raw private key (32 bytes) and public key (32 bytes)
der = subprocess.run(['openssl', 'pkey', '-in', kp, '-outform', 'DER'],
                     capture_output=True, check=True).stdout
# Ed25519 DER private key: last 32 bytes of the nested OCTET STRING
sk_raw = der[-32:]

pub_der = subprocess.run(['openssl', 'pkey', '-in', kp, '-pubout', '-outform', 'DER'],
                         capture_output=True, check=True).stdout
# Ed25519 DER public key: last 32 bytes
pk_raw = pub_der[-32:]

# Sign with openssl
with tempfile.NamedTemporaryFile(delete=False) as df:
    df.write(payload)
    data_path = df.name

sig_raw = subprocess.run(
    ['openssl', 'pkeyutl', '-sign', '-inkey', kp, '-rawin', '-in', data_path],
    capture_output=True, check=True
).stdout

os.unlink(kp)
os.unlink(data_path)

print(json.dumps({
    "public_key": pk_raw.hex(),
    "signature": sig_raw.hex(),
}))
PYEOF
}

# ── 1. Health check ──────────────────────────────────────────
step "Health check"
curl -sf "$API/health" >/dev/null 2>&1 || fail "Node unreachable at $NODE"
ok "Node alive at $NODE"

# ── 2. Create two DIDs ───────────────────────────────────────
step "Creating identities"

# Generate keypairs for DID derivation
alice_kp=$(keygen_and_sign "init")
alice_pk=$(echo "$alice_kp" | python3 -c "import sys,json; print(json.load(sys.stdin)['public_key'])")
alice_did="did:goya:${alice_pk:0:16}"

bob_kp=$(keygen_and_sign "init")
bob_pk=$(echo "$bob_kp" | python3 -c "import sys,json; print(json.load(sys.stdin)['public_key'])")
bob_did="did:goya:${bob_pk:0:16}"

now=$(date +%s)

# Register DIDs via store endpoint
curl -sf -X POST "$API/store/identities" \
  -H "Content-Type: application/json" \
  -d "{\"did\":\"$alice_did\",\"public_key\":\"$alice_pk\",\"created_at\":$now,\"updated_at\":$now,\"status\":\"active\"}" >/dev/null \
  || fail "Failed to register Alice"
ok "Alice: $alice_did"

curl -sf -X POST "$API/store/identities" \
  -H "Content-Type: application/json" \
  -d "{\"did\":\"$bob_did\",\"public_key\":\"$bob_pk\",\"created_at\":$now,\"updated_at\":$now,\"status\":\"active\"}" >/dev/null \
  || fail "Failed to register Bob"
ok "Bob:   $bob_did"

# ── 3. Deploy NDA contract ──────────────────────────────────
step "Deploying NDA contract"

deploy_body=$(python3 -c "
import json
print(json.dumps({
    'type': 'non_disclosure_agreement',
    'parties': [
        {'role': 'discloser', 'did': '$alice_did', 'signature_level': 'simple'},
        {'role': 'recipient', 'did': '$bob_did', 'signature_level': 'simple'}
    ],
    'payload': {'scope': 'Project X confidential materials', 'effective_date': '2026-08-18'},
    'require_notarization': True,
    'deadline_secs': 86400
}))
")

deploy_resp=$(curl -sf -X POST "$API/lexchain/deploy" \
  -H "Content-Type: application/json" \
  -d "$deploy_body") || fail "Deploy failed"

contract_id=$(echo "$deploy_resp" | python3 -c "import sys,json; print(json.load(sys.stdin)['data']['id'])")
content_hash=$(echo "$deploy_resp" | python3 -c "import sys,json; print(json.load(sys.stdin)['data']['content_hash'])")
state=$(echo "$deploy_resp" | python3 -c "import sys,json; print(json.load(sys.stdin)['data']['state'])")

ok "Contract: $contract_id"
ok "Hash:     $content_hash"
ok "State:    $state"

[ "$state" = "pending_signatures" ] || fail "Expected pending_signatures, got $state"

# ── 4. Alice signs (FES) ────────────────────────────────────
step "Alice signs (FES / Ed25519)"

alice_payload="fes:${alice_did}:${content_hash}"
alice_sig_data=$(keygen_and_sign "$alice_payload")
alice_sign_pk=$(echo "$alice_sig_data" | python3 -c "import sys,json; print(json.load(sys.stdin)['public_key'])")
alice_sig=$(echo "$alice_sig_data" | python3 -c "import sys,json; print(json.load(sys.stdin)['signature'])")

sign_alice_body=$(python3 -c "
import json
print(json.dumps({
    'did': '$alice_did',
    'signature': '$alice_sig',
    'public_key': '$alice_sign_pk'
}))
")

sign_alice_resp=$(curl -sf -X POST "$API/lexchain/$contract_id/sign" \
  -H "Content-Type: application/json" \
  -d "$sign_alice_body") || fail "Alice sign failed"

state_after_alice=$(echo "$sign_alice_resp" | python3 -c "import sys,json; print(json.load(sys.stdin)['data']['state'])")
ok "Alice signed → state: $state_after_alice"

[ "$state_after_alice" = "pending_signatures" ] || fail "Expected pending_signatures after first sign"

# ── 5. Bob signs (FES) ──────────────────────────────────────
step "Bob signs (FES / Ed25519)"

bob_payload="fes:${bob_did}:${content_hash}"
bob_sig_data=$(keygen_and_sign "$bob_payload")
bob_sign_pk=$(echo "$bob_sig_data" | python3 -c "import sys,json; print(json.load(sys.stdin)['public_key'])")
bob_sig=$(echo "$bob_sig_data" | python3 -c "import sys,json; print(json.load(sys.stdin)['signature'])")

sign_bob_body=$(python3 -c "
import json
print(json.dumps({
    'did': '$bob_did',
    'signature': '$bob_sig',
    'public_key': '$bob_sign_pk'
}))
")

sign_bob_resp=$(curl -sf -X POST "$API/lexchain/$contract_id/sign" \
  -H "Content-Type: application/json" \
  -d "$sign_bob_body") || fail "Bob sign failed"

final_state=$(echo "$sign_bob_resp" | python3 -c "import sys,json; print(json.load(sys.stdin)['data']['state'])")
ok "Bob signed → state: $final_state"

# With require_notarization=true and TSA available, should be notarized
# If no TSA on node, will be fully_signed
case "$final_state" in
  notarized)   ok "Contract notarized with TSA timestamp" ;;
  fully_signed) ok "Contract fully signed (TSA not configured on node)" ;;
  *) fail "Unexpected final state: $final_state" ;;
esac

# ── 6. Retrieve final contract ──────────────────────────────
step "Retrieving signed contract"

get_resp=$(curl -sf "$API/lexchain/$contract_id") || fail "GET contract failed"

echo "$get_resp" | python3 -c "
import sys, json
c = json.load(sys.stdin)['data']
print(f'  Contract:  {c[\"id\"]}')
print(f'  Type:      {c[\"definition\"].get(\"type\", c[\"definition\"].get(\"contract_type\",\"?\"))}')
print(f'  State:     {c[\"state\"]}')
print(f'  Parties:   {len(c[\"parties\"])}')
for p in c['parties']:
    sig_algo = p.get('envelope',{}).get('signature_algorithm','—') if p.get('envelope') else '—'
    print(f'    {p[\"role\"]:12} {p[\"did\"]:30} signed={p[\"signed\"]}  algo={sig_algo}')
if c.get('tsa_token'):
    print(f'  TSA:       serial={c[\"tsa_token\"][\"tst_info\"][\"serial_number\"]}')
print(f'  Hash:      {c[\"content_hash\"][:16]}...')
"

# ── Done ─────────────────────────────────────────────────────
echo ""
echo -e "${G}${B}FES end-to-end complete.${N}"
echo -e "Contract $contract_id signed by both parties with Ed25519."
echo -e "15 lines of JSON → legally valid NDA with cryptographic proof."
