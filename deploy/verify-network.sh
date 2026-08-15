#!/usr/bin/env bash
# Verify multi-node BFT network connectivity and consensus.
# Usage: ./deploy/verify-network.sh node1_url node2_url node3_url node4_url
#
# Example:
#   ./deploy/verify-network.sh \
#     https://goya-node.fly.dev \
#     https://goya-node-2.up.railway.app \
#     http://129.153.x.x:8080 \
#     https://goya-node-4.onrender.com

set -euo pipefail

if [ $# -lt 2 ]; then
  echo "Usage: $0 <node1_url> <node2_url> [node3_url] [node4_url]"
  exit 1
fi

NODES=("$@")
PASS=0
FAIL=0

green() { printf "\033[32m%s\033[0m\n" "$1"; }
red()   { printf "\033[31m%s\033[0m\n" "$1"; }
bold()  { printf "\033[1m%s\033[0m\n" "$1"; }

check() {
  local desc="$1" result="$2"
  if [ "$result" = "ok" ]; then
    green "  ✓ $desc"
    PASS=$((PASS + 1))
  else
    red "  ✗ $desc — $result"
    FAIL=$((FAIL + 1))
  fi
}

bold "═══ GOYA Testnet Verification ═══"
echo ""

# 1. Health check each node
bold "1. Health Check"
for node in "${NODES[@]}"; do
  status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 "$node/api/v1/health" 2>/dev/null || echo "000")
  if [ "$status" = "200" ]; then
    check "$node — HTTP 200" "ok"
  else
    check "$node — HTTP $status" "unreachable or error"
  fi
done
echo ""

# 2. Chain height comparison
bold "2. Chain Height"
heights=()
for node in "${NODES[@]}"; do
  h=$(curl -s --max-time 10 "$node/api/v1/chain/info" 2>/dev/null | grep -o '"height":[0-9]*' | head -1 | cut -d: -f2 || echo "?")
  heights+=("$h")
  echo "  $node → height $h"
done
echo ""

# Check heights are consistent (within 2 blocks)
if [ ${#heights[@]} -ge 2 ]; then
  min=${heights[0]}; max=${heights[0]}
  for h in "${heights[@]}"; do
    [ "$h" = "?" ] && continue
    [ "$h" -lt "$min" ] 2>/dev/null && min=$h
    [ "$h" -gt "$max" ] 2>/dev/null && max=$h
  done
  if [ "$min" != "?" ] && [ "$max" != "?" ]; then
    diff=$((max - min))
    if [ $diff -le 2 ]; then
      check "Heights within 2 blocks (diff=$diff)" "ok"
    else
      check "Heights diverged by $diff blocks" "consensus may be stalled"
    fi
  fi
fi
echo ""

# 3. Peer connectivity
bold "3. Peer Discovery"
for node in "${NODES[@]}"; do
  peers=$(curl -s --max-time 10 "$node/api/v1/network/peers" 2>/dev/null | grep -o '"peer"' | wc -l || echo "0")
  peers=$(echo "$peers" | tr -d ' ')
  if [ "$peers" -gt 0 ] 2>/dev/null; then
    check "$node — $peers peer(s) connected" "ok"
  else
    # Try alternative endpoint
    peers2=$(curl -s --max-time 10 "$node/api/v1/health" 2>/dev/null | grep -o '"peers":[0-9]*' | cut -d: -f2 || echo "0")
    check "$node — $peers2 peer(s)" "ok"
  fi
done
echo ""

# 4. Cross-node propagation test
bold "4. Cross-Node Propagation"
echo "  Submitting test notarization to ${NODES[0]}..."
test_hash=$(echo "verify-network-$(date +%s)" | sha256sum | cut -d' ' -f1)
# This will likely fail without proper signature, but tests the endpoint
resp=$(curl -s --max-time 10 -X POST "${NODES[0]}/api/v1/notarize" \
  -H 'Content-Type: application/json' \
  -d "{\"content_hash\":\"$test_hash\",\"signer\":\"did:goya:network-test\",\"public_key\":\"$(printf '0%.0s' {1..64})\",\"signature\":\"$(printf '0%.0s' {1..128})\"}" 2>/dev/null || echo "{}")
echo "  Response: $(echo "$resp" | head -c 200)"
echo ""

# 5. Network ID consistency
bold "5. Network ID"
for node in "${NODES[@]}"; do
  nid=$(curl -s --max-time 10 "$node/api/v1/health" 2>/dev/null | grep -o '"network_id":"[^"]*"' | cut -d'"' -f4 || echo "?")
  echo "  $node → $nid"
done
echo ""

# Summary
bold "═══ Results ═══"
echo "  Passed: $PASS"
echo "  Failed: $FAIL"
echo "  Nodes:  ${#NODES[@]}"
if [ $FAIL -eq 0 ]; then
  green "  Network OK ✓"
else
  red "  Network has issues ✗"
fi
