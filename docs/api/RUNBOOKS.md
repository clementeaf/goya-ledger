# Operational Runbooks

Procedures for operating a Goya Ledger node in production. Each section is self-contained with detection, diagnosis, and resolution steps.

---

## 1. Node Recovery

**Symptoms:** Node unresponsive, health endpoint returns non-200, Docker container restarting.

### Detection

```bash
# Check health endpoint
curl -sf http://NODE:8080/api/v1/health | jq .

# Check container status
docker compose ps

# Check via operator CLI
./scripts/bcctl.sh status
```

### Resolution

1. **Check logs** for panic or OOM:
   ```bash
   docker compose logs --tail=100 node1
   ```

2. **Restart the node** (data persists in RocksDB volume):
   ```bash
   docker compose restart node1
   ```

3. **Verify storage integrity** after restart:
   ```bash
   curl -s http://NODE:8080/api/v1/chain/verify | jq .
   ```

4. **If RocksDB is corrupted**, restore from backup:
   ```bash
   ./scripts/sandbox-backup.sh restore backups/latest.tar.gz
   docker compose restart node1
   ```

5. **If node cannot catch up**, trigger pull-sync manually — the node will request missing blocks from peers automatically on startup (interval: 10s).

### Validation

```bash
# Node is healthy
curl -sf http://NODE:8080/api/v1/health | jq '.data.status'
# Expected: "healthy"

# Chain height matches peers
curl -s http://NODE:8080/api/v1/chain/info | jq '.data.height'
```

---

## 2. Chain Inconsistency Detection and Repair

**Symptoms:** Different heights across peers, `chain/verify` reports invalid block, transaction not found on all nodes.

### Detection

```bash
# Verify chain integrity on each node
for NODE in node1:8080 node2:8082 node3:8084; do
  echo "=== $NODE ==="
  curl -s http://$NODE/api/v1/chain/verify | jq '{valid: .data.valid, height: .data.height}'
done

# Compare latest block across peers
for NODE in node1:8080 node2:8082 node3:8084; do
  curl -s http://$NODE/api/v1/chain/info | jq '{height: .data.height, hash: .data.latest_block_hash}'
done
```

### Resolution

1. **Height mismatch (node behind):** The pull-sync mechanism runs every 10s and will catch up automatically. Wait 1-2 minutes and re-check.

2. **Hash mismatch at same height (fork):** This indicates a consensus failure.
   - Check if the Raft ordering service is healthy across all orderers.
   - Identify which node diverged by comparing block hashes at each height.
   - The minority fork must be resolved — typically by restarting the diverged node to re-sync.

3. **`chain/verify` reports `first_invalid_height`:**
   ```bash
   curl -s http://NODE:8080/api/v1/chain/verify | jq '.data.first_invalid_height'
   ```
   - If the invalid height is recent, restart the node to re-sync from peers.
   - If the invalid height is deep, restore from backup (see Node Recovery).

### Prevention

Run `./scripts/demo-consistency.sh` regularly to verify cross-node consistency.

---

## 3. Performance Troubleshooting

**Symptoms:** High latency (>500ms p95), transaction timeouts, low throughput (<50 tx/s).

### Detection

```bash
# Check Prometheus metrics
curl -s http://NODE:8080/metrics | grep -E 'http_request|mempool|blocks_total'

# Run load test to measure baseline
./scripts/load-test.sh --duration 60 --rate 50

# Check mempool depth
curl -s http://NODE:8080/api/v1/health | jq '.data.blockchain_info'
```

### Diagnosis

| Metric | Healthy | Action if exceeded |
|--------|---------|-------------------|
| HTTP p95 latency | < 200ms | Check CPU/memory, increase workers |
| Mempool pending | < 500 | Increase `MEMPOOL_MAX_SIZE` or block production rate |
| Connected peers | >= 2 | Check network, bootstrap nodes config |
| Rate limit hits | < 1% of requests | Tune `RATE_LIMIT_RPM`/`RPS`/`RPH` |

### Resolution

1. **High latency:** Check if RocksDB is on SSD. Increase worker threads (auto-detected from CPU cores).
2. **Mempool backlog:** Increase `ORDERING_BATCH_TIMEOUT_MS` (default 2000ms) to cut blocks more frequently.
3. **Network bottleneck:** Check `P2P_RESPONSE_BUFFER_BYTES` (default 4MB) and peer connectivity.
4. **Rate limiting too aggressive:** Adjust via env vars:
   ```bash
   RATE_LIMIT_RPS=50 RATE_LIMIT_RPM=500 RATE_LIMIT_RPH=10000
   ```

### Benchmarking

```bash
./scripts/benchmark.sh          # Criterion benchmarks
./scripts/stress-test.sh        # Stress test with metrics
```

---

## 4. Security Incident Response

**Symptoms:** Unauthorized access detected in audit log, compromised key material, unexpected API activity.

### Immediate Actions (P1)

1. **Export audit trail:**
   ```bash
   curl -s "http://NODE:8080/api/v1/audit/export?from=2026-06-01T00:00:00Z" \
     -o incident-audit.csv
   ```

2. **Rotate TLS certificates** (zero-downtime via SIGHUP):
   ```bash
   # Replace cert files on disk, then signal the process
   kill -HUP $(pgrep rust-bc)
   ```

3. **Switch to strict ACL** if in permissive mode:
   ```bash
   # Restart with strict ACL
   ACL_MODE=strict docker compose restart
   ```

4. **Review rate limiting** — tighten if under attack:
   ```bash
   RATE_LIMIT_RPS=5 RATE_LIMIT_RPM=30 docker compose restart
   ```

### Investigation

```bash
# Check for unusual patterns
curl -s "http://NODE:8080/api/v1/audit/requests?action=http_request&limit=100" | \
  jq '.data.data[] | {path: .path, org_id: .org_id, ip: .source_ip, status: .status_code}'

# Run penetration test suite
./scripts/pentest.sh
```

### Post-Incident

1. Document the incident timeline.
2. Rotate any potentially compromised secrets (`JWT_SECRET`, TLS certs).
3. Review and update ACL policies.
4. Run `cargo deny check advisories` to check for new CVEs.

---

## 5. Support Escalation Matrix

### Severity Levels

| Level | Definition | Response Time | Examples |
|-------|-----------|---------------|---------|
| **P1 Critical** | Network down, data loss risk, security breach | 1 hour | All nodes unreachable, chain fork, key compromise |
| **P2 High** | Degraded service, single node failure | 4 hours | One node down (redundancy active), high latency |
| **P3 Medium** | Non-critical feature issue, performance concern | 24 hours | Audit export slow, rate limit tuning needed |
| **P4 Low** | Documentation, feature requests, cosmetic issues | 72 hours | Dashboard question, config advice |

### Escalation Triggers

- **P3 -> P2:** Issue persists > 4 hours or affects multiple users.
- **P2 -> P1:** Second node fails (quorum at risk) or data integrity issue detected.
- **Any -> P1:** Security incident confirmed.

### Diagnostic Data to Collect

Before escalating, gather:
1. `curl http://NODE:8080/api/v1/health` output from all nodes
2. `docker compose logs --tail=500` from affected nodes
3. `curl http://NODE:8080/metrics` snapshot
4. `curl http://NODE:8080/api/v1/chain/verify` from all nodes
5. Audit export CSV for the relevant time window

### Useful Scripts

| Script | Purpose |
|--------|---------|
| `scripts/bcctl.sh status` | Quick node health check |
| `scripts/e2e-test.sh` | 71 assertions across all subsystems |
| `scripts/recovery-test.sh` | Validate crash recovery |
| `scripts/pentest.sh` | Security test suite |
| `scripts/load-test.sh` | Performance baseline |
| `scripts/sandbox-backup.sh` | Backup/restore RocksDB data |
