# Performance Baseline

Procedure and targets for measuring Goya Ledger performance before production deployment.

## SLA Targets

| Metric | Target | Measurement |
|--------|--------|-------------|
| Throughput | >= 50 tx/s sustained | `load-test.sh --rate 50` success rate |
| Latency p95 | < 200ms | Prometheus `http_request_duration_seconds` |
| Latency p99 | < 500ms | Prometheus histogram |
| Error rate | < 1% | HTTP 5xx / total requests |
| Availability | 99.5% (SaaS tier) | `/api/v1/health` uptime checks |

## Test Procedure

### 1. Setup

```bash
# Start a sandbox node (single node, RocksDB, Prometheus + Grafana)
./scripts/sandbox.sh up

# Wait for health
./scripts/sandbox.sh health
```

### 2. Warm-up

```bash
# Seed test data
./scripts/seed-sandbox.sh
```

### 3. Load Test

```bash
# Sustained load: 50 tx/s for 60 seconds
./scripts/load-test.sh --duration 60 --rate 50
```

The script reports:
- Transactions submitted / succeeded / failed
- Latency percentiles (p50, p95, p99)
- Throughput (tx/s achieved)

### 4. Capture Metrics

```bash
# Prometheus metrics snapshot
curl -s http://localhost:8080/metrics > baseline-metrics.txt

# Key metrics to check:
grep 'http_request_duration' baseline-metrics.txt
grep 'blocks_total' baseline-metrics.txt
grep 'mempool_pending' baseline-metrics.txt
grep 'peers_connected' baseline-metrics.txt
```

### 5. Stress Test (optional)

```bash
# Find the breaking point
./scripts/stress-test.sh
```

## Grafana Dashboard

Available at `http://localhost:3000` (admin/admin) when running with sandbox compose.

Pre-built dashboard: `deploy/sandbox/dashboard-sandbox.json`

Key panels:
- Transaction throughput (tx/s)
- Block production rate
- HTTP request latency histogram
- Mempool depth
- Peer connectivity

## Performance Tuning

| Bottleneck | Env Var | Default | Recommendation |
|-----------|---------|---------|----------------|
| Block production | `ORDERING_BATCH_TIMEOUT_MS` | 2000 | Lower for higher throughput |
| Mempool capacity | `MEMPOOL_MAX_SIZE` | 1000 | Increase for bursty workloads |
| Rate limiting | `RATE_LIMIT_RPS` | 20 | Increase for load testing |
| HTTP timeout | `HTTP_REQUEST_TIMEOUT_SECS` | 30 | Increase for large chaincode deploys |
| Worker threads | *(auto)* | CPU cores | Override with `ACTIX_WORKERS` if needed |

## Benchmarks

Criterion benchmarks for isolated subsystems:

```bash
# Ordering throughput
cargo bench --bench ordering_throughput

# PQC crypto performance
cargo bench --bench pqc_performance

# Results in target/criterion/ with HTML reports
```
