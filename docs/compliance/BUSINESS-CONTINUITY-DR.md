# Business Continuity and Disaster Recovery Plan

**Document ID:** GOYA-BCDR-001
**Version:** 1.0
**Status:** Draft
**Last Updated:** 2026-08-05
**Owner:** Operations Lead

## 1. Purpose

Ensure continuity of Goya Ledger's trust services (CA, TSA, OCSP, RA) during and after disruptive events. Fulfills ETSI TS 102 042 §7.4.9 and Chilean PSC accreditation requirements.

## 2. Service Tiers and Recovery Objectives

| Service | RTO | RPO | Justification |
|---------|-----|-----|---------------|
| **OCSP Responder** | 15 min | 0 (stateless) | Certificate validation must not stall |
| **CRL Publication** | 1 hour | Last CRL | DS 181 requires timely revocation info |
| **TSA** | 4 hours | Last token serial | Timestamp continuity, serial monotonicity |
| **CA (issuance)** | 24 hours | Last issued cert | New certs can wait; revocation cannot |
| **RA (proofing)** | 48 hours | Last proofing record | Human process, can queue |
| **Audit Log** | 4 hours | 0 (hash chain) | Regulatory requirement, tamper-evidence |
| **API Gateway** | 15 min | N/A | Subscriber access to all services |

**RTO** = Recovery Time Objective (max downtime).
**RPO** = Recovery Point Objective (max data loss).

## 3. Architecture for Resilience

### 3.1 Data Protection

- **Blockchain state:** Replicated across consensus nodes (BFT/Raft)
- **Audit logs:** Append-only with SHA-256 hash chain; RocksDB WAL + checkpoints
- **CA keys:** M-of-N custodian shares (key ceremony); root key offline
- **Certificates/CRL:** Generated from CA key + serial state; reproducible
- **TSA serial counter:** Persisted; monotonicity verified on restart

### 3.2 Checkpoint and Snapshot

- `src/checkpoint.rs` — periodic state snapshots
- `src/storage/snapshot.rs` — RocksDB snapshot export/import
- `src/ordering/raft_storage.rs` — Raft log persistence
- Checkpoint frequency: every 1000 blocks or 1 hour (whichever first)

### 3.3 Geographic Distribution

| Site | Role | Services |
|------|------|----------|
| **Primary (Santiago)** | Active | All services |
| **Secondary (backup)** | Standby | OCSP, CRL mirror, read-only API |
| **Offline vault** | Cold storage | Root CA key shares, backup media |

## 4. Disaster Scenarios

### 4.1 Single Node Failure

- **Detection:** Health check failure (< 30 seconds)
- **Response:** Automatic failover via Raft consensus
- **Recovery:** Replace node, restore from peer sync
- **RTO:** < 1 minute (consensus continues with remaining nodes)

### 4.2 Datacenter Outage

- **Detection:** All nodes unreachable from monitoring
- **Response:** Activate secondary site
- **Recovery:**
  1. Promote secondary to active
  2. Restore latest checkpoint to new primary
  3. Verify audit chain integrity
  4. Resume TSA with next serial number
  5. Publish fresh CRL
- **RTO:** 4 hours

### 4.3 CA Key Compromise

- See Incident Response Plan (GOYA-IRP-001) §5.3
- **Recovery:**
  1. Revoke compromised CA certificate
  2. Reconstruct CA key from custodian shares (M-of-N)
  3. Issue new intermediate CA certificate from root
  4. Re-issue all subscriber certificates
  5. Publish emergency CRL
- **RTO:** 24 hours

### 4.4 Data Corruption

- **Detection:** Audit chain verification failure (`verify_audit_chain()`)
- **Response:** Isolate affected storage
- **Recovery:**
  1. Identify last valid checkpoint before corruption
  2. Restore from checkpoint
  3. Replay transactions from peer nodes
  4. Verify chain integrity post-restore
- **RTO:** 4 hours
- **RPO:** Last valid checkpoint

### 4.5 Ransomware / Complete Data Loss

- **Recovery:**
  1. Rebuild from clean OS image
  2. Restore CA from offline key ceremony shares
  3. Restore latest off-site backup
  4. Sync blockchain state from peer network
  5. Verify all service integrity
- **RTO:** 24–48 hours

## 5. Backup Strategy

| Data | Method | Frequency | Retention | Location |
|------|--------|-----------|-----------|----------|
| RocksDB state | Checkpoint snapshot | Hourly | 30 days | Primary + secondary |
| Audit logs | Export + hash verification | Daily | 7 years | Off-site encrypted |
| CA key shares | Key ceremony custodian | On generation | Permanent | Separate secure facilities |
| Configuration | Git repository | On change | Permanent | Remote repository |
| TSA serial state | Atomic counter persist | Per token | 7 years | With audit logs |

## 6. Recovery Procedures

### 6.1 Service Restart Order

1. Storage layer (RocksDB restore)
2. Consensus engine (Raft state recovery)
3. Audit log (verify hash chain)
4. CA (load intermediate key)
5. CRL (publish current list)
6. OCSP (start responder)
7. TSA (verify serial monotonicity)
8. RA (restore proofing queue)
9. API gateway (enable endpoints)

### 6.2 Verification Checklist

- [ ] `verify_audit_chain()` passes on restored log
- [ ] TSA serial number > last known serial
- [ ] NTP sync validated (`NtpTimeSource::validate()`)
- [ ] CRL published and accessible
- [ ] OCSP responds correctly for known serials
- [ ] CA can issue test certificate
- [ ] All API endpoints return 200 on health check

## 7. Testing

| Test | Frequency | Scope |
|------|-----------|-------|
| Checkpoint restore | Monthly | Restore from snapshot, verify state |
| Failover drill | Quarterly | Simulate primary failure, activate secondary |
| Full DR exercise | Annually | Complete rebuild from backups |
| Audit chain verification | Weekly | Run `verify_audit_chain()` on production log |
| CA key reconstruction | Annually | M-of-N share reassembly (test environment) |

## 8. Regulatory References

- ETSI TS 102 042 §7.4.9 — Business continuity and disaster recovery
- Ley 19.799 Art. 17 — PSC obligations for service availability
- DS 181/2002 — Reglamento
- ISO 22301:2019 — Business continuity management systems

## 9. Document Control

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2026-08-05 | Operations Lead | Initial draft |
