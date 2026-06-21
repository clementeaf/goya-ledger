# API Integration Guide

Guide for developers integrating with the Goya Ledger REST API. All examples use `curl`, JavaScript `fetch`, and Python `requests`.

**Base URL:** `https://NODE:8080/api/v1`

---

## 1. Authentication

Production deployments use **mTLS** (mutual TLS). You need a client certificate and key issued by the network CA.

```bash
# curl with client certificate
curl --cert client.crt --key client.key --cacert ca.crt \
  https://node1:8080/api/v1/health
```

```javascript
// Node.js with mTLS
const https = require('https');
const fs = require('fs');

const agent = new https.Agent({
  cert: fs.readFileSync('client.crt'),
  key: fs.readFileSync('client.key'),
  ca: fs.readFileSync('ca.crt'),
});

const res = await fetch('https://node1:8080/api/v1/health', { agent });
```

```python
import requests

res = requests.get(
    'https://node1:8080/api/v1/health',
    cert=('client.crt', 'client.key'),
    verify='ca.crt',
)
```

For development without TLS, connect directly to `http://localhost:8080`.

---

## 2. Health Check

```bash
curl -s http://localhost:8080/api/v1/health | jq .
```

**Response:**
```json
{
  "status": "Success",
  "data": {
    "status": "healthy",
    "uptime_seconds": 120,
    "components": {
      "storage": "ok",
      "peers": { "count": 2, "status": "connected" },
      "ordering": "ok"
    }
  },
  "trace_id": "550e8400-e29b-41d4-a716-446655440000"
}
```

---

## 3. Submit a Transaction

```bash
curl -s -X POST http://localhost:8080/api/v1/transactions \
  -H "Content-Type: application/json" \
  -d '{
    "input_did": "did:goya:alice",
    "output_recipient": "did:goya:bob",
    "amount": 100,
    "signature": "hex-encoded-ed25519-signature",
    "signature_algorithm": "Ed25519"
  }' | jq .
```

```javascript
const res = await fetch('http://localhost:8080/api/v1/transactions', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    input_did: 'did:goya:alice',
    output_recipient: 'did:goya:bob',
    amount: 100,
    signature: 'hex-encoded-ed25519-signature',
    signature_algorithm: 'Ed25519',
  }),
});
const data = await res.json();
console.log(data.data.id); // transaction ID
```

```python
res = requests.post('http://localhost:8080/api/v1/transactions', json={
    'input_did': 'did:goya:alice',
    'output_recipient': 'did:goya:bob',
    'amount': 100,
    'signature': 'hex-encoded-ed25519-signature',
    'signature_algorithm': 'Ed25519',
})
print(res.json()['data']['id'])
```

---

## 4. Query Blocks (Paginated)

All list endpoints support pagination via `page` and `limit` query parameters.

```bash
# First page, 10 items per page
curl -s "http://localhost:8080/api/v1/store/blocks?page=1&limit=10" | jq .
```

**Response:**
```json
{
  "status": "Success",
  "data": {
    "data": [ ... ],
    "pagination": {
      "total": 150,
      "page": 1,
      "limit": 10,
      "total_pages": 15,
      "has_next": true
    }
  }
}
```

| Parameter | Default | Max | Description |
|-----------|---------|-----|-------------|
| `page` | 1 | - | Page number (1-based) |
| `limit` | 20 | 100 | Items per page |

---

## 5. Notarize a Document

Register a document hash on-chain as proof of existence.

```bash
# Step 1: Hash the document locally (never upload the document)
HASH=$(sha256sum document.pdf | awk '{print $1}')

# Step 2: Submit the hash
curl -s -X POST http://localhost:8080/api/v1/notarize \
  -H "Content-Type: application/json" \
  -d "{
    \"content_hash\": \"$HASH\",
    \"signer\": \"did:goya:alice\",
    \"signature\": \"hex-signature-of-notarize:did:goya:alice:$HASH\",
    \"metadata\": { \"filename\": \"document.pdf\" }
  }" | jq .

# Step 3: Verify later
curl -s "http://localhost:8080/api/v1/notarize/verify/$HASH" | jq .
```

The signing payload format is `notarize:{signer}:{content_hash}`.

---

## 6. Chain Verification

```bash
# Get chain info
curl -s http://localhost:8080/api/v1/chain/info | jq .

# Verify chain integrity
curl -s http://localhost:8080/api/v1/chain/verify | jq .
```

---

## 7. Response Envelope

All endpoints return a consistent envelope:

```json
{
  "status": "Success",
  "status_code": 200,
  "message": "OK",
  "data": { ... },
  "timestamp": "2026-06-21T12:00:00Z",
  "trace_id": "uuid-v4"
}
```

On error:

```json
{
  "status": "Error",
  "status_code": 400,
  "message": "Validation failed",
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "name is required",
    "field": "name"
  },
  "trace_id": "uuid-v4"
}
```

### Common Error Codes

| HTTP Status | Code | Meaning |
|-------------|------|---------|
| 400 | `VALIDATION_ERROR` | Invalid request body or parameters |
| 401 | `UNAUTHORIZED` | Missing or invalid mTLS identity |
| 403 | `FORBIDDEN` | Insufficient ACL permissions |
| 404 | `NOT_FOUND` | Resource does not exist |
| 409 | `CONFLICT` | Duplicate resource (e.g., notarization hash already exists) |
| 429 | `RATE_LIMITED` | Too many requests |
| 500 | `INTERNAL_ERROR` | Server error (check trace_id for debugging) |

---

## 8. Rate Limits

Default limits per IP address:

| Window | Limit | Write-heavy endpoints |
|--------|-------|-----------------------|
| Per second | 20 | 10 |
| Per minute | 100 | 50 |
| Per hour | 3000 | 1500 |

Write-heavy endpoints: `POST /transactions`, `POST /gateway/*`, `POST /contracts/*`, `POST /governance/proposals/*`, `POST /chaincode/*`.

The `/api/v1/health` endpoint is exempt from rate limiting.

When rate-limited, the API returns HTTP 429 with a `Rate limit exceeded` message.

---

## 9. OpenAPI Specification

The full OpenAPI 3.0 spec is available at:

```bash
curl -s http://localhost:8080/api/v1/openapi.json | jq .
```

Swagger UI is available at `http://localhost:8080/swagger`.
