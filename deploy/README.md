# Multi-Node BFT Network Deployment

4 validator nodes across 4 platforms demonstrating real Byzantine Fault Tolerance.

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                    GOYA Testnet (BFT 3f+1)                   │
│                                                              │
│  node-1 (Fly.io)          node-2 (Railway)                   │
│  Virginia, US ◄──────────► Oregon, US                        │
│  :8080 API / :8081 P2P     :8080 API / :8081 P2P             │
│       ▲                         ▲                            │
│       │                         │                            │
│       ▼                         ▼                            │
│  node-3 (Oracle Cloud)    node-4 (Render)                    │
│  São Paulo, BR ◄──────────► Frankfurt, EU                    │
│  :8080 API / :8081 P2P     :8080 API / :8081 P2P             │
└──────────────────────────────────────────────────────────────┘
```

HotStuff BFT requires 3f+1 nodes. With f=1 (tolerate 1 Byzantine node), we need 4 nodes.

## Platform Setup

### Node 1: Fly.io (already deployed)

App: `goya-node` — already running at `goya-node.fly.dev`.

Update fly.toml to expose P2P port and add bootstrap config:

```bash
cd deploy/fly
flyctl deploy
```

### Node 2: Railway

1. Create account at railway.app
2. New project → Deploy from GitHub repo
3. Set root directory to `/` and Dockerfile to `Dockerfile.fly`
4. Add environment variables from `deploy/railway/.env.example`
5. Add TCP proxy on port 8081 (Settings → Networking → TCP Proxy)

### Node 3: Oracle Cloud (Always Free ARM)

Best option — full VM, never sleeps, any port.

1. Create always-free ARM instance (Ampere A1, 1 OCPU, 6GB RAM)
2. SSH in, install Docker
3. Run: `docker compose -f deploy/oracle/docker-compose.yml up -d`

### Node 4: Render

1. Create account at render.com
2. New Web Service → Connect repo
3. Set Dockerfile path to `Dockerfile.fly`
4. Add environment variables from `deploy/render/.env.example`
5. Note: Render only exposes HTTP. P2P will use WebSocket fallback on :8080/ws/p2p

## Network Verification

After all 4 nodes are running:

```bash
# Check each node's peers
curl https://goya-node.fly.dev/api/v1/network/peers
curl https://goya-node-2.up.railway.app/api/v1/network/peers
curl http://<oracle-ip>:8080/api/v1/network/peers
curl https://goya-node-4.onrender.com/api/v1/network/peers

# Verify consensus — submit a transaction to node-1, verify on node-3
curl -X POST https://goya-node.fly.dev/api/v1/notarize \
  -H 'Content-Type: application/json' \
  -d '{"content_hash":"abc123...","signer":"did:goya:test","signature":"..."}'

# Check it propagated
curl https://goya-node-4.onrender.com/api/v1/notarize/verify/abc123...

# Chain height should be consistent across nodes
for node in goya-node.fly.dev goya-node-2.up.railway.app; do
  echo "$node: $(curl -s https://$node/api/v1/chain/info | jq .data.height)"
done
```

## Environment Variables (per node)

| Variable | Node 1 | Node 2 | Node 3 | Node 4 |
|----------|--------|--------|--------|--------|
| `NETWORK_ID` | goya-testnet | goya-testnet | goya-testnet | goya-testnet |
| `API_PORT` | 8080 | 8080 | 8080 | 8080 |
| `P2P_PORT` | 8081 | 8081 | 8081 | 8081 |
| `STORAGE_BACKEND` | rocksdb | rocksdb | rocksdb | rocksdb |
| `BOOTSTRAP_NODES` | (all others) | (all others) | (all others) | (all others) |
| `ACL_MODE` | permissive | permissive | permissive | permissive |
| `LOG_FORMAT` | json | json | json | json |
