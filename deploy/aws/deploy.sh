#!/usr/bin/env bash
set -euo pipefail

NODE_IP="44.220.142.37"
SSH_KEY="$HOME/.ssh/goya-node.pem"
SSH="ssh -o StrictHostKeyChecking=no -i $SSH_KEY ubuntu@$NODE_IP"
SCP="scp -o StrictHostKeyChecking=no -i $SSH_KEY"

case "${1:-help}" in
    push)
        echo "=== Saving image ==="
        docker save goya-node:latest | gzip > /tmp/goya-node.tar.gz
        echo "  Size: $(du -h /tmp/goya-node.tar.gz | cut -f1)"

        echo "=== Uploading to $NODE_IP ==="
        $SCP /tmp/goya-node.tar.gz ubuntu@$NODE_IP:~/goya-node.tar.gz
        rm -f /tmp/goya-node.tar.gz

        echo "=== Loading image ==="
        $SSH "docker load < ~/goya-node.tar.gz && rm ~/goya-node.tar.gz"

        echo "=== Uploading compose ==="
        $SCP "$(dirname "$0")/docker-compose.yml" ubuntu@$NODE_IP:~/docker-compose.yml

        echo "=== Done ==="
        ;;

    start)
        $SSH "docker compose up -d"
        echo "=== Node starting at http://$NODE_IP:8080 ==="
        ;;

    stop)
        $SSH "docker compose down"
        ;;

    status)
        $SSH "docker compose ps && echo '---' && curl -s http://localhost:8080/api/v1/health | python3 -m json.tool 2>/dev/null || echo 'Not responding'"
        ;;

    logs)
        $SSH "docker compose logs --tail=50 -f"
        ;;

    verify)
        echo "=== Health ==="
        curl -s "http://$NODE_IP:8080/api/v1/health" | python3 -m json.tool 2>/dev/null || echo "FAIL"
        echo ""
        echo "=== TSA ==="
        curl -s "http://$NODE_IP:8080/api/v1/tsa/info" | python3 -m json.tool 2>/dev/null || echo "No TSA endpoint"
        echo ""
        echo "=== CRL ==="
        curl -s "http://$NODE_IP:8080/api/v1/crl" | python3 -m json.tool 2>/dev/null || echo "No CRL endpoint"
        echo ""
        echo "=== OCSP ==="
        curl -s "http://$NODE_IP:8080/api/v1/ocsp/status" | python3 -m json.tool 2>/dev/null || echo "No OCSP endpoint"
        ;;

    *)
        echo "Usage: $0 {push|start|stop|status|logs|verify}"
        ;;
esac
