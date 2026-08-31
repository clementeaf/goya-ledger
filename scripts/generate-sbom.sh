#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
OUTPUT="${1:-$REPO_ROOT/sbom.cdx.json}"

cd "$REPO_ROOT"

if command -v cargo-cyclonedx &>/dev/null; then
    cargo cyclonedx --format json --output-file "$OUTPUT"
    echo "SBOM generated via cargo-cyclonedx: $OUTPUT"
    exit 0
fi

VERSION=$(grep '^version' Cargo.toml | head -1 | sed 's/.*"\(.*\)".*/\1/')
NAME=$(grep '^name' Cargo.toml | head -1 | sed 's/.*"\(.*\)".*/\1/')
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

COMPONENTS=$(cargo metadata --format-version 1 2>/dev/null \
    | python3 -c "
import json, sys
meta = json.load(sys.stdin)
workspace = {p['name'] for p in meta['packages'] if p['source'] is None}
components = []
for pkg in meta['packages']:
    if pkg['source'] is None:
        continue
    lic = pkg.get('license', '')
    licenses = []
    if lic:
        licenses = [{'license': {'id': lic}}]
    components.append({
        'type': 'library',
        'name': pkg['name'],
        'version': pkg['version'],
        'purl': f\"pkg:cargo/{pkg['name']}@{pkg['version']}\",
        'licenses': licenses
    })
json.dump(components, sys.stdout)
" 2>/dev/null || echo "[]")

cat > "$OUTPUT" <<SBOM
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "version": 1,
  "metadata": {
    "timestamp": "${TIMESTAMP}",
    "tools": [{"vendor": "goya", "name": "generate-sbom.sh", "version": "1.0.0"}],
    "component": {
      "type": "application",
      "name": "${NAME}",
      "version": "${VERSION}",
      "purl": "pkg:cargo/${NAME}@${VERSION}"
    }
  },
  "components": ${COMPONENTS}
}
SBOM

COUNT=$(echo "$COMPONENTS" | python3 -c 'import json,sys;print(len(json.load(sys.stdin)))' 2>/dev/null || echo '?')
echo "SBOM generated: $OUTPUT ($COUNT components, CycloneDX 1.5)"
