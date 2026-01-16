#!/bin/bash
# Generate SHA256 checksums for release artifacts

set -e

VERSION="${1:-0.1.0}"
OUTPUT="CHECKSUMS.txt"
BASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"

cd "$BASE_DIR"

echo "# MCP Audit Release Checksums" > "$OUTPUT"
echo "# Version: ${VERSION}" >> "$OUTPUT"
echo "# Generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$OUTPUT"
echo "# Verify with: shasum -a 256 -c CHECKSUMS.txt" >> "$OUTPUT"
echo "" >> "$OUTPUT"

# Generate checksum for CLI zip
if [ -f "mcp-audit-cli.zip" ]; then
    shasum -a 256 "mcp-audit-cli.zip" >> "$OUTPUT"
    echo "Added checksum for mcp-audit-cli.zip"
fi

# Generate checksums for dist artifacts if they exist
for file in dist/*.whl dist/*.tar.gz; do
    if [ -f "$file" ]; then
        shasum -a 256 "$file" >> "$OUTPUT"
        echo "Added checksum for $file"
    fi
done

echo ""
echo "Checksums written to $OUTPUT"
echo "---"
cat "$OUTPUT"
