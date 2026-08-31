#!/bin/bash
# Build CLI zip file for web download

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
OUTPUT_DIR="$PROJECT_ROOT/webapp"
ZIP_NAME="mcp-audit-cli.zip"
TEMP_DIR=$(mktemp -d)

echo "Building MCP Audit CLI package..."

# Create package structure
mkdir -p "$TEMP_DIR/mcp-audit-cli"

# Copy CLI source files
cp -r "$PROJECT_ROOT/mcp_audit" "$TEMP_DIR/mcp-audit-cli/"
cp "$PROJECT_ROOT/pyproject.toml" "$TEMP_DIR/mcp-audit-cli/"

# Copy data files
mkdir -p "$TEMP_DIR/mcp-audit-cli/mcp_audit/data"
cp "$PROJECT_ROOT/mcp_audit/data/known_mcps.json" "$TEMP_DIR/mcp-audit-cli/mcp_audit/data/"

# Copy policies
cp -r "$PROJECT_ROOT/policies" "$TEMP_DIR/mcp-audit-cli/"

# Copy MDM collectors (if exists)
if [ -d "$PROJECT_ROOT/collectors" ]; then
    cp -r "$PROJECT_ROOT/collectors" "$TEMP_DIR/mcp-audit-cli/"
fi

# Create a simple README for the CLI package
cat > "$TEMP_DIR/mcp-audit-cli/README.md" << 'EOF'
MCP Audit CLI
=============

A command-line tool to discover and audit MCP (Model Context Protocol) servers.

INSTALLATION
------------
1. Make sure you have Python 3.9 or higher installed
   Check with: python --version

2. Open Terminal (Mac) or Command Prompt (Windows)

3. Navigate to this folder:
   cd mcp-audit-cli

4. Install the tool:
   pip install -e .

5. Run a scan:
   mcp-audit scan

COMMANDS
--------
mcp-audit scan              # Scan your machine for MCPs
mcp-audit scan --verbose    # Detailed output
mcp-audit registry          # View known MCP registry
mcp-audit registry stats    # Registry statistics
mcp-audit --help            # All options

TROUBLESHOOTING
---------------
- If "mcp-audit" is not found, try: python -m mcp_audit.cli scan
- On Mac, you may need to use pip3 instead of pip
- Make sure Python is added to your PATH

For more help, see the docs/ folder or run: mcp-audit --help
EOF

# Remove any __pycache__ directories
find "$TEMP_DIR" -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
find "$TEMP_DIR" -type f -name "*.pyc" -delete 2>/dev/null || true

# Create zip file
cd "$TEMP_DIR"
zip -r "$ZIP_NAME" "mcp-audit-cli" -x "*.pyc" -x "*__pycache__*" -x "*.git*"

# Move to webapp folder
mv "$ZIP_NAME" "$OUTPUT_DIR/"

# Cleanup
rm -rf "$TEMP_DIR"

echo "✓ Created $OUTPUT_DIR/$ZIP_NAME"
echo ""
echo "File size: $(ls -lh "$OUTPUT_DIR/$ZIP_NAME" | awk '{print $5}')"
