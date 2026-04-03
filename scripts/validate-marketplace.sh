#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MARKETPLACE="$ROOT/.claude-plugin/marketplace.json"
ERRORS=0

echo "Validating toolshed marketplace..."

# Check marketplace.json exists and is valid JSON
if ! jq empty "$MARKETPLACE" 2>/dev/null; then
  echo "FAIL: marketplace.json is not valid JSON"
  exit 1
fi

# Check required top-level fields
for field in name owner plugins; do
  if ! jq -e ".$field" "$MARKETPLACE" >/dev/null 2>&1; then
    echo "FAIL: marketplace.json missing required field: $field"
    ERRORS=$((ERRORS + 1))
  fi
done

# Validate each plugin entry
PLUGIN_COUNT=$(jq '.plugins | length' "$MARKETPLACE")
for i in $(seq 0 $((PLUGIN_COUNT - 1))); do
  NAME=$(jq -r ".plugins[$i].name" "$MARKETPLACE")
  SOURCE=$(jq -r ".plugins[$i].source" "$MARKETPLACE")
  PLUGIN_DIR="$ROOT/$SOURCE"

  echo "  Checking plugin: $NAME"

  # Source directory exists
  if [ ! -d "$PLUGIN_DIR" ]; then
    echo "    FAIL: source directory does not exist: $SOURCE"
    ERRORS=$((ERRORS + 1))
    continue
  fi

  # plugin.json exists
  if [ ! -f "$PLUGIN_DIR/.claude-plugin/plugin.json" ]; then
    echo "    FAIL: missing .claude-plugin/plugin.json"
    ERRORS=$((ERRORS + 1))
    continue
  fi

  # plugin.json is valid JSON
  if ! jq empty "$PLUGIN_DIR/.claude-plugin/plugin.json" 2>/dev/null; then
    echo "    FAIL: plugin.json is not valid JSON"
    ERRORS=$((ERRORS + 1))
    continue
  fi

  # Version sync: package.json version == plugin.json version
  if [ -f "$PLUGIN_DIR/package.json" ]; then
    PKG_VERSION=$(jq -r '.version' "$PLUGIN_DIR/package.json")
    PLUGIN_VERSION=$(jq -r '.version' "$PLUGIN_DIR/.claude-plugin/plugin.json")
    if [ "$PKG_VERSION" != "$PLUGIN_VERSION" ]; then
      echo "    FAIL: version mismatch — package.json=$PKG_VERSION, plugin.json=$PLUGIN_VERSION"
      ERRORS=$((ERRORS + 1))
    fi
  fi

  echo "    OK"
done

if [ "$ERRORS" -gt 0 ]; then
  echo ""
  echo "FAILED: $ERRORS error(s) found"
  exit 1
fi

echo ""
echo "All checks passed."
