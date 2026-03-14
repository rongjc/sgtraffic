#!/bin/bash
# Install local git hooks for this repository.
# Run once after cloning: bash scripts/install-hooks.sh

set -e

HOOKS_DIR="$(git rev-parse --git-dir)/hooks"
SCRIPTS_DIR="$(git rev-parse --show-toplevel)/scripts/hooks"

echo "Installing git hooks from $SCRIPTS_DIR → $HOOKS_DIR"

for hook in "$SCRIPTS_DIR"/*; do
  name="$(basename "$hook")"
  target="$HOOKS_DIR/$name"
  cp "$hook" "$target"
  chmod +x "$target"
  echo "  ✓ Installed $name"
done

echo ""
echo "Hooks installed. Every push will now run the build first."
