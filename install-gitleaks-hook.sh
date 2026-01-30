#!/bin/bash
# Install gitleaks pre-commit hook in a git repository
# Usage: ./install-gitleaks-hook.sh [repo-path]

REPO_PATH="${1:-.}"

if [ ! -d "$REPO_PATH/.git" ]; then
    echo "❌ Not a git repository: $REPO_PATH"
    exit 1
fi

if ! command -v gitleaks &> /dev/null; then
    echo "❌ gitleaks not installed. Install with:"
    echo "   brew install gitleaks  # macOS"
    echo "   sudo apt install gitleaks  # Ubuntu"
    exit 1
fi

cat > "$REPO_PATH/.git/hooks/pre-commit" << 'EOF'
#!/bin/bash
echo "🔍 Scanning for secrets..."

if ! command -v gitleaks &> /dev/null; then
    echo "⚠️  gitleaks not installed, skipping scan"
    exit 0
fi

gitleaks protect --staged --no-banner

if [ $? -ne 0 ]; then
    echo ""
    echo "❌ Gitleaks detected secrets in your staged changes!"
    echo "   Please remove them before committing."
    echo ""
    echo "   To bypass (NOT RECOMMENDED): git commit --no-verify"
    exit 1
fi

echo "✅ No secrets detected"
EOF

chmod +x "$REPO_PATH/.git/hooks/pre-commit"
echo "✅ Pre-commit hook installed in $REPO_PATH"
