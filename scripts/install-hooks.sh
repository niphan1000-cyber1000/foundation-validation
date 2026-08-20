#!/bin/sh
# Script to install git pre-commit hook automatically

HOOK_DIR=".git/hooks"
PRE_COMMIT_HOOK="$HOOK_DIR/pre-commit"

if [ ! -d ".git" ]; then
    echo "Error: .git directory not found. Are you in the root of the repository?"
    exit 1
fi

echo "Installing pre-commit hook..."

cat << 'EOF' > "$PRE_COMMIT_HOOK"
#!/bin/sh
echo "Running Governed Validation Gate pre-commit check..."
python run_all.py
if [ $? -ne 0 ]; then
    echo "❌ Validation failed! Commit aborted. Please fix the issues before committing."
    exit 1
fi
echo "✅ Validation passed! Proceeding with commit..."
EOF

chmod +x "$PRE_COMMIT_HOOK"
echo "Pre-commit hook installed successfully in $PRE_COMMIT_HOOK"