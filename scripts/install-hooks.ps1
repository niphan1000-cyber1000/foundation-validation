# Script to install git pre-commit hook automatically (Windows / PowerShell)

$HookDir = ".git/hooks"
$PreCommitHook = Join-Path $HookDir "pre-commit"

if (-not (Test-Path ".git")) {
    Write-Error "Error: .git directory not found. Are you in the root of the repository?"
    exit 1
}

Write-Host "Installing pre-commit hook..."

if (-not (Test-Path $HookDir)) {
    New-Item -ItemType Directory -Path $HookDir | Out-Null
}

$HookContent = @"
#!/bin/sh
echo "Running Governed Validation Gate pre-commit check..."
python run_all.py
if [ `$? -ne 0 ]; then
    echo "❌ Validation failed! Commit aborted. Please fix the issues before committing."
    exit 1
fi
echo "✅ Validation passed! Proceeding with commit..."
"@

Set-Content -Path $PreCommitHook -Value $HookContent -Encoding utf8 -NoNewline

Write-Host "Pre-commit hook installed successfully in $PreCommitHook" -ForegroundColor Green
