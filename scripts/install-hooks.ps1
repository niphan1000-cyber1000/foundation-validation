$HookDir = ".git/hooks"
$PreCommitHook = Join-Path $HookDir "pre-commit"

if (-not (Test-Path ".git")) {
    Write-Error "Error: .git directory not found. Are you in the root of the repository?"
    exit 1
}

Write-Host "Installing pre-commit hook..."

$HookContent = @"
#!/bin/sh
echo "Running Governed Validation Gate pre-commit check..."
python validators/run_all.py --spec openapi.json --output validation-result.json
if [ `$? -ne 0 ]; then
    echo "Validation failed! Commit aborted. Please fix the issues before committing."
    exit 1
fi
echo "Validation passed! Proceeding with commit..."
"@

Set-Content -Path $PreCommitHook -Value $HookContent -NoNewline
Write-Host "Pre-commit hook installed successfully in $PreCommitHook"
