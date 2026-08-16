$HookDir = ".git/hooks"
$PreCommitHook = "$Join-Path $HookDir 'pre-commit'"

if (-not (Test-Path ".git")) {
    Write-Error "Error: .git directory not found. Are you in the root of the repository?"
    exit 1
}

Write-Host "Installing pre-commit hook..."

$HookContent = @"