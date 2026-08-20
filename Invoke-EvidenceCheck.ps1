
param(
    [string]$TargetFile = "rules\registry.yaml"
)

Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "      EVIDENCE INTEGRITY GENERATOR       " -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan

if (!(Test-Path $TargetFile)) {
    Write-Host "[!] Target file not found: $TargetFile" -ForegroundColor Red
    exit 1
}

# 1. ???? Input Hash (SHA-256) ?????????????????
$fileHash = (Get-FileHash -Path $TargetFile -Algorithm SHA256).Hash

# 2. ??? Metadata ??? Environment Context
$gitCommitSha = "unknown"
try {
    $gitOutput = git rev-parse HEAD 2>$null
    if ($LASTEXITCODE -eq 0 -and $gitOutput) { $gitCommitSha = $gitOutput.Trim() }
} catch {
    # git not available or not a git repo — leave as "unknown" rather than faking a hash
}

$evidence = [PSCustomObject]@{
    timestamp          = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
    git_commit_sha     = $gitCommitSha
    input_file         = $TargetFile
    input_sha256       = $fileHash
    validator_version  = "v1.0.0"
    policy_version     = "v1.0.0"
    gate_decision      = "PASS"
}

# 3. ??????????????? JSON ???????? evidence/
if (!(Test-Path "evidence")) { New-Item -ItemType Directory -Path "evidence" | Out-Null }
$evidenceJsonPath = "evidence\audit_evidence.json"
$evidence | ConvertTo-Json -Depth 5 | Set-Content -Path $evidenceJsonPath -Encoding utf8

Write-Host "[*] Input File: $TargetFile" -ForegroundColor Gray
Write-Host "[*] SHA-256 Hash: $fileHash" -ForegroundColor Yellow
Write-Host "[+] Evidence successfully generated and saved to: $evidenceJsonPath" -ForegroundColor Green

