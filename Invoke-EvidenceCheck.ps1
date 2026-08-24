
param(
    [string]$TargetFile = "rules\registry.yaml",
    [string]$Spec       = "openapi.yaml",
    [string]$Policy     = "gate_policy.yaml",
    [string]$Registry   = "rules\registry.yaml",
    [string]$Environment = "production"
)

Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "      EVIDENCE INTEGRITY GENERATOR       " -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan

if (!(Test-Path $TargetFile)) {
    Write-Host "[!] Target file not found: $TargetFile" -ForegroundColor Red
    exit 1
}

# 1. Input Hash (SHA-256) - identifies exactly which artifact this evidence covers.
$fileHash = (Get-FileHash -Path $TargetFile -Algorithm SHA256).Hash

# 2. Environment context (git commit).
$gitCommitSha = "unknown"
try {
    $gitOutput = git rev-parse HEAD 2>$null
    if ($LASTEXITCODE -eq 0 -and $gitOutput) { $gitCommitSha = $gitOutput.Trim() }
} catch {
    # git not available or not a git repo - leave as "unknown" rather than faking a hash
}

# 3. Run the REAL gate engine (run_all.py -> src/cli.py -> GateDecisionEngine) and
#    read the decision back from its own exit code / stdout. This evidence file
#    must never assert a decision the engine itself did not produce - a hardcoded
#    "PASS" here would be exactly the kind of self-attestation the gate exists to
#    prevent, so if the engine can't even be invoked, that is recorded as ERROR,
#    never as PASS.
$gateOutput = ""
$gateExitCode = -1
try {
    $gateOutput = & python run_all.py --spec $Spec --policy $Policy --registry $Registry --env $Environment 2>&1 | Out-String
    $gateExitCode = $LASTEXITCODE
} catch {
    Write-Host "[!] CRITICAL: could not invoke the gate engine (run_all.py): $_" -ForegroundColor Red
    $gateOutput = "ERROR: failed to invoke run_all.py: $_"
    $gateExitCode = -1
}

# Map the engine's own exit code to a decision. This mirrors src/cli.py's
# contract exactly: 0 = ALLOW, 1 = BLOCK, anything else (including a failed
# invocation, exit 2, etc.) is ERROR - fail-closed, never defaulted to PASS.
$gateDecision = switch ($gateExitCode) {
    0       { "PASS" }
    1       { "BLOCK" }
    default { "ERROR" }
}

$actionLine = ($gateOutput -split "`n" | Where-Object { $_ -match "Gate Action Result:" } | Select-Object -Last 1)
if (-not $actionLine) { $actionLine = "(no 'Gate Action Result' line found in engine output)" }

$evidence = [PSCustomObject]@{
    timestamp          = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
    git_commit_sha     = $gitCommitSha
    input_file         = $TargetFile
    input_sha256       = $fileHash
    validator_version  = "v1.0.0"
    policy_version     = "v1.0.0"
    gate_exit_code     = $gateExitCode
    gate_engine_output = $actionLine.Trim()
    gate_decision      = $gateDecision
}

# 4. Persist the evidence JSON.
if (!(Test-Path "evidence")) { New-Item -ItemType Directory -Path "evidence" | Out-Null }
$evidenceJsonPath = "evidence\audit_evidence.json"
$evidence | ConvertTo-Json -Depth 5 | Set-Content -Path $evidenceJsonPath -Encoding utf8

Write-Host "[*] Input File: $TargetFile" -ForegroundColor Gray
Write-Host "[*] SHA-256 Hash: $fileHash" -ForegroundColor Yellow
Write-Host "[*] Gate Exit Code: $gateExitCode" -ForegroundColor Yellow
Write-Host "[*] Gate Decision: $gateDecision" -ForegroundColor $(if ($gateDecision -eq "PASS") { "Green" } else { "Red" })
Write-Host "[+] Evidence successfully generated and saved to: $evidenceJsonPath" -ForegroundColor Green

# 5. Fail-closed: this script's own exit code must reflect the real decision,
#    not silently return 0 regardless (which is what let the hardcoded "PASS"
#    go unnoticed before - nothing downstream ever checked this script's exit
#    code because it always returned 0). Any decision other than PASS, or a
#    gate engine that couldn't be invoked at all (-1), fails this script too.
if ($gateDecision -ne "PASS") {
    Write-Host "[!] Evidence recorded a non-PASS gate decision ($gateDecision). Failing this check." -ForegroundColor Red
    exit 1
}

exit 0
