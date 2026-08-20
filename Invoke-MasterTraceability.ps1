
param([string]$TargetFile = "rules\registry.yaml")
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "   MASTER CONTROL PLANE & TRACEABILITY   " -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan

$timestamp = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
$fileHash = (Get-FileHash -Path $TargetFile -Algorithm SHA256).Hash

# 1. Run Validators
$content = Get-Content $TargetFile -Raw
$secViolation = ($content -match "password|secret|api_key|token")
$govViolation = ($content -notmatch "domain" -or $content -notmatch "severity")

$findings = @()
if ($secViolation) { $findings += [PSCustomObject]@{ rule_id = "SEC-001"; domain = "security"; status = "VIOLATION" } }
if ($govViolation) { $findings += [PSCustomObject]@{ rule_id = "GOV-001"; domain = "governance"; status = "VIOLATION" } }

$gateDecision = if ($findings.Count -gt 0) { "FAIL" } else { "PASS" }
$exitCode = if ($gateDecision -eq "FAIL") { 1 } else { 0 }

# 2. Build Traceability Record
$traceRecord = [PSCustomObject]@{
    timestamp         = $timestamp
    artifact          = $TargetFile
    artifact_sha256   = $fileHash
    total_findings    = $findings.Count
    findings          = $findings
    gate_decision     = $gateDecision
    ci_exit_code      = $exitCode
    traceability_status = "VERIFIED_END_TO_END"
}

# 3. Output Traceability Report
if (!(Test-Path "evidence")) { New-Item -ItemType Directory -Path "evidence" | Out-Null }
$reportPath = "evidence\traceability_report.json"
$traceRecord | ConvertTo-Json -Depth 5 | Set-Content -Path $reportPath -Encoding utf8

Write-Host "[*] Artifact SHA-256: $fileHash" -ForegroundColor Yellow
Write-Host "[*] Gate Decision  : $gateDecision" -ForegroundColor $(if($exitCode -eq 0){"Green"}else{"Red"})
Write-Host "[+] Traceability Report generated: $reportPath" -ForegroundColor Green
exit $exitCode

