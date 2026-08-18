
param([string]$InputType = "GOOD")
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "  GOVERNANCE CONTROL PLANE - GATE CHECK  " -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "Mode: $InputType Input Test`n" -ForegroundColor Yellow

# ??????? Single Source of Truth (registry\rules.yaml)
if (Test-Path "registry\rules.yaml") {
    Write-Host "[*] Loading rules from Registry (registry\rules.yaml)..." -ForegroundColor Gray
    # ???????????????? YAML ????????????????????????? rule_id
    $registryContent = Get-Content "registry\rules.yaml"
} else {
    Write-Host "[!] Warning: registry\rules.yaml not found!" -ForegroundColor Red
}

$findings = @()
switch ($InputType.ToUpper()) {
    "GOOD"  { $findings = @(@{ rule_id = "OAS-001"; severity = "MEDIUM"; status = "PASSED" }) }
    "BAD"   { $findings = @(@{ rule_id = "SEC-001"; severity = "CRITICAL"; status = "VIOLATION" }) }
    "ERROR" { $findings = @(@{ rule_id = "GOV-001"; severity = "HIGH"; status = "ERROR" }) }
}

$hasError = ($findings | Where-Object { $_.status -eq "ERROR" }).Count -gt 0
$hasViolation = ($findings | Where-Object { $_.severity -eq "CRITICAL" -or $_.severity -eq "HIGH" }).Count -gt 0

$exitCode = if ($hasError -or $hasViolation) { 1 } else { 0 }
$gateState = if ($hasError) { "ERROR" } elseif ($hasViolation) { "FAIL" } else { "PASS" }

Write-Host "GATE DECISION: $gateState" -ForegroundColor $(if($exitCode -eq 0){"Green"}else{"Red"})
exit $exitCode

