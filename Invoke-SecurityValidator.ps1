
param([string]$TargetFile = "registry\rules.yaml")
Write-Host "[*] Running Security Validator against $TargetFile..." -ForegroundColor Cyan

$content = Get-Content $TargetFile -Raw
$findings = @()

# ?????? SEC-001: ????????????????????????????
if ($content -match "password|secret|api_key|token") {
    $findings += [PSCustomObject]@{
        rule_id = "SEC-001"
        domain = "security"
        severity = "CRITICAL"
        status = "VIOLATION"
        message = "Potential sensitive data or secret detected!"
    }
}

if ($findings.Count -gt 0) {
    Write-Host "[!] Security Check FAILED: Found $($findings.Count) violation(s)." -ForegroundColor Red
    $findings | Format-Table
    exit 1
} else {
    Write-Host "[+] Security Check PASSED: No secrets found." -ForegroundColor Green
    exit 0
}

