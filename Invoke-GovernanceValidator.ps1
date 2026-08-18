
param([string]$TargetFile = "registry\rules.yaml")
Write-Host "[*] Running Governance Validator against $TargetFile..." -ForegroundColor Cyan

$content = Get-Content $TargetFile -Raw
$findings = @()

# ?????? GOV-001: ??????????????????????????????
if ($content -notmatch "domain" -or $content -notmatch "severity") {
    $findings += [PSCustomObject]@{
        rule_id = "GOV-001"
        domain = "governance"
        severity = "HIGH"
        status = "VIOLATION"
        message = "Missing mandatory governance attributes (domain or severity)!"
    }
}

if ($findings.Count -gt 0) {
    Write-Host "[!] Governance Check FAILED: Found $($findings.Count) violation(s)." -ForegroundColor Red
    $findings | Format-Table
    exit 1
} else {
    Write-Host "[+] Governance Check PASSED: All governance policies met." -ForegroundColor Green
    exit 0
}

