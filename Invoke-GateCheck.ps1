
param(
    [string]$InputType = "GOOD",
    [string]$Spec = "openapi.yaml"
)

Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "  GOVERNANCE CONTROL PLANE - GATE CHECK  " -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "Mode: $InputType`n" -ForegroundColor Yellow

if (!(Test-Path "rules\registry.yaml")) {
    Write-Host "[!] Warning: rules\registry.yaml not found!" -ForegroundColor Red
}

if ($InputType.ToUpper() -eq "ERROR" -or $InputType.ToUpper() -eq "BAD") {
    # Negative control / failure-injection path — proves the gate fails closed.
    # This does NOT run the real validators; it exercises run_all.py's
    # --test-failure-injection flag the same way validators/tests/test_process_boundary.py does.
    Write-Host "[*] Running failure-injection negative control (no real validators executed)..." -ForegroundColor Gray
    python run_all.py --test-failure-injection
    $exitCode = $LASTEXITCODE
    Write-Host "GATE DECISION: $(if ($exitCode -eq 0) { 'PASS' } else { 'BLOCK/ERROR' })" -ForegroundColor $(if ($exitCode -eq 0) { "Green" } else { "Red" })
    exit $exitCode
}

# Positive control — runs the real validation engine (validators/run_all.py,
# via the root run_all.py wrapper) against the given OpenAPI spec.
Write-Host "[*] Running real validation engine against $Spec..." -ForegroundColor Gray
python run_all.py --spec $Spec
$exitCode = $LASTEXITCODE
Write-Host "GATE DECISION: $(if ($exitCode -eq 0) { 'PASS' } else { 'BLOCK/ERROR' })" -ForegroundColor $(if ($exitCode -eq 0) { "Green" } else { "Red" })
exit $exitCode
