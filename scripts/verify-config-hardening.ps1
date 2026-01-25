<#
.SYNOPSIS
    Verify NetBird Machine Tunnel configuration security hardening.

.DESCRIPTION
    This script checks the security configuration of NetBird Machine Tunnel:
    1. Filesystem ACLs on config directory
    2. Owner verification (should be SYSTEM)
    3. Permission verification (SYSTEM=Full, Admins=Read, Users=None)
    4. Config file permissions
    5. Setup key handling (should be encrypted or removed)

.PARAMETER Verbose
    Show detailed permission information.

.EXAMPLE
    .\verify-config-hardening.ps1
    Basic verification with pass/fail output.

.EXAMPLE
    .\verify-config-hardening.ps1 -Verbose
    Detailed permission listing.

.NOTES
    Requires: Administrator privileges (for some checks)
    Author: NetBird Machine Tunnel Fork
    Version: 1.0.0
#>

[CmdletBinding()]
param()

$DataPath = "$env:ProgramData\NetBird"
$ConfigPath = "$DataPath\config.yaml"

$issuesFound = $false

Write-Host @"

+=====================================================================+
|          NetBird Machine Tunnel - Security Verification             |
+=====================================================================+

"@ -ForegroundColor Cyan

# ============================================
# Check 1: Data Directory Exists
# ============================================
Write-Host ">> Checking: Data directory" -ForegroundColor Yellow

if (Test-Path $DataPath) {
    Write-Host "   [OK] Directory exists: $DataPath" -ForegroundColor Green
} else {
    Write-Host "   [FAIL] Directory not found: $DataPath" -ForegroundColor Red
    Write-Host "   Run install-netbird-machine.ps1 first." -ForegroundColor Yellow
    exit 1
}

# ============================================
# Check 2: Directory Owner
# ============================================
Write-Host "`n>> Checking: Directory owner" -ForegroundColor Yellow

$acl = Get-Acl $DataPath
$owner = $acl.Owner

if ($owner -eq "NT AUTHORITY\SYSTEM") {
    Write-Host "   [OK] Owner is SYSTEM" -ForegroundColor Green
} else {
    Write-Host "   [FAIL] Owner is $owner (expected: NT AUTHORITY\SYSTEM)" -ForegroundColor Red
    $issuesFound = $true
}

# ============================================
# Check 3: Directory ACLs
# ============================================
Write-Host "`n>> Checking: Directory ACLs" -ForegroundColor Yellow

$expectedAcls = @{
    "NT AUTHORITY\SYSTEM" = @("FullControl")
    "BUILTIN\Administrators" = @("ReadAndExecute", "Synchronize")
}

$accessRules = $acl.Access

# Check inheritance is disabled
if ($acl.AreAccessRulesProtected) {
    Write-Host "   [OK] Inheritance disabled" -ForegroundColor Green
} else {
    Write-Host "   [WARN] Inheritance NOT disabled (security risk)" -ForegroundColor Yellow
    $issuesFound = $true
}

# Check SYSTEM has Full Control
$systemRule = $accessRules | Where-Object { $_.IdentityReference -eq "NT AUTHORITY\SYSTEM" }
if ($systemRule -and $systemRule.FileSystemRights -match "FullControl") {
    Write-Host "   [OK] SYSTEM: Full Control" -ForegroundColor Green
} else {
    Write-Host "   [FAIL] SYSTEM does not have Full Control" -ForegroundColor Red
    $issuesFound = $true
}

# Check Administrators have Read only (not Write)
$adminRule = $accessRules | Where-Object { $_.IdentityReference -eq "BUILTIN\Administrators" }
if ($adminRule) {
    $hasWrite = $adminRule.FileSystemRights -match "Write|Modify|FullControl"
    if ($hasWrite) {
        Write-Host "   [WARN] Administrators have WRITE access (should be Read only)" -ForegroundColor Yellow
        $issuesFound = $true
    } else {
        Write-Host "   [OK] Administrators: Read & Execute (no Write)" -ForegroundColor Green
    }
} else {
    Write-Host "   [WARN] No explicit Administrators rule" -ForegroundColor Yellow
}

# Check for Users access (should be none)
$usersRule = $accessRules | Where-Object { $_.IdentityReference -match "Users|Everyone|Authenticated Users" }
if ($usersRule) {
    Write-Host "   [FAIL] Users/Everyone have access (should be none)" -ForegroundColor Red
    foreach ($rule in $usersRule) {
        Write-Host "          $($rule.IdentityReference): $($rule.FileSystemRights)" -ForegroundColor Red
    }
    $issuesFound = $true
} else {
    Write-Host "   [OK] Users: No access" -ForegroundColor Green
}

# Verbose: Show all rules
if ($VerbosePreference -eq 'Continue') {
    Write-Host "`n   All ACL entries:" -ForegroundColor Gray
    foreach ($rule in $accessRules) {
        Write-Host "     $($rule.IdentityReference): $($rule.FileSystemRights) ($($rule.AccessControlType))" -ForegroundColor Gray
    }
}

# ============================================
# Check 4: Config File
# ============================================
Write-Host "`n>> Checking: Config file" -ForegroundColor Yellow

if (Test-Path $ConfigPath) {
    Write-Host "   [OK] Config exists: $ConfigPath" -ForegroundColor Green

    # Check config ACLs
    $configAcl = Get-Acl $ConfigPath
    $configOwner = $configAcl.Owner

    if ($configOwner -eq "NT AUTHORITY\SYSTEM") {
        Write-Host "   [OK] Config owner is SYSTEM" -ForegroundColor Green
    } else {
        Write-Host "   [WARN] Config owner is $configOwner (expected: SYSTEM)" -ForegroundColor Yellow
    }

    # Check for plaintext setup key
    $configContent = Get-Content $ConfigPath -Raw -ErrorAction SilentlyContinue
    if ($configContent -match 'setup_key:\s*"[^"]+"|setup_key:\s*[^\s#]+') {
        Write-Host "   [WARN] Plaintext setup_key found in config!" -ForegroundColor Yellow
        Write-Host "          Should be: setup_key_encrypted (DPAPI)" -ForegroundColor Yellow
        Write-Host "          Or removed after mTLS enrollment" -ForegroundColor Yellow
        $issuesFound = $true
    } elseif ($configContent -match 'setup_key_encrypted:') {
        Write-Host "   [OK] Setup key is DPAPI encrypted" -ForegroundColor Green
    } else {
        Write-Host "   [OK] No setup key in config (mTLS mode)" -ForegroundColor Green
    }
} else {
    Write-Host "   [--] Config not found (may be OK if not yet configured)" -ForegroundColor Gray
}

# ============================================
# Check 5: Service Status
# ============================================
Write-Host "`n>> Checking: Service" -ForegroundColor Yellow

$service = Get-Service -Name "NetBirdMachine" -ErrorAction SilentlyContinue
if ($service) {
    Write-Host "   [OK] Service installed" -ForegroundColor Green
    Write-Host "   Status: $($service.Status)" -ForegroundColor $(if ($service.Status -eq 'Running') { 'Green' } else { 'Yellow' })

    # Check service account
    $serviceWmi = Get-WmiObject Win32_Service -Filter "Name='NetBirdMachine'" -ErrorAction SilentlyContinue
    if ($serviceWmi) {
        if ($serviceWmi.StartName -eq "LocalSystem") {
            Write-Host "   [OK] Service runs as LocalSystem" -ForegroundColor Green
        } else {
            Write-Host "   [WARN] Service runs as $($serviceWmi.StartName) (expected: LocalSystem)" -ForegroundColor Yellow
        }
    }
} else {
    Write-Host "   [--] Service not installed" -ForegroundColor Gray
}

# ============================================
# Check 6: EventLog Source
# ============================================
Write-Host "`n>> Checking: EventLog source" -ForegroundColor Yellow

$eventLogSource = "NetBirdMachine"
if ([System.Diagnostics.EventLog]::SourceExists($eventLogSource)) {
    Write-Host "   [OK] EventLog source registered: $eventLogSource" -ForegroundColor Green
} else {
    Write-Host "   [WARN] EventLog source not registered" -ForegroundColor Yellow
}

# ============================================
# Summary
# ============================================
Write-Host ""
if ($issuesFound) {
    Write-Host "+=====================================================================+" -ForegroundColor Yellow
    Write-Host "|  VERIFICATION WARNING: Security issues found                        |" -ForegroundColor Yellow
    Write-Host "+=====================================================================+" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Run install-netbird-machine.ps1 to fix ACLs." -ForegroundColor Yellow
    Write-Host "Or manually fix with:" -ForegroundColor Gray
    Write-Host '  $acl = Get-Acl $env:ProgramData\NetBird' -ForegroundColor Gray
    Write-Host '  $acl.SetAccessRuleProtection($true, $false)' -ForegroundColor Gray
    Write-Host '  Set-Acl -Path $env:ProgramData\NetBird -AclObject $acl' -ForegroundColor Gray
    exit 1
} else {
    Write-Host "+=====================================================================+" -ForegroundColor Green
    Write-Host "|  VERIFICATION PASSED: Security hardening is properly configured     |" -ForegroundColor Green
    Write-Host "+=====================================================================+" -ForegroundColor Green
    exit 0
}
