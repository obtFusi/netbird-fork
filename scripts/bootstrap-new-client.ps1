<#
.SYNOPSIS
    Bootstraps a new Windows client for NetBird Machine Tunnel.

.DESCRIPTION
    This script performs the complete two-phase bootstrap workflow:

    Phase 1 (Setup-Key):
    1. Install NetBird Machine Binary
    2. Configure with Setup-Key (DPAPI encrypted)
    3. Start service, establish tunnel
    4. Verify DC connectivity

    Phase 2 (Domain Join + mTLS):
    5. Sync NTP (required for Kerberos)
    6. Join Active Directory domain
    7. Trigger certificate enrollment
    8. Update config for mTLS (Smart Cert Selection)
    9. Restart service with mTLS

    IMPORTANT: Revoke the setup-key in NetBird Dashboard after bootstrap!

.PARAMETER SetupKey
    Temporary setup key from NetBird Dashboard.
    - 24 hour TTL (configurable in dashboard)
    - One-time use per machine
    - MUST be revoked after successful bootstrap

.PARAMETER DomainName
    Active Directory domain to join (e.g., corp.local).

.PARAMETER ManagementURL
    NetBird Management Server URL (default: from existing config or prompt).

.PARAMETER DomainController
    Optional: Specific DC IP to use for connectivity test.
    If not specified, uses DNS to discover DCs.

.PARAMETER SkipDomainJoin
    Skip domain join (useful if machine is already domain-joined).

.PARAMETER SkipCertEnrollment
    Skip certificate enrollment (useful for manual cert management).

.PARAMETER BinaryPath
    Path to netbird-machine.exe binary (if not already installed).

.PARAMETER Force
    Skip confirmation prompts.

.EXAMPLE
    .\bootstrap-new-client.ps1 -SetupKey "nb-setup-abc123" -DomainName "corp.local"
    Full bootstrap with prompts.

.EXAMPLE
    .\bootstrap-new-client.ps1 -SetupKey "nb-setup-abc123" -DomainName "corp.local" -Force
    Full bootstrap without prompts.

.EXAMPLE
    .\bootstrap-new-client.ps1 -SetupKey "nb-setup-abc123" -DomainName "corp.local" -SkipDomainJoin
    Bootstrap for already domain-joined machine.

.NOTES
    Requires: Administrator privileges
    Author: NetBird Machine Tunnel Fork
    Version: 1.0.0
    Security: Setup-Key is redacted in logs (only last 4 chars shown)
#>

#Requires -RunAsAdministrator

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$SetupKey,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*$')]
    [string]$DomainName,

    [Parameter(Mandatory = $false)]
    [ValidatePattern('^https?://')]
    [string]$ManagementURL,

    [Parameter(Mandatory = $false)]
    [string]$DomainController,

    [Parameter(Mandatory = $false)]
    [switch]$SkipDomainJoin,

    [Parameter(Mandatory = $false)]
    [switch]$SkipCertEnrollment,

    [Parameter(Mandatory = $false)]
    [ValidateScript({ Test-Path $_ })]
    [string]$BinaryPath,

    [Parameter(Mandatory = $false)]
    [switch]$Force
)

$ErrorActionPreference = 'Stop'

# Configuration
$ServiceName = "NetBirdMachine"
$InterfaceName = "wg-nb-machine"
$ConfigDir = "$env:ProgramData\NetBird"
$ConfigPath = "$ConfigDir\config.yaml"
$InstallPath = "$env:ProgramFiles\NetBird Machine"
$LogPath = "$ConfigDir\bootstrap.log"

# Security: Redact setup key in logs (show only last 4 chars)
$SetupKeyRedacted = if ($SetupKey.Length -gt 4) {
    "***" + $SetupKey.Substring($SetupKey.Length - 4)
} else {
    "****"
}

#region Helper Functions

function Write-Step {
    param([string]$Step, [string]$Message)
    $text = "[$Step] $Message"
    Write-Host $text -ForegroundColor Cyan
    Add-Content -Path $LogPath -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') $text"
}

function Write-Success {
    param([string]$Message)
    Write-Host "  [OK] $Message" -ForegroundColor Green
    Add-Content -Path $LogPath -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')   [OK] $Message"
}

function Write-Failure {
    param([string]$Message)
    Write-Host "  [FAIL] $Message" -ForegroundColor Red
    Add-Content -Path $LogPath -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')   [FAIL] $Message"
}

function Write-Warning {
    param([string]$Message)
    Write-Host "  [WARN] $Message" -ForegroundColor Yellow
    Add-Content -Path $LogPath -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')   [WARN] $Message"
}

function Write-Info {
    param([string]$Message)
    Write-Host "  $Message" -ForegroundColor Gray
    Add-Content -Path $LogPath -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')   $Message"
}

function Test-Administrator {
    $currentUser = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentUser.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-DCFromDNS {
    param([string]$Domain)
    try {
        $dcs = Resolve-DnsName -Name "_ldap._tcp.dc._msdcs.$Domain" -Type SRV -ErrorAction Stop
        if ($dcs) {
            $dcName = $dcs[0].NameTarget
            $dcIPs = Resolve-DnsName -Name $dcName -Type A -ErrorAction Stop
            return $dcIPs[0].IPAddress
        }
    } catch {
        return $null
    }
    return $null
}

function Test-DCConnectivity {
    param(
        [string]$DC,
        [int]$TimeoutSec = 5
    )

    $ports = @(
        @{ Port = 389; Name = "LDAP" },
        @{ Port = 88; Name = "Kerberos" },
        @{ Port = 53; Name = "DNS" }
    )

    $allOk = $true
    foreach ($p in $ports) {
        $result = Test-NetConnection -ComputerName $DC -Port $p.Port -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
        if ($result.TcpTestSucceeded) {
            Write-Info "  $($p.Name) (TCP $($p.Port)): OK"
        } else {
            Write-Info "  $($p.Name) (TCP $($p.Port)): FAILED"
            $allOk = $false
        }
    }

    return $allOk
}

function Wait-TunnelUp {
    param([int]$TimeoutSeconds = 60)

    $elapsed = 0
    while ($elapsed -lt $TimeoutSeconds) {
        $adapter = Get-NetAdapter -Name $InterfaceName -ErrorAction SilentlyContinue
        if ($adapter -and $adapter.Status -eq 'Up') {
            return $true
        }
        Start-Sleep -Seconds 2
        $elapsed += 2
        Write-Host "." -NoNewline
    }
    Write-Host ""
    return $false
}

function Find-MachineCertificate {
    # Smart Cert Selection: Find the best machine certificate
    $certs = Get-ChildItem Cert:\LocalMachine\My | Where-Object {
        # Must have Client Authentication EKU
        $hasClientAuth = $_.EnhancedKeyUsageList | Where-Object { $_.ObjectId -eq "1.3.6.1.5.5.7.3.2" }

        # Must have SAN with machine DNS name
        $hasSAN = $_.DnsNameList.Count -gt 0

        # Must not be expired
        $notExpired = $_.NotAfter -gt (Get-Date)

        # Must be valid (not before)
        $isValid = $_.NotBefore -lt (Get-Date)

        $hasClientAuth -and $hasSAN -and $notExpired -and $isValid
    } | Sort-Object NotAfter -Descending

    if ($certs) {
        return $certs[0]
    }
    return $null
}

#endregion

#region Pre-flight Checks

# Check administrator
if (-not (Test-Administrator)) {
    throw "This script must be run as Administrator"
}

# Create directories
if (-not (Test-Path $ConfigDir)) {
    New-Item -Path $ConfigDir -ItemType Directory -Force | Out-Null
}

# Initialize log
"" | Out-File $LogPath -Force
Add-Content -Path $LogPath -Value "=== NetBird Machine Bootstrap Log ==="
Add-Content -Path $LogPath -Value "Started: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Add-Content -Path $LogPath -Value "Setup-Key: $SetupKeyRedacted"
Add-Content -Path $LogPath -Value "Domain: $DomainName"
Add-Content -Path $LogPath -Value ""

#endregion

#region Main Script

Write-Host @"

+=====================================================================+
|          NetBird Machine Tunnel - Client Bootstrap                  |
+=====================================================================+

Setup-Key: $SetupKeyRedacted
Domain:    $DomainName

"@ -ForegroundColor Cyan

# Confirmation
if (-not $Force) {
    $confirm = Read-Host "This will bootstrap the machine for NetBird. Continue? (y/N)"
    if ($confirm -ne 'y' -and $confirm -ne 'Y') {
        Write-Host "Aborted." -ForegroundColor Yellow
        exit 0
    }
}

# ============================================
# Step 1: Install Binary (if provided)
# ============================================
Write-Step "1/9" "Installing NetBird Machine binary"

if ($BinaryPath) {
    if (-not (Test-Path $InstallPath)) {
        New-Item -Path $InstallPath -ItemType Directory -Force | Out-Null
    }

    $targetBinary = Join-Path $InstallPath "netbird-machine.exe"
    Copy-Item -Path $BinaryPath -Destination $targetBinary -Force
    Write-Success "Binary installed to: $targetBinary"

    # Install service
    if ($PSCmdlet.ShouldProcess($targetBinary, "Install service")) {
        $result = & $targetBinary install 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Success "Service installed"
        } else {
            Write-Failure "Service install failed: $result"
            throw "Service installation failed"
        }
    }
} else {
    $existingBinary = Get-Command netbird-machine.exe -ErrorAction SilentlyContinue
    if ($existingBinary) {
        Write-Success "Using existing binary: $($existingBinary.Source)"
    } else {
        Write-Failure "Binary not found and -BinaryPath not specified"
        throw "NetBird Machine binary not found. Specify -BinaryPath or install manually."
    }
}

# ============================================
# Step 2: Get Management URL
# ============================================
Write-Step "2/9" "Configuring management URL"

if (-not $ManagementURL) {
    # Try to read from existing config
    if (Test-Path $ConfigPath) {
        $existingConfig = Get-Content $ConfigPath -Raw
        if ($existingConfig -match 'management_url:\s*"([^"]+)"') {
            $ManagementURL = $Matches[1]
            Write-Success "Using existing management URL: $ManagementURL"
        }
    }

    if (-not $ManagementURL) {
        $ManagementURL = Read-Host "Enter Management Server URL (e.g., https://netbird.example.com:443)"
        if (-not $ManagementURL) {
            throw "Management URL is required"
        }
    }
} else {
    Write-Success "Management URL: $ManagementURL"
}

# ============================================
# Step 3: Create Phase 1 Config (Setup-Key)
# ============================================
Write-Step "3/9" "Creating Phase 1 config (Setup-Key authentication)"

$phase1Config = @"
# NetBird Machine Tunnel - Phase 1 (Setup-Key Bootstrap)
# Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
# WARNING: Setup-Key will be removed after mTLS enrollment!

management_url: "$ManagementURL"
setup_key: "$SetupKey"
tunnel_mode: "machine"

# Phase 1: Using Setup-Key for initial authentication
# After domain join + cert enrollment, this will switch to mTLS
"@

if ($PSCmdlet.ShouldProcess($ConfigPath, "Write Phase 1 config")) {
    $phase1Config | Out-File $ConfigPath -Encoding UTF8 -Force
    Write-Success "Config written to: $ConfigPath"
}

# ============================================
# Step 4: Start Service & Establish Tunnel
# ============================================
Write-Step "4/9" "Starting service and establishing tunnel"

if ($PSCmdlet.ShouldProcess($ServiceName, "Start service")) {
    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if (-not $service) {
        throw "Service $ServiceName not found. Is the binary installed?"
    }

    if ($service.Status -eq 'Running') {
        Stop-Service -Name $ServiceName -Force
        Start-Sleep -Seconds 2
    }

    Start-Service -Name $ServiceName
    Write-Success "Service started"

    # Wait for tunnel
    Write-Host "  Waiting for tunnel interface" -NoNewline
    if (Wait-TunnelUp -TimeoutSeconds 60) {
        Write-Success "Tunnel established"

        # Show interface details
        $adapter = Get-NetAdapter -Name $InterfaceName
        $ipConfig = Get-NetIPAddress -InterfaceAlias $InterfaceName -ErrorAction SilentlyContinue
        Write-Info "Interface: $($adapter.Name) - $($adapter.Status)"
        if ($ipConfig) {
            Write-Info "IP Address: $($ipConfig.IPAddress)"
        }
    } else {
        Write-Failure "Tunnel did not come up within 60 seconds"
        Write-Warning "Check service logs: Get-EventLog -LogName Application -Source $ServiceName -Newest 20"
        throw "Tunnel establishment failed"
    }
}

# ============================================
# Step 5: Discover and Verify DC Connectivity
# ============================================
Write-Step "5/9" "Verifying Domain Controller connectivity"

$dcIP = $DomainController
if (-not $dcIP) {
    Write-Info "Discovering DC via DNS..."
    $dcIP = Get-DCFromDNS -Domain $DomainName
}

if (-not $dcIP) {
    Write-Warning "Could not discover DC via DNS"
    $dcIP = Read-Host "Enter Domain Controller IP"
}

Write-Info "Testing connectivity to DC: $dcIP"
if (Test-DCConnectivity -DC $dcIP) {
    Write-Success "DC reachable via tunnel"
} else {
    Write-Failure "DC not fully reachable"
    Write-Warning "Some services may fail. Continue anyway? (y/N)"
    $continueAnyway = Read-Host
    if ($continueAnyway -ne 'y' -and $continueAnyway -ne 'Y') {
        throw "DC connectivity check failed"
    }
}

# ============================================
# Step 6: NTP Sync (Critical for Kerberos!)
# ============================================
Write-Step "6/9" "Configuring NTP (required for Kerberos, tolerance +/- 5 min)"

if ($PSCmdlet.ShouldProcess("W32Time", "Configure NTP")) {
    # Configure NTP to use DC
    w32tm /config /manualpeerlist:"$dcIP" /syncfromflags:manual /reliable:no /update 2>&1 | Out-Null

    # Restart time service
    Restart-Service W32Time -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2

    # Force sync
    w32tm /resync /nowait 2>&1 | Out-Null

    Write-Success "NTP configured to sync with: $dcIP"

    # Check time offset
    $timeStatus = w32tm /stripchart /computer:$dcIP /samples:1 /dataonly 2>&1
    if ($timeStatus -match '([+-]?\d+\.\d+)s') {
        $offset = [math]::Abs([double]$Matches[1])
        if ($offset -lt 300) {
            Write-Success "Time offset: ${offset}s (within Kerberos tolerance)"
        } else {
            Write-Warning "Time offset: ${offset}s (exceeds 5 min Kerberos tolerance!)"
        }
    }
}

# ============================================
# Step 7: Domain Join
# ============================================
if (-not $SkipDomainJoin) {
    Write-Step "7/9" "Joining Active Directory domain: $DomainName"

    # Check if already joined
    $computerSystem = Get-WmiObject Win32_ComputerSystem
    if ($computerSystem.PartOfDomain -and $computerSystem.Domain -eq $DomainName) {
        Write-Success "Already joined to $DomainName"
    } else {
        if ($PSCmdlet.ShouldProcess($DomainName, "Join domain")) {
            Write-Host ""
            Write-Host "  Enter credentials for domain join:" -ForegroundColor Yellow
            $credential = Get-Credential -Message "Domain Admin credentials for $DomainName"

            try {
                Add-Computer -DomainName $DomainName -Credential $credential -Restart:$false -Force
                Write-Success "Domain join successful (reboot required later)"
            } catch {
                Write-Failure "Domain join failed: $_"
                throw "Domain join failed"
            }
        }
    }
} else {
    Write-Step "7/9" "Skipping domain join (--SkipDomainJoin)"
}

# ============================================
# Step 8: Certificate Enrollment
# ============================================
if (-not $SkipCertEnrollment) {
    Write-Step "8/9" "Requesting machine certificate via AD CS"

    if ($PSCmdlet.ShouldProcess("Machine Certificate", "Request enrollment")) {
        # Force GPO refresh to trigger auto-enrollment
        Write-Info "Forcing Group Policy update..."
        gpupdate /force /target:computer 2>&1 | Out-Null
        Start-Sleep -Seconds 10

        # Check for certificate
        $cert = Find-MachineCertificate
        if ($cert) {
            Write-Success "Machine certificate found:"
            Write-Info "  Subject: $($cert.Subject)"
            Write-Info "  Issuer: $($cert.Issuer)"
            Write-Info "  Expires: $($cert.NotAfter)"
            Write-Info "  Thumbprint: $($cert.Thumbprint)"

            # Check SAN
            $san = $cert.DnsNameList | ForEach-Object { $_.Unicode }
            Write-Info "  SAN DNS Names: $($san -join ', ')"
        } else {
            Write-Warning "Machine certificate not found"
            Write-Info "Certificate enrollment may take additional time."
            Write-Info "Manual enrollment: certreq.exe -enroll -machine 'Machine'"

            # Try manual enrollment
            Write-Info "Attempting manual enrollment..."
            $enrollResult = certreq.exe -enroll -machine "Machine" 2>&1
            Start-Sleep -Seconds 5

            $cert = Find-MachineCertificate
            if ($cert) {
                Write-Success "Certificate enrolled successfully"
            } else {
                Write-Warning "Certificate still not available. Continue with Phase 2 anyway."
            }
        }
    }
} else {
    Write-Step "8/9" "Skipping certificate enrollment (--SkipCertEnrollment)"
}

# ============================================
# Step 9: Update Config for mTLS (Phase 2)
# ============================================
Write-Step "9/9" "Updating config for mTLS (Smart Cert Selection)"

$phase2Config = @"
# NetBird Machine Tunnel - Phase 2 (mTLS Authentication)
# Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
# Bootstrap completed - now using machine certificate for authentication

management_url: "$ManagementURL"
tunnel_mode: "machine"

# v3.6: Smart Cert Selection
# The client will automatically find and use the correct machine certificate
# based on: Client Auth EKU, SAN DNS Name, validity period
machine_cert_enabled: true
machine_cert_san_must_match: true

# Certificate selection criteria (Smart Selection):
# 1. Must have Client Authentication EKU (1.3.6.1.5.5.7.3.2)
# 2. Must have SAN DNS Name matching hostname.domain
# 3. Must be valid (not expired, not before)
# 4. Prefers certificate with latest expiry

# IMPORTANT: Setup-Key has been REMOVED
# ===> REVOKE the setup-key in NetBird Dashboard! <===
"@

if ($PSCmdlet.ShouldProcess($ConfigPath, "Write Phase 2 config")) {
    $phase2Config | Out-File $ConfigPath -Encoding UTF8 -Force
    Write-Success "Config updated for mTLS"

    # Restart service to use new config
    Write-Info "Restarting service with mTLS authentication..."
    Restart-Service $ServiceName
    Start-Sleep -Seconds 5

    $service = Get-Service -Name $ServiceName
    if ($service.Status -eq 'Running') {
        Write-Success "Service restarted with mTLS"
    } else {
        Write-Warning "Service status: $($service.Status)"
    }
}

# ============================================
# Summary
# ============================================
Write-Host @"

+=====================================================================+
|                    Bootstrap Complete                               |
+=====================================================================+

Phase 1 (Setup-Key): COMPLETE
Phase 2 (mTLS):      $(if ($cert) { "COMPLETE" } else { "PENDING (certificate enrollment)" })

IMPORTANT NEXT STEPS:
"@ -ForegroundColor Green

Write-Host @"
1. REVOKE the setup-key in NetBird Dashboard!
   Setup-Key: $SetupKeyRedacted
   This is critical for security.

2. If domain was joined, REBOOT the machine:

   Restart-Computer -Force

3. Verify mTLS authentication:
   - Check service logs for 'RegisterMachinePeer...success'
   - Dashboard should show machine peer with certificate info

4. If certificate is pending:
   - Run: gpupdate /force
   - Or: certreq.exe -enroll -machine "Machine"
   - Then: Restart-Service $ServiceName

"@ -ForegroundColor Yellow

Write-Host "Log file: $LogPath" -ForegroundColor Gray

# Add final log entry
Add-Content -Path $LogPath -Value ""
Add-Content -Path $LogPath -Value "=== Bootstrap Completed: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ==="

#endregion
