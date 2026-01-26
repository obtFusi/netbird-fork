<#
.SYNOPSIS
    E2E Test: Domain-Join über Machine Tunnel
    Tests the full bootstrap flow: Setup-Key -> Tunnel -> Domain Join -> Cert -> mTLS

.DESCRIPTION
    This Pester test validates the complete two-phase bootstrap process:
    - Phase 1: Setup-Key authentication, tunnel establishment, domain join
    - Phase 2: Machine certificate enrollment, mTLS transition

    Designed to run on a fresh Windows VM with snapshot restore capability.

.PARAMETER VMHost
    Proxmox host for snapshot management.

.PARAMETER VMID
    VM ID on Proxmox for the test client.

.PARAMETER SnapshotName
    Snapshot name to restore before test (clean state).

.PARAMETER SetupKey
    NetBird Setup-Key for bootstrap.

.PARAMETER DomainName
    Target AD domain (e.g., "corp.local").

.PARAMETER DCAddress
    Domain Controller IP address.

.PARAMETER CertTemplateName
    AD CS certificate template name.

.EXAMPLE
    Invoke-Pester -Script @{
        Path = ".\Test-DomainJoinViaTunnel.ps1"
        Parameters = @{
            SetupKey = "a1b2c3d4-..."
            DomainName = "corp.local"
            DCAddress = "192.168.100.20"
        }
    }

.NOTES
    Prerequisites:
    - Pester v5+
    - Administrator privileges
    - NetBird Machine binary installed
    - Network access to DC (via tunnel)
    - AD CS certificate template configured
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$VMHost = "",

    [Parameter(Mandatory = $false)]
    [int]$VMID = 0,

    [Parameter(Mandatory = $false)]
    [string]$SnapshotName = "pre-bootstrap",

    [Parameter(Mandatory = $true)]
    [string]$SetupKey,

    [Parameter(Mandatory = $true)]
    [string]$DomainName,

    [Parameter(Mandatory = $true)]
    [string]$DCAddress,

    [Parameter(Mandatory = $false)]
    [string]$CertTemplateName = "NetBirdMachineTunnel",

    [Parameter(Mandatory = $false)]
    [string]$OUPath = "",

    [Parameter(Mandatory = $false)]
    [PSCredential]$DomainCredential
)

# Import Pester if needed
if (-not (Get-Module -Name Pester -ListAvailable | Where-Object Version -ge '5.0.0')) {
    throw "Pester v5+ is required. Install with: Install-Module Pester -Force -SkipPublisherCheck"
}
Import-Module Pester -MinimumVersion 5.0.0

# Configuration
$script:Config = @{
    ServiceName = "NetBirdMachine"
    ConfigPath = "$env:ProgramData\NetBird\config.yaml"
    LogPath = "$env:ProgramData\NetBird\machine-tunnel.log"
    TunnelInterface = "wg-nb-machine"
    TunnelTimeout = 60
    DCPorts = @(389, 88, 53)  # LDAP, Kerberos, DNS
}

#region Helper Functions

function Restore-VMSnapshot {
    param([string]$Host, [int]$VMID, [string]$Snapshot)

    if (-not $Host -or $VMID -eq 0) {
        Write-Warning "VM snapshot restore skipped (no VMHost/VMID configured)"
        return $false
    }

    try {
        # SSH to Proxmox and restore snapshot
        $result = ssh "root@$Host" "qm rollback $VMID $Snapshot" 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Host "VM snapshot '$Snapshot' restored" -ForegroundColor Green
            return $true
        } else {
            Write-Warning "Snapshot restore failed: $result"
            return $false
        }
    } catch {
        Write-Warning "Snapshot restore error: $_"
        return $false
    }
}

function Wait-ServiceRunning {
    param([string]$ServiceName, [int]$TimeoutSeconds = 30)

    $elapsed = 0
    while ($elapsed -lt $TimeoutSeconds) {
        $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if ($service -and $service.Status -eq 'Running') {
            return $true
        }
        Start-Sleep -Seconds 2
        $elapsed += 2
    }
    return $false
}

function Wait-TunnelInterface {
    param([string]$InterfaceName, [int]$TimeoutSeconds = 60)

    $elapsed = 0
    while ($elapsed -lt $TimeoutSeconds) {
        $interface = Get-NetAdapter -Name $InterfaceName -ErrorAction SilentlyContinue
        if ($interface -and $interface.Status -eq 'Up') {
            return $true
        }
        Start-Sleep -Seconds 2
        $elapsed += 2
    }
    return $false
}

function Test-PortConnectivity {
    param([string]$Host, [int]$Port)

    try {
        $result = Test-NetConnection -ComputerName $Host -Port $Port -WarningAction SilentlyContinue -ErrorAction Stop
        return $result.TcpTestSucceeded
    } catch {
        return $false
    }
}

function Get-MachineCertificate {
    param([string]$Hostname, [string]$Domain)

    $fqdn = "$Hostname.$Domain"

    # Find certificate with matching SAN or Subject
    $certs = Get-ChildItem Cert:\LocalMachine\My | Where-Object {
        ($_.DnsNameList -and $_.DnsNameList.Unicode -contains $fqdn) -or
        ($_.Subject -match "CN=$Hostname")
    }

    # Return most recent valid cert
    return $certs |
        Where-Object { $_.NotAfter -gt (Get-Date) } |
        Sort-Object NotAfter -Descending |
        Select-Object -First 1
}

#endregion

#region Pester Tests

Describe "T-6.3: Domain-Join über Tunnel E2E Test" -Tag "E2E", "DomainJoin", "T-6.3" {

    BeforeAll {
        # Store original computer state
        $script:OriginalComputerInfo = Get-WmiObject Win32_ComputerSystem
        $script:WasInDomain = $script:OriginalComputerInfo.PartOfDomain

        # Verify admin privileges
        $currentUser = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
        if (-not $currentUser.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            throw "This test requires Administrator privileges"
        }

        Write-Host "`n=== T-6.3: Domain-Join E2E Test ===" -ForegroundColor Cyan
        Write-Host "Domain: $DomainName"
        Write-Host "DC: $DCAddress"
        Write-Host "Template: $CertTemplateName"
        Write-Host ""
    }

    Context "Phase 0: Baseline Verification" {

        It "Should NOT have DC connectivity before tunnel" {
            # DC should be unreachable without tunnel
            $reachable = Test-PortConnectivity -Host $DCAddress -Port 389
            $reachable | Should -Be $false -Because "DC should be isolated before tunnel establishment"
        }

        It "Should NOT resolve domain DNS before tunnel" {
            $dns = Resolve-DnsName "$DomainName" -ErrorAction SilentlyContinue
            $dns | Should -BeNullOrEmpty -Because "Domain DNS should not resolve before NRPT"
        }

        It "Should have NetBird service installed" {
            $service = Get-Service -Name $script:Config.ServiceName -ErrorAction SilentlyContinue
            $service | Should -Not -BeNullOrEmpty
        }
    }

    Context "Phase 1: Setup-Key Bootstrap" {

        It "Should update config with Setup-Key" {
            # Update config with setup key
            if (Test-Path $script:Config.ConfigPath) {
                $config = Get-Content $script:Config.ConfigPath -Raw
                if ($config -notmatch 'setup_key:') {
                    Add-Content $script:Config.ConfigPath "`nsetup_key: $SetupKey"
                } else {
                    $config = $config -replace 'setup_key:.*', "setup_key: $SetupKey"
                    Set-Content $script:Config.ConfigPath $config
                }
            }

            $configContent = Get-Content $script:Config.ConfigPath -Raw
            $configContent | Should -Match "setup_key:" -Because "Config must contain Setup-Key"
        }

        It "Should start NetBird service" {
            Start-Service $script:Config.ServiceName -ErrorAction SilentlyContinue
            $started = Wait-ServiceRunning -ServiceName $script:Config.ServiceName -TimeoutSeconds 30
            $started | Should -Be $true -Because "Service must start successfully"
        }

        It "Should establish tunnel interface within 60 seconds" {
            $tunnelUp = Wait-TunnelInterface -InterfaceName $script:Config.TunnelInterface -TimeoutSeconds $script:Config.TunnelTimeout
            $tunnelUp | Should -Be $true -Because "Tunnel interface must come up"
        }

        It "Should have WireGuard IP address assigned" {
            $interface = Get-NetAdapter -Name $script:Config.TunnelInterface -ErrorAction SilentlyContinue
            $ipConfig = Get-NetIPAddress -InterfaceIndex $interface.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue

            $ipConfig | Should -Not -BeNullOrEmpty
            $ipConfig.IPAddress | Should -Match "^100\.64\." -Because "WireGuard IP should be in 100.64.0.0/10 CGNAT range"
        }
    }

    Context "Phase 1: DC Connectivity via Tunnel" {

        It "Should reach DC LDAP (port 389) via tunnel" {
            $reachable = Test-PortConnectivity -Host $DCAddress -Port 389
            $reachable | Should -Be $true -Because "DC LDAP must be reachable via tunnel"
        }

        It "Should reach DC Kerberos (port 88) via tunnel" {
            $reachable = Test-PortConnectivity -Host $DCAddress -Port 88
            $reachable | Should -Be $true -Because "DC Kerberos must be reachable via tunnel"
        }

        It "Should reach DC DNS (port 53) via tunnel" {
            $reachable = Test-PortConnectivity -Host $DCAddress -Port 53
            $reachable | Should -Be $true -Because "DC DNS must be reachable via tunnel"
        }

        It "Should resolve domain DNS via NRPT" {
            # Allow time for NRPT rules to apply
            Start-Sleep -Seconds 5

            $dns = Resolve-DnsName "dc01.$DomainName" -ErrorAction SilentlyContinue
            $dns | Should -Not -BeNullOrEmpty -Because "Domain DNS should resolve via NRPT"
        }
    }

    Context "Phase 1: Domain Join" {

        BeforeAll {
            # Skip if already joined to target domain
            $computerSystem = Get-WmiObject Win32_ComputerSystem
            $script:AlreadyJoined = ($computerSystem.PartOfDomain -and $computerSystem.Domain -eq $DomainName)
        }

        It "Should successfully join domain" -Skip:$script:AlreadyJoined {
            # Get credentials if not provided
            if (-not $DomainCredential) {
                $DomainCredential = Get-Credential -Message "Enter domain admin credentials for $DomainName"
            }

            $joinParams = @{
                DomainName = $DomainName
                Credential = $DomainCredential
                Force = $true
                Restart = $false
            }

            if ($OUPath) {
                $joinParams.OUPath = $OUPath
            }

            { Add-Computer @joinParams } | Should -Not -Throw
        }

        It "Should be member of target domain" -Skip:(-not $script:AlreadyJoined) {
            $computerSystem = Get-WmiObject Win32_ComputerSystem
            $computerSystem.PartOfDomain | Should -Be $true
            $computerSystem.Domain | Should -Be $DomainName
        }
    }

    Context "Phase 2: Certificate Enrollment" {

        BeforeAll {
            $script:CertEnrolled = $false
        }

        It "Should request machine certificate from AD CS" {
            # Create certificate request
            $infContent = @"
[NewRequest]
Subject = "CN=$env:COMPUTERNAME.$DomainName"
KeySpec = 1
KeyLength = 2048
Exportable = TRUE
MachineKeySet = TRUE
SMIME = FALSE
PrivateKeyArchive = FALSE
UserProtected = FALSE
UseExistingKeySet = FALSE
ProviderName = "Microsoft RSA SChannel Cryptographic Provider"
ProviderType = 12
RequestType = PKCS10
KeyUsage = 0xa0

[RequestAttributes]
CertificateTemplate = $CertTemplateName
"@

            $infPath = "$env:TEMP\test-certreq.inf"
            $reqPath = "$env:TEMP\test-certreq.req"
            $cerPath = "$env:TEMP\test-certreq.cer"

            try {
                Set-Content -Path $infPath -Value $infContent

                # Generate request
                $result = certreq -new -machine $infPath $reqPath 2>&1
                $LASTEXITCODE | Should -Be 0 -Because "certreq -new must succeed: $result"

                # Submit to CA
                $result = certreq -submit -machine $reqPath $cerPath 2>&1
                $LASTEXITCODE | Should -Be 0 -Because "certreq -submit must succeed: $result"

                # Accept certificate
                $result = certreq -accept -machine $cerPath 2>&1
                $LASTEXITCODE | Should -Be 0 -Because "certreq -accept must succeed: $result"

                $script:CertEnrolled = $true
            } finally {
                Remove-Item $infPath, $reqPath, $cerPath -ErrorAction SilentlyContinue
            }
        }

        It "Should have valid machine certificate in store" {
            $cert = Get-MachineCertificate -Hostname $env:COMPUTERNAME -Domain $DomainName

            $cert | Should -Not -BeNullOrEmpty -Because "Machine certificate must be in store"
            $cert.NotAfter | Should -BeGreaterThan (Get-Date) -Because "Certificate must be valid"
            $cert.HasPrivateKey | Should -Be $true -Because "Certificate must have private key"
        }

        It "Should have Client Authentication EKU" {
            $cert = Get-MachineCertificate -Hostname $env:COMPUTERNAME -Domain $DomainName
            $clientAuthOid = "1.3.6.1.5.5.7.3.2"

            $hasClientAuth = $cert.EnhancedKeyUsageList | Where-Object { $_.ObjectId -eq $clientAuthOid }
            $hasClientAuth | Should -Not -BeNullOrEmpty -Because "Certificate must have Client Authentication EKU"
        }
    }

    Context "Phase 2: mTLS Transition" {

        It "Should update config for mTLS (remove Setup-Key)" {
            # Update config for mTLS
            $configContent = Get-Content $script:Config.ConfigPath -Raw

            # Remove setup_key
            $configContent = $configContent -replace 'setup_key:.*\n', ''

            # Add mTLS settings if not present
            if ($configContent -notmatch 'machine_cert_enabled:') {
                $configContent += @"

# Machine Certificate Authentication (Phase 2)
machine_cert_enabled: true
machine_cert_template_name: $CertTemplateName
machine_cert_san_must_match: true
"@
            }

            Set-Content $script:Config.ConfigPath $configContent

            # Verify
            $verifyConfig = Get-Content $script:Config.ConfigPath -Raw
            $verifyConfig | Should -Not -Match "setup_key:" -Because "Setup-Key must be removed"
            $verifyConfig | Should -Match "machine_cert_enabled:\s*true" -Because "mTLS must be enabled"
        }

        It "Should restart service for mTLS" {
            Restart-Service $script:Config.ServiceName
            $running = Wait-ServiceRunning -ServiceName $script:Config.ServiceName -TimeoutSeconds 30
            $running | Should -Be $true -Because "Service must restart successfully"
        }

        It "Should re-establish tunnel with mTLS" {
            $tunnelUp = Wait-TunnelInterface -InterfaceName $script:Config.TunnelInterface -TimeoutSeconds $script:Config.TunnelTimeout
            $tunnelUp | Should -Be $true -Because "Tunnel must reconnect with mTLS"
        }

        It "Should still have DC connectivity after mTLS transition" {
            Start-Sleep -Seconds 5  # Allow connection to stabilize

            $reachable = Test-PortConnectivity -Host $DCAddress -Port 389
            $reachable | Should -Be $true -Because "DC must remain reachable after mTLS transition"
        }

        It "Should show mTLS in service logs" {
            Start-Sleep -Seconds 3

            if (Test-Path $script:Config.LogPath) {
                $logs = Get-Content $script:Config.LogPath -Tail 50
                # Check for mTLS-related log entries
                $mTLSLog = $logs | Where-Object { $_ -match "mTLS|machine.cert|RegisterMachinePeer" }
                $mTLSLog | Should -Not -BeNullOrEmpty -Because "Logs should show mTLS activity"
            } else {
                Set-ItResult -Inconclusive -Because "Log file not found"
            }
        }
    }

    Context "Phase 2: Kerberos Validation" {

        It "Should obtain Kerberos TGT" {
            # Purge existing tickets
            klist purge 2>&1 | Out-Null

            # Trigger Kerberos auth (access DC)
            $null = nltest /dsgetdc:$DomainName 2>&1
            Start-Sleep -Seconds 2

            # Check for TGT
            $klistOutput = klist 2>&1
            $hasTGT = $klistOutput | Where-Object { $_ -match "krbtgt" }
            $hasTGT | Should -Not -BeNullOrEmpty -Because "Kerberos TGT should be obtainable via tunnel"
        }

        It "Should have secure channel to domain" {
            $secureChannel = Test-ComputerSecureChannel -ErrorAction SilentlyContinue
            $secureChannel | Should -Be $true -Because "Secure channel to domain must be established"
        }
    }

    AfterAll {
        Write-Host "`n=== Test Complete ===" -ForegroundColor Cyan
        Write-Host "REMINDER: Revoke the Setup-Key in NetBird Dashboard!" -ForegroundColor Yellow

        # Summary
        $cert = Get-MachineCertificate -Hostname $env:COMPUTERNAME -Domain $DomainName
        if ($cert) {
            Write-Host "`nCertificate Info:" -ForegroundColor Green
            Write-Host "  Thumbprint: $($cert.Thumbprint)"
            Write-Host "  Valid Until: $($cert.NotAfter)"
        }
    }
}

#endregion
