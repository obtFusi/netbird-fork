<#
.SYNOPSIS
    E2E Test Cycle Runner with VM Snapshot Support
    Automates: Snapshot Restore -> Run Tests -> Capture Results

.DESCRIPTION
    This script orchestrates E2E test cycles using Proxmox VM snapshots
    for repeatable, clean-state testing.

.PARAMETER ProxmoxHost
    Proxmox server hostname or IP (default: uses SSH config).

.PARAMETER VMID
    The VM ID of the test client on Proxmox.

.PARAMETER SnapshotName
    Snapshot to restore before each test cycle (default: "pre-bootstrap").

.PARAMETER TestScript
    Path to the Pester test script to run.

.PARAMETER SetupKey
    NetBird Setup-Key for bootstrap tests.

.PARAMETER DomainName
    Target AD domain.

.PARAMETER DCAddress
    Domain Controller IP address.

.PARAMETER OutputPath
    Path to save test results (default: ./test-results).

.EXAMPLE
    .\Invoke-E2ETestCycle.ps1 -VMID 105 -SetupKey "a1b2c3d4-..." -DomainName "corp.local" -DCAddress "192.168.100.20"

.NOTES
    Prerequisites:
    - SSH access to Proxmox host (key-based auth recommended)
    - Proxmox qm command access
    - Test VM with snapshot ready
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$ProxmoxHost = "10.0.0.106",

    [Parameter(Mandatory = $true)]
    [int]$VMID,

    [Parameter(Mandatory = $false)]
    [string]$SnapshotName = "pre-bootstrap",

    [Parameter(Mandatory = $false)]
    [string]$TestScript = ".\Test-DomainJoinViaTunnel.ps1",

    [Parameter(Mandatory = $true)]
    [string]$SetupKey,

    [Parameter(Mandatory = $true)]
    [string]$DomainName,

    [Parameter(Mandatory = $true)]
    [string]$DCAddress,

    [Parameter(Mandatory = $false)]
    [string]$CertTemplateName = "NetBirdMachineTunnel",

    [Parameter(Mandatory = $false)]
    [string]$OutputPath = ".\test-results",

    [Parameter(Mandatory = $false)]
    [switch]$SkipRestore,

    [Parameter(Mandatory = $false)]
    [switch]$CreateSnapshot
)

$ErrorActionPreference = 'Stop'

#region Functions

function Write-Header {
    param([string]$Message)
    Write-Host "`n$('=' * 60)" -ForegroundColor Cyan
    Write-Host "  $Message" -ForegroundColor Cyan
    Write-Host "$('=' * 60)`n" -ForegroundColor Cyan
}

function Invoke-ProxmoxCommand {
    param([string]$Command)

    Write-Host "  Proxmox: $Command" -ForegroundColor Gray
    $result = ssh "root@$ProxmoxHost" $Command 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Proxmox command failed: $result"
    }
    return $result
}

function Get-VMStatus {
    param([int]$VMID)

    $status = Invoke-ProxmoxCommand "qm status $VMID"
    if ($status -match "status:\s+(\w+)") {
        return $Matches[1]
    }
    return "unknown"
}

function Wait-VMRunning {
    param([int]$VMID, [int]$TimeoutSeconds = 180)

    $elapsed = 0
    while ($elapsed -lt $TimeoutSeconds) {
        $status = Get-VMStatus -VMID $VMID
        if ($status -eq "running") {
            return $true
        }
        Start-Sleep -Seconds 5
        $elapsed += 5
        Write-Host "." -NoNewline
    }
    Write-Host ""
    return $false
}

function Restore-Snapshot {
    param([int]$VMID, [string]$Snapshot)

    Write-Host "  Restoring snapshot '$Snapshot' for VM $VMID..."

    # Stop VM if running
    $status = Get-VMStatus -VMID $VMID
    if ($status -eq "running") {
        Write-Host "  Stopping VM..."
        Invoke-ProxmoxCommand "qm stop $VMID"
        Start-Sleep -Seconds 5
    }

    # Restore snapshot
    Invoke-ProxmoxCommand "qm rollback $VMID $Snapshot"
    Write-Host "  Snapshot restored" -ForegroundColor Green

    # Start VM
    Write-Host "  Starting VM..."
    Invoke-ProxmoxCommand "qm start $VMID"

    # Wait for VM to be running
    Write-Host "  Waiting for VM boot" -NoNewline
    if (-not (Wait-VMRunning -VMID $VMID -TimeoutSeconds 180)) {
        throw "VM did not start within 180 seconds"
    }
    Write-Host "  VM is running" -ForegroundColor Green

    # Additional wait for Windows to fully boot
    Write-Host "  Waiting for Windows boot (60s)..."
    Start-Sleep -Seconds 60
}

function New-Snapshot {
    param([int]$VMID, [string]$Snapshot, [string]$Description = "")

    Write-Host "  Creating snapshot '$Snapshot' for VM $VMID..."
    $cmd = "qm snapshot $VMID $Snapshot"
    if ($Description) {
        $cmd += " --description '$Description'"
    }
    Invoke-ProxmoxCommand $cmd
    Write-Host "  Snapshot created" -ForegroundColor Green
}

#endregion

#region Main

Write-Header "E2E Test Cycle Runner"

Write-Host "Configuration:" -ForegroundColor White
Write-Host "  Proxmox Host: $ProxmoxHost"
Write-Host "  VM ID: $VMID"
Write-Host "  Snapshot: $SnapshotName"
Write-Host "  Domain: $DomainName"
Write-Host "  DC: $DCAddress"
Write-Host "  Test Script: $TestScript"
Write-Host ""

# Create output directory
if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath | Out-Null
}

$timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$resultFile = Join-Path $OutputPath "test-results-$timestamp.xml"

# Step 1: Create snapshot if requested
if ($CreateSnapshot) {
    Write-Header "Creating Pre-Test Snapshot"
    New-Snapshot -VMID $VMID -Snapshot $SnapshotName -Description "Pre-bootstrap clean state"
    Write-Host "Snapshot '$SnapshotName' created. Exiting." -ForegroundColor Green
    exit 0
}

# Step 2: Restore snapshot
if (-not $SkipRestore) {
    Write-Header "Restoring VM Snapshot"
    Restore-Snapshot -VMID $VMID -Snapshot $SnapshotName
} else {
    Write-Host "Skipping snapshot restore (--SkipRestore)" -ForegroundColor Yellow
}

# Step 3: Run tests
Write-Header "Running E2E Tests"

$pesterConfig = New-PesterConfiguration
$pesterConfig.Run.Path = $TestScript
$pesterConfig.Run.PassThru = $true
$pesterConfig.Output.Verbosity = 'Detailed'
$pesterConfig.TestResult.Enabled = $true
$pesterConfig.TestResult.OutputPath = $resultFile
$pesterConfig.TestResult.OutputFormat = 'NUnitXml'

# Pass parameters to test script
$pesterConfig.Run.Container = New-PesterContainer -Path $TestScript -Data @{
    SetupKey = $SetupKey
    DomainName = $DomainName
    DCAddress = $DCAddress
    CertTemplateName = $CertTemplateName
}

try {
    $results = Invoke-Pester -Configuration $pesterConfig

    # Step 4: Report results
    Write-Header "Test Results"

    Write-Host "Tests Run:    $($results.TotalCount)"
    Write-Host "Passed:       $($results.PassedCount)" -ForegroundColor Green
    Write-Host "Failed:       $($results.FailedCount)" -ForegroundColor $(if ($results.FailedCount -gt 0) { 'Red' } else { 'Green' })
    Write-Host "Skipped:      $($results.SkippedCount)" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Results saved to: $resultFile"

    if ($results.FailedCount -gt 0) {
        Write-Host "`nFailed Tests:" -ForegroundColor Red
        foreach ($test in $results.Failed) {
            Write-Host "  - $($test.Name)" -ForegroundColor Red
            Write-Host "    Error: $($test.ErrorRecord.Exception.Message)" -ForegroundColor Gray
        }
        exit 1
    }

    exit 0
} catch {
    Write-Host "`nTest execution failed: $_" -ForegroundColor Red
    exit 1
}

#endregion
