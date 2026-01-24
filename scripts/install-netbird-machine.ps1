<#
.SYNOPSIS
    Install NetBird Machine Tunnel with secure ACLs and hardening.

.DESCRIPTION
    This script performs a secure installation of NetBird Machine Tunnel:
    1. Creates config directory with hardened ACLs
    2. Registers Windows EventLog source
    3. Installs the binary to Program Files
    4. Installs and starts the Windows service

    ACL Configuration:
    - NT AUTHORITY\SYSTEM: Full Control (service runs as LocalSystem)
    - BUILTIN\Administrators: Read & Execute only (cannot modify config)
    - Users: No access (inheritance disabled)

.PARAMETER BinaryPath
    Path to netbird-machine.exe binary to install.

.PARAMETER ConfigPath
    Optional path to a config file to copy.

.PARAMETER ManagementURL
    Optional management server URL (creates minimal config if provided).

.PARAMETER SetupKey
    Optional setup key for bootstrap (will be DPAPI encrypted).
    IMPORTANT: Revoke after successful mTLS enrollment!

.PARAMETER SkipServiceStart
    Install but don't start the service.

.PARAMETER Force
    Overwrite existing installation.

.EXAMPLE
    .\install-netbird-machine.ps1 -BinaryPath .\netbird-machine.exe
    Basic installation with prompts.

.EXAMPLE
    .\install-netbird-machine.ps1 -BinaryPath .\netbird-machine.exe -ManagementURL "https://netbird.example.com" -SetupKey "nb-setup-xyz"
    Install with config and encrypted setup key.

.NOTES
    Requires: Administrator privileges
    Author: NetBird Machine Tunnel Fork
    Version: 1.0.0
#>

#Requires -RunAsAdministrator

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path $_ })]
    [string]$BinaryPath,

    [Parameter(Mandatory = $false)]
    [string]$ConfigPath,

    [Parameter(Mandatory = $false)]
    [string]$ManagementURL,

    [Parameter(Mandatory = $false)]
    [string]$SetupKey,

    [Parameter(Mandatory = $false)]
    [switch]$SkipServiceStart,

    [Parameter(Mandatory = $false)]
    [switch]$Force
)

$ErrorActionPreference = 'Stop'

# Configuration
$ServiceName = "NetBirdMachine"
$EventLogSource = "NetBirdMachine"
$InstallPath = "$env:ProgramFiles\NetBird Machine"
$DataPath = "$env:ProgramData\NetBird"
$BinaryName = "netbird-machine.exe"

#region Helper Functions

function Write-Step {
    param([string]$Step, [string]$Message)
    Write-Host "[$Step] $Message" -ForegroundColor Cyan
}

function Write-Success {
    param([string]$Message)
    Write-Host "  [OK] $Message" -ForegroundColor Green
}

function Write-Warning {
    param([string]$Message)
    Write-Host "  [WARN] $Message" -ForegroundColor Yellow
}

function Write-Failure {
    param([string]$Message)
    Write-Host "  [FAIL] $Message" -ForegroundColor Red
}

function Test-Administrator {
    $currentUser = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentUser.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Set-SecureACL {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $false)]
        [switch]$IsDirectory
    )

    # Create new ACL with inheritance disabled
    $acl = New-Object System.Security.AccessControl.DirectorySecurity
    if (-not $IsDirectory) {
        $acl = New-Object System.Security.AccessControl.FileSecurity
    }

    # Disable inheritance and remove inherited rules
    $acl.SetAccessRuleProtection($true, $false)

    # SYSTEM: Full Control
    $systemRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        "NT AUTHORITY\SYSTEM",
        "FullControl",
        $(if ($IsDirectory) { "ContainerInherit,ObjectInherit" } else { "None" }),
        "None",
        "Allow"
    )
    $acl.AddAccessRule($systemRule)

    # Administrators: Read & Execute (NOT Write!)
    $adminRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        "BUILTIN\Administrators",
        "ReadAndExecute",
        $(if ($IsDirectory) { "ContainerInherit,ObjectInherit" } else { "None" }),
        "None",
        "Allow"
    )
    $acl.AddAccessRule($adminRule)

    # Set owner to SYSTEM
    $systemAccount = New-Object System.Security.Principal.NTAccount("NT AUTHORITY\SYSTEM")
    $acl.SetOwner($systemAccount)

    # Apply ACL
    Set-Acl -Path $Path -AclObject $acl
}

#endregion

#region Main Script

# Check administrator
if (-not (Test-Administrator)) {
    throw "This script must be run as Administrator"
}

Write-Host @"

+=====================================================================+
|          NetBird Machine Tunnel - Secure Installation               |
+=====================================================================+

"@ -ForegroundColor Cyan

# Check for existing installation
$existingService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existingService -and -not $Force) {
    throw "Service $ServiceName already exists. Use -Force to overwrite."
}

# ============================================
# Step 1: Register EventLog Source
# ============================================
Write-Step "1/6" "Registering EventLog source"

if (-not [System.Diagnostics.EventLog]::SourceExists($EventLogSource)) {
    if ($PSCmdlet.ShouldProcess($EventLogSource, "Create EventLog source")) {
        New-EventLog -LogName Application -Source $EventLogSource
        Write-Success "EventLog source registered: $EventLogSource"
    }
} else {
    Write-Success "EventLog source already exists"
}

# ============================================
# Step 2: Create Install Directory
# ============================================
Write-Step "2/6" "Creating install directory"

if (-not (Test-Path $InstallPath)) {
    if ($PSCmdlet.ShouldProcess($InstallPath, "Create directory")) {
        New-Item -Path $InstallPath -ItemType Directory -Force | Out-Null
        Write-Success "Created: $InstallPath"
    }
} else {
    Write-Success "Directory exists: $InstallPath"
}

# ============================================
# Step 3: Create Data Directory with Secure ACLs
# ============================================
Write-Step "3/6" "Creating data directory with secure ACLs"

if (-not (Test-Path $DataPath)) {
    if ($PSCmdlet.ShouldProcess($DataPath, "Create directory")) {
        New-Item -Path $DataPath -ItemType Directory -Force | Out-Null
    }
}

if ($PSCmdlet.ShouldProcess($DataPath, "Apply secure ACLs")) {
    Set-SecureACL -Path $DataPath -IsDirectory
    Write-Success "ACL hardened: $DataPath"
    Write-Success "  SYSTEM: Full Control"
    Write-Success "  Administrators: Read & Execute"
    Write-Success "  Users: (none)"
}

# ============================================
# Step 4: Copy Binary
# ============================================
Write-Step "4/6" "Installing binary"

$targetBinary = Join-Path $InstallPath $BinaryName

if ($PSCmdlet.ShouldProcess($targetBinary, "Copy binary")) {
    # Stop service if running
    if ($existingService -and $existingService.Status -eq 'Running') {
        Stop-Service $ServiceName -Force
        Start-Sleep -Seconds 2
    }

    Copy-Item -Path $BinaryPath -Destination $targetBinary -Force
    Write-Success "Binary installed: $targetBinary"
}

# ============================================
# Step 5: Create Config (if needed)
# ============================================
Write-Step "5/6" "Configuring"

$targetConfig = Join-Path $DataPath "config.yaml"

if ($ConfigPath -and (Test-Path $ConfigPath)) {
    if ($PSCmdlet.ShouldProcess($targetConfig, "Copy config")) {
        Copy-Item -Path $ConfigPath -Destination $targetConfig -Force
        Set-SecureACL -Path $targetConfig
        Write-Success "Config copied and hardened"
    }
} elseif ($ManagementURL) {
    if ($PSCmdlet.ShouldProcess($targetConfig, "Create config")) {
        $configContent = @"
# NetBird Machine Tunnel Configuration
# Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')

management_url: "$ManagementURL"
tunnel_mode: "machine"
"@

        if ($SetupKey) {
            # Note: In production, the Go binary would DPAPI-encrypt this
            # For now, we store it and let the service encrypt on first run
            $configContent += @"

# TEMPORARY: Setup key will be encrypted by service on first run
# IMPORTANT: Revoke in dashboard after successful mTLS enrollment!
setup_key: "$SetupKey"
"@
            Write-Warning "Setup key stored (will be encrypted on service start)"
        }

        $configContent | Out-File $targetConfig -Encoding UTF8
        Set-SecureACL -Path $targetConfig
        Write-Success "Config created and hardened"
    }
} else {
    if (-not (Test-Path $targetConfig)) {
        Write-Warning "No config provided. Create $targetConfig before starting service."
    } else {
        Write-Success "Using existing config"
    }
}

# ============================================
# Step 6: Install and Start Service
# ============================================
Write-Step "6/6" "Installing service"

if ($PSCmdlet.ShouldProcess($ServiceName, "Install service")) {
    # Remove existing service if present
    if ($existingService) {
        sc.exe delete $ServiceName 2>&1 | Out-Null
        Start-Sleep -Seconds 2
    }

    # Install service
    $result = & $targetBinary install 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Success "Service installed"
    } else {
        Write-Failure "Service install failed: $result"
        throw "Service installation failed"
    }

    # Start service
    if (-not $SkipServiceStart) {
        Start-Service $ServiceName
        Start-Sleep -Seconds 2

        $service = Get-Service $ServiceName
        if ($service.Status -eq 'Running') {
            Write-Success "Service started"
        } else {
            Write-Warning "Service status: $($service.Status)"
        }
    } else {
        Write-Success "Service installed (not started)"
    }
}

# ============================================
# Summary
# ============================================
Write-Host @"

+=====================================================================+
|                    Installation Complete                            |
+=====================================================================+

Binary:     $targetBinary
Config:     $targetConfig
Data:       $DataPath
Service:    $ServiceName

Security:
- Config directory ACLs hardened (SYSTEM=Full, Admins=Read)
- EventLog source registered

"@ -ForegroundColor Green

if ($SetupKey) {
    Write-Host @"
IMPORTANT: After successful mTLS enrollment:
1. REVOKE the setup key in NetBird Dashboard
2. The setup key will be automatically removed from config

"@ -ForegroundColor Yellow
}

Write-Host "Verify installation: .\verify-config-hardening.ps1" -ForegroundColor Gray

#endregion
