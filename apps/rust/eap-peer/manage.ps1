#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Install', 'Enable', 'Restore', 'Uninstall', 'Status')]
    [string]$Action,
    [string]$DllPath,
    [string]$Interface,
    [System.Management.Automation.PSCredential]$Credential
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# A native host is required for the registry view, system paths and DLL machine.
$osArch = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
$processArch = [System.Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture.ToString()
if ($osArch -notin @('X64', 'Arm64') -or $processArch -ne $osArch) {
    throw 'Run this script in native x64 or ARM64 PowerShell on the matching Windows system.'
}
$dataDir = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'SYSUNetAuth\EapHost'
$installDir = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'SYSUNetAuth\EapHost'
$installedDll = Join-Path $installDir 'sysu_netauth_eap_peer.dll'
$credentialsPath = Join-Path $dataDir 'credentials.json'
$statePath = Join-Path $dataDir 'restore.json'
$key = 'HKLM:\SYSTEM\CurrentControlSet\Services\EapHost\Methods\32473\4'
$profile = Join-Path $PSScriptRoot 'wired-profile.xml'

function Invoke-Netsh([string[]]$Arguments) {
    & "$env:SystemRoot\System32\netsh.exe" @Arguments
    if ($LASTEXITCODE -ne 0) { throw "netsh failed ($LASTEXITCODE): $($Arguments -join ' ')" }
}

function Set-PrivateDirectory([string]$Path) {
    [void][IO.Directory]::CreateDirectory($Path)
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($sid in @('S-1-5-18', 'S-1-5-32-544')) {
        $identity = New-Object Security.Principal.SecurityIdentifier($sid)
        $rule = New-Object Security.AccessControl.FileSystemAccessRule(
            $identity, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
        $acl.AddAccessRule($rule)
    }
    $acl.SetOwner((New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')))
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Write-Json([string]$Path, $Value) {
    [IO.File]::WriteAllText($Path, ($Value | ConvertTo-Json -Depth 5), (New-Object Text.UTF8Encoding($false)))
}

function Get-ServiceState([string]$Name) {
    $service = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if (!$service) { return $null }
    $settings = Get-ItemProperty -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\$Name"
    $delayed = Get-ItemPropertyValue -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\$Name" `
        -Name DelayedAutoStart -ErrorAction SilentlyContinue
    return @{ Name = $Name; Start = $settings.Start; Delayed = $delayed; Running = ($service.Status -eq 'Running') }
}

function Restore-ServiceState($State) {
    if (!$State) { return }
    $modes = @{ 2 = 'Automatic'; 3 = 'Manual'; 4 = 'Disabled' }
    Set-Service -Name $State.Name -StartupType $modes[[int]$State.Start]
    $path = "HKLM:\SYSTEM\CurrentControlSet\Services\$($State.Name)"
    if ($null -ne $State.Delayed) {
        Set-ItemProperty -LiteralPath $path -Name DelayedAutoStart -Value ([int]$State.Delayed)
    } else {
        Remove-ItemProperty -LiteralPath $path -Name DelayedAutoStart -ErrorAction SilentlyContinue
    }
    if ($State.Running) { Start-Service -Name $State.Name }
    else {
        $service = Get-Service -Name $State.Name
        if ($service.Status -ne 'Stopped') {
            $service.Stop()
            $service.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(20))
        }
    }
}

function Export-Profile([string]$Name, [string]$Folder) {
    [void][IO.Directory]::CreateDirectory($Folder)
    Invoke-Netsh -Arguments @('lan', 'export', 'profile', "interface=$Name", "folder=$Folder")
    $files = @(Get-ChildItem -LiteralPath $Folder -Filter '*.xml' -File)
    if ($files.Count -gt 1) { throw 'Expected at most one interface profile.' }
    if ($files.Count -eq 1) { return $files[0].FullName }
    return $null
}

switch ($Action) {
    'Install' {
        if (!$DllPath) { throw '-DllPath is required.' }
        if ((Test-Path -LiteralPath $key) -or (Test-Path -LiteralPath $credentialsPath)) {
            throw 'An EAP method or prototype is already installed. Restore and uninstall it first.'
        }
        $resolved = (Resolve-Path -LiteralPath $DllPath).Path
        $bytes = [IO.File]::ReadAllBytes($resolved)
        if ($bytes.Length -lt 64 -or [BitConverter]::ToUInt16($bytes, 0) -ne 0x5a4d) { throw 'Invalid PE file.' }
        $offset = [BitConverter]::ToInt32($bytes, 60)
        if ($offset -lt 64 -or $offset -gt $bytes.Length - 24 -or [BitConverter]::ToUInt32($bytes, $offset) -ne 0x4550) {
            throw 'Invalid PE header.'
        }
        $machine = [BitConverter]::ToUInt16($bytes, $offset + 4)
        $expected = if ($osArch -eq 'Arm64') { 0xaa64 } else { 0x8664 }
        if ($machine -ne $expected -or !([BitConverter]::ToUInt16($bytes, $offset + 22) -band 0x2000)) {
            throw 'Select a DLL built for this Windows architecture.'
        }
        if (!$Credential) { $Credential = Get-Credential -Message 'SYSU NetID and password for the EAPHost prototype' }
        if (!$Credential -or $Credential.UserName -notmatch '^[!-~]{1,512}$') { throw 'NetID must be printable ASCII.' }
        $plain = $Credential.GetNetworkCredential().Password
        if ($plain.Length -eq 0) { throw 'Password cannot be empty.' }
        $gbk = [Text.Encoding]::GetEncoding(936, (New-Object Text.EncoderExceptionFallback), (New-Object Text.DecoderExceptionFallback))
        $encoded = $gbk.GetBytes($plain)
        if ([Text.Encoding]::UTF8.GetByteCount($plain) -gt 1024) { throw 'Password is too long.' }
        [Array]::Clear($encoded, 0, $encoded.Length)
        Set-PrivateDirectory $dataDir
        Set-PrivateDirectory $installDir
        $registered = $false
        try {
            Copy-Item -LiteralPath $resolved -Destination $installedDll
            Write-Json $credentialsPath @{ username = $Credential.UserName; password = $plain }
            [void](New-Item -Path $key -Force)
            $registered = $true
            [void](New-ItemProperty -LiteralPath $key -Name PeerDllPath -PropertyType ExpandString -Value $installedDll)
            [void](New-ItemProperty -LiteralPath $key -Name PeerFriendlyName -PropertyType String -Value 'SYSU EAP-MD5 (experimental)')
            foreach ($name in @('PeerInvokeUsernameDialog', 'PeerInvokePasswordDialog')) {
                [void](New-ItemProperty -LiteralPath $key -Name $name -PropertyType DWord -Value 0)
            }
            [void](New-ItemProperty -LiteralPath $key -Name PeerRequireConfigUI -PropertyType DWord -Value 1)
            # Standalone, machine/user contexts using the configured NetID.
            # No encryption or mutual-authentication claims.
            [void](New-ItemProperty -LiteralPath $key -Name Properties -PropertyType DWord -Value 0x03040000)
        } catch {
            if ($registered) { Remove-Item -LiteralPath $key -Recurse }
            Remove-Item -LiteralPath $credentialsPath -Force -ErrorAction SilentlyContinue
            Remove-Item -LiteralPath $installedDll -Force -ErrorAction SilentlyContinue
            throw
        } finally { $plain = $null }
        Write-Output 'Installed. Restart Windows before enabling the test profile so EAPHost reloads its method list.'
    }
    'Enable' {
        if (!$Interface) { throw '-Interface is required.' }
        if (!(Test-Path -LiteralPath $key) -or !(Test-Path -LiteralPath $credentialsPath)) { throw 'Install the prototype first.' }
        if ((Get-ItemPropertyValue -LiteralPath $key -Name PeerDllPath) -ne $installedDll) { throw 'Another method owns this registration.' }
        if (Test-Path -LiteralPath $statePath) { throw 'A trial is already active or incomplete. Run Restore first.' }
        $adapter = @(Get-NetAdapter | Where-Object { $_.Name -eq $Interface })
        if ($adapter.Count -ne 1 -or $adapter[0].InterfaceType -ne 6 -or !$adapter[0].HardwareInterface) {
            throw 'Select one physical Ethernet interface by exact name.'
        }
        $state = @{
            InterfaceGuid = $adapter[0].InterfaceGuid.ToString(); Backup = $null; ProfileApplied = $false
            Dot3 = Get-ServiceState 'dot3svc'; App = Get-ServiceState 'SYSUNetAuth'
        }
        Write-Json $statePath $state
        try {
            if ($state.Dot3.Start -eq 4) { Set-Service dot3svc -StartupType Manual }
            Start-Service dot3svc
            $backupDir = Join-Path $dataDir 'backup'
            if (Test-Path -LiteralPath $backupDir) { throw 'Remove the previous backup directory after reviewing its contents.' }
            $state.Backup = Export-Profile $Interface $backupDir
            Write-Json $statePath $state
            if ($state.App) {
                Set-Service SYSUNetAuth -StartupType Disabled
                $service = Get-Service SYSUNetAuth
                if ($service.Status -ne 'Stopped') {
                    $service.Stop()
                    $service.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(20))
                }
            }
            Set-Service dot3svc -StartupType Automatic
            $state.ProfileApplied = $true
            Write-Json $statePath $state
            Invoke-Netsh -Arguments @('lan', 'add', 'profile', "filename=$profile", "interface=$Interface")
        } catch {
            Write-Warning 'Trial setup was interrupted. Run Restore to return to the saved profile and service settings.'
            throw
        }
        Invoke-Netsh -Arguments @('lan', 'show', 'interfaces')
    }
    'Restore' {
        if (!(Test-Path -LiteralPath $statePath)) { throw 'No saved trial state was found.' }
        $state = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
        $adapter = @(Get-NetAdapter | Where-Object { $_.InterfaceGuid.ToString() -eq $state.InterfaceGuid })
        if ($adapter.Count -ne 1) { throw 'Reconnect the original adapter before restoring its profile.' }
        if ($state.ProfileApplied) {
            if ((Get-Service dot3svc).StartType -eq 'Disabled') { Set-Service dot3svc -StartupType Manual }
            Start-Service dot3svc
            $currentDir = Join-Path $dataDir 'current'
            if (Test-Path -LiteralPath $currentDir) { Remove-Item -LiteralPath $currentDir -Recurse }
            $current = Export-Profile $adapter[0].Name $currentDir
            $alreadyRestored = !$current -and !$state.Backup
            if ($current) {
                $xml = [xml](Get-Content -LiteralPath $current -Raw)
                $author = $xml.SelectSingleNode("//*[local-name()='EapMethod']/*[local-name()='AuthorId']")
                $blob = $xml.SelectSingleNode("//*[local-name()='ConfigBlob']")
                if ($state.Backup) {
                    $backupXml = [xml](Get-Content -LiteralPath $state.Backup -Raw)
                    $alreadyRestored = $xml.OuterXml -eq $backupXml.OuterXml
                }
                if (!$alreadyRestored -and (!$author -or $author.InnerText -ne '32473' -or !$blob -or $blob.InnerText -ne '535953552D4541502D4D44352D7631')) {
                    throw 'The interface profile changed outside the trial. Review the saved backup before restoring it manually.'
                }
            }
            if (!$alreadyRestored) {
                if ($state.Backup) { Invoke-Netsh -Arguments @('lan', 'add', 'profile', "filename=$($state.Backup)", "interface=$($adapter[0].Name)") }
                else { Invoke-Netsh -Arguments @('lan', 'delete', 'profile', "interface=$($adapter[0].Name)") }
            }
            # Persist completion before restoring service state so retries do not
            # mistake the restored profile for an external replacement.
            $state.ProfileApplied = $false
            Write-Json $statePath $state
        }
        Restore-ServiceState $state.Dot3
        Restore-ServiceState $state.App
        Remove-Item -LiteralPath $statePath
        Write-Output "Restored. The exported profile remains in $dataDir\backup."
    }
    'Uninstall' {
        if (Test-Path -LiteralPath $statePath) { throw 'Run Restore before uninstalling the active trial.' }
        if (Test-Path -LiteralPath $key) {
            if ((Get-ItemPropertyValue -LiteralPath $key -Name PeerDllPath) -ne $installedDll) { throw 'Another method owns this registration.' }
            Remove-Item -LiteralPath $key -Recurse
        }
        Remove-Item -LiteralPath $credentialsPath -Force -ErrorAction SilentlyContinue
        if (Test-Path -LiteralPath $installedDll) {
            try { Remove-Item -LiteralPath $installedDll -Force }
            catch { throw 'The host still holds the DLL. Restart Windows and run Uninstall again.' }
        }
        Write-Output 'Unregistered. Profile backups were preserved.'
    }
    'Status' {
        Get-Service -Name dot3svc, EapHost, SYSUNetAuth -ErrorAction SilentlyContinue |
            Format-Table Name, Status, StartType
        Invoke-Netsh -Arguments @('lan', 'show', 'interfaces')
    }
}
