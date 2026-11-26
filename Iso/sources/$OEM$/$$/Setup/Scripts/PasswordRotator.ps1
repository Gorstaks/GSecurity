#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Clear the current local administrator's password at boot; rotate it every
    ten minutes while that administrator is signed in. Only switch: -Uninstall.
.DESCRIPTION
    Run from the intended user's desktop using 64-bit Windows PowerShell 5.1.
    Installation clears the password to verify that effective policy allows it.
    Startup tasks cannot guarantee reset before the Windows sign-in screen.
    Random passwords are never retained. Locking the session after rotation can
    prevent password sign-in until a successful reset. Uninstall restores blank
    before removing recovery tasks. No helper script files are created.
#>
param([switch]$Uninstall)

$ErrorActionPreference = 'Stop'
if ($PSVersionTable.PSEdition -ne 'Desktop' -or [IntPtr]::Size -ne 8) {
    throw 'Run this script in 64-bit Windows PowerShell 5.1, as administrator.'
}
Import-Module Microsoft.PowerShell.LocalAccounts -ErrorAction Stop

# This same source is embedded in each task. It never writes another script.
$runtime = {
    if (-not ('PasswordRotatorNative' -as [type])) {
        Add-Type -ErrorAction Stop -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;
public static class PasswordRotatorNative {
    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
    public struct PasswordInfo {
        [MarshalAs(UnmanagedType.LPWStr)] public string Password;
    }
    [StructLayout(LayoutKind.Sequential)]
    public struct PolicyInfo {
        public uint MinimumLength, MaximumAge, MinimumAge, ForceLogoff, HistoryLength;
    }
    [DllImport("Netapi32.dll", CharSet=CharSet.Unicode)]
    public static extern uint NetUserSetInfo(string server, string user,
        uint level, ref PasswordInfo info, out uint error);
    [DllImport("Netapi32.dll", CharSet=CharSet.Unicode)]
    static extern uint NetUserModalsGet(string server, uint level, out IntPtr buffer);
    [DllImport("Netapi32.dll")] static extern uint NetApiBufferFree(IntPtr buffer);
    [DllImport("Wtsapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern bool WTSQuerySessionInformation(IntPtr server, int session,
        int infoClass, out IntPtr buffer, out int bytes);
    [DllImport("Wtsapi32.dll")] static extern void WTSFreeMemory(IntPtr buffer);
    static string SessionText(int session, int infoClass) {
        IntPtr buffer; int bytes;
        if (!WTSQuerySessionInformation(IntPtr.Zero, session, infoClass, out buffer, out bytes))
            throw new Win32Exception(Marshal.GetLastWin32Error());
        try { return Marshal.PtrToStringUni(buffer) ?? ""; }
        finally { WTSFreeMemory(buffer); }
    }
    public static string SessionSid(int session) {
        string user = SessionText(session, 5);
        if (String.IsNullOrEmpty(user)) return "";
        string domain = SessionText(session, 7);
        return new NTAccount(domain, user).Translate(typeof(SecurityIdentifier)).Value;
    }
    public static uint MinimumPasswordLength() {
        IntPtr buffer;
        uint result = NetUserModalsGet(null, 0, out buffer);
        if (result != 0) throw new Win32Exception((int)result);
        try { return ((PolicyInfo)Marshal.PtrToStructure(buffer, typeof(PolicyInfo))).MinimumLength; }
        finally { NetApiBufferFree(buffer); }
    }
}
'@
    }

    function Write-RotatorLog { param([string]$Message)
        try {
            Add-Content -LiteralPath (Join-Path $script:StateDirectory 'events.log') -Value (
                '{0:o} {1}' -f [datetime]::UtcNow, $Message) -Encoding UTF8 -ErrorAction Stop
        } catch { Write-Warning "PasswordRotator could not write its log: $_" }
    }
    function Get-RotatorBootStamp {
        return (Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).LastBootUpTime.ToUniversalTime().Ticks.ToString()
    }
    function Get-RotatorState {
        $path = Join-Path $script:StateDirectory 'state.json'
        if (-not (Test-Path -LiteralPath $path)) { return $null }
        return Get-Content -LiteralPath $path -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    }
    function Set-RotatorState { param($State)
        $path = Join-Path $script:StateDirectory 'state.json'
        $temporary = Join-Path $script:StateDirectory (([guid]::NewGuid().ToString()) + '.tmp')
        try {
            $State | ConvertTo-Json -Compress | Set-Content -LiteralPath $temporary -Encoding UTF8 -ErrorAction Stop
            Move-Item -LiteralPath $temporary -Destination $path -Force -ErrorAction Stop
        } finally {
            if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue }
        }
    }
    function Invoke-RotatorLocked { param([scriptblock]$Action)
        # Both SYSTEM and the elevated target administrator must open the same mutex.
        $security = New-Object Security.AccessControl.MutexSecurity
        foreach ($principalSid in @('S-1-5-18','S-1-5-32-544')) {
            $principal = New-Object Security.Principal.SecurityIdentifier($principalSid)
            $security.AddAccessRule((New-Object Security.AccessControl.MutexAccessRule(
                $principal, 'FullControl', 'Allow')))
        }
        $created = $false
        $mutex = [Threading.Mutex]::new($false, ('Global\PasswordRotator.' + $script:TargetSid), [ref]$created, $security)
        $owned = $false
        try {
            try { $owned = $mutex.WaitOne([TimeSpan]::FromSeconds(60)) }
            catch [Threading.AbandonedMutexException] { $owned = $true }
            if (-not $owned) { throw 'Timed out waiting for the password reset/rotation lock.' }
            & $Action
        } finally {
            if ($owned) { $mutex.ReleaseMutex() }
            $mutex.Dispose()
        }
    }
    function Get-RotatorSessionSid {
        return [PasswordRotatorNative]::SessionSid([Diagnostics.Process]::GetCurrentProcess().SessionId)
    }
    function Test-RotatorSession {
        try { return (Get-RotatorSessionSid) -eq $script:TargetSid }
        catch { return $false }
    }
    function Assert-RotatorLocalAccount { param($User)
        if ([string]$User.PrincipalSource -ne 'Local') {
            throw 'Only a standalone local Windows account is supported; Microsoft, domain, and Entra accounts are refused.'
        }
        if (-not $User.Enabled) { throw 'The local account is disabled.' }
    }
    function Assert-RotatorAccount { param($User, [string]$DesktopSid)
        Assert-RotatorLocalAccount $User
        if ($User.SID.Value -ne $DesktopSid) {
            throw 'Elevation used a different account. Sign in to the intended local administrator account and run the script there.'
        }
    }
    function Get-RotatorMinimumLength { return [PasswordRotatorNative]::MinimumPasswordLength() }
    function Assert-RotatorBlankPolicy {
        if ((Get-RotatorMinimumLength) -gt 0) {
            throw 'Effective local password policy requires a nonempty password. No policy was changed.'
        }
    }
    function Reset-RotatorPassword {
        $account = Get-LocalUser -SID $script:TargetSid -ErrorAction Stop
        Assert-RotatorLocalAccount $account
        $info = New-Object PasswordRotatorNative+PasswordInfo
        $info.Password = ''
        [uint32]$parameterError = 0
        $result = [PasswordRotatorNative]::NetUserSetInfo($null, $account.Name, 1003, [ref]$info, [ref]$parameterError)
        if ($result -ne 0) {
            throw "Windows rejected the blank password (error $result). Password policy was not changed."
        }
    }
    function Set-RotatorRandomPassword {
        # Revalidate on every operation in case the account was linked to Microsoft later.
        $account = Get-LocalUser -SID $script:TargetSid -ErrorAction Stop
        Assert-RotatorLocalAccount $account
        $bytes = New-Object byte[] 32
        $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
        try {
            $rng.GetBytes($bytes)
            $password = ConvertTo-SecureString ('Aa1!' + [Convert]::ToBase64String($bytes)) -AsPlainText -Force
            try { Set-LocalUser -SID $script:TargetSid -Password $password -ErrorAction Stop }
            finally { $password.Dispose() }
        } finally {
            [Array]::Clear($bytes, 0, $bytes.Length)
            $rng.Dispose()
        }
    }
    function Invoke-RotatorBootReset {
        # Caller holds the shared mutex. Missing or disabled installations cannot reset accounts.
        $state = Get-RotatorState
        if (-not $state -or -not $state.Installed) { return }
        $boot = Get-RotatorBootStamp
        if ($state.ResetSucceeded -and $state.BootStamp -eq $boot) { return }
        $state.ResetSucceeded = $false
        $state.BootStamp = $boot
        Set-RotatorState $state
        try {
            Reset-RotatorPassword
            $state.ResetSucceeded = $true
            $state.ResetUtc = [datetime]::UtcNow.ToString('o')
            Set-RotatorState $state
            Write-RotatorLog 'Boot password reset succeeded.'
        } catch {
            Write-RotatorLog "Boot password reset failed; rotation blocked. $_"
            throw
        }
    }
    function Invoke-RotatorRotationStep { param([string]$BootStamp, [string]$ResetToken, [double]$ElapsedSeconds)
        # Caller holds the same lock used by boot reset and uninstall.
        $state = Get-RotatorState
        if (-not $state -or -not $state.Installed -or -not $state.RotationEnabled) { return 'Stop' }
        if (-not (Test-RotatorSession)) { return 'Stop' }
        if (-not $state.ResetSucceeded -or $state.BootStamp -ne $BootStamp) { return 'WaitingForReset' }
        if ($ResetToken -ne $state.ResetUtc) { return 'ResetTimer' }
        if ($ElapsedSeconds -lt 600) { return 'Waiting' }
        # Recheck the desktop immediately before changing the password.
        if (-not (Test-RotatorSession)) { return 'Stop' }
        Set-RotatorRandomPassword
        Write-RotatorLog 'Password rotated; password not retained.'
        return 'Rotated'
    }
    function Start-RotatorSession {
        if (-not (Test-RotatorSession)) { throw 'Rotation requires the target user interactive session.' }
        $boot = Get-RotatorBootStamp
        $timer = [Diagnostics.Stopwatch]::StartNew()
        $resetToken = ''
        $waiting = [Diagnostics.Stopwatch]::StartNew()
        while ($true) {
            $result = Invoke-RotatorLocked {
                Invoke-RotatorRotationStep -BootStamp $boot -ResetToken $resetToken -ElapsedSeconds $timer.Elapsed.TotalSeconds
            }
            switch ($result) {
                'Stop' { return }
                'WaitingForReset' {
                    if ($waiting.Elapsed.TotalSeconds -gt 180) { throw 'Boot reset has not succeeded; rotation was not started. Inspect events.log and the Boot task.' }
                }
                'ResetTimer' {
                    $state = Invoke-RotatorLocked { Get-RotatorState }
                    $resetToken = $state.ResetUtc
                    $timer.Restart()
                    $waiting.Restart()
                    Write-RotatorLog 'Session rotation timer started; first rotation in ten minutes.'
                }
                'Rotated' { $timer.Restart() }
            }
            Start-Sleep -Seconds 5
        }
    }
}
. $runtime
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$user = Get-LocalUser -SID $identity.User -ErrorAction Stop
Assert-RotatorAccount -User $user -DesktopSid (Get-RotatorSessionSid)
$script:TargetSid = $user.SID.Value
$script:StateDirectory = Join-Path $env:ProgramData ('LocalPasswordRotator-' + $script:TargetSid)
$taskPrefix = 'LocalPasswordRotator-' + $script:TargetSid

function Initialize-RotatorDirectory {
    if (Test-Path -LiteralPath $script:StateDirectory) {
        if ((Get-Item -LiteralPath $script:StateDirectory -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw 'PasswordRotator state directory must not be a reparse point.'
        }
    } else { New-Item -ItemType Directory -Path $script:StateDirectory -ErrorAction Stop | Out-Null }
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner((New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')))
    foreach ($principalSid in @('S-1-5-18','S-1-5-32-544')) {
        $principal = New-Object Security.Principal.SecurityIdentifier($principalSid)
        $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule(
            $principal, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
    }
    Set-Acl -LiteralPath $script:StateDirectory -AclObject $acl -ErrorAction Stop
    foreach ($name in @('state.json','events.log')) {
        $path = Join-Path $script:StateDirectory $name
        if (Test-Path -LiteralPath $path) {
            if ((Get-Item -LiteralPath $path -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {
                throw "State file must not be a reparse point: $name"
            }
        }
    }
}
function Stop-RotatorTask { param([string]$Name)
    $task = Get-ScheduledTask -TaskName $Name -ErrorAction SilentlyContinue
    if (-not $task) { return }
    Disable-ScheduledTask -TaskName $Name -ErrorAction Stop | Out-Null
    Stop-ScheduledTask -TaskName $Name -ErrorAction Stop
    $deadline = [datetime]::UtcNow.AddSeconds(10)
    while ((Get-ScheduledTask -TaskName $Name -ErrorAction Stop).State -eq 'Running') {
        if ([datetime]::UtcNow -ge $deadline) { throw "Could not stop task $Name; no password was reset." }
        Start-Sleep -Milliseconds 100
    }
}
function Uninstall-Rotator {
    $tasks = @('Boot','Logon') | ForEach-Object { Get-ScheduledTask -TaskName "$taskPrefix-$_" -ErrorAction SilentlyContinue }
    if (-not $tasks) { Write-Output 'No PasswordRotator tasks are installed for this account.'; return }
    Initialize-RotatorDirectory
    try {
        foreach ($suffix in @('Logon','Boot')) { Stop-RotatorTask -Name "$taskPrefix-$suffix" }
        Invoke-RotatorLocked {
            $state = Get-RotatorState
            if ($state) { $state.RotationEnabled = $false; Set-RotatorState $state }
            # Validate the actual reset before deleting the boot recovery mechanism.
            Reset-RotatorPassword
            if ($state) { $state.Installed = $false; Set-RotatorState $state }
            Write-RotatorLog 'Uninstall restored blank password; rotation disabled.'
        }
    } catch {
        $bootTask = Get-ScheduledTask -TaskName "$taskPrefix-Boot" -ErrorAction SilentlyContinue
        if ($bootTask) { Enable-ScheduledTask -TaskName "$taskPrefix-Boot" -ErrorAction Stop | Out-Null }
        throw "Uninstall could not restore a blank password. Tasks were retained; rotation remains disabled and the Boot task was retained for recovery. $_"
    }
    foreach ($suffix in @('Logon','Boot')) {
        $task = Get-ScheduledTask -TaskName "$taskPrefix-$suffix" -ErrorAction SilentlyContinue
        if ($task) { $task | Unregister-ScheduledTask -Confirm:$false -ErrorAction Stop }
    }
    Write-Output 'Uninstalled. The target account password is blank. Non-secret state and logs remain in ProgramData.'
}
function New-RotatorTaskCommands { param([scriptblock]$Runtime, [string]$TargetSid, [string]$StateDirectory)
    $header = '$ErrorActionPreference = ''Stop''; Import-Module Microsoft.PowerShell.LocalAccounts -ErrorAction Stop' + "`r`n" +
        '$script:TargetSid = ''' + $TargetSid.Replace("'", "''") + "'`r`n" +
        '$script:StateDirectory = ''' + $StateDirectory.Replace("'", "''") + "'`r`n" + $Runtime.ToString() + "`r`n"
    $boot = $header + @'
try { Invoke-RotatorLocked { Invoke-RotatorBootReset } }
catch { Write-RotatorLog "Boot worker failed: $_"; throw }
'@
    $logon = $header + @'
try { Start-RotatorSession }
catch { Write-RotatorLog "Session worker failed: $_"; throw }
'@
    $result = @{}
    foreach ($entry in @{ Boot=$boot; Logon=$logon }.GetEnumerator()) {
        $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($entry.Value))
        $arguments = '-NoProfile -NonInteractive -WindowStyle Hidden -EncodedCommand ' + $encoded
        if ($arguments.Length -gt 30000) { throw 'Embedded task command exceeds the supported command-line size.' }
        $result[$entry.Key] = $arguments
    }
    return $result
}
if ($Uninstall) { Uninstall-Rotator; return }
foreach ($suffix in @('Boot','Logon')) {
    if (Get-ScheduledTask -TaskName "$taskPrefix-$suffix" -ErrorAction SilentlyContinue) {
        throw 'An existing PasswordRotator installation was found. Run this new script with -Uninstall first to restore blank safely, then run it again.'
    }
}
Assert-RotatorBlankPolicy
$commands = New-RotatorTaskCommands -Runtime $runtime -TargetSid $script:TargetSid -StateDirectory $script:StateDirectory
Initialize-RotatorDirectory
$powershell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
try {
    Invoke-RotatorLocked {
        $state = [pscustomobject]@{Installed=$true; RotationEnabled=$false; BootStamp=''; ResetSucceeded=$false; ResetUtc=''}
        Set-RotatorState $state
        # This real reset also verifies password filters that a policy query cannot predict.
        Invoke-RotatorBootReset
        $bootAction = New-ScheduledTaskAction -Execute $powershell -Argument $commands.Boot
        $bootPrincipal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
        $bootSettings = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Minutes 2) -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -MultipleInstances IgnoreNew
        Register-ScheduledTask -TaskName "$taskPrefix-Boot" -Action $bootAction -Trigger (New-ScheduledTaskTrigger -AtStartup) -Principal $bootPrincipal -Settings $bootSettings -ErrorAction Stop | Out-Null
        $logonAction = New-ScheduledTaskAction -Execute $powershell -Argument $commands.Logon
        $logonPrincipal = New-ScheduledTaskPrincipal -UserId $script:TargetSid -LogonType Interactive -RunLevel Highest
        $logonSettings = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew
        Register-ScheduledTask -TaskName "$taskPrefix-Logon" -Action $logonAction -Trigger (New-ScheduledTaskTrigger -AtLogOn -User $script:TargetSid) -Principal $logonPrincipal -Settings $logonSettings -ErrorAction Stop | Out-Null
        $state = Get-RotatorState
        $state.RotationEnabled = $true
        Set-RotatorState $state
    }
    Start-ScheduledTask -TaskName "$taskPrefix-Logon" -ErrorAction Stop
} catch {
    $failure = $_
    foreach ($suffix in @('Logon','Boot')) {
        $task = Get-ScheduledTask -TaskName "$taskPrefix-$suffix" -ErrorAction SilentlyContinue
        if ($task) { Stop-RotatorTask -Name "$taskPrefix-$suffix"; $task | Unregister-ScheduledTask -Confirm:$false -ErrorAction Stop }
    }
    Invoke-RotatorLocked {
        $state = Get-RotatorState
        if ($state) { $state.Installed=$false; $state.RotationEnabled=$false; Set-RotatorState $state }
    }
    throw $failure
}
Write-Output "Installed for $($user.Name). Password is blank now; rotation begins in ten minutes while signed in. Boot reset is enabled. Inspect $script:StateDirectory\events.log for failures."
