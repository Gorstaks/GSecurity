#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    AntivirusLite v4.0.0 - Unified file and behavioral monitor for Windows 10/11
    Author: Gorstak
    Website: https://gorstak.eu
.DESCRIPTION
    Behavioral endpoint detection and response. Detects threats by what
    processes DO, not what they're called. Assumes the attacker has read
    this source code.

    Combines AntivirusLite, the original file antivirus, Sentinel, Antivirus,
    GorstaksEDR, and the later merged Antivirus: behavioral correlation,
    bounded file scanning, AMSI, hash reputation, persistence inventory,
    recoverable quarantine, circuit breakers, self-test and health telemetry.
    Companion mode is the default: leave process termination and quarantine to
    the installed AV/EDR. -ResponseMode Standalone explicitly enables response.
    Best-effort hash reputation is enabled unless -NoNetwork is specified.
    Use -AuditMode to log proposed responses without killing or quarantining.
    Copies itself to an administrator-controlled ProgramData folder, registers
    an elevated interactive logon task for the installing user, and launches it
    immediately with a hidden console. No extra switches. Clipboard inspection
    runs in that user's desktop session. Network telemetry
    is sampled established TCP connections, not packet capture.
    Scores are heuristic rule weights, not calibrated probabilities.
    Use -Uninstall to remove.

.PARAMETER Uninstall
    Remove scheduled task, stop running instances, and exit.
.PARAMETER AuditMode
    Log detections without terminating processes or removing files.
.PARAMETER ResponseMode
    Companion (default) observes only. Standalone enables process termination
    and quarantine of files confirmed malicious by AMSI or hash reputation.
.PARAMETER NoNetwork
    Disable external hash lookups. AMSI may still use its provider's own network.
.PARAMETER Foreground
    Run the monitor directly without installing a scheduled task.
.PARAMETER ScanPath
    Scan a file or directory once without installing. Reparse points are skipped.
.PARAMETER ListQuarantine
    List quarantine metadata without starting the monitor.
.PARAMETER Restore
    Restore the specified quarantine ID to the explicit RestorePath. Never overwrites.
.PARAMETER RestorePath
    Full destination file path for Restore; its parent directory must already exist.
.PARAMETER SelfTest
    Run local storage, archive, telemetry and AMSI diagnostics without installing,
    creating test malware, changing security settings, or remediating files.
#>
[CmdletBinding(DefaultParameterSetName='Monitor')]
param(
    [Parameter(ParameterSetName='Monitor')][switch]$Uninstall,
    [Parameter(ParameterSetName='Monitor')][switch]$Foreground,
    [Parameter(ParameterSetName='Monitor')][switch]$Install,
    [Parameter(ParameterSetName='Monitor')]
    [Parameter(ParameterSetName='Scan')][switch]$AuditMode,
    [Parameter(ParameterSetName='Monitor')]
    [Parameter(ParameterSetName='Scan')][switch]$NoNetwork,
    [Parameter(ParameterSetName='Monitor')]
    [Parameter(ParameterSetName='Scan')][ValidateSet('Companion','Standalone')][string]$ResponseMode = 'Companion',
    [Parameter(Mandatory,ParameterSetName='Scan')][string]$ScanPath,
    [Parameter(Mandatory,ParameterSetName='List')][switch]$ListQuarantine,
    [Parameter(Mandatory,ParameterSetName='Restore')][ValidatePattern('^[a-fA-F0-9]{32}$')][string]$Restore,
    [Parameter(Mandatory,ParameterSetName='Restore')][string]$RestorePath,
    [Parameter(Mandatory,ParameterSetName='SelfTest')][switch]$SelfTest
)

$ErrorActionPreference = "Continue"
$Script:LogPath = "$env:ProgramData\AntivirusLite\events.jsonl"
$Script:MonitorPath = "Local user profiles"
$Script:SessionId = [Diagnostics.Process]::GetCurrentProcess().SessionId
$Script:InteractiveSession = $Script:SessionId -ne 0
$Script:MaxLogSizeMB = 50
$Script:MaxLogFiles = 5
$Script:ScanIntervalSeconds = 5

# ============================================================================
# GLOBALS & STATE
# ============================================================================
$Script:Version = "4.0.0"
if ([IntPtr]::Size -ne 8) { throw 'Use 64-bit Windows PowerShell 5.1 or later.' }
$Script:IsElevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$Script:Dedup = @{}
$Script:Correlation = @{}
$Script:CorrelationTTL = 120
$Script:ProcessAncestry = @{}
$Script:BeaconTracker = @{}
$Script:LogCount = 0; $Script:LogWindow = Get-Date; $Script:LogBurst = 200
$Script:FileEvents = New-Object 'System.Collections.Concurrent.ConcurrentQueue[object]'
$Script:FileWatchers = @()
$Script:FileSubscriptions = @()
$Script:ConnectionSnapshot = $null
$Script:FileRateTracker = @{ Count = 0; Start = Get-Date }
$Script:ClipboardBaseline = ""
$Script:ClipboardChangeCount = 0; $Script:ClipboardWindow = Get-Date
$Script:ModuleBaseline = @{}
$Script:SelfHash = $null
$Script:HashCache = @{}
$Script:ReportedIndicators = @{}
$Script:DnsQueryTracker = @{}
$Script:TaskName = "AntivirusLite"
$Script:InstallDirectory = Join-Path $env:ProgramData "AntivirusLite"
$Script:InstalledScript = Join-Path $Script:InstallDirectory "AntivirusLite.ps1"
$Script:QuarantineDirectory = Join-Path $Script:InstallDirectory 'Quarantine'
$Script:AuditOnly = [bool]$AuditMode -or $ResponseMode -eq 'Companion'
$Script:ResponseMode = $ResponseMode
$Script:Offline = [bool]$NoNetwork
$Script:FileVerdicts = @{}
$Script:PendingFiles = New-Object 'System.Collections.Generic.Queue[string]'
$Script:PendingFileSet = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
$Script:MaxScanBytes = 32MB
$Script:AMSIContext = [IntPtr]::Zero
$Script:AMSIAvailable = $false
$Script:CircuitBreakers = @{}
$Script:StageHealth = @{}
$Script:EventWatermarks = @{}
$Script:SecurityBaseline = @{}
$Script:ScanExtensions = @('.exe','.dll','.sys','.scr','.com','.cpl','.msi','.ocx',
    '.ps1','.psm1','.psd1','.bat','.cmd','.vbs','.js','.jse','.wsf','.hta')

# JIT/Electron - legitimately have RWX memory (exclude from memory scan)
$Script:JitPaths = @(
    '*\java.exe','*\javaw.exe','*\node.exe','*\electron.exe',
    '*\chrome.exe','*\msedge.exe','*\firefox.exe','*\brave.exe',
    '*\Code.exe','*\kiro.exe','*\Discord.exe','*\Slack.exe','*\Teams.exe',
    '*\steam.exe','*\steamwebhelper.exe','*\obs64.exe','*\obs32.exe',
    '*\dotnet.exe','*\w3wp.exe','*\Spotify.exe','*\Signal.exe',
    '*\Notion.exe','*\Obsidian.exe','*\GitKraken.exe','*\Postman.exe',
    '*\1Password.exe','*\Bitwarden.exe','*\WindowsTerminal.exe'
)

# ============================================================================
# NATIVE METHODS
# ============================================================================
if (-not ('AntivirusLiteNative' -as [type])) {
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class AntivirusLiteNative {
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr OpenProcess(uint a, bool b, int pid);
    [DllImport("kernel32.dll")]
    public static extern bool CloseHandle(IntPtr h);
    [DllImport("kernel32.dll")]
    public static extern int VirtualQueryEx(IntPtr h, IntPtr addr, out MBI buf, int len);
    [DllImport("kernel32.dll")]
    public static extern bool ReadProcessMemory(IntPtr h, IntPtr b, byte[] buf, UIntPtr sz, out UIntPtr read);
    [DllImport("user32.dll")]
    public static extern IntPtr GetClipboardOwner();
    [DllImport("user32.dll")]
    public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint pid);
    [StructLayout(LayoutKind.Sequential)]
    public struct MBI {
        public IntPtr BaseAddress; public IntPtr AllocationBase; public uint AllocationProtect;
        public IntPtr RegionSize; public uint State; public uint Protect; public uint Type;
    }
    public const uint QI = 0x0400, VMR = 0x0010, COMMIT = 0x1000, PRIV = 0x20000;
    public const uint RWX = 0x40, RWC = 0x80;
}
"@ -ErrorAction Stop
}

# ============================================================================
# LOGGING (JSONL, rotation, rate-limited, concurrent-reader safe)
# ============================================================================
function Initialize-Log {
    $dir = Split-Path $Script:LogPath -Parent
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force -ErrorAction Stop | Out-Null }
}
function Rotate-Log {
    if (-not (Test-Path $Script:LogPath)) { return }
    if ((Get-Item $Script:LogPath -ErrorAction SilentlyContinue).Length / 1MB -ge $Script:MaxLogSizeMB) {
        for ($i = $Script:MaxLogFiles; $i -ge 1; $i--) {
            $o = "$($Script:LogPath).$i"
            if ($i -eq $Script:MaxLogFiles -and (Test-Path $o)) { Remove-Item $o -Force }
            if (Test-Path $o) { Rename-Item $o "$($Script:LogPath).$($i+1)" -Force }
        }
        Rename-Item $Script:LogPath "$($Script:LogPath).1" -Force
    }
}
function Log-Event {
    param([string]$Type,[string]$Rule,[string]$Evidence,[string]$Reasoning,
          [double]$Conf,[string]$Tier,[string]$PName="",[int]$ProcessId=0,[hashtable]$Meta=@{})
    $now = Get-Date
    if (($now - $Script:LogWindow).TotalSeconds -ge 1) { $Script:LogCount = 0; $Script:LogWindow = $now }
    if ($Script:LogCount -ge $Script:LogBurst) { return }
    $Script:LogCount++
    $obj = @{ type=$Type; timestamp=$now.ToString("o"); data=@{
        ruleName=$Rule; evidence=$Evidence; reasoning=$Reasoning
        confidence=$Conf; tier=$Tier; processName=$PName; processId=$ProcessId; metadata=$Meta
    }}
    $json = $obj | ConvertTo-Json -Depth 10 -Compress
    try { Rotate-Log; Add-Content -Path $Script:LogPath -Value $json -Encoding UTF8 -ErrorAction Stop }
    catch { Write-Warning "Unable to write AntivirusLite log: $_" }
}

# ============================================================================
# DEDUPLICATION & CORRELATION ENGINE
# ============================================================================
function Is-Dup { param([string]$K,[int]$TTL=60)
    $now = Get-Date
    $old = @($Script:Dedup.Keys | Where-Object { ($now - $Script:Dedup[$_]).TotalSeconds -gt $TTL })
    foreach ($expiredKey in $old) { $Script:Dedup.Remove($expiredKey) }
    if ($Script:Dedup.ContainsKey($K)) { return $true }
    $Script:Dedup[$K] = $now; return $false
}
function Test-NewIndicatorObservation { param([int]$ProcessId,[string]$Rule,[string]$Fingerprint)
    if ($null -eq $Script:ReportedIndicators) { $Script:ReportedIndicators = @{} }
    $info = $Script:ProcessAncestry[$ProcessId]
    # Creation time scopes observations to a process lifetime, not just a reusable PID.
    $generation = if ($info -and $info.T) { ([datetime]$info.T).ToUniversalTime().Ticks.ToString() } else { '' }
    if (-not $Script:ReportedIndicators.ContainsKey($ProcessId)) { $Script:ReportedIndicators[$ProcessId] = @{} }
    $previous = $Script:ReportedIndicators[$ProcessId][$Rule]
    if ($previous -and $previous.Generation -eq $generation -and $previous.Fingerprint -eq $Fingerprint) { return $false }
    $Script:ReportedIndicators[$ProcessId][$Rule] = @{ Generation=$generation; Fingerprint=$Fingerprint }
    return $true
}

function Add-Signal { param([int]$ProcessId,[string]$Cat,[double]$Conf)
    $now = Get-Date
    if (-not $Script:Correlation.ContainsKey($ProcessId)) { $Script:Correlation[$ProcessId] = @() }
    $Script:Correlation[$ProcessId] = @($Script:Correlation[$ProcessId] | Where-Object { ($now - $_.T).TotalSeconds -le $Script:CorrelationTTL })
    $Script:Correlation[$ProcessId] += @{ C=$Cat; V=$Conf; T=$now }
}
function Get-Categories { param([int]$ProcessId)
    if (-not $Script:Correlation.ContainsKey($ProcessId)) { return @() }
    $now = Get-Date
    @($Script:Correlation[$ProcessId] | Where-Object { ($now - $_.T).TotalSeconds -le $Script:CorrelationTTL } | ForEach-Object { $_.C } | Select-Object -Unique)
}
function Get-SignalCount { param([int]$ProcessId)
    if (-not $Script:Correlation.ContainsKey($ProcessId)) { return 0 }
    $now = Get-Date
    @($Script:Correlation[$ProcessId] | Where-Object { ($now - $_.T).TotalSeconds -le $Script:CorrelationTTL }).Count
}

# ============================================================================
# PROCESS ANCESTRY
# ============================================================================
function Initialize-FileEngine {
    param([switch]$SkipAMSI)
    # C# source is fixed. No downloaded executables, rules, or dynamic code.
    if (-not ('AntivirusLiteFiles' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.IO.Compression;
using System.ComponentModel;
using System.Text;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Microsoft.Win32.SafeHandles;
public static class AntivirusLiteFiles {
    [DllImport("amsi.dll", CharSet=CharSet.Unicode, ExactSpelling=true)]
    public static extern int AmsiInitialize(string name, out IntPtr context);
    [DllImport("amsi.dll", CharSet=CharSet.Unicode, ExactSpelling=true)]
    public static extern int AmsiScanBuffer(IntPtr context, byte[] bytes, uint length, string name, IntPtr session, out int result);
    [DllImport("amsi.dll", ExactSpelling=true)]
    public static extern void AmsiUninitialize(IntPtr context);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    private static extern SafeFileHandle CreateFile(string name, uint access, uint share, IntPtr security, uint disposition, uint flags, IntPtr template);
    [StructLayout(LayoutKind.Sequential)]
    private struct FileInfo {
        public uint Attributes;
        public System.Runtime.InteropServices.ComTypes.FILETIME Creation, Access, Write;
        public uint Volume, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;
    }
    [DllImport("kernel32.dll", SetLastError=true)]
    private static extern bool GetFileInformationByHandle(SafeFileHandle handle, out FileInfo info);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    private static extern uint GetFinalPathNameByHandle(SafeFileHandle handle, StringBuilder path, uint size, uint flags);
    [DllImport("kernel32.dll", SetLastError=true)]
    private static extern bool SetFileInformationByHandle(SafeFileHandle handle, int kind, ref byte info, uint size);
    public static FileStream OpenForQuarantine(string path) {
        // DELETE + GENERIC_READ; deny concurrent writers/renames. Open the link
        // itself so reparse points can be rejected instead of followed.
        SafeFileHandle h = CreateFile(path, 0x80010000, 1, IntPtr.Zero, 3, 0x00200000, IntPtr.Zero);
        if (h.IsInvalid) { h.Dispose(); throw new Win32Exception(Marshal.GetLastWin32Error()); }
        FileInfo i;
        if (!GetFileInformationByHandle(h, out i)) { int e=Marshal.GetLastWin32Error(); h.Dispose(); throw new Win32Exception(e); }
        if ((i.Attributes & (0x400 | 0x10)) != 0 || i.Links != 1) { h.Dispose(); throw new IOException("Links and directories are not quarantine candidates."); }
        StringBuilder finalPath = new StringBuilder(32768);
        uint size=GetFinalPathNameByHandle(h,finalPath,32768,0);
        if (size==0 || size>=32768) { h.Dispose(); throw new IOException("Cannot verify the opened file path."); }
        string resolved=finalPath.ToString();
        if (resolved.StartsWith(@"\\?\")) resolved=resolved.Substring(4);
        if (!String.Equals(resolved,Path.GetFullPath(path),StringComparison.OrdinalIgnoreCase)) {
            h.Dispose(); throw new IOException("Opened path resolves through an alias or redirect.");
        }
        return new FileStream(h, FileAccess.Read);
    }
    public static void DeleteLockedSource(FileStream source) {
        byte disposition = 1;
        if (!SetFileInformationByHandle(source.SafeFileHandle, 4, ref disposition, 1))
            throw new Win32Exception(Marshal.GetLastWin32Error());
    }
    public static string Hash(Stream source) {
        source.Position=0;
        using (SHA256 hash=SHA256.Create()) {
            string value=BitConverter.ToString(hash.ComputeHash(source)).Replace("-", "");
            source.Position=0; return value;
        }
    }
    public static void Pack(Stream source, string target) {
        source.Position=0;
        using (FileStream file=new FileStream(target, FileMode.CreateNew, FileAccess.Write, FileShare.None))
        using (GZipStream zip=new GZipStream(file, CompressionMode.Compress)) { source.CopyTo(zip); }
        source.Position=0;
    }
    public static void Unpack(string source, string target, long expectedLength, string expectedHash) {
        if (expectedLength < 0 || expectedLength > 33554432) throw new IOException("Invalid payload size.");
        bool created=false;
        try {
            using (FileStream input=File.OpenRead(source))
            using (GZipStream zip=new GZipStream(input, CompressionMode.Decompress))
            using (FileStream output=new FileStream(target, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None)) {
                created=true;
                byte[] buffer=new byte[65536]; long total=0; int count;
                while ((count=zip.Read(buffer,0,buffer.Length))>0) {
                    total+=count; if (total>expectedLength) throw new IOException("Payload exceeds recorded size.");
                    output.Write(buffer,0,count);
                }
                if (total!=expectedLength || !String.Equals(Hash(output),expectedHash,StringComparison.OrdinalIgnoreCase))
                    throw new IOException("Payload integrity check failed.");
            }
        } catch { if (created) File.Delete(target); throw; }
    }
}
'@ -ErrorAction Stop
    }
    if (-not $SkipAMSI -and -not $Script:AMSIAvailable) {
        try {
            $context = [IntPtr]::Zero
            $hr = [AntivirusLiteFiles]::AmsiInitialize('Gorstak.AntivirusLite', [ref]$context)
            if ($hr -lt 0 -or $context -eq [IntPtr]::Zero) { throw "AMSI initialization HRESULT=$hr" }
            $Script:AMSIContext = $context
            $Script:AMSIAvailable = $true
        } catch {
            Write-Warning "AMSI unavailable; file scans will report unknown, not clean: $_"
        }
    }
}

function Close-FileEngine {
    if ($Script:AMSIAvailable) { [AntivirusLiteFiles]::AmsiUninitialize($Script:AMSIContext) }
    $Script:AMSIAvailable = $false
    $Script:AMSIContext = [IntPtr]::Zero
}

function Test-PathWithin {
    param([string]$Path,[string]$Root)
    if ([string]::IsNullOrWhiteSpace($Root)) { return $false }
    $p = [IO.Path]::GetFullPath($Path)
    $r = [IO.Path]::GetFullPath($Root).TrimEnd([IO.Path]::DirectorySeparatorChar,[IO.Path]::AltDirectorySeparatorChar)
    return $p.Equals($r,[StringComparison]::OrdinalIgnoreCase) -or
        $p.StartsWith($r + [IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)
}

function Assert-NoReparsePath {
    param([string]$Path)
    $current = [IO.Path]::GetFullPath($Path)
    while ($current) {
        if (Test-Path -LiteralPath $current) {
            if ((Get-Item -LiteralPath $current -Force -ErrorAction Stop).Attributes -band [IO.FileAttributes]::ReparsePoint) {
                throw "Reparse points are not supported: $current"
            }
        }
        $current = [IO.Path]::GetDirectoryName($current)
    }
}

function Test-ProtectedFile {
    param([string]$Path)
    if (-not $Path -or -not [IO.Path]::IsPathRooted($Path)) { return $true }
    if ($env:OS -eq 'Windows_NT' -and ($Path -notmatch '^[a-zA-Z]:\\' -or $Path.Substring(2).Contains(':'))) { return $true }
    # Preserve Windows, installed software, this monitor, and shared script hosts.
    foreach ($root in @($env:SystemRoot,$env:ProgramFiles,${env:ProgramFiles(x86)},$Script:InstallDirectory)) {
        if (Test-PathWithin -Path $Path -Root $root) { return $true }
    }
    if ($PSCommandPath -and [string]::Equals([IO.Path]::GetFullPath($Path),[IO.Path]::GetFullPath($PSCommandPath),[StringComparison]::OrdinalIgnoreCase)) { return $true }
    return [IO.Path]::GetFileName($Path) -in @('powershell.exe','pwsh.exe','cmd.exe','wscript.exe','cscript.exe','mshta.exe','rundll32.exe','regsvr32.exe','msiexec.exe')
}

function Set-PrivateStorageAcl {
    param([string]$Path)
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true,$false)
    $acl.SetOwner((New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')))
    foreach ($sid in @('S-1-5-18','S-1-5-32-544')) {
        $identity = New-Object Security.Principal.SecurityIdentifier($sid)
        $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($identity,'FullControl','ContainerInherit,ObjectInherit','None','Allow')))
    }
    Set-Acl -LiteralPath $Path -AclObject $acl -ErrorAction Stop
}

function Initialize-Storage {
    Assert-NoReparsePath -Path $Script:InstallDirectory
    if (-not (Test-Path -LiteralPath $Script:InstallDirectory)) {
        New-Item -ItemType Directory -Path $Script:InstallDirectory -ErrorAction Stop | Out-Null
    }
    Set-PrivateStorageAcl -Path $Script:InstallDirectory
    # Reject pre-existing redirects before log/quarantine writes.
    Assert-NoReparsePath -Path $Script:LogPath
    if (-not $Script:AuditOnly) {
        Assert-NoReparsePath -Path $Script:QuarantineDirectory
        if (-not (Test-Path -LiteralPath $Script:QuarantineDirectory)) {
            New-Item -ItemType Directory -Path $Script:QuarantineDirectory -ErrorAction Stop | Out-Null
        }
        Set-PrivateStorageAcl -Path $Script:QuarantineDirectory
    }
}

function Write-QuarantineRecord {
    param([string]$Id,[object]$Record)
    if ($Id -notmatch '^[a-fA-F0-9]{32}$') { throw 'Invalid quarantine ID.' }
    $path = Join-Path $Script:QuarantineDirectory ($Id + '.json')
    $temp = Join-Path $Script:QuarantineDirectory (([guid]::NewGuid().ToString('N')) + '.tmp')
    try {
        [IO.File]::WriteAllText($temp,($Record | ConvertTo-Json -Depth 6),[Text.UTF8Encoding]::new($false))
        if ([IO.File]::Exists($path)) { [IO.File]::Replace($temp,$path,[NullString]::Value) }
        else { [IO.File]::Move($temp,$path) }
    } finally { if ([IO.File]::Exists($temp)) { [IO.File]::Delete($temp) } }
}

function Move-ToQuarantine {
    param([string]$Path,[string]$Hash,[string]$Reason)
    # Only content-backed verdicts reach here. A heuristic process alert never
    # authorizes moving its executable (which might be a legitimate host).
    if ($Script:AuditOnly) { return $false }
    if (Test-ProtectedFile -Path $Path) { return $false }
    Assert-NoReparsePath -Path $Path
    Assert-NoReparsePath -Path $Script:QuarantineDirectory
    $id = [guid]::NewGuid().ToString('N')
    $payload = Join-Path $Script:QuarantineDirectory ($id + '.quarantine')
    $source = $null
    $recordSaved = $false
    try {
        $source = [AntivirusLiteFiles]::OpenForQuarantine($Path)
        if ($source.Length -gt $Script:MaxScanBytes) { throw 'File exceeds quarantine size limit.' }
        if ([AntivirusLiteFiles]::Hash($source) -ne $Hash) { throw 'File changed after detection; no removal performed.' }
        [AntivirusLiteFiles]::Pack($source,$payload)
        # Verify the archive before authorizing deletion of the locked source.
        $verify = Join-Path $Script:QuarantineDirectory ($id + '.verify')
        try { [AntivirusLiteFiles]::Unpack($payload,$verify,$source.Length,$Hash) }
        finally { if ([IO.File]::Exists($verify)) { [IO.File]::Delete($verify) } }
        $record = [ordered]@{ schema=1; id=$id; originalPath=[IO.Path]::GetFullPath($Path); sha256=$Hash;
            length=$source.Length; reason=$Reason; timeUtc=[datetime]::UtcNow.ToString('o'); state='Copied'; format='gzip' }
        Write-QuarantineRecord -Id $id -Record $record
        $recordSaved = $true
        [AntivirusLiteFiles]::DeleteLockedSource($source)
        $source.Dispose(); $source = $null
        $record.state = 'Quarantined'
        Write-QuarantineRecord -Id $id -Record $record
        Log-Event -Type 'response' -Rule 'Quarantine' -Evidence $Path -Reasoning $Reason -Conf 1 -Tier 'Response' -Meta @{id=$id; sha256=$Hash}
        return $true
    } catch {
        Log-Event -Type 'system' -Rule 'QuarantineFailed' -Evidence $Path -Reasoning ([string]$_) -Conf 1 -Tier 'System' -Meta @{id=$id; recoveryRecord=$recordSaved}
        Write-Warning "Quarantine failed for ${Path}: $_"
        # Never report a copy/locked file as isolated. Retain a durable record
        # if source removal failed; the third-party AV may have won the race.
        if (-not $recordSaved -and [IO.File]::Exists($payload)) { [IO.File]::Delete($payload) }
        return $false
    } finally { if ($source) { $source.Dispose() } }
}

function Get-QuarantineRecords {
    if (-not (Test-Path -LiteralPath $Script:QuarantineDirectory)) { return }
    Assert-NoReparsePath -Path $Script:QuarantineDirectory
    foreach ($file in Get-ChildItem -LiteralPath $Script:QuarantineDirectory -Filter '*.json' -File) {
        Assert-NoReparsePath -Path $file.FullName
        try { Get-Content -LiteralPath $file.FullName -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop }
        catch { Write-Warning "Unreadable quarantine record $($file.Name): $_" }
    }
}

function Restore-QuarantineFile {
    param([string]$Id,[string]$Destination)
    if ($Id -notmatch '^[a-fA-F0-9]{32}$') { throw 'Invalid quarantine ID.' }
    if (-not [IO.Path]::IsPathRooted($Destination)) { throw 'RestorePath must be absolute.' }
    $Destination = [IO.Path]::GetFullPath($Destination)
    if (Test-ProtectedFile -Path $Destination) { throw 'Restore to a user-controlled location outside Windows, Program Files, or monitor storage.' }
    Assert-NoReparsePath -Path $Destination
    Assert-NoReparsePath -Path $Script:QuarantineDirectory
    $metadata = Join-Path $Script:QuarantineDirectory ($Id + '.json')
    $payload = Join-Path $Script:QuarantineDirectory ($Id + '.quarantine')
    Assert-NoReparsePath -Path $metadata
    Assert-NoReparsePath -Path $payload
    $record = Get-Content -LiteralPath $metadata -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    if ($record.id -ne $Id -or $record.schema -ne 1 -or $record.format -ne 'gzip' -or
        $record.sha256 -notmatch '^[a-fA-F0-9]{64}$' -or $record.state -notin @('Quarantined','Copied','Restored')) { throw 'Invalid quarantine metadata.' }
    $parent = [IO.Path]::GetDirectoryName($Destination)
    if (-not [IO.Directory]::Exists($parent)) { throw 'Restore destination directory must already exist.' }
    if (Test-Path -LiteralPath $Destination) { throw 'Restore never overwrites an existing file.' }
    # Verify inside protected storage before making bytes available at destination.
    $temp = Join-Path $Script:QuarantineDirectory (([guid]::NewGuid().ToString('N')) + '.restore')
    try {
        [AntivirusLiteFiles]::Unpack($payload,$temp,[long]$record.length,$record.sha256)
        # Publish only a complete copy; never overwrite a concurrent file.
        $staged = Join-Path $parent (([guid]::NewGuid().ToString('N')) + '.restoring')
        $output = [IO.File]::Open($staged,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
        try {
            $input = [IO.File]::OpenRead($temp)
            try { $input.CopyTo($output) } finally { $input.Dispose() }
        } finally { $output.Dispose() }
        [IO.File]::Move($staged,$Destination)
        $record.state = 'Restored'
        $record | Add-Member -NotePropertyName restoredPath -NotePropertyValue $Destination -Force
        Write-QuarantineRecord -Id $Id -Record $record
        Log-Event -Type 'response' -Rule 'Restore' -Evidence $Destination -Reasoning 'Explicit administrator restore; archive retained' -Conf 1 -Tier 'Response' -Meta @{id=$Id}
    } finally {
        if ([IO.File]::Exists($temp)) { [IO.File]::Delete($temp) }
        if ($staged -and [IO.File]::Exists($staged)) { [IO.File]::Delete($staged) }
    }
}

function Get-ContentVerdict {
    param([string]$Path)
    Assert-NoReparsePath -Path $Path
    $file = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($file.PSIsContainer -or $file.Length -gt $Script:MaxScanBytes) {
        return [pscustomobject]@{ Path=$Path; Verdict='Skipped'; Hash=''; Reason='Not a regular file or exceeds 32 MiB' }
    }
    $stream = [IO.File]::Open($file.FullName,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    try {
        $hash = [AntivirusLiteFiles]::Hash($stream)
        if ($Script:FileVerdicts.ContainsKey($hash)) {
            $cached = $Script:FileVerdicts[$hash]
            if (([datetime]::UtcNow - $cached.Time).TotalMinutes -lt 5) {
                return [pscustomobject]@{ Path=$file.FullName; Verdict=$cached.Verdict; Hash=$hash; Reason=$cached.Reason }
            }
        }
        $verdict = 'Unknown'; $reasons = @()
        if ($Script:AMSIAvailable) {
            $bytes = New-Object byte[] ([int]$stream.Length)
            $offset = 0
            while ($offset -lt $bytes.Length) {
                $read = $stream.Read($bytes,$offset,($bytes.Length-$offset))
                if (-not $read) { throw 'Short read while scanning file.' }
                $offset += $read
            }
            $result = 0
            $hr = [AntivirusLiteFiles]::AmsiScanBuffer($Script:AMSIContext,$bytes,[uint32]$bytes.Length,$file.FullName,[IntPtr]::Zero,[ref]$result)
            if ($hr -lt 0) { $reasons += "AMSI failed HRESULT=$hr" }
            elseif ($result -ge 32768) { $verdict='Malicious'; $reasons += 'AMSI malware verdict' }
            elseif ($result -ge 16384) { $verdict='Blocked'; $reasons += 'AMSI administrator policy block; not a malware verdict' }
            else { $reasons += 'AMSI returned no detection; not proof of safety' }
        } else { $reasons += 'AMSI unavailable' }
        if ($verdict -ne 'Malicious') {
            $rep = Test-HashReputation -Hash $hash
            if ($rep.Bad) { $verdict='Malicious' }
            $reasons += "$($rep.Src): $($rep.Detail)"
        }
        if ($Script:FileVerdicts.Count -ge 4096) { $Script:FileVerdicts.Clear() }
        $reason = $reasons -join '; '
        $Script:FileVerdicts[$hash] = @{ Time=[datetime]::UtcNow; Verdict=$verdict; Reason=$reason }
        return [pscustomobject]@{ Path=$file.FullName; Verdict=$verdict; Hash=$hash; Reason=$reason }
    } finally { $stream.Dispose() }
}

function Invoke-FileVerdict {
    param([string]$Path)
    try {
        $result = Get-ContentVerdict -Path $Path
        if ($result.Verdict -in @('Malicious','Blocked')) {
            Log-Event -Type 'detection' -Rule 'FileVerdict' -Evidence $result.Path -Reasoning $result.Reason -Conf 1 -Tier 'Content' -Meta @{sha256=$result.Hash; verdict=$result.Verdict; responseMode=$Script:ResponseMode; audit=$Script:AuditOnly}
            if ($result.Verdict -eq 'Malicious' -and -not $Script:AuditOnly) {
                $isolated = Move-ToQuarantine -Path $result.Path -Hash $result.Hash -Reason $result.Reason
                $result | Add-Member -NotePropertyName Quarantined -NotePropertyValue $isolated
            }
        }
        return $result
    } catch {
        # Files may vanish because another AV has already remediated them.
        Log-Event -Type 'system' -Rule 'FileScanUnavailable' -Evidence $Path -Reasoning ([string]$_) -Conf 1 -Tier 'System'
        return [pscustomobject]@{ Path=$Path; Verdict='Unavailable'; Hash=''; Reason=[string]$_ }
    }
}

function Add-PendingFile {
    param([string]$Path)
    if ([IO.Path]::GetExtension($Path) -notin $Script:ScanExtensions) { return }
    if (Test-PathWithin -Path $Path -Root $Script:InstallDirectory) { return }
    if (Test-ProtectedFile -Path $Path) { return }
    if ($Script:PendingFiles.Count -ge 2048) {
        if (-not (Is-Dup -K 'FileScanQueueFull' -TTL 60)) {
            Log-Event -Type 'system' -Rule 'FileScanQueueFull' -Evidence '2048 pending files' -Reasoning 'New candidates dropped; use ScanPath for a complete scan' -Conf 1 -Tier 'System'
        }
        return
    }
    if ($Script:PendingFileSet.Add($Path)) { $Script:PendingFiles.Enqueue($Path) }
}

function Invoke-PendingFileScans {
    # Bound network latency and memory per monitor cycle; AMSI scans <=32 MiB.
    for ($count=0; $count -lt 2 -and $Script:PendingFiles.Count -gt 0; $count++) {
        $path = $Script:PendingFiles.Dequeue()
        $null = $Script:PendingFileSet.Remove($path)
        $null = Invoke-FileVerdict -Path $path
    }
}

function Invoke-PathScan {
    param([string]$Path)
    $full = [IO.Path]::GetFullPath($Path)
    Assert-NoReparsePath -Path $full
    if (-not (Test-Path -LiteralPath $full)) { throw 'Scan path does not exist.' }
    $directories = New-Object 'System.Collections.Generic.Queue[string]'
    $stats = @{ Scanned=0; Malicious=0; Blocked=0; Unknown=0; Unavailable=0; Skipped=0 }
    $item = Get-Item -LiteralPath $full -Force -ErrorAction Stop
    if ($item.PSIsContainer) { $directories.Enqueue($full) } else {
        $result = Invoke-FileVerdict -Path $full
        $stats.Scanned++; $stats[$result.Verdict]++
        Write-Output $result
    }
    while ($directories.Count -gt 0) {
        $dir = $directories.Dequeue()
        try {
            Assert-NoReparsePath -Path $dir
            foreach ($entry in Get-ChildItem -LiteralPath $dir -Force -ErrorAction Stop) {
                if ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) { $stats.Skipped++; continue }
                if (Test-PathWithin -Path $entry.FullName -Root $Script:InstallDirectory) { $stats.Skipped++; continue }
                if ($entry.PSIsContainer) { $directories.Enqueue($entry.FullName) }
                elseif ($entry.Extension -in $Script:ScanExtensions) {
                    $result = Invoke-FileVerdict -Path $entry.FullName
                    $stats.Scanned++; $stats[$result.Verdict]++
                    Write-Output $result
                } else { $stats.Skipped++ }
            }
        } catch { $stats.Unavailable++; Write-Warning "Cannot enumerate ${dir}: $_" }
    }
    Write-Host ("Scan summary: " + ($stats | ConvertTo-Json -Compress))
    if ($stats.Scanned -eq 0) { Write-Warning 'No eligible files scanned.' }
}

function Test-AutorunCommand {
    param([string]$Command)
    # Shell use alone is common. Require a staging location, remote URL, or
    # encoded/download-and-execute pattern before emitting an inventory alert.
    return $Command -match '(?i)https?://|\\(?:AppData|Temp|Downloads)\\|-(?:enc|encodedcommand)\s+[A-Za-z0-9+/=]{40,}|downloadstring|invoke-expression'
}

function Invoke-PersistenceInventory {
    $keys = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce')
    foreach ($key in $keys) {
        if (-not (Test-Path -LiteralPath $key)) { continue }
        $values = Get-ItemProperty -LiteralPath $key -ErrorAction Stop
        foreach ($property in $values.PSObject.Properties) {
            if ($property.Name -like 'PS*' -or $property.Value -isnot [string]) { continue }
            if ((Test-AutorunCommand -Command $property.Value) -and -not (Is-Dup -K "Autorun|$key|$($property.Name)|$($property.Value)" -TTL 1800)) {
                Log-Event -Type 'detection' -Rule 'RegistryAutorun' -Evidence "$key : $($property.Name) = $($property.Value)" -Reasoning 'Review suspicious autorun; no modification performed' -Conf 0.65 -Tier 'Inventory'
            }
        }
    }
    foreach ($task in Get-ScheduledTask -ErrorAction Stop) {
        foreach ($action in $task.Actions) {
            $command = "$($action.Execute) $($action.Arguments)"
            if ((Test-AutorunCommand -Command $command) -and -not (Is-Dup -K "Task|$($task.TaskPath)|$($task.TaskName)|$command" -TTL 1800)) {
                Log-Event -Type 'detection' -Rule 'ScheduledAutorun' -Evidence "$($task.TaskPath)$($task.TaskName) : $command" -Reasoning 'Review suspicious scheduled action; task retained' -Conf 0.65 -Tier 'Inventory'
            }
        }
    }
}

function Invoke-SecurityPosture {
    # Observe state and changes. Never enable/disable another security product.
    $snapshot = @{}
    foreach ($profile in Get-NetFirewallProfile -ErrorAction Stop) {
        $snapshot['Firewall.' + $profile.Name] = [string]$profile.Enabled
    }
    foreach ($service in Get-CimInstance Win32_Service -Property Name,PathName,StartMode -ErrorAction Stop) {
        $snapshot['Service.' + $service.Name] = "$($service.PathName)|$($service.StartMode)"
    }
    foreach ($key in $snapshot.Keys) {
        $changed = $Script:SecurityBaseline.ContainsKey($key) -and $Script:SecurityBaseline[$key] -ne $snapshot[$key]
        $newService = $Script:SecurityBaseline.Count -gt 0 -and $key -like 'Service.*' -and -not $Script:SecurityBaseline.ContainsKey($key)
        $disabledFirewall = $key -like 'Firewall.*' -and $snapshot[$key] -eq 'False'
        if (($changed -or $newService -or $disabledFirewall) -and -not (Is-Dup -K "Posture|$key|$($snapshot[$key])" -TTL 1800)) {
            Log-Event -Type 'detection' -Rule 'SecurityPosture' -Evidence "$key = $($snapshot[$key])" -Reasoning 'Configuration change or disabled firewall; review with the installed security product' -Conf 0.6 -Tier 'Inventory' -Meta @{previous=$Script:SecurityBaseline[$key]}
        }
    }
    $Script:SecurityBaseline = $snapshot
}

function Invoke-SecurityEvents {
    $channels = @(
        @{ Name='System'; Ids=@(104,7045) },
        @{ Name='Security'; Ids=@(1102) },
        @{ Name='Microsoft-Windows-Windows Defender/Operational'; Ids=@(1116,1117) }
    )
    foreach ($channel in $channels) {
        $end = Get-Date
        $start = if ($Script:EventWatermarks.ContainsKey($channel.Name)) { $Script:EventWatermarks[$channel.Name].AddSeconds(-1) } else { $end.AddMinutes(-5) }
        try {
            $events = @(Get-WinEvent -FilterHashtable @{LogName=$channel.Name;Id=$channel.Ids;StartTime=$start;EndTime=$end} -MaxEvents 100 -ErrorAction Stop)
            if ($events.Count -eq 100) {
                Log-Event -Type 'system' -Rule 'EventScanLimit' -Evidence $channel.Name -Reasoning '100-event limit reached; older events in this interval may be omitted' -Conf 1 -Tier 'System'
            }
            foreach ($eventRecord in $events) {
                $key = "Event|$($channel.Name)|$($eventRecord.RecordId)|$($eventRecord.TimeCreated.Ticks)"
                if (Is-Dup -K $key -TTL 600) { continue }
                Log-Event -Type 'observation' -Rule 'WindowsSecurityEvent' -Evidence "$($channel.Name): event $($eventRecord.Id), provider $($eventRecord.ProviderName)" -Reasoning 'Security log clear, service install, or Defender detection/action; no duplicate remediation' -Conf 1 -Tier 'ExternalTelemetry' -Meta @{channel=$channel.Name; eventId=$eventRecord.Id; recordId=$eventRecord.RecordId; eventTime=$eventRecord.TimeCreated.ToUniversalTime().ToString('o')}
            }
            $Script:EventWatermarks[$channel.Name] = $end
        } catch {
            if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { $Script:EventWatermarks[$channel.Name]=$end; continue }
            if (-not (Is-Dup -K ('EventAccess|' + $channel.Name) -TTL 1800)) {
                Log-Event -Type 'system' -Rule 'EventLogUnavailable' -Evidence $channel.Name -Reasoning 'Channel unavailable or inaccessible; other telemetry continues' -Conf 1 -Tier 'System'
            }
        }
    }
}

function Write-HealthHeartbeat {
    $stages = @{}
    foreach ($key in $Script:StageHealth.Keys) { $stages[$key] = $Script:StageHealth[$key] }
    $process = [Diagnostics.Process]::GetCurrentProcess()
    try {
        Log-Event -Type 'system' -Rule 'Health' -Evidence "AntivirusLite v$Script:Version" -Reasoning 'Periodic health snapshot; capability availability is not detection coverage' -Conf 1 -Tier 'System' -Meta @{
            mode=$Script:ResponseMode; observeOnly=$Script:AuditOnly; amsi=$Script:AMSIAvailable;
            noNetwork=$Script:Offline; queuedFiles=$Script:PendingFiles.Count;
            watchers=$Script:FileWatchers.Count; workingSetMB=[Math]::Round($process.WorkingSet64/1MB);
            stages=$stages; circuits=$Script:CircuitBreakers
        }
    } finally { $process.Dispose() }
}

function Invoke-LocalSelfTest {
    # Benign local bytes only. Does not install a task, emit EICAR, or invoke
    # quarantine/remediation. AMSI no-detection is not labeled "AV works".
    $results = New-Object 'System.Collections.Generic.List[object]'
    $temp = Join-Path $Script:InstallDirectory ([guid]::NewGuid().ToString('N'))
    $memory = [IO.MemoryStream]::new([Text.Encoding]::UTF8.GetBytes('AntivirusLite benign archive round-trip'))
    try {
        $hash = [AntivirusLiteFiles]::Hash($memory)
        [AntivirusLiteFiles]::Pack($memory,($temp + '.quarantine'))
        [AntivirusLiteFiles]::Unpack(($temp + '.quarantine'),($temp + '.out'),$memory.Length,$hash)
        $results.Add([pscustomobject]@{Check='Archive SHA-256 round trip';Status='Pass'})
    } finally {
        $memory.Dispose()
        foreach ($suffix in @('.quarantine','.out')) { if ([IO.File]::Exists($temp+$suffix)) { [IO.File]::Delete($temp+$suffix) } }
    }
    $results.Add([pscustomobject]@{Check='AMSI initialization';Status=$(if ($Script:AMSIAvailable) {'Pass'} else {'Unavailable'})})
    foreach ($check in @(
        @{ Name='Process telemetry'; Action={ $null=Get-CimInstance Win32_Process -Property ProcessId -ErrorAction Stop | Select-Object -First 1 } },
        @{ Name='Scheduled tasks'; Action={ $null=Get-ScheduledTask -ErrorAction Stop | Select-Object -First 1 } },
        @{ Name='Firewall telemetry'; Action={ $null=Get-NetFirewallProfile -ErrorAction Stop } }
    )) {
        try { & $check.Action; $results.Add([pscustomobject]@{Check=$check.Name;Status='Pass'}) }
        catch { $results.Add([pscustomobject]@{Check=$check.Name;Status='Unavailable';Detail=[string]$_}) }
    }
    # Client editions may expose third-party AV registrations here. Their raw
    # productState is deliberately not decoded into an unsupported health claim.
    try {
        $products = @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction Stop | Select-Object -ExpandProperty displayName)
        $results.Add([pscustomobject]@{Check='Registered AV products (inventory only)';Status='Info';Detail=($products -join '; ')})
    } catch { $results.Add([pscustomobject]@{Check='Security Center inventory';Status='Unavailable';Detail='May be absent on Windows Server'}) }
    $results
}

function Update-Ancestry {
    $s = @{}
    try {
        Get-CimInstance Win32_Process -Property ProcessId,ParentProcessId,Name,CommandLine,ExecutablePath,CreationDate -ErrorAction Stop | ForEach-Object {
            $s[$_.ProcessId] = @{ N=$_.Name; PP=$_.ParentProcessId; CL=$_.CommandLine; P=$_.ExecutablePath; T=$_.CreationDate }
        }
    } catch { throw "Process snapshot failed; previous state retained: $_" }
    foreach ($processKey in @($Script:ProcessAncestry.Keys)) {
        if (-not $s.ContainsKey($processKey) -or
            $s[$processKey].T -ne $Script:ProcessAncestry[$processKey].T) {
            $Script:Correlation.Remove($processKey)
            $Script:ModuleBaseline.Remove($processKey)
            $Script:ReportedIndicators.Remove($processKey)
        }
    }
    $Script:ProcessAncestry = $s
}

# ============================================================================
# ENTROPY (Shannon) - used for DGA detection and DLL analysis
# ============================================================================
function Get-Entropy { param([string]$S)
    if ([string]::IsNullOrEmpty($S)) { return 0 }
    $f = @{}; foreach ($c in $S.ToCharArray()) { if ($f.ContainsKey($c)){$f[$c]++}else{$f[$c]=1} }
    $l = $S.Length; $e = 0.0
    foreach ($v in $f.Values) { $p = $v/$l; if ($p -gt 0) { $e -= $p * [Math]::Log($p,2) } }
    return $e
}

# ============================================================================
# HASH REPUTATION (Live API - like AV.ps1 approach)
# ============================================================================
function Test-CircuitAvailable {
    param([string]$Service)
    $circuit = $Script:CircuitBreakers[$Service]
    return -not $circuit -or $circuit.Failures -lt 3 -or [datetime]::UtcNow -ge $circuit.RetryAfter
}

function Set-CircuitOutcome {
    param([string]$Service,[bool]$Success)
    if ($Success) { $Script:CircuitBreakers.Remove($Service); return }
    if (-not $Script:CircuitBreakers.ContainsKey($Service)) {
        $Script:CircuitBreakers[$Service] = @{ Failures=0; RetryAfter=[datetime]::MinValue }
    }
    $entry = $Script:CircuitBreakers[$Service]
    $entry.Failures++
    if ($entry.Failures -ge 3) { $entry.RetryAfter = [datetime]::UtcNow.AddMinutes(5) }
}

function Test-HashReputation { param([string]$Hash)
    if ($Hash -notmatch '^[a-fA-F0-9]{64}$') { throw 'Invalid SHA-256.' }
    if ($Script:Offline) { return @{ Bad=$false; Src='Offline'; Detail='External reputation disabled' } }
    if ($Script:HashCache.ContainsKey($Hash) -and
        ([datetime]::UtcNow - $Script:HashCache[$Hash].Time).TotalMinutes -lt 5) { return $Script:HashCache[$Hash] }
    $verdict = @{ Bad=$false; Src='Unknown'; Detail='No verdict; unknown hash or lookup unavailable'; Time=[datetime]::UtcNow }
    # Known-malicious evidence takes precedence over a known-file lookup.
    if ($env:SENTINEL_ABUSECH_AUTH_KEY -and (Test-CircuitAvailable -Service 'MalwareBazaar')) {
        try {
            $r = Invoke-RestMethod -Uri 'https://mb-api.abuse.ch/api/v1/' -Method Post -Body @{query='get_info';hash=$Hash} -Headers @{'Auth-Key'=$env:SENTINEL_ABUSECH_AUTH_KEY} -ContentType 'application/x-www-form-urlencoded' -TimeoutSec 4 -ErrorAction Stop
            Set-CircuitOutcome -Service 'MalwareBazaar' -Success $true
            $match = @($r.data | Where-Object { $_.sha256_hash -eq $Hash })
            if ($r.query_status -eq 'ok' -and $match.Count -gt 0) {
                $verdict.Bad=$true; $verdict.Src='MalwareBazaar'; $verdict.Detail='Exact SHA-256 malware match'
            }
        } catch {
            Set-CircuitOutcome -Service 'MalwareBazaar' -Success $false
            if (-not (Is-Dup -K 'ReputationUnavailable' -TTL 300)) {
                Log-Event -Type 'system' -Rule 'ReputationUnavailable' -Evidence 'MalwareBazaar lookup failed' -Reasoning 'No verdict; AMSI and behavioral scanning continue' -Conf 1 -Tier 'System'
            }
        }
    }
    if (-not $verdict.Bad -and (Test-CircuitAvailable -Service 'CIRCL')) {
        try {
            $r = Invoke-RestMethod -Uri "https://hashlookup.circl.lu/lookup/sha256/$Hash" -Method Get -TimeoutSec 4 -ErrorAction Stop
            Set-CircuitOutcome -Service 'CIRCL' -Success $true
            if ($r.'SHA-256' -eq $Hash) {
                $verdict.Src='CIRCL'; $verdict.Detail='Known file; not an allowlist or proof of safety'
            }
        } catch {
            # A missing hash is a successful lookup with no verdict, not outage.
            $notFound = $_.Exception.Response -and [int]$_.Exception.Response.StatusCode -eq 404
            Set-CircuitOutcome -Service 'CIRCL' -Success ([bool]$notFound)
        }
    }
    if ($Script:HashCache.Count -ge 4096) { $Script:HashCache.Clear() }
    $Script:HashCache[$Hash] = $verdict
    return $Script:HashCache[$Hash]
}

# ============================================================================
# SELF-PROTECTION (detect tampering of own script/process)
# ============================================================================
function Initialize-SelfProtection {
    if ($PSCommandPath) {
        try { $Script:SelfHash = (Get-FileHash -Path $PSCommandPath -Algorithm SHA256 -ErrorAction Stop).Hash }
        catch { $Script:SelfHash = $null }
    }
}
function Test-SelfIntegrity {
    if (-not $Script:SelfHash -or -not $PSCommandPath) { return }
    try {
        $current = (Get-FileHash -Path $PSCommandPath -Algorithm SHA256 -ErrorAction Stop).Hash
        if ($current -ne $Script:SelfHash) {
            if (-not (Is-Dup -K "SelfTamper" -TTL 300)) {
                Log-Event -Type "detection" -Rule "SelfProtection" -Evidence "Script file modified on disk" `
                    -Reasoning "AntivirusLite script hash changed - possible tampering" -Conf 0.97 -Tier "Tier1Behavioral" -PName "AntivirusLite" -ProcessId $PID
                Write-Host "[CRITICAL] Self-protection: script file tampered" -ForegroundColor Red
            }
        }
    } catch {}
}

# ============================================================================
# MEMORY ANALYSIS (allocation patterns require separate structural evidence)
# ============================================================================
function Invoke-MemoryAnalysis { param([int]$ProcessId,[string]$Name,[string]$Path)
    if ($ProcessId -le 4 -or $ProcessId -eq $PID) { return $null }
    $h = [AntivirusLiteNative]::OpenProcess(([AntivirusLiteNative]::QI -bor [AntivirusLiteNative]::VMR), $false, $ProcessId)
    if ($h -eq [IntPtr]::Zero) { return $null }
    $flags = @()
    try {
        $addr = [IntPtr]::Zero; $rwx = 0; $unbacked = 0; $privExec = [int64]0
        $mbi = New-Object AntivirusLiteNative+MBI
        for ($i = 0; $i -lt 2000; $i++) {
            if ([AntivirusLiteNative]::VirtualQueryEx($h, $addr, [ref]$mbi, [Runtime.InteropServices.Marshal]::SizeOf($mbi)) -eq 0) { break }
            if ($mbi.State -eq [AntivirusLiteNative]::COMMIT) {
                if ($mbi.Protect -eq [AntivirusLiteNative]::RWX -or $mbi.Protect -eq [AntivirusLiteNative]::RWC) { $rwx++ }
                if ($mbi.Type -eq [AntivirusLiteNative]::PRIV -and ($mbi.Protect -band 0xF0) -ne 0) {
                    $unbacked++; $privExec += [int64]$mbi.RegionSize
                }
            }
            $n = [int64]$addr + [int64]$mbi.RegionSize
            if ($n -le [int64]$addr) { break }
            $addr = [IntPtr]$n
        }
        if ($rwx -ge 5) { $flags += "RWX:$rwx" }
        if ($unbacked -ge 8) { $flags += "Unbacked:$unbacked" }
        if ($privExec -gt 50MB) { $flags += "PrivExec:$([Math]::Round($privExec/1MB))MB" }
    } finally { [AntivirusLiteNative]::CloseHandle($h) | Out-Null }

    # Hollowing: image path vs main module mismatch
    try {
        $p = Get-Process -Id $ProcessId -ErrorAction Stop
        if ($p.Path -and $p.Modules.Count -gt 0 -and $p.Modules[0].FileName) {
            if ($p.Modules[0].FileName.ToLower() -ne $p.Path.ToLower()) { $flags += "Hollowed" }
        }
        # High memory, few modules = packed/injected
        if ($p.PrivateMemorySize64 -gt 500MB -and $p.Modules.Count -lt 10) { $flags += "HighMemLowMod" }
        # An unreadable image path is missing telemetry, not evidence of a missing file.
        if ($p.Path -and -not (Test-Path -LiteralPath $p.Path -ErrorAction Stop)) { $flags += "NoBackingFile" }
    } catch {}

    return New-MemoryFinding -ProcessId $ProcessId -Name $Name -Flags $flags
}

function New-MemoryFinding { param([int]$ProcessId,[string]$Name,[string[]]$Flags)
    # RWX/private executable pages are correlated observations of normal JIT activity.
    # Do not count them as independent proof of injection, regardless of process name.
    $structural = @($Flags | Where-Object { $_ -in @('Hollowed','NoBackingFile') } | Select-Object -Unique)
    $allocation = @($Flags | Where-Object { $_ -match '^(RWX:|Unbacked:|PrivExec:|HighMemLowMod$)' })
    if ($structural.Count -eq 0 -or ($structural.Count -lt 2 -and $allocation.Count -eq 0)) { return $null }
    return @{
        Rule='MemoryAnomaly'; Evidence="$Name (PID $ProcessId): $($Flags -join ' | ')"
        Reasoning='Memory allocation pattern corroborated by image/file inconsistency; injection is not confirmed'
        Conf=0.75; Tier='Tier2Indicator'; Cat='memory'
        Fingerprint=(@($structural | Sort-Object) -join '|')
    }
}

# ============================================================================
# BEHAVIORAL: DESTRUCTIVE OPS (Ransomware)
# ============================================================================
function Test-Destructive { param([string]$CL,[int]$ProcessId,[string]$N)
    if ([string]::IsNullOrEmpty($CL)) { return $null }
    $c = $CL.ToLower()
    $hit = $null
    if ($c -match 'vssadmin.*delete|shadowcopy.*delete|shadows.*\/all|resize.*shadowstorage') {
        $hit = "Shadow copy destruction"
    } elseif ($c -match 'recoveryenabled.*no|bootstatuspolicy.*ignore') {
        $hit = "Boot recovery disabled"
    } elseif ($c -match 'wbadmin.*delete.*(catalog|systemstate)') {
        $hit = "Backup catalog destruction"
    } elseif ($c -match '(net\s+stop|sc\s+(stop|config.*disabled))' -and $c -match '(sql|exchange|backup|vss|veeam)') {
        $hit = "Critical service disruption"
    }
    if ($hit) { return @{ Rule="Destructive"; Evidence="$hit by $N (PID $ProcessId)"; Reasoning="Destroying recovery mechanisms - ransomware precursor"; Conf=0.93; Tier="Tier1Behavioral"; Cat="ransomware" } }
    return $null
}

# ============================================================================
# BEHAVIORAL: CREDENTIAL ACCESS
# ============================================================================
function Test-CredentialAccess { param([string]$CL,[int]$ProcessId,[string]$N,[string]$Path)
    if ([string]::IsNullOrEmpty($CL)) { return $null }
    $c = $CL.ToLower()
    # comsvcs MiniDump (structural Windows API export)
    if ($c -match 'comsvcs.*minidump|comsvcs\.dll.*#24|comsvcs.*full') {
        return @{ Rule="CredentialDump"; Evidence="MiniDump via comsvcs.dll (PID $ProcessId)"; Reasoning="Windows built-in DLL used for process memory dump"; Conf=0.92; Tier="Tier1Behavioral"; Cat="credential" }
    }
    # LSASS targeting (structural - must reference the process)
    if ($c -match 'lsass' -and $c -match 'dump|mini|dbg|clone|fork|snap|\.dmp') {
        return @{ Rule="CredentialDump"; Evidence="LSASS memory targeting (PID $ProcessId)"; Reasoning="Explicit LSASS memory extraction attempt"; Conf=0.90; Tier="Tier1Behavioral"; Cat="credential" }
    }
    # Registry hive extraction (structural paths)
    if ($c -match '(?:^|[\s&;|])(?:"?[^"\s]*[\\/])?reg(?:\.exe)?"?\s+(?:save|export)\s+"?(?:hklm|hkey_local_machine)\\(?:sam|security|system)(?=[\s"\\]|$)') {
        return @{ Rule="CredentialDump"; Evidence="Registry hive extraction (PID $ProcessId)"; Reasoning="Extracting credential hives for offline cracking"; Conf=0.91; Tier="Tier1Behavioral"; Cat="credential" }
    }
    # DPAPI abuse
    if ($c -match 'dpapi' -and $c -match 'masterkey|credential|protect|unprotect') {
        return @{ Rule="CredentialDump"; Evidence="DPAPI credential extraction (PID $ProcessId)"; Reasoning="Targeting DPAPI for stored credential theft"; Conf=0.85; Tier="Tier1Behavioral"; Cat="credential" }
    }
    # Browser credential stores (structural file paths, not tool names)
    if ($c -match '(login\s*data|local\s*state|cookies).*chrome|key4\.db|logins\.json|cookies\.sqlite|\.tbres|tokenbroker') {
        if ($c -match 'copy|type|get-content|select-string|sqlite|cryptunprotect') {
            return @{ Rule="BrowserCredTheft"; Evidence="Browser credential store access (PID $ProcessId)"; Reasoning="Accessing browser credential files with extraction intent"; Conf=0.87; Tier="Tier1Behavioral"; Cat="credential" }
        }
    }
    return $null
}

# ============================================================================
# BEHAVIORAL: DEFENSE EVASION (structural Windows API/registry targets)
# ============================================================================
function Test-Evasion { param([string]$CL,[int]$ProcessId,[string]$N)
    if ([string]::IsNullOrEmpty($CL)) { return $null }
    $c = $CL.ToLower()
    if ($c -match 'amsiscanbuffer|amsiinitialized|amsicontext') {
        return @{ Rule="Evasion"; Evidence="AMSI manipulation (PID $ProcessId)"; Reasoning="Patching Windows AMSI interface"; Conf=0.92; Tier="Tier1Behavioral"; Cat="evasion" }
    }
    if ($c -match 'nttracevent|etweventwrite') {
        return @{ Rule="Evasion"; Evidence="ETW blinding (PID $ProcessId)"; Reasoning="Patching ETW to blind security tools"; Conf=0.93; Tier="Tier1Behavioral"; Cat="evasion" }
    }
    if ($c -match 'wevtutil.*(cl|clear-log)\s+(security|system|application)') {
        return @{ Rule="Evasion"; Evidence="Event log clearing (PID $ProcessId)"; Reasoning="Destroying forensic evidence"; Conf=0.90; Tier="Tier1Behavioral"; Cat="evasion" }
    }
    if ($c -match 'set-mppreference.*-disable(realtimemonitoring|ioavprotection|behaviormonitoring)') {
        return @{ Rule="Evasion"; Evidence="Defender disabled (PID $ProcessId)"; Reasoning="Programmatically disabling endpoint protection"; Conf=0.91; Tier="Tier1Behavioral"; Cat="evasion" }
    }
    if ($c -match 'add-mppreference.*-exclusion') {
        return @{ Rule="Evasion"; Evidence="Defender exclusion added (PID $ProcessId)"; Reasoning="Adding exclusion to hide malware"; Conf=0.85; Tier="Tier1Behavioral"; Cat="evasion" }
    }
    if ($c -match 'fltmc.*unload') {
        return @{ Rule="Evasion"; Evidence="Minifilter unload (PID $ProcessId)"; Reasoning="Unloading security filter driver"; Conf=0.90; Tier="Tier1Behavioral"; Cat="evasion" }
    }
    return $null
}

# ============================================================================
# BEHAVIORAL: PERSISTENCE (structural locations, not tool names)
# ============================================================================
function Test-Persistence { param([string]$CL,[int]$ProcessId,[string]$N)
    if ([string]::IsNullOrEmpty($CL)) { return $null }
    $c = $CL.ToLower()
    if ($c -match '(reg\s+add|new-itemproperty|set-itemproperty).*\\(run|runonce)\b') {
        return @{ Rule="Persistence"; Evidence="Registry Run key (PID $ProcessId)"; Reasoning="Auto-start registry persistence"; Conf=0.82; Tier="Tier1Behavioral"; Cat="persistence" }
    }
    if ($c -match '(__eventfilter|__eventconsumer|filtertoconsumerbinding)') {
        return @{ Rule="Persistence"; Evidence="WMI subscription (PID $ProcessId)"; Reasoning="Fileless WMI persistence"; Conf=0.88; Tier="Tier1Behavioral"; Cat="persistence" }
    }
    if ($c -match '(schtasks\s*/create|register-scheduledtask)' -and $c -notmatch 'antiviruslite') {
        return @{ Rule="Persistence"; Evidence="Scheduled task (PID $ProcessId)"; Reasoning="Task-based persistence"; Conf=0.75; Tier="Tier2Indicator"; Cat="persistence" }
    }
    if ($c -match '(sc\s+create|new-service)' -and $c -notmatch 'antiviruslite') {
        return @{ Rule="Persistence"; Evidence="Service creation (PID $ProcessId)"; Reasoning="Service-based persistence"; Conf=0.78; Tier="Tier2Indicator"; Cat="persistence" }
    }
    return $null
}

# ============================================================================
# BEHAVIORAL: OBFUSCATED EXECUTION (structural patterns)
# ============================================================================
function Test-Execution { param([string]$CL,[int]$ProcessId,[string]$N)
    if ([string]::IsNullOrEmpty($CL)) { return $null }
    $CL = Get-InspectedCommandLine -CommandLine $CL
    $c = $CL.ToLower()
    # A TCP stream is normal client behavior. Require command execution and
    # bidirectional stream use before classifying a PowerShell socket shell.
    if ($c -match 'net\.sockets\.tcpclient|system\.net\.sockets' -and
        $c -match 'getstream|networkstream' -and $c -match '\.read\s*\(' -and
        $c -match '\.write\s*\(' -and $c -match '\biex\b|invoke-expression|redirectstandardinput|redirectstandardoutput') {
        return @{ Rule='ReverseShell'; Evidence="Socket command loop (PID $ProcessId)"; Reasoning='Socket reads and writes combined with command execution or redirected shell I/O'; Conf=0.92; Tier='Tier1Behavioral'; Cat='c2' }
    }
    # Download + execute (structural .NET APIs)
    if (($c -match 'downloadstring|downloadfile|downloaddata|invoke-webrequest') -and ($c -match 'invoke-expression|iex\s|start-process|\.invoke\(')) {
        return @{ Rule="DownloadExec"; Evidence="Download-and-execute (PID $ProcessId)"; Reasoning="Downloading and immediately executing remote content"; Conf=0.87; Tier="Tier1Behavioral"; Cat="execution" }
    }
    # Reflective loading (.NET reflection APIs)
    if ($c -match 'reflection\.assembly.*load|gettype.*getmethod.*invoke|\[convert\]::frombase64.*load') {
        return @{ Rule="ReflectiveLoad"; Evidence="Reflective assembly load (PID $ProcessId)"; Reasoning="In-memory code loading via .NET reflection"; Conf=0.88; Tier="Tier1Behavioral"; Cat="execution" }
    }
    # Encoded execution remains a weak indicator unless decoded content above
    # supplies stronger evidence. Decoding never invokes the supplied text.
    if ($CL -match '(?i)-(?:enc|encodedcommand)\s+[A-Za-z0-9+/=]{100,}') {
        return @{ Rule='EncodedExec'; Evidence="Encoded payload (PID $ProcessId)"; Reasoning='Encoded command line; also used by legitimate automation'; Conf=0.70; Tier='Tier2Indicator'; Cat='execution' }
    }
    # Execution policy bypass + hidden window (staging pattern)
    if ($c -match '-executionpolicy\s*(bypass|unrestricted)' -and $c -match '-w(indowstyle)?\s*h(idden)?') {
        return @{ Rule="HiddenExec"; Evidence="Hidden+bypass execution (PID $ProcessId)"; Reasoning="PowerShell running hidden with policy bypass"; Conf=0.72; Tier="Tier2Indicator"; Cat="execution" }
    }
    return $null
}

function Get-InspectedCommandLine {
    param([string]$CommandLine)
    # PowerShell -EncodedCommand uses UTF-16LE. Limit decoding work and do not
    # recursively unpack/execute anything. Retain the original for other rules.
    if ($CommandLine -and
        $CommandLine -match '(?i)(?:^|\s)-(?:e|en|enc|enco|encod|encode|encoded|encodedc|encodedco|encodedcom|encodedcomm|encodedcomma|encodedcomman|encodedcommand)\s+["'']?([A-Za-z0-9+/=]{8,65536})(?=["''\s]|$)') {
        try {
            $decoded = [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($Matches[1]))
            return $CommandLine + "`n[DecodedCommand]`n" + $decoded
        } catch { }
    }
    return $CommandLine
}

function Get-PowerShellPayloadPath {
    param([string]$Name,[string]$CommandLine)
    if ($Name -notin @('powershell.exe','pwsh.exe')) { return $null }
    # Only an explicit absolute -File argument. Do not guess paths from -Command,
    # relative working directories, or strings embedded inside the script body.
    if ($CommandLine -match '(?i)(?:^|\s)-File\s+(?:"([^"]+)"|''([^'']+)''|(\S+))') {
        $path = if ($Matches[1]) { $Matches[1] } elseif ($Matches[2]) { $Matches[2] } else { $Matches[3] }
        if ([IO.Path]::IsPathRooted($path) -and [IO.Path]::GetExtension($path) -in @('.ps1','.psm1')) { return $path }
    }
    return $null
}

# ============================================================================
# BEHAVIORAL: PRIVILEGE ESCALATION (structural Windows mechanisms)
# ============================================================================
function Test-Escalation { param([string]$CL,[int]$ProcessId,[string]$N)
    if ([string]::IsNullOrEmpty($CL)) { return $null }
    $c = $CL.ToLower()
    if ($c -match 'duplicatetokenex|createprocesswithtoken|impersonateloggedonuser|adjusttokenprivileges.*sedebug') {
        return @{ Rule="Escalation"; Evidence="Token manipulation (PID $ProcessId)"; Reasoning="Windows token API abuse for privilege escalation"; Conf=0.88; Tier="Tier1Behavioral"; Cat="escalation" }
    }
    if ($c -match 'impersonatenamedpipeclient|createnamedpipe.*impersonate') {
        return @{ Rule="Escalation"; Evidence="Pipe impersonation (PID $ProcessId)"; Reasoning="Named pipe impersonation for escalation"; Conf=0.90; Tier="Tier1Behavioral"; Cat="escalation" }
    }
    if ($c -match 'fodhelper|computerdefaults|sdclt.*\/kickoffelev|eventvwr.*mmc') {
        return @{ Rule="Escalation"; Evidence="UAC bypass (PID $ProcessId)"; Reasoning="Exploiting auto-elevation for UAC bypass"; Conf=0.89; Tier="Tier1Behavioral"; Cat="escalation" }
    }
    return $null
}

# ============================================================================
# BEHAVIORAL: LATERAL MOVEMENT (structural patterns)
# ============================================================================
function Test-LateralMovement { param([string]$CL,[int]$ProcessId,[string]$N)
    if ([string]::IsNullOrEmpty($CL)) { return $null }
    $c = $CL.ToLower()
    # Remote service/WMI execution (structural: must specify remote target)
    if ($c -match '(sc|wmic|invoke-wmimethod|invoke-command).*\\\\' -or $c -match '/node:.*process.*call.*create') {
        return @{ Rule="LateralMovement"; Evidence="Remote execution pattern (PID $ProcessId)"; Reasoning="Executing commands on remote system"; Conf=0.85; Tier="Tier1Behavioral"; Cat="lateral" }
    }
    # WinRM/PSRemoting
    if ($c -match 'enter-pssession|invoke-command.*-computer|new-pssession.*-computer') {
        return @{ Rule="LateralMovement"; Evidence="PSRemoting (PID $ProcessId)"; Reasoning="PowerShell remoting to other systems"; Conf=0.70; Tier="Tier2Indicator"; Cat="lateral" }
    }
    return $null
}

# ============================================================================
# NETWORK MONITOR + STATISTICAL BEACONING
# ============================================================================
function Get-Connections {
    # Use structured TCP data. Nested -match calls overwrite PowerShell's $Matches.
    # This is an established-TCP snapshot, not UDP or packet-level telemetry.
    $connections = @()
    try {
        # The filtered CIM query throws ObjectNotFound when there are no established
        # connections. An unfiltered table followed by a local filter allows zero matches.
        foreach ($connection in (Get-NetTCPConnection -ErrorAction Stop | Where-Object { $_.State -eq 'Established' })) {
            if ($connection.OwningProcess -le 4) { continue }
            $key = '{0}|{1}|{2}|{3}|{4}|{5}' -f $connection.OwningProcess,
                $connection.LocalAddress, $connection.LocalPort,
                $connection.RemoteAddress, $connection.RemotePort, $connection.CreationTime
            $connections += @{
                R=$connection.RemoteAddress; P=[int]$connection.RemotePort
                PID=[int]$connection.OwningProcess; Key=$key
                Created=$connection.CreationTime
            }
        }
    } catch {
        # A failed snapshot must not reset the baseline and manufacture new connections.
        throw
    }
    return $connections
}

function Is-Private { param([string]$IP)
    $address = $null
    if (-not [Net.IPAddress]::TryParse($IP, [ref]$address)) { return $true }
    if ($address.IsIPv4MappedToIPv6) { $address = $address.MapToIPv4() }
    if ([Net.IPAddress]::IsLoopback($address)) { return $true }
    $bytes = $address.GetAddressBytes()
    if ($bytes.Length -eq 4) {
        return ($bytes[0] -eq 0 -or $bytes[0] -eq 10 -or
            ($bytes[0] -eq 172 -and $bytes[1] -ge 16 -and $bytes[1] -le 31) -or
            ($bytes[0] -eq 192 -and $bytes[1] -eq 168) -or
            ($bytes[0] -eq 169 -and $bytes[1] -eq 254) -or $bytes[0] -ge 224)
    }
    return ($address.IsIPv6LinkLocal -or $address.IsIPv6Multicast -or
        (($bytes[0] -band 0xFE) -eq 0xFC) -or $address.Equals([Net.IPAddress]::IPv6Any))
}

function Invoke-NetworkAnalysis { param($Conns)
    $byPid = @{}
    $previous = $Script:ConnectionSnapshot
    $current = @{}
    foreach ($c in $Conns) {
        $current[$c.Key] = $true
        $c.New = $null -ne $previous -and -not $previous.ContainsKey($c.Key)
        if (-not $byPid.ContainsKey($c.PID)) { $byPid[$c.PID] = @() }
        $byPid[$c.PID] += $c
    }
    $Script:ConnectionSnapshot = $current
    foreach ($ProcessId in $byPid.Keys) {
        if ($ProcessId -le 4 -or $ProcessId -eq $PID) { continue }
        $info = $Script:ProcessAncestry[$ProcessId]
        if (-not $info) { continue }
        $path = $info.P; $name = $info.N
        # Skip installed software (Program Files)
        if ($path -and ($path -like "$env:ProgramFiles*" -or $path -like "${env:ProgramFiles(x86)}*" -or $path -like "$env:SystemRoot*")) { continue }

        $pub = @($byPid[$ProcessId] | Where-Object { -not (Is-Private $_.R) })
        if ($pub.Count -eq 0) { continue }

        # Staged binary with public connections
        $staging = @("$env:TEMP","$env:APPDATA","$env:LOCALAPPDATA\Temp","Downloads","Desktop","Public")
        $fromStaging = $false
        if ($path) { foreach ($sp in $staging) { if ($path -like "*$sp*") { $fromStaging=$true; break } } }

        if ($fromStaging) {
            $dk = "NetStage|$ProcessId"
            if (-not (Is-Dup -K $dk -TTL 300)) {
                Log-Event -Type "detection" -Rule "StagedPayloadNetwork" -Evidence "$name from staging path -> $($pub.Count) public connections" `
                    -Reasoning "Binary in temp/download location making outbound connections" -Conf 0.82 -Tier "Tier1Behavioral" -PName $name -ProcessId $ProcessId
                Add-Signal -ProcessId $ProcessId -Cat "network" -Conf 0.82
                Write-Host "[Tier1] StagedPayload: $name (PID $ProcessId) from $path" -ForegroundColor Yellow
            }
        }

        # Beaconing tracking
        foreach ($c in $pub) {
            if ($c.New -and $c.Created -is [datetime] -and $c.Created -gt [datetime]::MinValue) {
                Track-Beacon -ProcessId $ProcessId -Addr $c.R -Port $c.P -Name $name -ObservedAt $c.Created
            }
        }
    }
}

function Track-Beacon { param([int]$ProcessId,[string]$Addr,[int]$Port,[string]$Name,[datetime]$ObservedAt)
    $k = "${ProcessId}|${Addr}|${Port}"; $now = Get-Date
    if (-not $Script:BeaconTracker.ContainsKey($k)) { $Script:BeaconTracker[$k] = @{ T=@($ObservedAt); N=$Name }; return }
    $t = $Script:BeaconTracker[$k]
    # Count unique connection creation timestamps, never repeated snapshots.
    if ($ObservedAt -in $t.T) { return }
    $t.T += $ObservedAt
    $t.T = @($t.T | Where-Object { ($now-$_).TotalMinutes -le 10 } | Sort-Object | Select-Object -Last 20)
    $Script:BeaconTracker[$k] = $t
    if ($t.T.Count -ge 5) {
        $iv = @(); for ($i=1; $i -lt $t.T.Count; $i++) { $iv += ($t.T[$i]-$t.T[$i-1]).TotalSeconds }
        $m = ($iv | Measure-Object -Average).Average
        if ($m -gt 0 -and $m -lt 300) {
            $var = ($iv | ForEach-Object { [Math]::Pow($_-$m,2) } | Measure-Object -Average).Average
            $cv = [Math]::Sqrt($var) / $m
            if ($cv -lt 0.40) {
                $dk = "Beacon|$k"
                if (-not (Is-Dup -K $dk -TTL 300)) {
                    $conf = [Math]::Min(0.95, 0.70 + (0.40-$cv)*0.6)
                    Log-Event -Type "detection" -Rule "Beaconing" -Evidence "$Name -> ${Addr}:${Port} CV=$([Math]::Round($cv,3)) int=$([Math]::Round($m,1))s obs=$($t.T.Count)" `
                        -Reasoning "Repeated new TCP connections with regular creation intervals; heuristic only" -Conf $conf -Tier "Tier2Indicator" -PName $Name -ProcessId $ProcessId
                    Add-Signal -ProcessId $ProcessId -Cat "beaconing" -Conf $conf
                    Write-Host "[Tier2] Beaconing: $Name (PID $ProcessId) CV=$([Math]::Round($cv,3))" -ForegroundColor Yellow
                    # Regular connections alone do not authorize process termination.
                }
            }
        }
    }
}

# ============================================================================
# CLIPBOARD MONITOR (crypto swappers, stealers, session hijack)
# ============================================================================
function Get-ClipboardOwnerProcessId {
    if (-not $Script:InteractiveSession) { return 0 }
    $owner = [AntivirusLiteNative]::GetClipboardOwner()
    if ($owner -eq [IntPtr]::Zero) { return 0 }
    $ownerProcessId = [uint32]0
    [AntivirusLiteNative]::GetWindowThreadProcessId($owner, [ref]$ownerProcessId) | Out-Null
    return [int]$ownerProcessId
}

function Test-ClipboardAnomaly {
    # SYSTEM session 0 cannot inspect an interactive user's clipboard.
    if (-not $Script:InteractiveSession) { return }
    try {
        $ownerPid = Get-ClipboardOwnerProcessId
        if ($ownerPid -gt 0) {
            if ($ownerPid -gt 0 -and $ownerPid -ne $PID) {
                $info = $Script:ProcessAncestry[[int]$ownerPid]
                if ($info) {
                    $path = $info.P
                    # Background process holding clipboard (not explorer, not browser)
                    $legitimate = @('explorer.exe','chrome.exe','msedge.exe','firefox.exe',
                                    'powershell.exe','pwsh.exe','code.exe','WindowsTerminal.exe')
                    if ($info.N -notin $legitimate) {
                        # Check if from staging path
                        $staging = @("$env:TEMP","$env:APPDATA","Downloads")
                        $fromStaging = $false
                        if ($path) { foreach ($sp in $staging) { if ($path -like "*$sp*") { $fromStaging=$true; break } } }
                        if ($fromStaging) {
                            $dk = "Clipboard|$ownerPid"
                            if (-not (Is-Dup -K $dk -TTL 120)) {
                                Log-Event -Type "detection" -Rule "ClipboardHijack" `
                                    -Evidence "$($info.N) (PID $ownerPid) owns clipboard from staging path" `
                                    -Reasoning "Background process from temp location holding clipboard ownership" `
                                    -Conf 0.78 -Tier "Tier2Indicator" -PName $info.N -ProcessId ([int]$ownerPid)
                                Add-Signal -ProcessId ([int]$ownerPid) -Cat "clipboard" -Conf 0.78
                            }
                        }
                    }
                }
            }
        }
    } catch {}
}

# ============================================================================
# DLL/MODULE INTEGRITY MONITOR
# ============================================================================
function Initialize-ModuleBaseline {
    try {
        Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Id -gt 4 -and $_.Id -ne $PID } | ForEach-Object {
            try {
                $mods = @($_.Modules | ForEach-Object { $_.FileName.ToLower() })
                $Script:ModuleBaseline[$_.Id] = $mods
            } catch {}
        }
    } catch {}
}

function Test-ModuleInjection {
    try {
        Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Id -gt 4 -and $_.Id -ne $PID } | ForEach-Object {
            $ProcessId = $_.Id; $name = $_.ProcessName
            try {
                $currentMods = @($_.Modules | ForEach-Object { $_.FileName.ToLower() })
                if ($Script:ModuleBaseline.ContainsKey($ProcessId)) {
                    $baseline = $Script:ModuleBaseline[$ProcessId]
                    $newMods = @($currentMods | Where-Object { $_ -notin $baseline })
                    foreach ($mod in $newMods) {
                        # Phantom module: DLL loaded but file deleted from disk
                        if (-not (Test-Path $mod -ErrorAction SilentlyContinue)) {
                            $dk = "Phantom|$ProcessId|$mod"
                            if (-not (Is-Dup -K $dk -TTL 300)) {
                                Log-Event -Type "detection" -Rule "PhantomModule" `
                                    -Evidence "$name (PID $ProcessId) has loaded DLL with deleted backing file: $mod" `
                                    -Reasoning "Loaded module file deleted from disk - dropper pattern" `
                                    -Conf 0.82 -Tier "Tier2Indicator" -PName $name -ProcessId $ProcessId
                                Add-Signal -ProcessId $ProcessId -Cat "dll_injection" -Conf 0.82
                            }
                        }
                        # DLL from staging/temp path loaded into established process
                        $staging = @("$env:TEMP","$env:APPDATA","$env:LOCALAPPDATA\Temp","downloads")
                        foreach ($sp in $staging) {
                            if ($mod -like "*$($sp.ToLower())*") {
                                $dk = "TempDLL|$ProcessId|$mod"
                                if (-not (Is-Dup -K $dk -TTL 300)) {
                                    Log-Event -Type "detection" -Rule "StagedDllInjection" `
                                        -Evidence "$name (PID $ProcessId) loaded DLL from staging: $mod" `
                                        -Reasoning "New DLL from temp/staging path injected into running process" `
                                        -Conf 0.80 -Tier "Tier2Indicator" -PName $name -ProcessId $ProcessId
                                    Add-Signal -ProcessId $ProcessId -Cat "dll_injection" -Conf 0.80
                                }
                                break
                            }
                        }
                    }
                }
                # Update baseline
                $Script:ModuleBaseline[$ProcessId] = $currentMods
            } catch {}
        }
    } catch {}
}

# ============================================================================
# SCREEN CAPTURE / WEBCAM DETECTION (DLL-based, behavioral)
# ============================================================================
function New-SurveillanceFinding {
    param([int]$ProcessId,[string]$Name,[bool]$HasWindow,[string[]]$Modules,[string[]]$Categories)
    if ($HasWindow) { return $null }
    $corroboration = @($Categories | Where-Object { $_ -in @('credential','evasion','c2','escalation','memory','clipboard') } | Select-Object -Unique)
    # A background GUI/audio component with these DLLs is normal. Require another
    # behavioral observation before reporting its capture-related capability.
    if ($corroboration.Count -eq 0) { return $null }
    $devices = @()
    if (@($Modules | Where-Object { $_ -in @('d3d11.dll','dxgi.dll','d3d9.dll') }).Count) { $devices += 'screen' }
    if (@($Modules | Where-Object { $_ -in @('mfplat.dll','mf.dll','mfreadwrite.dll','ksuser.dll') }).Count) { $devices += 'camera' }
    if (@($Modules | Where-Object { $_ -in @('audioses.dll','mmdevapi.dll') }).Count) { $devices += 'microphone' }
    if ($devices.Count -eq 0) { return $null }
    return @{
        Rule='BackgroundSurveillance'
        Evidence="$Name (PID $ProcessId) loaded $($devices -join '/')-related DLLs with other indicators: $($corroboration -join ', ')"
        Reasoning='Corroborated capability indicator; actual device access or surveillance was not observed'
        Conf=0.70; Tier='Tier2Indicator'; Cat='surveillance'; PName=$Name; PId=$ProcessId
        Fingerprint=(($devices -join '|') + ':' + (@($corroboration | Sort-Object) -join '|'))
    }
}

function Test-SurveillanceAccess {
    $results = @()
    Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Id -gt 4 -and $_.Id -ne $PID } | ForEach-Object {
        try {
            $categories = @(Get-Categories -ProcessId $_.Id)
            if (@($categories | Where-Object { $_ -in @('credential','evasion','c2','escalation','memory','clipboard') }).Count -eq 0) { return }
            $mods = @($_.Modules | ForEach-Object { $_.ModuleName.ToLower() })
            $finding = New-SurveillanceFinding -ProcessId $_.Id -Name $_.ProcessName -HasWindow ($_.MainWindowHandle -ne [IntPtr]::Zero) -Modules $mods -Categories $categories
            if ($finding) {
                Add-Signal -ProcessId $_.Id -Cat $finding.Cat -Conf $finding.Conf
                if (Test-NewIndicatorObservation -ProcessId $_.Id -Rule $finding.Rule -Fingerprint $finding.Fingerprint) { $results += $finding }
            }
        } catch { Write-Verbose "Capability inspection failed: $_" }
    }
    return $results
}

# ============================================================================
# DNS ENTROPY (DGA Detection) - via process command lines with DNS patterns
# ============================================================================
function Test-DnsAnomaly {
    # Check for high-entropy domain access in command lines
    foreach ($ProcessId in $Script:ProcessAncestry.Keys) {
        $info = $Script:ProcessAncestry[$ProcessId]
        if (-not $info -or [string]::IsNullOrEmpty($info.CL)) { continue }
        $cl = $info.CL

        # Extract potential domains from command lines (http/https URLs, nslookup, etc)
        $domains = @()
        if ($cl -match 'https?://([a-zA-Z0-9][-a-zA-Z0-9]*(\.[a-zA-Z0-9][-a-zA-Z0-9]*)+)') {
            $domains += $Matches[1]
        }
        if ($cl -match '(nslookup|resolve-dnsname|dig)\s+(\S+)') {
            $domains += $Matches[2]
        }

        foreach ($domain in $domains) {
            # Split into labels, check entropy of longest non-TLD label
            $labels = $domain.Split('.')
            if ($labels.Count -lt 2) { continue }
            $mainLabel = ($labels[0..($labels.Count-2)] | Sort-Object { $_.Length } -Descending | Select-Object -First 1)
            if ($mainLabel.Length -lt 8) { continue }

            $entropy = Get-Entropy -S $mainLabel
            if ($entropy -gt 3.8) {
                $dk = "DGA|$ProcessId|$domain"
                if (-not (Is-Dup -K $dk -TTL 300)) {
                    Log-Event -Type "detection" -Rule "DgaDomain" `
                        -Evidence "$($info.N) (PID $ProcessId) accessing high-entropy domain: $domain (entropy=$([Math]::Round($entropy,2)))" `
                        -Reasoning "Domain label has high Shannon entropy suggesting DGA-generated name" `
                        -Conf 0.72 -Tier "Tier2Indicator" -PName $info.N -ProcessId $ProcessId
                    Add-Signal -ProcessId $ProcessId -Cat "dga" -Conf 0.72
                }
            }
        }
    }
}

# ============================================================================
# UNSIGNED FROM STAGING (structural fact about the binary)
# ============================================================================
function Test-UnsignedStaged { param([int]$ProcessId,[string]$Name,[string]$Path)
    if ([string]::IsNullOrEmpty($Path)) { return $null }
    if (-not (Test-Path $Path -ErrorAction SilentlyContinue)) { return $null }
    # Skip trusted locations
    if ($Path -like "$env:SystemRoot*" -or $Path -like "$env:ProgramFiles*" -or $Path -like "${env:ProgramFiles(x86)}*") { return $null }
    # Must be in staging path
    $staging = @("$env:TEMP","$env:APPDATA","$env:LOCALAPPDATA\Temp","Downloads","Desktop","Public")
    $inStaging = $false
    foreach ($sp in $staging) { if ($Path -like "*$sp*") { $inStaging=$true; break } }
    if (-not $inStaging) { return $null }

    try {
        $sig = Get-AuthenticodeSignature -FilePath $Path -ErrorAction Stop
        if ($sig.Status -ne 'Valid') {
            $conf = 0.68
            # Content/reputation scans run through the bounded file queue, not
            # once per process in this hot loop. Unsigned alone is not malware.
            return @{ Rule="UnsignedStaged"; Evidence="$Name (PID $ProcessId) unsigned from $Path"; Reasoning="Unsigned binary executing from staging location"; Conf=$conf; Tier="Tier2Indicator"; Cat="unsigned" }
        }
    } catch {}
    return $null
}

# ============================================================================
# PROCESS GENEALOGY (structural parent-child anomalies)
# ============================================================================
function Test-Genealogy { param([int]$ProcessId,[string]$Name,[int]$PPid)
    if ($ProcessId -le 4) { return $null }
    $parent = $Script:ProcessAncestry[$PPid]
    $pName = if ($parent) { $parent.N } else { "DEAD" }
    $info = $Script:ProcessAncestry[$ProcessId]

    # Shell spawned by unusual parent
    $shells = @('cmd.exe','powershell.exe','pwsh.exe')
    $normalParents = @('explorer.exe','cmd.exe','powershell.exe','pwsh.exe','svchost.exe',
                       'services.exe','code.exe','WindowsTerminal.exe','wt.exe','conhost.exe')
    # Office/browser spawning shell (classic macro/exploit delivery)
    $officeApps = @('WINWORD.EXE','EXCEL.EXE','POWERPNT.EXE','OUTLOOK.EXE','MSACCESS.EXE')
    if ($Name -in $shells -and $pName -in $officeApps) {
        return @{ Rule="OfficeShellSpawn"; Evidence="$pName spawned $Name (PID $ProcessId)"; Reasoning="Office application spawning command shell - macro/exploit execution"; Conf=0.88; Tier="Tier1Behavioral"; Cat="execution" }
    }

    if ($Name -in $shells -and $pName -notin $normalParents -and $pName -ne "DEAD") {
        return @{ Rule="UnusualShellParent"; Evidence="$Name spawned by $pName (PID $PPid)"; Reasoning="Shell from unexpected parent - possible exploitation"; Conf=0.72; Tier="Tier2Indicator"; Cat="genealogy" }
    }


    # Orphan from staging (parent dead, running from temp)
    if ($pName -eq "DEAD" -and $info -and $info.P) {
        $staging = @("$env:TEMP","$env:APPDATA","Downloads")
        foreach ($sp in $staging) {
            if ($info.P -like "*$sp*") {
                return @{ Rule="OrphanStaged"; Evidence="$Name (PID $ProcessId) orphaned from $($info.P)"; Reasoning="Orphan process from staging path - dropped payload"; Conf=0.70; Tier="Tier2Indicator"; Cat="genealogy" }
            }
        }
    }
    return $null
}

# ============================================================================
# WMI PERSISTENCE SCAN
# ============================================================================
function Test-WmiPersistence {
    try {
        Get-CimInstance -Namespace "root\subscription" -ClassName "CommandLineEventConsumer" -ErrorAction Stop | ForEach-Object {
            $dk = "WMI|$($_.Name)"
            if (-not (Is-Dup -K $dk -TTL 600)) {
                Log-Event -Type "detection" -Rule "WmiPersistence" -Evidence "WMI consumer: $($_.Name) -> $($_.CommandLineTemplate)" `
                    -Reasoning "WMI event subscription for fileless persistence" -Conf 0.88 -Tier "Tier1Behavioral" -PName "WMI" -ProcessId 0
                Write-Host "[Tier1] WMI Persistence: $($_.Name)" -ForegroundColor Yellow
            }
        }
    } catch {}
}

# ============================================================================
# FILE ACTIVITY (ransomware rate detection)
# ============================================================================
$Script:RansomExts = @('.encrypted','.enc','.locked','.crypto','.crypt','.locky',
    '.wncry','.ryuk','.lockbit','.conti','.hive','.blackcat','.play','.royal',
    '.clop','.akira','.blackbasta','.rhysida','.medusa','.trigona')

function Initialize-FileMonitor {
    $roots = @(Get-CimInstance Win32_UserProfile -ErrorAction Stop |
        Where-Object { -not $_.Special -and $_.LocalPath -and (Test-Path -LiteralPath $_.LocalPath) } |
        Select-Object -ExpandProperty LocalPath -Unique)
    foreach ($root in $roots) {
        $watcher = $null
        try {
            $watcher = New-Object System.IO.FileSystemWatcher
            $watcher.Path = $root
            $watcher.IncludeSubdirectories = $true
            $watcher.NotifyFilter = [IO.NotifyFilters]::FileName -bor [IO.NotifyFilters]::LastWrite
            $watcher.Filter = '*'
            foreach ($eventName in @('Renamed','Created','Changed','Error')) {
                $source = 'AntivirusLite.{0}.{1}' -f [guid]::NewGuid(), $eventName
                $job = Register-ObjectEvent -InputObject $watcher -EventName $eventName -SourceIdentifier $source -MessageData $Script:FileEvents -Action {
                    # Event jobs have their own script scope. MessageData carries the shared queue.
                    $queue = $Event.MessageData
                    if ($queue.Count -lt 10000) {
                        $eventArgs = $Event.SourceEventArgs
                        if ($eventArgs -is [IO.ErrorEventArgs]) {
                            $queue.Enqueue(@{ P=''; T=Get-Date; Kind='Error'; Detail=$eventArgs.GetException().Message })
                        } else {
                            $queue.Enqueue(@{ P=$eventArgs.FullPath; T=Get-Date; Kind=[string]$eventArgs.ChangeType })
                        }
                    } elseif ($queue.Count -eq 10000) {
                        $queue.Enqueue(@{ P=''; T=Get-Date; Kind='Error'; Detail='Event queue capacity exceeded; some file events were dropped.' })
                    }
                } -ErrorAction Stop
                $Script:FileSubscriptions += @{ Source=$source; Job=$job.Id }
            }
            $Script:FileWatchers += $watcher
            $watcher.EnableRaisingEvents = $true
        } catch {
            Write-Warning "File monitor unavailable for ${root}: $_"
            if ($watcher) { $watcher.Dispose() }
        }
    }
    $Script:MonitorPath = $roots -join '; '
    return $Script:FileWatchers.Count -gt 0
}

function Invoke-FileAnalysis {
    if ($Script:FileEvents.IsEmpty) { return }
    $eventsByPath = @{}
    $eventRecord = $null
    $drained = 0
    while ($drained -lt 10000 -and $Script:FileEvents.TryDequeue([ref]$eventRecord)) {
        $drained++
        if ($eventRecord.Kind -eq 'Error') {
            Log-Event -Type 'system' -Rule 'FileMonitorError' -Evidence $eventRecord.Detail -Reasoning 'File events may have been lost' -Conf 1 -Tier 'System'
        } else { $eventsByPath[$eventRecord.P] = $eventRecord }
    }
    $evts = @($eventsByPath.Values)
    $now = Get-Date; $ransomHits = 0
    # Reset BEFORE counting the current batch, so a quiet period cannot discard it.
    if (($now - $Script:FileRateTracker.Start).TotalSeconds -gt 30) {
        $Script:FileRateTracker = @{ Count=0; Start=$now }
    }

    foreach ($e in $evts) {
        $ext = [System.IO.Path]::GetExtension($e.P)
        if ($ext -in $Script:RansomExts) { $ransomHits++ }
        Add-PendingFile -Path $e.P
    }

    $Script:FileRateTracker.Count += $evts.Count
    $elapsed = ($now - $Script:FileRateTracker.Start).TotalSeconds


    # Bulk file ops (rate-based, extension-agnostic)
    if ($Script:FileRateTracker.Count -ge 50 -and $elapsed -le 30) {
        if (-not (Is-Dup -K "BulkFile" -TTL 60)) {
            $conf = [Math]::Min(0.95, 0.75 + $Script:FileRateTracker.Count * 0.002)
            Log-Event -Type "detection" -Rule "BulkFileOps" -Evidence "$($Script:FileRateTracker.Count) file ops in $([Math]::Round($elapsed))s" `
                -Reasoning "High file activity; may also be caused by copying, installation or synchronization" -Conf $conf -Tier "Tier1Behavioral" -PName "FileSystem" -ProcessId 0
            Add-Signal -ProcessId 0 -Cat "ransomware_rate" -Conf $conf
            Write-Host "[RANSOMWARE] Bulk: $($Script:FileRateTracker.Count) ops in ${elapsed}s" -ForegroundColor Red
        }
    }
    # Ransomware extensions
    if ($ransomHits -ge 5 -and $elapsed -le 30) {
        if (-not (Is-Dup -K "RansomExt" -TTL 60)) {
            Log-Event -Type "detection" -Rule "RansomwareExtensions" -Evidence "$ransomHits files with ransomware extensions in $([Math]::Round($elapsed))s" `
                -Reasoning "Mass rename to known encryption extensions" -Conf 0.92 -Tier "Tier1Behavioral" -PName "FileSystem" -ProcessId 0
            Add-Signal -ProcessId 0 -Cat "ransomware_ext" -Conf 0.92
            Write-Host "[RANSOMWARE] Extensions: $ransomHits files" -ForegroundColor Red
        }
    }
}

# ============================================================================
# COMPOSITE CORRELATION ENGINE (multi-signal kills)
# ============================================================================
function Invoke-Composite { param([int]$ProcessId,[string]$Name)
    $cats = Get-Categories -ProcessId $ProcessId
    $cnt = Get-SignalCount -ProcessId $ProcessId
    if ($cnt -lt 2) { return }

    $composites = @()
    # Memory + Network = Injected C2 Beacon (0.96)
    if ($cats -contains "memory" -and ($cats -contains "network" -or $cats -contains "beaconing")) {
        $composites += @{ N="InjectedC2Beacon"; Conf=0.96 }
    }
    # Credential + Network = Exfiltration (0.95)
    if ($cats -contains "credential" -and ($cats -contains "network" -or $cats -contains "beaconing")) {
        $composites += @{ N="CredentialExfiltration"; Conf=0.95 }
    }
    # Evasion + Execution = Fileless (0.93)
    if ($cats -contains "evasion" -and ($cats -contains "execution" -or $cats -contains "c2")) {
        $composites += @{ N="FilelessAttack"; Conf=0.93 }
    }
    # Unsigned + Network/Beaconing = Covert RAT (0.90)
    if ($cats -contains "unsigned" -and ($cats -contains "network" -or $cats -contains "beaconing")) {
        $composites += @{ N="CovertRAT"; Conf=0.90 }
    }
    # Ransomware multi-signal (0.98)
    $rCats = @($cats | Where-Object { $_ -match "ransomware" })
    if ($rCats.Count -ge 2) { $composites += @{ N="ActiveRansomware"; Conf=0.98 } }
    # Escalation + Persistence (0.91)
    if ($cats -contains "escalation" -and $cats -contains "persistence") {
        $composites += @{ N="PostExploitation"; Conf=0.91 }
    }
    # DLL injection + Network (0.95)
    if ($cats -contains "dll_injection" -and ($cats -contains "network" -or $cats -contains "beaconing")) {
        $composites += @{ N="InjectedImplantC2"; Conf=0.95 }
    }
    # Clipboard + Network (0.93)
    if ($cats -contains "clipboard" -and ($cats -contains "network" -or $cats -contains "beaconing")) {
        $composites += @{ N="ClipboardExfil"; Conf=0.93 }
    }
    # Surveillance + Network (0.94)
    if ($cats -contains "surveillance" -and ($cats -contains "network" -or $cats -contains "beaconing")) {
        $composites += @{ N="SurveillanceExfil"; Conf=0.94 }
    }
    # DGA + Beaconing (0.94)
    if ($cats -contains "dga" -and $cats -contains "beaconing") {
        $composites += @{ N="DgaC2Beacon"; Conf=0.94 }
    }
    # Lateral + Credential (0.95)
    if ($cats -contains "lateral" -and $cats -contains "credential") {
        $composites += @{ N="LateralCredTheft"; Conf=0.95 }
    }
    # Genealogy + Network (orphan phoning home) (0.88)
    if ($cats -contains "genealogy" -and ($cats -contains "network" -or $cats -contains "beaconing")) {
        $composites += @{ N="OrphanPhoneHome"; Conf=0.88 }
    }
    # 3+ distinct categories = Advanced Attack Chain (0.96)
    if ($cats.Count -ge 3) {
        $composites += @{ N="AdvancedAttackChain"; Conf=0.96 }
    }

    foreach ($comp in $composites) {
        $dk = "Comp|$($comp.N)|$ProcessId"
        if (Is-Dup -K $dk -TTL 120) { continue }
        Log-Event -Type "detection" -Rule "Composite:$($comp.N)" `
            -Evidence "$Name (PID $ProcessId): $($cats -join '+') [$cnt signals in 120s]" `
            -Reasoning "Multiple behavioral signals correlated on same process" `
            -Conf $comp.Conf -Tier "Tier1Behavioral" -PName $Name -ProcessId $ProcessId
        Write-Host "[COMPOSITE] $($comp.N): $Name (PID $ProcessId) conf=$($comp.Conf)" -ForegroundColor Magenta
        $strongCategories = @($cats | Where-Object { $_ -in @('credential','evasion','ransomware','escalation','c2') })
        if ($comp.Conf -ge 0.85 -and $strongCategories.Count -gt 0) {
            Invoke-Kill -ProcessId $ProcessId -Name $Name -Rule "Composite:$($comp.N)" -Conf $comp.Conf
        }
    }
}

# ============================================================================
# RESPONSE ENGINE (kill gate)
# ============================================================================
function Invoke-Kill { param([int]$ProcessId,[string]$Name,[string]$Rule,[double]$Conf)
    if ($ProcessId -le 4 -or $ProcessId -eq $PID) { return }
    if ($Conf -lt 0.85) { return }
    if ($Script:AuditOnly) {
        if (-not (Is-Dup -K "ObserveResponse|$ProcessId|$Rule" -TTL 120)) {
            Log-Event -Type 'observation' -Rule $Rule -Evidence "Would terminate $Name (PID $ProcessId) in Standalone mode" -Reasoning 'Companion/audit mode leaves response to the installed AV/EDR' -Conf $Conf -Tier 'ResponseSuppressed'
        }
        return
    }
    $target = $null
    try {
        $expected = $Script:ProcessAncestry[$ProcessId]
        if (-not $expected -or -not $expected.T) { return }
        $target = Get-Process -Id $ProcessId -ErrorAction Stop
        # Hold the process handle and allow CIM's sub-millisecond timestamp rounding.
        $null = $target.Handle
        if ([Math]::Abs(($target.StartTime.ToUniversalTime() - ([datetime]$expected.T).ToUniversalTime()).TotalMilliseconds) -gt 1) { return }
        # Never terminate Windows critical processes on a heuristic match.
        if ($target.ProcessName -in @('System','Registry','smss','csrss','wininit','winlogon','lsass','services')) { return }
        $target.Kill()
        Log-Event -Type "response" -Rule $Rule -Evidence "KILL: $Name (PID $ProcessId)" -Reasoning "Kill authorized at conf $Conf" -Conf $Conf -Tier "Response" -PName $Name -ProcessId $ProcessId
        Write-Host "[KILL] $Name (PID $ProcessId) - $Rule (conf=$Conf)" -ForegroundColor Red
    } catch {
        Write-Host "[KILL FAILED] $Name (PID $ProcessId) - $($_.Exception.Message)" -ForegroundColor DarkRed
    } finally { if ($target) { $target.Dispose() } }
}

# ============================================================================
# MAIN SCAN ENGINES
# ============================================================================
function Invoke-ProcessScan {
    foreach ($ProcessId in $Script:ProcessAncestry.Keys) {
        $i = $Script:ProcessAncestry[$ProcessId]
        if (-not $i -or $ProcessId -le 4 -or $ProcessId -eq $PID) { continue }
        $n=$i.N; $cl=Get-InspectedCommandLine -CommandLine $i.CL; $p=$i.P; $pp=$i.PP
        if ($p -and -not (Is-Dup -K "ImageScan|$p" -TTL 300)) { Add-PendingFile -Path $p }
        $payloadPath = Get-PowerShellPayloadPath -Name $n -CommandLine $i.CL
        if ($payloadPath -and -not (Is-Dup -K "PayloadScan|$payloadPath" -TTL 300)) { Add-PendingFile -Path $payloadPath }

        $dets = @(
            (Test-Destructive -CL $cl -ProcessId $ProcessId -N $n),
            (Test-CredentialAccess -CL $cl -ProcessId $ProcessId -N $n -Path $p),
            (Test-Evasion -CL $cl -ProcessId $ProcessId -N $n),
            (Test-Persistence -CL $cl -ProcessId $ProcessId -N $n),
            (Test-Execution -CL $cl -ProcessId $ProcessId -N $n),
            (Test-Escalation -CL $cl -ProcessId $ProcessId -N $n),
            (Test-LateralMovement -CL $cl -ProcessId $ProcessId -N $n),
            (Test-Genealogy -ProcessId $ProcessId -Name $n -PPid $pp),
            (Test-UnsignedStaged -ProcessId $ProcessId -Name $n -Path $p)
        )

        foreach ($d in $dets) {
            if (-not $d) { continue }
            $dk = "$($d.Rule)|$ProcessId"
            if ($d.Rule -eq 'EncodedExec') {
                # Suppress repeated log lines, not ongoing correlation evidence.
                Add-Signal -ProcessId $ProcessId -Cat $d.Cat -Conf $d.Conf
                if (-not (Test-NewIndicatorObservation -ProcessId $ProcessId -Rule $d.Rule -Fingerprint $cl)) { continue }
            } elseif (Is-Dup -K $dk) { continue }
            Log-Event -Type "detection" -Rule $d.Rule -Evidence $d.Evidence -Reasoning $d.Reasoning -Conf $d.Conf -Tier $d.Tier -PName $n -ProcessId $ProcessId
            if ($d.Rule -ne 'EncodedExec') { Add-Signal -ProcessId $ProcessId -Cat $d.Cat -Conf $d.Conf }
            $color = if ($d.Tier -eq "Tier1Behavioral") {"Yellow"} else {"Cyan"}
            Write-Host "[$($d.Tier)] $($d.Rule): $n (PID $ProcessId)" -ForegroundColor $color
            if ($d.Tier -eq "Tier1Behavioral" -and $d.Conf -ge 0.85) {
                Invoke-Kill -ProcessId $ProcessId -Name $n -Rule $d.Rule -Conf $d.Conf
            }
        }
        Invoke-Composite -ProcessId $ProcessId -Name $n
    }
}

function Invoke-MemoryScan {
    $procs = @(Get-Process -ErrorAction SilentlyContinue | Where-Object {
        $_.Id -gt 4 -and $_.Id -ne $PID
    })
    # Filter JIT processes by path
    $filtered = @()
    foreach ($p in $procs) {
        $isJit = $false
        foreach ($jp in $Script:JitPaths) { if ($p.Path -like $jp) { $isJit=$true; break } }
        if (-not $isJit) { $filtered += $p }
    }
    if ($filtered.Count -eq 0) { return }
    $sample = $filtered | Get-Random -Count ([Math]::Min(25, $filtered.Count)) -ErrorAction SilentlyContinue
    foreach ($p in $sample) {
        $d = Invoke-MemoryAnalysis -ProcessId $p.Id -Name $p.ProcessName -Path $p.Path
        if ($d) {
            Add-Signal -ProcessId $p.Id -Cat $d.Cat -Conf $d.Conf
            if (-not (Test-NewIndicatorObservation -ProcessId $p.Id -Rule $d.Rule -Fingerprint $d.Fingerprint)) { continue }
            Log-Event -Type "detection" -Rule $d.Rule -Evidence $d.Evidence -Reasoning $d.Reasoning -Conf $d.Conf -Tier $d.Tier -PName $p.ProcessName -ProcessId $p.Id
            Write-Host "[Tier2] $($d.Rule): $($d.Evidence)" -ForegroundColor Yellow
            # Memory allocation patterns alone are an alert, not proof of injection.
            Invoke-Composite -ProcessId $p.Id -Name $p.ProcessName
        }
    }
}

# ============================================================================
# STARTUP & MAIN LOOP
# ============================================================================
function Show-Banner {
    Write-Host ""
    Write-Host " ================================================" -ForegroundColor Green
    Write-Host "  AntivirusLite v$Script:Version" -ForegroundColor Green
    Write-Host "  Author: Gorstak | https://gorstak.eu" -ForegroundColor Green
    Write-Host "  Behavioral monitor - heuristic detections" -ForegroundColor Gray
    Write-Host " ================================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "  Detection: Memory | Behavior | Network | Beaconing | Files" -ForegroundColor Gray
    Write-Host "             Clipboard | DLL | Screen/Cam | DNS | Genealogy" -ForegroundColor Gray
    Write-Host "             Self-Protection | Lateral | Hash Reputation" -ForegroundColor Gray
    Write-Host "  Correlation: 120s window, 13 composite rules" -ForegroundColor Gray
    Write-Host ""

    $checks = @()
    if ($Script:IsElevated) { $checks += @{S="[OK] Elevated"; C="Green"} }
    else { $checks += @{S="[DEGRADED] Standard user"; C="Yellow"} }
    try { Initialize-Log; $checks += @{S="[OK] Log: $($Script:LogPath)"; C="Green"} } catch { $checks += @{S="[FAIL] Log"; C="Red"} }
    try { $null = Get-CimInstance Win32_Process -Property ProcessId -ErrorAction Stop | Select-Object -First 1; $checks += @{S="[OK] Process (WMI)"; C="Green"} } catch { $checks += @{S="[FAIL] Process"; C="Red"} }
    $fw = $false
    try { $fw = Initialize-FileMonitor } catch { Write-Warning "File monitor initialization failed: $_" }
    if ($fw) { $checks += @{S="[OK] FileWatcher: $Script:MonitorPath"; C="Green"} } else { $checks += @{S="[DEGRADED] FileWatcher"; C="Yellow"} }
    $checks += @{S="[INFO] Hash reputation: best effort, connectivity not verified"; C="Gray"}
    if ($Script:InteractiveSession) {
        $checks += @{S="[INFO] Clipboard monitoring in interactive session $Script:SessionId"; C="Gray"}
    } else {
        $checks += @{S="[UNAVAILABLE] Clipboard: no interactive desktop"; C="Yellow"}
    }
    $checks += @{S="[INFO] Response mode: $Script:ResponseMode; observe-only=$Script:AuditOnly"; C="Gray"}
    $checks += @{S="[INFO] AMSI available: $Script:AMSIAvailable; external lookups disabled: $Script:Offline"; C="Gray"}

    foreach ($c in $checks) { Write-Host "  $($c.S)" -ForegroundColor $c.C }
    Write-Host ""
    if ($Script:AuditOnly) { Write-Host '  Companion/audit: no process termination or quarantine.' -ForegroundColor Green }
    else { Write-Host '  Standalone: process termination and content-confirmed quarantine enabled.' -ForegroundColor Red }
    Write-Host ""
    Write-Host "  Ctrl+C to stop." -ForegroundColor Gray
    Write-Host ""

    Initialize-SelfProtection
    Initialize-ModuleBaseline
    Log-Event -Type "system" -Rule "Startup" -Evidence "AntivirusLite v$Script:Version Elevated=$Script:IsElevated" `
        -Reasoning "Initialization complete" -Conf 1.0 -Tier "System" -PName "AntivirusLite" -ProcessId $PID
}

function Invoke-ScanStage { param([string]$Name,[scriptblock]$Action)
    $ErrorActionPreference = 'Stop'
    $timer = [Diagnostics.Stopwatch]::StartNew()
    try {
        & $Action | Out-Null
        $Script:StageHealth[$Name] = @{state='Completed';timeUtc=[datetime]::UtcNow.ToString('o')}
    }
    catch {
        $Script:StageHealth[$Name] = @{state='Failed';timeUtc=[datetime]::UtcNow.ToString('o')}
        Write-Warning "$Name scan failed: $_"
        if (-not (Is-Dup -K ("ScanError|" + $Name) -TTL 60)) {
            Log-Event -Type 'system' -Rule 'ScanError' -Evidence ([string]$_) -Reasoning "$Name stage failed; other stages continue" -Conf 1 -Tier 'System' -Meta @{stage=$Name}
        }
    } finally {
        $timer.Stop()
        if ($Script:StageHealth.ContainsKey($Name)) { $Script:StageHealth[$Name].durationMs = $timer.ElapsedMilliseconds }
    }
}

function Start-AntivirusLite {
    Show-Banner
    $cycle = 0
    try {
        while ($true) {
            $t0 = Get-Date; $cycle++
            try {
                Invoke-ScanStage -Name 'Ancestry' -Action { Update-Ancestry }
                Invoke-ScanStage -Name 'Process' -Action { Invoke-ProcessScan }
                Invoke-ScanStage -Name 'Network' -Action { Invoke-NetworkAnalysis -Conns @(Get-Connections) }
                Invoke-ScanStage -Name 'Files' -Action { Invoke-FileAnalysis }
                Invoke-ScanStage -Name 'FileContent' -Action { Invoke-PendingFileScans }

                if ($cycle % 9 -eq 0) { Invoke-ScanStage -Name 'Memory' -Action { Invoke-MemoryScan } }
                if ($cycle % 4 -eq 0) { Invoke-ScanStage -Name 'Clipboard' -Action { Test-ClipboardAnomaly } }
                if ($cycle % 6 -eq 0) { Invoke-ScanStage -Name 'DNS' -Action { Test-DnsAnomaly } }
                if ($cycle % 12 -eq 0) { Invoke-ScanStage -Name 'Modules' -Action { Test-ModuleInjection } }
                if ($cycle % 60 -eq 0) { Invoke-ScanStage -Name 'WMI' -Action { Test-WmiPersistence } }
                if ($cycle -eq 1 -or $cycle % 60 -eq 0) { Invoke-ScanStage -Name 'Autoruns' -Action { Invoke-PersistenceInventory } }
                if ($cycle -eq 1 -or $cycle % 12 -eq 0) {
                    Invoke-ScanStage -Name 'SecurityEvents' -Action { Invoke-SecurityEvents }
                    Invoke-ScanStage -Name 'SecurityPosture' -Action { Invoke-SecurityPosture }
                    Write-HealthHeartbeat
                }
                if ($cycle % 6 -eq 0) { Invoke-ScanStage -Name 'Integrity' -Action { Test-SelfIntegrity } }
                if ($cycle % 4 -eq 0) { Invoke-ScanStage -Name 'Capabilities' -Action {
                    $surveil = Test-SurveillanceAccess
                    foreach ($s in $surveil) {
                        Log-Event -Type "detection" -Rule $s.Rule -Evidence $s.Evidence -Reasoning $s.Reasoning -Conf $s.Conf -Tier $s.Tier -PName $s.PName -ProcessId $s.PId
                        Write-Host "[$($s.Tier)] $($s.Rule): $($s.Evidence)" -ForegroundColor Cyan
                    }
                } }
            } catch {
                Write-Warning "Cycle $cycle failed: $_"
                Log-Event -Type 'system' -Rule 'ScanError' -Evidence ([string]$_) -Reasoning "Cycle $cycle did not complete" -Conf 1 -Tier 'System'
            }

            # Prune stale beacon data
            if ($cycle % 20 -eq 0) {
                $now = Get-Date
                $stale = @($Script:BeaconTracker.Keys | Where-Object { $Script:BeaconTracker[$_].T.Count -eq 0 -or ($now - $Script:BeaconTracker[$_].T[-1]).TotalMinutes -gt 15 })
                foreach ($k in $stale) { $Script:BeaconTracker.Remove($k) }
                # Prune dead PIDs from correlation
                $deadPids = @($Script:Correlation.Keys | Where-Object { -not $Script:ProcessAncestry.ContainsKey($_) })
                foreach ($k in $deadPids) { $Script:Correlation.Remove($k) }
            }

            $ms = [Math]::Max(100, ($Script:ScanIntervalSeconds*1000) - ((Get-Date)-$t0).TotalMilliseconds)
            Start-Sleep -Milliseconds $ms
        }
    } finally {
        Write-Host "`nAntivirusLite shutting down..." -ForegroundColor Yellow
        foreach ($watcher in $Script:FileWatchers) { $watcher.EnableRaisingEvents=$false; $watcher.Dispose() }
        foreach ($subscription in $Script:FileSubscriptions) {
            Unregister-Event -SourceIdentifier $subscription.Source -ErrorAction SilentlyContinue
            Remove-Job -Id $subscription.Job -Force -ErrorAction SilentlyContinue
        }
        Log-Event -Type "system" -Rule "Shutdown" -Evidence "Stopped after $cycle cycles" -Reasoning "Clean shutdown" -Conf 1.0 -Tier "System" -PName "AntivirusLite" -ProcessId $PID
        Write-Host "AntivirusLite stopped. $cycle cycles." -ForegroundColor Green
    }
}

# ============================================================================
# PERSISTENCE (scheduled task, same as AV.ps1)
# ============================================================================
function New-MonitorTaskDefinition {
    param([string]$UserSid, [string]$InstalledScript)
    if ([string]::IsNullOrWhiteSpace($UserSid)) { throw 'A logged-in user SID is required.' }
    $powershell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $modeArguments = ' -ResponseMode ' + $Script:ResponseMode
    if ($Script:AuditOnly -and $Script:ResponseMode -eq 'Standalone') { $modeArguments += ' -AuditMode' }
    if ($Script:Offline) { $modeArguments += ' -NoNetwork' }
    $action = New-ScheduledTaskAction -Execute $powershell -Argument ("-NoProfile -NonInteractive -STA -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$InstalledScript`"" + $modeArguments)
    $trigger = New-ScheduledTaskTrigger -AtLogOn -User $UserSid
    # InteractiveToken uses the existing desktop login; no account password is saved.
    $principal = New-ScheduledTaskPrincipal -UserId $UserSid -LogonType Interactive -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -MultipleInstances IgnoreNew
    return @{ Action=$action; Trigger=$trigger; Principal=$principal; Settings=$settings }
}

function Install-Startup {
    if (-not $Script:InteractiveSession) { throw 'Install from the logged-in administrator desktop, not a session-0 service.' }
    $runIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
    if ($runIdentity.IsSystem) { throw 'Install as the logged-in administrator, not SYSTEM.' }
    if (-not $PSCommandPath) { throw 'Run AntivirusLite from a saved .ps1 file.' }
    $directory = $Script:InstallDirectory
    if (Test-Path -LiteralPath $directory) {
        if ((Get-Item -LiteralPath $directory -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw 'The install directory must not be a reparse point.'
        }
    } else { New-Item -ItemType Directory -Path $directory -ErrorAction Stop | Out-Null }
    # The task runs elevated. Only administrators and SYSTEM may alter its code.
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    $administrators = New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')
    $acl.SetOwner($administrators)
    foreach ($principalSid in @('S-1-5-18','S-1-5-32-544')) {
        $identity = New-Object Security.Principal.SecurityIdentifier($principalSid)
        $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule(
            $identity, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
    }
    Set-Acl -LiteralPath $directory -AclObject $acl -ErrorAction Stop
    if (Test-Path -LiteralPath $Script:InstalledScript) {
        if ((Get-Item -LiteralPath $Script:InstalledScript -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw 'The installed script must not be a reparse point.'
        }
    }
    $existing = Get-ScheduledTask -TaskName $Script:TaskName -ErrorAction SilentlyContinue
    if ($existing) { Stop-ScheduledTask -TaskName $Script:TaskName -ErrorAction Stop }
    if (-not [string]::Equals($PSCommandPath, $Script:InstalledScript, [StringComparison]::OrdinalIgnoreCase)) {
        $staged = Join-Path $directory (([guid]::NewGuid().ToString()) + '.tmp')
        try {
            Copy-Item -LiteralPath $PSCommandPath -Destination $staged -ErrorAction Stop
            Move-Item -LiteralPath $staged -Destination $Script:InstalledScript -Force -ErrorAction Stop
        } finally {
            if (Test-Path -LiteralPath $staged) { Remove-Item -LiteralPath $staged -Force -ErrorAction SilentlyContinue }
        }
    }
    $fileAcl = New-Object Security.AccessControl.FileSecurity
    $fileAcl.SetAccessRuleProtection($true, $false)
    $fileAcl.SetOwner($administrators)
    foreach ($principalSid in @('S-1-5-18','S-1-5-32-544')) {
        $identity = New-Object Security.Principal.SecurityIdentifier($principalSid)
        $fileAcl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($identity, 'FullControl', 'Allow')))
    }
    Set-Acl -LiteralPath $Script:InstalledScript -AclObject $fileAcl -ErrorAction Stop
    $definition = New-MonitorTaskDefinition -UserSid $runIdentity.User.Value -InstalledScript $Script:InstalledScript
    Register-ScheduledTask -TaskName $Script:TaskName @definition -Description 'AntivirusLite interactive background monitor' -Force -ErrorAction Stop | Out-Null
    Start-ScheduledTask -TaskName $Script:TaskName -ErrorAction Stop
    Write-Host 'AntivirusLite installed in ProgramData; hidden interactive logon task launched. Check events.jsonl for runtime health.' -ForegroundColor Green
}

function Uninstall-AntivirusLite {
    $task = Get-ScheduledTask -TaskName $Script:TaskName -ErrorAction SilentlyContinue
    if ($task) {
        Stop-ScheduledTask -TaskName $Script:TaskName -ErrorAction Stop
        Unregister-ScheduledTask -TaskName $Script:TaskName -Confirm:$false -ErrorAction Stop
    }
    # Match the exact installed script argument, not arbitrary commands mentioning AntivirusLite.
    $escapedPath = [regex]::Escape($Script:InstalledScript)
    $pattern = '(?i)(?:^|\s)-File\s+(?:"' + $escapedPath + '"|' + $escapedPath + '(?=\s|$))'
    Get-CimInstance Win32_Process -Filter "Name='powershell.exe' OR Name='pwsh.exe'" -ErrorAction Stop |
        Where-Object { $_.ProcessId -ne $PID -and $_.CommandLine -match $pattern } |
        ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction Stop }
    Write-Host 'AntivirusLite task removed. Installed script and logs remain in ProgramData\AntivirusLite.' -ForegroundColor Green
}

# ============================================================================
# ENTRY POINT
# ============================================================================
if ($Uninstall) { Uninstall-AntivirusLite; return }
if ($Install -and $Foreground) { throw 'Choose Install or Foreground, not both.' }
Initialize-Storage
if ($SelfTest) {
    Initialize-FileEngine
    try { Invoke-LocalSelfTest } finally { Close-FileEngine }
    return
}
if ($ListQuarantine) { Get-QuarantineRecords; return }
if ($Restore) {
    Initialize-FileEngine -SkipAMSI
    Restore-QuarantineFile -Id $Restore -Destination $RestorePath
    return
}
if ($ScanPath) {
    Initialize-FileEngine
    try { Invoke-PathScan -Path $ScanPath } finally { Close-FileEngine }
    return
}
if (-not $Script:InteractiveSession) {
    throw 'AntivirusLite needs an interactive desktop. Reinstall by running this script as the logged-in administrator.'
}
$fromInstalledPath = $PSCommandPath -and [string]::Equals(
    [IO.Path]::GetFullPath($PSCommandPath), [IO.Path]::GetFullPath($Script:InstalledScript),
    [StringComparison]::OrdinalIgnoreCase)
if ($Install -or (-not $Foreground -and (-not $fromInstalledPath -or -not (Get-ScheduledTask -TaskName $Script:TaskName -ErrorAction SilentlyContinue)))) {
    Install-Startup
    return
}
# Protect against duplicate manually launched monitors as well as scheduled instances.
$mutex = New-Object Threading.Mutex($false, ('Local\AntivirusLite.Monitor.' + $Script:SessionId))
$ownsMutex = $false
try {
    try { $ownsMutex = $mutex.WaitOne(0) }
    catch [Threading.AbandonedMutexException] { $ownsMutex = $true }
    if (-not $ownsMutex) { return }
    Initialize-FileEngine
    Start-AntivirusLite
} finally {
    Close-FileEngine
    if ($ownsMutex) { $mutex.ReleaseMutex() }
    $mutex.Dispose()
}
