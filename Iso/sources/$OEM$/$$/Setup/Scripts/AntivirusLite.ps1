#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    AntivirusLite v3.5.2 - Behavioral EDR for Windows 10/11
    Author: Gorstak
    Website: https://gorstak.eu
.DESCRIPTION
    Behavioral endpoint detection and response. Detects threats by what
    processes DO, not what they're called. Assumes the attacker has read
    this source code.

    Active response (kill) and best-effort hash reputation are ON by default.
    Copies itself to an administrator-controlled ProgramData folder, registers
    an elevated interactive logon task for the installing user, and launches it
    immediately with a hidden console. No extra switches. Clipboard inspection
    runs in that user's desktop session. Network telemetry
    is sampled established TCP connections, not packet capture.
    Scores are heuristic rule weights, not calibrated probabilities.
    Use -Uninstall to remove.

.PARAMETER Uninstall
    Remove scheduled task, stop running instances, and exit.
#>
[CmdletBinding()]
param(
    [switch]$Uninstall
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
$Script:Version = "3.5.2"
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
    $json = $obj | ConvertTo-Json -Depth 5 -Compress
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
function Update-Ancestry {
    $s = @{}
    try {
        Get-CimInstance Win32_Process -Property ProcessId,ParentProcessId,Name,CommandLine,ExecutablePath,CreationDate -ErrorAction Stop | ForEach-Object {
            $s[$_.ProcessId] = @{ N=$_.Name; PP=$_.ParentProcessId; CL=$_.CommandLine; P=$_.ExecutablePath; T=$_.CreationDate }
        }
    } catch {}
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
function Test-HashReputation { param([string]$Hash)
    if ($Script:HashCache.ContainsKey($Hash)) { return $Script:HashCache[$Hash] }

    # CIRCL hashlookup - known good
    try {
        $r = Invoke-RestMethod -Uri "https://hashlookup.circl.lu/lookup/sha256/$Hash" -Method Get -TimeoutSec 6 -ErrorAction Stop
        if ($r.'hashlookup:trust' -and [int]$r.'hashlookup:trust' -gt 50) {
            $Script:HashCache[$Hash] = @{ Bad=$false; Src="CIRCL"; Detail="Trust=$($r.'hashlookup:trust')" }
            return $Script:HashCache[$Hash]
        }
    } catch {}

    # MalwareBazaar - known bad
    try {
        if (-not $env:SENTINEL_ABUSECH_AUTH_KEY) { throw 'Optional MalwareBazaar authentication is not configured.' }
        $body = @{ query='get_info'; hash=$Hash }
        $r = Invoke-RestMethod -Uri "https://mb-api.abuse.ch/api/v1/" -Method Post -Body $body -Headers @{'Auth-Key'=$env:SENTINEL_ABUSECH_AUTH_KEY} -ContentType 'application/x-www-form-urlencoded' -TimeoutSec 8 -ErrorAction Stop
        if ($r.query_status -eq "ok" -or $r.query_status -eq "hash_found") {
            $Script:HashCache[$Hash] = @{ Bad=$true; Src="MalwareBazaar"; Detail="Known malware" }
            return $Script:HashCache[$Hash]
        }
    } catch {}

    $Script:HashCache[$Hash] = @{ Bad=$false; Src="Unknown"; Detail="No verdict; unknown hash or lookup unavailable" }
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
    # Large encoded payload (structural: -enc + base64 block)
    if ($CL -match '-[eE][nN][cC]\w*\s+[A-Za-z0-9+/=]{100,}') {
        return @{ Rule="EncodedExec"; Evidence="Encoded payload ($([Math]::Round($CL.Length/1024,1))KB) (PID $ProcessId)"; Reasoning="Encoded command line; also used by legitimate automation"; Conf=0.70; Tier="Tier2Indicator"; Cat="execution" }
    }
    $c = $CL.ToLower()
    # Download + execute (structural .NET APIs)
    if (($c -match 'downloadstring|downloadfile|downloaddata|invoke-webrequest') -and ($c -match 'invoke-expression|iex\s|start-process|\.invoke\(')) {
        return @{ Rule="DownloadExec"; Evidence="Download-and-execute (PID $ProcessId)"; Reasoning="Downloading and immediately executing remote content"; Conf=0.87; Tier="Tier1Behavioral"; Cat="execution" }
    }
    # Reflective loading (.NET reflection APIs)
    if ($c -match 'reflection\.assembly.*load|gettype.*getmethod.*invoke|\[convert\]::frombase64.*load') {
        return @{ Rule="ReflectiveLoad"; Evidence="Reflective assembly load (PID $ProcessId)"; Reasoning="In-memory code loading via .NET reflection"; Conf=0.88; Tier="Tier1Behavioral"; Cat="execution" }
    }
    # Raw socket shell (structural: TCPClient + Stream)
    if ($c -match 'net\.sockets\.tcpclient|system\.net\.sockets' -and $c -match 'getstream|networkstream') {
        return @{ Rule="ReverseShell"; Evidence="Socket shell (PID $ProcessId)"; Reasoning="Building network stream shell via .NET socket APIs"; Conf=0.92; Tier="Tier1Behavioral"; Cat="c2" }
    }
    # Execution policy bypass + hidden window (staging pattern)
    if ($c -match '-executionpolicy\s*(bypass|unrestricted)' -and $c -match '-w(indowstyle)?\s*h(idden)?') {
        return @{ Rule="HiddenExec"; Evidence="Hidden+bypass execution (PID $ProcessId)"; Reasoning="PowerShell running hidden with policy bypass"; Conf=0.72; Tier="Tier2Indicator"; Cat="execution" }
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
            # Hash reputation boost
            try {
                $hash = (Get-FileHash -Path $Path -Algorithm SHA256 -ErrorAction Stop).Hash
                $rep = Test-HashReputation -Hash $hash
                if ($rep -and $rep.Bad) { $conf = 0.92 }
            } catch {}
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
        Get-WmiObject -Namespace "root\subscription" -Class "CommandLineEventConsumer" -ErrorAction Stop | ForEach-Object {
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
    }
}

# ============================================================================
# MAIN SCAN ENGINES
# ============================================================================
function Invoke-ProcessScan {
    foreach ($ProcessId in $Script:ProcessAncestry.Keys) {
        $i = $Script:ProcessAncestry[$ProcessId]
        if (-not $i -or $ProcessId -le 4 -or $ProcessId -eq $PID) { continue }
        $n=$i.N; $cl=$i.CL; $p=$i.P; $pp=$i.PP

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
    $checks += @{S="[ARMED] Active Response ENABLED"; C="Red"}

    foreach ($c in $checks) { Write-Host "  $($c.S)" -ForegroundColor $c.C }
    Write-Host ""
    Write-Host "  Processes will be KILLED on high-confidence behavioral match." -ForegroundColor Red
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
    try { & $Action | Out-Null }
    catch {
        Write-Warning "$Name scan failed: $_"
        if (-not (Is-Dup -K ("ScanError|" + $Name) -TTL 60)) {
            Log-Event -Type 'system' -Rule 'ScanError' -Evidence ([string]$_) -Reasoning "$Name stage failed; other stages continue" -Conf 1 -Tier 'System' -Meta @{stage=$Name}
        }
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

                if ($cycle % 9 -eq 0) { Invoke-ScanStage -Name 'Memory' -Action { Invoke-MemoryScan } }
                if ($cycle % 4 -eq 0) { Invoke-ScanStage -Name 'Clipboard' -Action { Test-ClipboardAnomaly } }
                if ($cycle % 6 -eq 0) { Invoke-ScanStage -Name 'DNS' -Action { Test-DnsAnomaly } }
                if ($cycle % 12 -eq 0) { Invoke-ScanStage -Name 'Modules' -Action { Test-ModuleInjection } }
                if ($cycle % 60 -eq 0) { Invoke-ScanStage -Name 'WMI' -Action { Test-WmiPersistence } }
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
    $action = New-ScheduledTaskAction -Execute $powershell -Argument "-NoProfile -NonInteractive -STA -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$InstalledScript`""
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
if (-not $Script:InteractiveSession) {
    throw 'AntivirusLite needs an interactive desktop. Reinstall by running this script as the logged-in administrator.'
}
$fromInstalledPath = $PSCommandPath -and [string]::Equals(
    [IO.Path]::GetFullPath($PSCommandPath), [IO.Path]::GetFullPath($Script:InstalledScript),
    [StringComparison]::OrdinalIgnoreCase)
if (-not $fromInstalledPath -or -not (Get-ScheduledTask -TaskName $Script:TaskName -ErrorAction SilentlyContinue)) {
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
    Start-AntivirusLite
} finally {
    if ($ownsMutex) { $mutex.ReleaseMutex() }
    $mutex.Dispose()
}
