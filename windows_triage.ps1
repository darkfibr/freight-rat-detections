<#
GOOSE 20261020 - READ-ONLY Windows triage for the NodeRemote Node.js RAT
=======================================================================
WHAT THIS IS
  Determines whether a Windows host shows artifacts of the "NodeRemote"
  Node.js remote-access trojan delivered by the freight-onboarding lure
  (case GOOSE 20261020). Detection content, not a remover.

READ-ONLY GUARANTEE
  This script only reads and reports. It runs Get-* cmdlets, CIM/WMI
  queries and read-only file opens. It does not write, delete, stop,
  modify, remediate or configure anything, it makes no network requests,
  and it resolves no names. Output goes to the console only. Every check
  prints exactly one verdict:
    PASS - the check ran and no indicator was found
    FAIL - the check ran and an indicator was found
    SKIP - the check could not be evaluated (missing rights, or the
           cmdlet is not available on this host / PowerShell version)

CHECKS
  (a) Scheduled tasks whose name matches NodeRemote*
      The installer registers NodeRemote{GUID} (GUID = first 16 bytes of
      SHA256(username)), description "My Custom Important Task", action
      wscript.exe //nologo "<tree>\nodeupdate.vbs", logon trigger with an
      hourly (PT1H) repetition. Task names, actions and triggers are
      printed for triage.
  (b) The install tree %LOCALAPPDATA%\WebServer-<COMPUTERNAME>\node\node.exe
      The installer unpacks Node.js v20.11.0 there and drops main.js next
      to it. The tree's directory contents are listed. The legacy
      directory name %LOCALAPPDATA%\NodeRemoteSupport is also checked.
  (c) nodeupdate.vbs anywhere in that tree
      The hidden WScript launcher that runs node.exe main.js in a hidden
      window - the bridge between the scheduled task and the agent.
  (d) A .env file in that tree containing SUPER_ADMIN_KEY
      The agent's frozen config (relay URL, contract, admin key). Only the
      PRESENCE of the key name is reported; the value is never read into
      the report and never printed.
  (e) Running node.exe processes whose command line contains main.js
      The live agent shape: node.exe "<tree>\main.js", normally started by
      wscript.exe through the scheduled task. Read via Win32_Process.
  (f) A main.js anywhere under %LOCALAPPDATA% with a 'use strict' prefix
      and a size over 1 MB
      The installer validates downloaded payloads by exactly this shape
      (length at least 100 and a 'use strict' prefix); the real builds are
      1.1-2.4 MB of obfuscated JavaScript. Reading the first bytes of a
      file is a read, not a change.
  (g) Outbound connections from node.exe to the known hosting classes
      (*.workers.dev, *.ngrok*)
      Correlated against the local DNS client cache so addresses are
      mapped to names WITHOUT resolving anything. REPORT ONLY - nothing is
      blocked, killed or interrupted.
  (h) The known installer artifact hello.hta
      The 456-byte HTA stub from the delivery repository (remote icon
      load, created and deleted within minutes upstream). Searched in the
      profile root, Downloads, Desktop, Documents, %TEMP% and
      %LOCALAPPDATA%.

WHAT TO PRESERVE BEFORE CLEANUP
  If any check returns FAIL, capture evidence BEFORE removing anything,
  and involve your IR team and law enforcement as appropriate:
    1. The scheduled task definition, exported as XML (Task Scheduler
       "Export", or Get-ScheduledTask ... | Export-ScheduledTask). It is
       the proof of the persistence mechanism.
    2. nodeupdate.vbs - the hidden launcher. Small and high-value.
    3. The .env file - shows which relay and contract the host was pointed
       at. Redact SUPER_ADMIN_KEY from anything you share.
    4. main.js - the agent itself. Hash it (SHA-256) and keep the file.
    5. A memory image if practical - live node.exe and wscript.exe state
       shows the connected relay and session material that files alone
       do not.
  Preserve timestamps and original hashes; work from copies.

EXIT CODES
  0 = every check ran and the host shows none of these indicators
  1 = one or more checks found indicators (FAIL)
  2 = no indicators found, but one or more checks could not run (SKIP)

USAGE
  powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\windows_triage.ps1
  Runs as a normal user. Where rights are missing the affected check
  reports SKIP instead of failing. Nothing is left behind on disk.
#>

#Requires -Version 5.1

$ErrorActionPreference = 'Continue'

$script:PassCount = 0
$script:FailCount = 0
$script:SkipCount = 0
$script:InstallDirs = @()
$script:NodePids = @()
$script:MainJsScanDone = $false
$script:HtaHits = @()

function Report {
    param(
        [Parameter(Mandatory = $true)][string]$Check,
        [Parameter(Mandatory = $true)][string]$Status,
        [string]$Detail = ''
    )
    if ($Status -eq 'PASS') { $script:PassCount++ }
    elseif ($Status -eq 'FAIL') { $script:FailCount++ }
    else { $script:SkipCount++ }
    $line = '[' + $Status + '] ' + $Check
    if ($Detail -ne '') { $line = $line + ' -- ' + $Detail }
    Write-Host $line
}

function Note {
    param([string]$Text)
    Write-Host ('    ' + $Text)
}

function Get-FileAsciiPrefix {
    param([string]$Path, [int]$Bytes = 16)
    try {
        $fs = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open,
            [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        try {
            $buf = New-Object byte[] $Bytes
            $n = $fs.Read($buf, 0, $Bytes)
            return [System.Text.Encoding]::ASCII.GetString($buf, 0, $n)
        }
        finally {
            $fs.Close()
        }
    }
    catch {
        return $null
    }
}

# ---------------------------------------------------------------- (a)
function Test-NodeRemoteTasks {
    $check = '(a) scheduled tasks matching NodeRemote*'
    if (-not (Get-Command Get-ScheduledTask -ErrorAction SilentlyContinue)) {
        Report $check 'SKIP' 'Get-ScheduledTask is not available on this host'
        return
    }
    $tasks = $null
    try {
        $tasks = @(Get-ScheduledTask -ErrorAction Stop |
            Where-Object { $_.TaskName -like 'NodeRemote*' })
    }
    catch {
        Report $check 'SKIP' ('task enumeration failed: ' + $_.Exception.Message)
        return
    }
    if ($tasks.Count -eq 0) {
        Report $check 'PASS' 'no scheduled task name matches NodeRemote*'
        return
    }
    Report $check 'FAIL' (([string]$tasks.Count) + ' task(s) matching NodeRemote* (installer task shape: NodeRemote{GUID}, GUID = first 16 bytes of SHA256(username))')
    foreach ($t in $tasks) {
        $state = '?'
        try { $state = [string]$t.State } catch { }
        Note ('task: ' + $t.TaskName + '   state=' + $state)
        $actions = @()
        try { $actions = @($t.Actions) } catch { }
        if ($actions.Count -eq 0) {
            Note '  action: (none readable)'
        }
        else {
            foreach ($a in $actions) {
                $path = ''
                $argStr = ''
                try { $path = [string]$a.Path } catch { }
                try { $argStr = [string]$a.Arguments } catch { }
                Note ('  action: ' + $path + ' ' + $argStr)
            }
        }
        $triggers = @()
        try { $triggers = @($t.Triggers) } catch { }
        if ($triggers.Count -eq 0) {
            Note '  trigger: (none readable)'
        }
        else {
            foreach ($tr in $triggers) {
                $kind = '?'
                try { $kind = [string]$tr.CimClass.CimClassName } catch { }
                $rep = ''
                try {
                    if ($null -ne $tr.Repetition -and $null -ne $tr.Repetition.Interval -and $tr.Repetition.Interval -ne '') {
                        $rep = ', repeats every ' + $tr.Repetition.Interval
                    }
                }
                catch { }
                Note ('  trigger: ' + $kind + $rep)
            }
        }
    }
}

# ---------------------------------------------------------------- (b)
function Test-InstallTree {
    $check = '(b) install tree %LOCALAPPDATA%\WebServer-*\node\node.exe'
    $root = $env:LOCALAPPDATA
    if ([string]::IsNullOrEmpty($root) -or -not (Test-Path -LiteralPath $root)) {
        Report $check 'SKIP' '%LOCALAPPDATA% is not reachable on this host'
        return
    }
    $dirs = @()
    try {
        $dirs = @(Get-ChildItem -LiteralPath $root -Directory -Force -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -like 'WebServer-*' })
    }
    catch { }
    $legacy = Join-Path $root 'NodeRemoteSupport'
    if (Test-Path -LiteralPath $legacy) {
        try { $dirs += @(Get-Item -LiteralPath $legacy -ErrorAction SilentlyContinue) } catch { }
    }
    $script:InstallDirs = @($dirs)
    if ($dirs.Count -eq 0) {
        Report $check 'PASS' 'no WebServer-* directory (and no legacy NodeRemoteSupport) under %LOCALAPPDATA%'
        return
    }
    Report $check 'FAIL' (([string]$dirs.Count) + ' install-tree director(y/ies) under %LOCALAPPDATA% (installer layout: node\node.exe = Node.js v20.11.0, main.js beside it)')
    foreach ($d in $dirs) {
        Note ('dir: ' + $d.FullName)
        $nodeExe = Join-Path (Join-Path $d.FullName 'node') 'node.exe'
        if (Test-Path -LiteralPath $nodeExe) {
            Note '  node\node.exe: PRESENT'
        }
        else {
            Note '  node\node.exe: absent'
        }
        $items = @()
        try {
            $items = @(Get-ChildItem -LiteralPath $d.FullName -Force -ErrorAction SilentlyContinue |
                Select-Object -First 40)
        }
        catch { }
        foreach ($i in $items) {
            if ($i.PSIsContainer) {
                Note ('  [dir ] ' + $i.Name)
            }
            else {
                Note ('  [file] ' + $i.Name + '   ' + [string]$i.Length + ' bytes')
            }
        }
        if ($items.Count -ge 40) {
            Note '  (listing truncated at 40 entries)'
        }
    }
}

# ---------------------------------------------------------------- (c)
function Test-NodeUpdateVbs {
    $check = '(c) nodeupdate.vbs launcher in the install tree'
    if ($script:InstallDirs.Count -eq 0) {
        Report $check 'PASS' 'no install tree to search (check (b) found nothing)'
        return
    }
    $hits = @()
    foreach ($d in $script:InstallDirs) {
        try {
            $hits += @(Get-ChildItem -LiteralPath $d.FullName -Recurse -Force -File -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -ieq 'nodeupdate.vbs' })
        }
        catch { }
    }
    if ($hits.Count -eq 0) {
        Report $check 'PASS' 'nodeupdate.vbs not found in the install tree'
        return
    }
    Report $check 'FAIL' (([string]$hits.Count) + ' nodeupdate.vbs launcher file(s) found (runs node.exe main.js hidden)')
    foreach ($h in $hits) {
        Note ($h.FullName + '   ' + [string]$h.Length + ' bytes, modified ' + $h.LastWriteTime.ToString('u'))
    }
}

# ---------------------------------------------------------------- (d)
function Test-EnvFile {
    $check = '(d) .env in the install tree containing SUPER_ADMIN_KEY (presence only)'
    if ($script:InstallDirs.Count -eq 0) {
        Report $check 'PASS' 'no install tree to search (check (b) found nothing)'
        return
    }
    $hits = @()
    foreach ($d in $script:InstallDirs) {
        try {
            $hits += @(Get-ChildItem -LiteralPath $d.FullName -Recurse -Force -File -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -ieq '.env' })
        }
        catch { }
    }
    if ($hits.Count -eq 0) {
        Report $check 'PASS' 'no .env file in the install tree'
        return
    }
    $withKey = 0
    foreach ($h in $hits) {
        $hasKey = $false
        try {
            $content = Get-Content -LiteralPath $h.FullName -Raw -ErrorAction Stop
            if ($null -ne $content -and $content -match 'SUPER_ADMIN_KEY') { $hasKey = $true }
        }
        catch {
            Note ($h.FullName + '   (unreadable without rights - value not requested)')
            continue
        }
        if ($hasKey) { $withKey++ }
        # Presence only. The value is never copied into this report.
        Note ($h.FullName + '   SUPER_ADMIN_KEY name present: ' + $(if ($hasKey) { 'YES' } else { 'no' }) + '   (value deliberately not read into the report)')
    }
    if ($withKey -gt 0) {
        Report $check 'FAIL' (([string]$hits.Count) + ' .env file(s), ' + [string]$withKey + ' containing the SUPER_ADMIN_KEY name (agent config marker)')
    }
    else {
        Report $check 'FAIL' (([string]$hits.Count) + ' .env file(s) in the install tree (none readable or none carrying SUPER_ADMIN_KEY)')
    }
}

# ---------------------------------------------------------------- (e)
function Test-NodeProcesses {
    $check = '(e) running node.exe processes with main.js on the command line'
    if (-not (Get-Command Get-CimInstance -ErrorAction SilentlyContinue)) {
        Report $check 'SKIP' 'Get-CimInstance (Win32_Process) is not available on this host'
        return
    }
    $procs = $null
    try {
        $procs = @(Get-CimInstance Win32_Process -Filter "Name='node.exe'" -ErrorAction Stop)
    }
    catch {
        Report $check 'SKIP' ('process query failed: ' + $_.Exception.Message)
        return
    }
    $script:NodePids = @($procs | ForEach-Object { $_.ProcessId })
    if ($procs.Count -eq 0) {
        Report $check 'PASS' 'no node.exe process is running'
        return
    }
    $readable = @($procs | Where-Object { $null -ne $_.CommandLine -and $_.CommandLine -ne '' })
    $suspect = @($readable | Where-Object { $_.CommandLine -match 'main\.js' })
    foreach ($p in $procs) {
        $cmd = [string]$p.CommandLine
        if ($cmd -eq '') { $cmd = '(command line not readable without rights)' }
        if ($cmd.Length -gt 160) { $cmd = $cmd.Substring(0, 160) + '...' }
        Note ('pid ' + [string]$p.ProcessId + ': ' + $cmd)
    }
    if ($readable.Count -eq 0) {
        Report $check 'SKIP' (([string]$procs.Count) + ' node.exe process(es) running but no command line is readable - inconclusive')
        return
    }
    if ($suspect.Count -gt 0) {
        Report $check 'FAIL' (([string]$suspect.Count) + ' of ' + [string]$procs.Count + ' node.exe process(es) running main.js (agent shape)')
        foreach ($p in $suspect) {
            Note ('SUSPECT pid ' + [string]$p.ProcessId + ' parent pid ' + [string]$p.ParentProcessId)
        }
        return
    }
    Report $check 'PASS' (([string]$procs.Count) + ' node.exe process(es) running, none with main.js on the command line')
}

# ---------------------------------------------------------------- (f)
function Test-MainJs {
    $check = "(f) main.js under %LOCALAPPDATA% with a 'use strict' prefix and size over 1 MB"
    $root = $env:LOCALAPPDATA
    if ([string]::IsNullOrEmpty($root) -or -not (Test-Path -LiteralPath $root)) {
        Report $check 'SKIP' '%LOCALAPPDATA% is not reachable on this host'
        return
    }
    $mainJs = @()
    $hta = @()
    try {
        $mainJs = @(Get-ChildItem -LiteralPath $root -Recurse -Force -File -Filter 'main.js' -ErrorAction SilentlyContinue)
    }
    catch { }
    try {
        $hta = @(Get-ChildItem -LiteralPath $root -Recurse -Force -File -Filter 'hello.hta' -ErrorAction SilentlyContinue)
    }
    catch { }
    $script:MainJsScanDone = $true
    $script:HtaHits = @($hta)
    if ($mainJs.Count -eq 0) {
        Report $check 'PASS' 'no main.js anywhere under %LOCALAPPDATA%'
        return
    }
    $fullHits = 0
    foreach ($m in $mainJs) {
        $prefix = Get-FileAsciiPrefix -Path $m.FullName -Bytes 16
        $useStrict = $false
        if ($null -ne $prefix) {
            $trimmed = $prefix.TrimStart()
            if ($trimmed.StartsWith("'use strict") -or $trimmed.StartsWith('"use strict')) { $useStrict = $true }
        }
        $big = ($m.Length -gt 1MB)
        $shape = ''
        if ($useStrict -and $big) { $shape = '  <-- matches the installer payload shape'; $fullHits++ }
        Note ($m.FullName + '   ' + [string]$m.Length + ' bytes   use-strict-prefix=' + $(if ($useStrict) { 'YES' } else { 'no' }) + $shape)
    }
    if ($fullHits -gt 0) {
        Report $check 'FAIL' (([string]$fullHits) + ' of ' + [string]$mainJs.Count + " main.js file(s) match the agent shape ('use strict' prefix + over 1 MB)")
        return
    }
    Report $check 'PASS' (([string]$mainJs.Count) + " main.js file(s) found, none match both the 'use strict' prefix and the over-1-MB size shape")
}

# ---------------------------------------------------------------- (g)
function Test-NodeEgress {
    $check = '(g) node.exe outbound connections to *.workers.dev / *.ngrok* (report only)'
    if ($script:NodePids.Count -eq 0) {
        Report $check 'PASS' 'no node.exe process is running, so no node.exe egress to classify'
        return
    }
    if (-not (Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue)) {
        Report $check 'SKIP' 'Get-NetTCPConnection is not available on this host'
        return
    }
    $conns = @()
    foreach ($p in $script:NodePids) {
        try {
            $conns += @(Get-NetTCPConnection -OwningProcess $p -ErrorAction SilentlyContinue)
        }
        catch { }
    }
    $ext = @($conns | Where-Object {
        $null -ne $_.RemoteAddress -and $_.RemoteAddress -ne '' -and
        $_.RemoteAddress -ne '0.0.0.0' -and $_.RemoteAddress -ne '::' -and
        $_.RemoteAddress -ne '127.0.0.1' -and $_.RemoteAddress -ne '::1'
    })
    $dnsMap = @{}
    $hostingNames = @()
    $mapAvailable = $false
    if (Get-Command Get-DnsClientCache -ErrorAction SilentlyContinue) {
        $entries = @()
        try { $entries = @(Get-DnsClientCache -ErrorAction SilentlyContinue) } catch { }
        foreach ($e in $entries) {
            $n = [string]$e.Name
            if ($n -match 'workers\.dev|ngrok') {
                $mapAvailable = $true
                if ($hostingNames -notcontains $n) { $hostingNames += $n }
                $d = [string]$e.Data
                if ($d -ne '') { $dnsMap[$d] = $n }
            }
        }
    }
    foreach ($n in $hostingNames) {
        Note ('DNS cache holds hosting-class name: ' + $n + ' (recent lookup; the installer and agent fetch from these)')
    }
    $hits = 0
    foreach ($c in $ext) {
        $ra = [string]$c.RemoteAddress
        $mapped = ''
        if ($dnsMap.ContainsKey($ra)) { $mapped = ' -> ' + $dnsMap[$ra] }
        if ($mapped -ne '') { $hits++ }
        Note ('node.exe pid ' + [string]$c.OwningProcess + ' -> ' + $ra + ':' + [string]$c.RemotePort + '   state=' + [string]$c.State + $mapped)
    }
    if ($hits -gt 0) {
        Report $check 'FAIL' (([string]$hits) + ' node.exe connection(s) map to a *.workers.dev / *.ngrok* name (reported only - nothing blocked)')
        return
    }
    if ($ext.Count -gt 0 -and -not $mapAvailable) {
        Report $check 'SKIP' (([string]$ext.Count) + ' node.exe connection(s) seen but no DNS-cache mapping is available to classify destinations (names are not resolved on purpose)')
        return
    }
    if ($ext.Count -eq 0) {
        Report $check 'PASS' 'node.exe holds no external connection right now'
        return
    }
    Report $check 'PASS' (([string]$ext.Count) + ' node.exe connection(s), none mapped to a hosting-class name')
}

# ---------------------------------------------------------------- (h)
function Test-HelloHta {
    $check = '(h) installer artifact hello.hta'
    $hits = @()
    if ($script:MainJsScanDone) { $hits += @($script:HtaHits) }
    $root = $env:USERPROFILE
    if (-not [string]::IsNullOrEmpty($root) -and (Test-Path -LiteralPath $root)) {
        try {
            $hits += @(Get-ChildItem -LiteralPath $root -Force -File -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -ieq 'hello.hta' })
        }
        catch { }
        foreach ($sub in @('Downloads', 'Desktop', 'Documents')) {
            $p = Join-Path $root $sub
            if (Test-Path -LiteralPath $p) {
                try {
                    $hits += @(Get-ChildItem -LiteralPath $p -Recurse -Force -File -ErrorAction SilentlyContinue |
                        Where-Object { $_.Name -ieq 'hello.hta' })
                }
                catch { }
            }
        }
    }
    if (-not [string]::IsNullOrEmpty($env:TEMP) -and (Test-Path -LiteralPath $env:TEMP)) {
        try {
            $hits += @(Get-ChildItem -LiteralPath $env:TEMP -Recurse -Depth 2 -Force -File -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -ieq 'hello.hta' })
        }
        catch { }
    }
    $uniq = @($hits | Sort-Object FullName -Unique)
    if ($uniq.Count -eq 0) {
        Report $check 'PASS' 'hello.hta not found in the searched locations'
        return
    }
    Report $check 'FAIL' (([string]$uniq.Count) + ' hello.hta artifact(s) found (known 456-byte delivery stub)')
    foreach ($h in $uniq) {
        Note ($h.FullName + '   ' + [string]$h.Length + ' bytes, modified ' + $h.LastWriteTime.ToString('u'))
    }
}

# ---------------------------------------------------------------- run
Write-Host 'GOOSE 20261020 - NodeRemote Node.js RAT triage (READ-ONLY)'
Write-Host ('host: ' + $env:COMPUTERNAME + '   user: ' + $env:USERDOMAIN + '\' + $env:USERNAME + '   time: ' + (Get-Date).ToString('u'))
Write-Host ''

Test-NodeRemoteTasks
Test-InstallTree
Test-NodeUpdateVbs
Test-EnvFile
Test-NodeProcesses
Test-MainJs
Test-NodeEgress
Test-HelloHta

Write-Host ''
Write-Host ('summary: ' + [string]$script:PassCount + ' PASS, ' + [string]$script:FailCount + ' FAIL, ' + [string]$script:SkipCount + ' SKIP')
if ($script:FailCount -gt 0) {
    Write-Host 'RESULT: FINDINGS - indicators of the NodeRemote install are present (exit 1)'
    Write-Host 'Preserve evidence before cleanup (see the header of this script).'
    exit 1
}
if ($script:SkipCount -gt 0) {
    Write-Host 'RESULT: INCONCLUSIVE - no indicators found, but some checks could not run (exit 2)'
    exit 2
}
Write-Host 'RESULT: CLEAN - no indicators found (exit 0)'
exit 0
