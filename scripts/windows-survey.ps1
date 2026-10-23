# DevAudit — Windows survey (READ-ONLY)
# Measures what uses memory and disk on this PC. It deletes, moves and changes nothing,
# reads no file contents (only sizes and dates) and makes no network calls.
#
# Run:   powershell -ExecutionPolicy Bypass -File .\windows-survey.ps1
# Optional extra project folders:  -Roots "D:\work","C:\Projects"
# Output: devaudit-survey-<computer>-<date>.txt next to this script.
# Before sharing the output, read it: it contains folder and project names.

param([string[]]$Roots = @())

$ErrorActionPreference = 'SilentlyContinue'
$out = Join-Path $PSScriptRoot ("devaudit-survey-{0}-{1}.txt" -f $env:COMPUTERNAME, (Get-Date -Format 'yyyyMMdd-HHmm'))
$lines = New-Object System.Collections.Generic.List[string]
function Say([string]$s) { $lines.Add($s); Write-Host $s }
function GB([double]$b) { '{0,8:N1} GB' -f ($b / 1GB) }

# Attributes we never descend into or count: reparse points (symlinks, junctions, OneDrive placeholders)
# and cloud-only files (RecallOnDataAccess 0x400000, RecallOnOpen 0x40000, Offline 0x1000).
$SKIP_ATTR = 0x400 -bor 0x400000 -bor 0x40000 -bor 0x1000

function Get-Size([string]$path, [int]$maxFiles = 2000000) {
    $total = [int64]0; $newest = [datetime]::MinValue; $n = 0
    if (-not (Test-Path -LiteralPath $path)) { return $null }
    $stack = New-Object System.Collections.Generic.Stack[string]
    $stack.Push($path)
    while ($stack.Count -gt 0 -and $n -lt $maxFiles) {
        $dir = $stack.Pop()
        try { $di = New-Object System.IO.DirectoryInfo($dir); $entries = $di.EnumerateFileSystemInfos() } catch { continue }
        try {
            foreach ($e in $entries) {
                if (([int]$e.Attributes -band $SKIP_ATTR) -ne 0) { continue }
                if ($e -is [System.IO.DirectoryInfo]) { $stack.Push($e.FullName) }
                else { $total += $e.Length; $n++; if ($e.LastWriteTime -gt $newest) { $newest = $e.LastWriteTime } }
            }
        } catch { }
    }
    [pscustomobject]@{ Bytes = $total; Files = $n; Newest = $newest }
}

Say "DevAudit Windows survey — $(Get-Date)"
$os = Get-CimInstance Win32_OperatingSystem
Say ("OS: {0} {1} (build {2})" -f $os.Caption, $os.OSArchitecture, $os.BuildNumber)

Say "`n== DISK =="
Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" | ForEach-Object {
    Say ("{0}  size {1}  free {2}  ({3:N0}% used)" -f $_.DeviceID, (GB $_.Size), (GB $_.FreeSpace), (100 - $_.FreeSpace * 100 / $_.Size))
}
$rb = Get-Size 'C:\$Recycle.Bin'
if ($rb) { Say ("Recycle Bin (C:) {0}" -f (GB $rb.Bytes)) }
foreach ($f in 'C:\hiberfil.sys', 'C:\pagefile.sys', 'C:\swapfile.sys') {
    $i = Get-Item -LiteralPath $f -Force
    if ($i) { Say ("{0} {1}" -f (GB $i.Length), $f) }
}

Say "`n== MEMORY =="
$totalRam = $os.TotalVisibleMemorySize * 1KB; $freeRam = $os.FreePhysicalMemory * 1KB
Say ("RAM {0}  available {1}" -f (GB $totalRam), (GB $freeRam))
Say ("Commit {0} of {1}" -f (GB (($os.TotalVirtualMemorySize - $os.FreeVirtualMemory) * 1KB)), (GB ($os.TotalVirtualMemorySize * 1KB)))
Get-CimInstance Win32_PageFileUsage | ForEach-Object { Say ("Page file {0}: {1} MB used of {2} MB (peak {3} MB)" -f $_.Name, $_.CurrentUsage, $_.AllocatedBaseSize, $_.PeakUsage) }

Say "`n-- memory by app (working set) --"
Get-Process | Group-Object ProcessName | ForEach-Object {
    [pscustomobject]@{ Name = $_.Name; Count = $_.Count; Mem = ($_.Group | Measure-Object WorkingSet64 -Sum).Sum }
} | Sort-Object Mem -Descending | Select-Object -First 25 | ForEach-Object {
    Say ("{0}  {1,4} procs  {2}" -f (GB $_.Mem), $_.Count, $_.Name)
}

Say "`n-- dev / AI processes --"
$procs = Get-CimInstance Win32_Process
$alive = @{}; $procs | ForEach-Object { $alive[[int]$_.ProcessId] = $_.CreationDate }
$procs | Where-Object { $_.Name -match '^(node|python|uv|bun|deno|claude|npm|npx)(\.exe)?$' -or $_.CommandLine -match 'mcp' } | ForEach-Object {
    $orphan = (-not $alive.ContainsKey([int]$_.ParentProcessId)) -or ($alive[[int]$_.ParentProcessId] -gt $_.CreationDate)
    $cmd = if ($_.CommandLine) { $_.CommandLine.Substring(0, [Math]::Min(110, $_.CommandLine.Length)) } else { $_.Name }
    Say ("pid {0,-6} {1,6:N0} MB {2} {3}" -f $_.ProcessId, ($_.WorkingSetSize / 1MB), $(if ($orphan) { '[parent gone]' } else { '             ' }), $cmd)
}

Say "`n== KNOWN CACHES AND APP DATA =="
$L = $env:LOCALAPPDATA; $A = $env:APPDATA; $H = $env:USERPROFILE
$npmCache = (& npm config get cache 2>$null); if (-not $npmCache) { $npmCache = "$L\npm-cache" }
$targets = [ordered]@{
    'npm cache'               = $npmCache
    'pnpm store'              = "$L\pnpm\store"
    'Yarn cache'              = "$L\Yarn\Cache"
    'pip cache'               = "$L\pip\Cache"
    'uv cache'                = "$L\uv\cache"
    'NuGet packages'          = "$H\.nuget\packages"
    'NuGet http cache'        = "$L\NuGet\v3-cache"
    'Gradle'                  = "$H\.gradle"
    'Maven'                   = "$H\.m2"
    'Playwright browsers'     = "$L\ms-playwright"
    'Chrome cache'            = "$L\Google\Chrome\User Data\Default\Cache"
    'Chrome code cache'       = "$L\Google\Chrome\User Data\Default\Code Cache"
    'Edge cache'              = "$L\Microsoft\Edge\User Data\Default\Cache"
    'VS Code old versions'    = "$A\Code\CachedData"
    'VS Code workspaceStorage'= "$A\Code\User\workspaceStorage"
    'VS Code extensions'      = "$H\.vscode\extensions"
    'Cursor old versions'     = "$A\Cursor\CachedData"
    'Claude (~\.claude)'      = "$H\.claude"
    'Claude transcripts'      = "$H\.claude\projects"
    '~\.cache'                = "$H\.cache"
    'Temp'                    = $env:TEMP
    'Docker data (WSL)'       = "$L\Docker\wsl"
    'Ollama models'           = "$H\.ollama\models"
    'Downloads'               = "$H\Downloads"
}
foreach ($k in $targets.Keys) {
    $s = Get-Size $targets[$k]
    if ($s -and $s.Bytes -gt 50MB) { Say ("{0}  {1,-26} {2}" -f (GB $s.Bytes), $k, $targets[$k]) }
}
$tmp = Get-ChildItem -LiteralPath $env:TEMP -Recurse -File -Force | Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-7) -and (([int]$_.Attributes -band $SKIP_ATTR) -eq 0) } | Measure-Object Length -Sum
Say ("{0}  Temp files older than 7 days" -f (GB $tmp.Sum))

Say "`n== WSL =="
$wslRaw = & wsl.exe -l -v 2>$null
if ($wslRaw) { ($wslRaw -join "`n").Replace("`0", '') -split "`n" | Where-Object { $_.Trim() } | ForEach-Object { Say $_ } } else { Say "WSL not installed or no distros" }
Get-ChildItem -Path "$L\Packages\*\LocalState\ext4.vhdx", "$L\Docker\wsl\*\*.vhdx", "$L\Docker\wsl\*.vhdx" -Force | ForEach-Object { Say ("{0}  {1}" -f (GB $_.Length), $_.FullName) }
$wslconfig = "$H\.wslconfig"
if (Test-Path $wslconfig) {
    Get-Content $wslconfig | Where-Object { $_ -match '^\s*(memory|swap)\s*=' } | ForEach-Object { Say (".wslconfig: " + $_.Trim()) }
} else { Say ".wslconfig: not present (WSL may use up to 50% of RAM)" }

Say "`n== DOCKER =="
$dv = & docker version --format '{{.Server.Version}}' 2>$null
if ($dv) {
    Say "Docker running, server $dv"
    & docker system df 2>$null | ForEach-Object { Say $_ }
    Say ("Running containers: {0}" -f ((& docker ps -q 2>$null) | Measure-Object).Count)
    & docker stats --no-stream --format "{{.MemUsage}}`t{{.Name}}" 2>$null | Sort-Object -Descending | Select-Object -First 15 | ForEach-Object { Say $_ }
} else { Say "Docker not running or not installed" }

Say "`n== PROJECT BUILD FOLDERS =="
$defaultRoots = @("$H\source\repos", "$H\Projects", "$H\Dev", "$H\code", "$H\Documents\GitHub", "$H\Desktop", "$H\Documents")
$allRoots = ($defaultRoots + $Roots) | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -Unique
Say ("Roots: " + ($allRoots -join '; '))
$names = @('node_modules', '.next', '.turbo', '.nuxt', 'dist', 'build', '.venv', 'venv', 'target', 'bin', 'obj')
$found = New-Object System.Collections.Generic.List[object]
function Find-Build([string]$dir, [int]$depth) {
    if ($depth -gt 6) { return }
    try { $subs = (New-Object System.IO.DirectoryInfo($dir)).EnumerateDirectories() } catch { return }
    foreach ($d in $subs) {
        if (([int]$d.Attributes -band $SKIP_ATTR) -ne 0 -or $d.Name -eq '.git') { continue }
        if ($names -contains $d.Name) { $found.Add($d); continue }
        Find-Build $d.FullName ($depth + 1)
    }
}
foreach ($r in $allRoots) { Find-Build $r 0 }
$rows = foreach ($d in $found) {
    $s = Get-Size $d.FullName
    $proj = $d.Parent.FullName
    $src = Get-ChildItem -LiteralPath $proj -File -Force | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    $idle = if ($src) { [int]((Get-Date) - $src.LastWriteTime).TotalDays } else { -1 }
    [pscustomobject]@{ Bytes = $s.Bytes; Idle = $idle; Path = $d.FullName; Pnpm = (Test-Path -LiteralPath "$proj\pnpm-lock.yaml") }
}
$rows | Sort-Object Bytes -Descending | Select-Object -First 40 | ForEach-Object {
    Say ("{0}  idle {1,4}d {2} {3}" -f (GB $_.Bytes), $_.Idle, $(if ($_.Pnpm) { '[pnpm]' } else { '      ' }), $_.Path)
}
$rows | Group-Object { Split-Path $_.Path -Leaf } | ForEach-Object {
    Say ("TOTAL {0}  {1,3} x {2}" -f (GB (($_.Group | Measure-Object Bytes -Sum).Sum)), $_.Count, $_.Name)
}

Say "`n== TOOLS =="
foreach ($t in 'git', 'node', 'npm', 'pnpm', 'yarn', 'docker', 'wsl', 'python', 'dotnet', 'claude') {
    $c = Get-Command $t -ErrorAction SilentlyContinue
    Say ("{0,-8} {1}" -f $t, $(if ($c) { $c.Source } else { '(not found)' }))
}

$lines | Set-Content -LiteralPath $out -Encoding UTF8
Write-Host "`nSaved: $out  — review it before sharing (contains folder names)."
