# End-to-end test of the installed Windows agent with the built-in presets, for CI only.
#
# Runs on a GitHub Windows runner after the MSI is installed. It changes machine settings
# freely (trusted root certificate, audit policy, PowerShell logging, local users, services):
# never run it on a real host. The agent itself never changes any of these.
#
# 1. A mock ingest endpoint (mock-ingest.py) on https://localhost:8443 with a CI-only root.
# 2. LocalService in Event Log Readers (the documented least privilege), enrol, start.
# 3. `status` reports audit policy gaps and the 4688 command line setting, then again after
#    CI turns them on.
# 4. Events are generated for each preset and must arrive in the WEF JSON shape.
# 5. Restart: events written while the service is stopped arrive once after it starts, and
#    nothing is sent twice.

$ErrorActionPreference = 'Stop'
$exe = "$env:ProgramFiles\Wedgetail Agent\wedgetail-agent.exe"
$data = "$env:ProgramData\Wedgetail"
$work = Join-Path $env:RUNNER_TEMP 'wt-e2e'
$received = Join-Path $work 'received.ndjson'
$run = [guid]::NewGuid().ToString('N').Substring(0, 8)
New-Item -ItemType Directory -Force $work | Out-Null
Set-Content -Path $received -Value $null

function Section($text) { Write-Host "`n=== $text" }

Section 'Host'
Get-CimInstance Win32_OperatingSystem | Format-List Caption, Version, BuildNumber
foreach ($ch in 'Security', 'System', 'Microsoft-Windows-PowerShell/Operational', 'Windows PowerShell',
    'Microsoft-Windows-Sysmon/Operational', 'Microsoft-Windows-Windows Defender/Operational',
    'Microsoft-Windows-TaskScheduler/Operational',
    'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational',
    'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational',
    'Microsoft-Windows-WMI-Activity/Operational',
    'Microsoft-Windows-Windows Firewall With Advanced Security/Firewall',
    'Microsoft-Windows-AppLocker/EXE and DLL', 'Microsoft-Windows-AppLocker/MSI and Script',
    'Microsoft-Windows-AppLocker/Packaged app-Execution', 'Microsoft-Windows-AppLocker/Packaged app-Deployment',
    'Microsoft-Windows-CodeIntegrity/Operational', 'Microsoft-Windows-Bits-Client/Operational') {
    $info = wevtutil gl "$ch" 2>&1
    $enabled = ($info | Select-String '^enabled:') -replace '\s+', ' '
    $access = ($info | Select-String 'channelAccess:') -replace '\s+', ' '
    Write-Host "$ch | $enabled | $access"
}
Write-Host 'auditpol /get /category:* /r (default policy on this runner):'
auditpol /get /category:* /r

Section 'Mock ingest endpoint'
$openssl = (Get-Command openssl -ErrorAction SilentlyContinue).Source
if (-not $openssl) { $openssl = "$env:ProgramFiles\Git\usr\bin\openssl.exe" }
$env:MSYS_NO_PATHCONV = '1'
Set-Content "$work\ca.cnf" "[req]`nprompt = no`ndistinguished_name = dn`nx509_extensions = v3_ca`n[dn]`nCN = Wedgetail CI test root $run`n[v3_ca]`nbasicConstraints = critical, CA:TRUE`nkeyUsage = critical, keyCertSign, cRLSign`nsubjectKeyIdentifier = hash`n"
Set-Content "$work\leaf.cnf" "[req]`nprompt = no`ndistinguished_name = dn`n[dn]`nCN = localhost`n[ext]`nbasicConstraints = critical, CA:FALSE`nkeyUsage = critical, digitalSignature, keyEncipherment`nextendedKeyUsage = serverAuth`nsubjectAltName = DNS:localhost`nauthorityKeyIdentifier = keyid`n"
& $openssl req -x509 -new -newkey rsa:2048 -nodes -keyout "$work\ca.key" -out "$work\ca.pem" -days 2 -config "$work\ca.cnf"
& $openssl req -new -newkey rsa:2048 -nodes -keyout "$work\leaf.key" -out "$work\leaf.csr" -config "$work\leaf.cnf"
& $openssl x509 -req -in "$work\leaf.csr" -CA "$work\ca.pem" -CAkey "$work\ca.key" -CAcreateserial -out "$work\leaf.pem" -days 2 -extfile "$work\leaf.cnf" -extensions ext
if ($LASTEXITCODE -ne 0) { throw 'certificate generation failed' }
Import-Certificate -FilePath "$work\ca.pem" -CertStoreLocation Cert:\LocalMachine\Root | Out-Null
$server = Start-Process python -ArgumentList "$PSScriptRoot\mock-ingest.py", 8443, "$work\leaf.pem", "$work\leaf.key", $received `
    -PassThru -NoNewWindow -RedirectStandardError "$work\mock.log"
$deadline = (Get-Date).AddSeconds(60)
while ($true) {
    if ($server.HasExited) { Get-Content "$work\mock.log"; throw 'mock ingest did not start' }
    try { [Net.Sockets.TcpClient]::new('localhost', 8443).Close(); break } catch {}
    if ((Get-Date) -gt $deadline) { Get-Content "$work\mock.log"; throw 'mock ingest is not listening' }
    Start-Sleep -Milliseconds 500
}

# Received lines, parsed once each; heartbeats (rule_id "agent") are left out.
$script:events = [System.Collections.Generic.List[object]]::new()
$script:offset = 0
function Events {
    $fs = [IO.File]::Open($received, 'Open', 'Read', 'ReadWrite')
    try {
        $fs.Position = $script:offset
        $text = [IO.StreamReader]::new($fs).ReadToEnd()
    } finally { $fs.Close() }
    $end = $text.LastIndexOf("`n")
    if ($end -ge 0) {
        $script:offset += [Text.Encoding]::UTF8.GetByteCount($text.Substring(0, $end + 1))
        foreach ($line in $text.Substring(0, $end).Split("`n")) {
            if (-not $line) { continue }
            try { $o = $line | ConvertFrom-Json } catch { Write-Warning "unparsable line: $($line.Substring(0, [Math]::Min(200, $line.Length)))"; continue }
            if ($o.rule_id -ne 'agent') { $script:events.Add($o) }
        }
    }
    $script:events
}
function WaitFor($desc, [scriptblock]$match, $seconds = 120) {
    $deadline = (Get-Date).AddSeconds($seconds)
    while ((Get-Date) -lt $deadline) {
        $hit = @(Events | Where-Object $match)
        if ($hit.Count -gt 0) { Write-Host "PASS $desc ($($hit[0].rule_id))"; return $hit }
        Start-Sleep -Seconds 2
    }
    Get-Content "$data\state\agent.log" -Tail 40
    & $exe status
    throw "FAIL ${desc}: not received within $seconds s"
}
function Status { & $exe status --json | ConvertFrom-Json }
function AppEvent($text) {
    if (-not [Diagnostics.EventLog]::SourceExists('WedgetailAgentE2E')) {
        [Diagnostics.EventLog]::CreateEventSource('WedgetailAgentE2E', 'Application')
    }
    # A newly registered source can take a moment to become writable (seen on Server 2025).
    for ($i = 1; ; $i++) {
        try { [Diagnostics.EventLog]::WriteEntry('WedgetailAgentE2E', $text, 'Information', 100); return }
        catch { if ($i -ge 10) { throw }; Start-Sleep -Seconds 2 }
    }
}

Section 'Least privilege, configuration and enrolment'
Stop-Service WedgetailAgent -ErrorAction SilentlyContinue
# Event Log Readers (S-1-5-32-573) for LOCAL SERVICE, as documented in docs/presets/windows.md.
Add-LocalGroupMember -SID 'S-1-5-32-573' -Member 'NT AUTHORITY\LOCAL SERVICE' -ErrorAction SilentlyContinue
Get-LocalGroupMember -SID 'S-1-5-32-573' | Format-Table Name, ObjectClass
Get-ChildItem "$data\state" -Force | Remove-Item -Recurse -Force
$config = "[agent]`nendpoint = `"https://localhost:8443`"`npresets = [`"auto`"]`n[[rule]]`nid = `"app`"`ntype = `"wineventlog`"`nchannel = `"Application`"`nxpath = `"*[System[Provider[@Name='WedgetailAgentE2E']]]`"`n"
Set-Content -Path "$data\agent.toml" -Value $config -Encoding utf8NoBOM
& $exe check-config
if ($LASTEXITCODE -ne 0) { throw 'check-config failed' }
$env:WEDGETAIL_ENROL_TOKEN = 'wge_0123456789az_' + ('A' * 43)
& $exe enrol
$enrolled = $LASTEXITCODE
Remove-Item Env:\WEDGETAIL_ENROL_TOKEN
if ($enrolled -ne 0) { Get-Content "$work\mock.log"; throw 'enrol failed' }
# Start from Process Creation auditing and 4688 command lines off, so status must report them.
auditpol /set /subcategory:'{0CCE922B-69AE-11D9-BED3-505054503030}' /success:disable /failure:disable | Out-Null
reg delete 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' /v ProcessCreationIncludeCmdLine_Enabled /f 2>$null | Out-Null
# The first event source registration writes a few events; do it before the agent starts.
AppEvent "wt-e2e-$run zero"
Start-Service WedgetailAgent
Start-Sleep -Seconds 10

Section 'Collectors and status'
$status = Status
$status.collectors | Format-Table rule_id, state, errors, last_error -AutoSize | Out-String -Width 300 | Write-Host
$status.presets
if ($status.presets -contains 'windows-sysmon') { throw 'windows-sysmon selected without Sysmon' }
$bad = @($status.collectors | Where-Object { $_.state -ne 'running' })
if ($bad.Count -gt 0) { throw "collectors not running: $(($bad | ForEach-Object { "$($_.rule_id): $($_.last_error)" }) -join '; ')" }
Write-Host "PASS every collector is running as LocalService (Event Log Readers), Security included"
& $exe status
$status.windows | ConvertTo-Json -Depth 6
if ($status.windows.audit_policy.checked -ne $true) { throw "audit policy not checked: $($status.windows.audit_policy.error)" }
if (-not ($status.windows.audit_policy.off.subcategory -contains 'Process Creation')) { throw 'Process Creation not reported as off' }
if ($status.windows.process_command_line -ne $false) { throw 'command line inclusion not reported as off' }
Write-Host 'PASS status reports Process Creation auditing and 4688 command lines as off'

Section 'CI turns on what the presets recommend (the agent never does)'
auditpol /set /subcategory:'{0CCE922B-69AE-11D9-BED3-505054503030}' /success:enable | Out-Null
auditpol /set /subcategory:'{0CCE9211-69AE-11D9-BED3-505054503030}' /success:enable | Out-Null
auditpol /set /subcategory:'{0CCE9227-69AE-11D9-BED3-505054503030}' /success:enable /failure:enable | Out-Null
auditpol /set /subcategory:'{0CCE9232-69AE-11D9-BED3-505054503030}' /success:enable /failure:enable | Out-Null
reg add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f | Out-Null
reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f | Out-Null
wevtutil sl Microsoft-Windows-TaskScheduler/Operational /e:true
$status = Status
if ($status.windows.audit_policy.off.subcategory -contains 'Process Creation') { throw 'Process Creation still reported as off' }
if ($status.windows.process_command_line -ne $true) { throw 'command line inclusion not reported as on' }
if ($status.windows.channels.channel -contains 'Microsoft-Windows-TaskScheduler/Operational') { throw 'TaskScheduler channel still reported' }
Write-Host 'PASS status follows the policy changes'
# A subscription made while a channel was disabled gets nothing once it is enabled: reload
# (as docs/presets/windows.md says) so the agent subscribes again.
sc.exe control WedgetailAgent paramchange | Out-Null
Start-Sleep -Seconds 10

Section 'Round 1: generate events for each preset'
AppEvent "wt-e2e-$run one"
$user = "wte2e$run"
$password = ConvertTo-SecureString ("Aa1!" + [guid]::NewGuid().ToString('N')) -AsPlainText -Force
New-LocalUser -Name $user -Password $password -Description 'Wedgetail CI' | Out-Null
Add-LocalGroupMember -Group 'Users' -Member $user
Remove-LocalUser -Name $user
cmd /c "net use \\127.0.0.1\IPC$ /user:wtnobody$run Wrong-Passw0rd-$run >nul 2>&1"
cmd /c "echo wt-e2e-proc-$run >nul"
sc.exe create "WtE2e$run" binPath= "C:\Windows\System32\cmd.exe /c exit 0" | Out-Null
sc.exe delete "WtE2e$run" | Out-Null
$script = @("# wt-e2e-sb-start-$run") + (1..1500 | ForEach-Object { "`$wtLine$_ = 'Wedgetail end-to-end script block line $_ with some padding text'" }) + @("# wt-e2e-sb-end-$run")
Set-Content -Path "$work\big.ps1" -Value $script
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$work\big.ps1"
New-NetFirewallRule -DisplayName "wt-e2e-$run" -Direction Inbound -Protocol TCP -LocalPort 4444 -Action Allow | Out-Null
Remove-NetFirewallRule -DisplayName "wt-e2e-$run"
$action = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument '/c exit 0'
Register-ScheduledTask -TaskName "wt-e2e-$run" -Action $action | Out-Null
Unregister-ScheduledTask -TaskName "wt-e2e-$run" -Confirm:$false

WaitFor 'Application rule (user rule next to presets)' { $_.rule_id -eq 'app' -and $_.fields.EventData.Data[0] -eq "wt-e2e-$run one" } | Out-Null
$e = WaitFor '4720 user created (windows-security.accounts)' { $_.rule_id -eq 'windows-security.accounts' -and $_.fields.System.EventID -eq 4720 -and $_.fields.EventData.TargetUserName -eq $user }
$e[0].fields | ConvertTo-Json -Depth 5
WaitFor '4732 member added to a local group' { $_.rule_id -eq 'windows-security.accounts' -and $_.fields.System.EventID -eq 4732 } | Out-Null
WaitFor '4726 user deleted' { $_.rule_id -eq 'windows-security.accounts' -and $_.fields.System.EventID -eq 4726 -and $_.fields.EventData.TargetUserName -eq $user } | Out-Null
WaitFor '4625 failed logon (windows-security.logon)' { $_.rule_id -eq 'windows-security.logon' -and $_.fields.System.EventID -eq 4625 -and $_.fields.EventData.TargetUserName -eq "wtnobody$run" } | Out-Null
$e = WaitFor '4688 with command line (windows-security.process)' { $_.rule_id -eq 'windows-security.process' -and $_.fields.EventData.CommandLine -like "*wt-e2e-proc-$run*" }
$e[0] | ConvertTo-Json -Depth 5
WaitFor '7045 service installed (windows-system.core)' { $_.rule_id -eq 'windows-system.core' -and $_.fields.System.EventID -eq 7045 -and $_.fields.EventData.ServiceName -eq "WtE2e$run" } | Out-Null
WaitFor '4697 service installed (windows-security.services)' { $_.rule_id -eq 'windows-security.services' -and $_.fields.System.EventID -eq 4697 -and $_.fields.EventData.ServiceName -eq "WtE2e$run" } | Out-Null
WaitFor '4698 scheduled task created (windows-security.services)' { $_.rule_id -eq 'windows-security.services' -and $_.fields.System.EventID -eq 4698 -and $_.fields.EventData.TaskName -like "*wt-e2e-$run" } | Out-Null
WaitFor '106 task registered (windows-operational.task-scheduler)' { $_.rule_id -eq 'windows-operational.task-scheduler' -and $_.fields.System.EventID -eq 106 } | Out-Null
WaitFor '400 engine started (windows-powershell.classic)' { $_.rule_id -eq 'windows-powershell.classic' -and $_.fields.System.EventID -eq 400 } | Out-Null
$sb = WaitFor '4104 script block reassembled (windows-powershell.operational)' { $_.rule_id -eq 'windows-powershell.operational' -and $_.fields.System.EventID -eq 4104 -and $_.fields.EventData.ScriptBlockText -like "*wt-e2e-sb-start-$run*" }
$sb = $sb[0]
Write-Host "script block: $($sb.fields.EventData.ScriptBlockText.Length) characters, parts $($sb.attrs.script_block_parts | ConvertTo-Json -Compress), truncated $($sb.attrs.truncated)"
if ($sb.fields.EventData.ScriptBlockText -notlike "*wt-e2e-sb-end-$run*") { throw 'script block is missing its end' }
if ($sb.attrs.script_block_parts.total -lt 2) { throw 'script block was not split; make the test script longer' }
if ($sb.attrs.truncated) { throw 'script block was truncated' }
$parts = @(Events | Where-Object { $_.fields.EventData.ScriptBlockId -eq $sb.fields.EventData.ScriptBlockId })
if ($parts.Count -ne 1) { throw "script block sent $($parts.Count) times" }
Write-Host 'PASS one event with the whole script block'
Write-Host 'Firewall channel, newest events on this build:'
Get-WinEvent -LogName 'Microsoft-Windows-Windows Firewall With Advanced Security/Firewall' -MaxEvents 6 | Format-Table Id, TimeCreated, Message -AutoSize -Wrap | Out-String -Width 200 | Write-Host
WaitFor 'firewall rule added (windows-operational.firewall)' { $_.rule_id -eq 'windows-operational.firewall' -and $_.fields.EventData.RuleName -eq "wt-e2e-$run" } | Out-Null
WaitFor '4946 firewall rule added (windows-security.policy)' { $_.rule_id -eq 'windows-security.policy' -and $_.fields.System.EventID -eq 4946 } | Out-Null

Section 'Round 2: restart'
Stop-Service WedgetailAgent
AppEvent "wt-e2e-$run two"
sc.exe create "WtE2eB$run" binPath= "C:\Windows\System32\cmd.exe /c exit 0" | Out-Null
sc.exe delete "WtE2eB$run" | Out-Null
Start-Service WedgetailAgent
Start-Sleep -Seconds 3
AppEvent "wt-e2e-$run three"
WaitFor 'event written while stopped is sent after the restart' { $_.rule_id -eq 'app' -and $_.fields.EventData.Data[0] -eq "wt-e2e-$run two" } | Out-Null
WaitFor 'event after the restart' { $_.rule_id -eq 'app' -and $_.fields.EventData.Data[0] -eq "wt-e2e-$run three" } | Out-Null
WaitFor '7045 written while stopped' { $_.rule_id -eq 'windows-system.core' -and $_.fields.EventData.ServiceName -eq "WtE2eB$run" } | Out-Null
WaitFor '7036 agent stopped (windows-system.service-stopped)' { $_.rule_id -eq 'windows-system.service-stopped' -and $_.fields.EventData.param1 -eq 'Wedgetail Agent' } | Out-Null

Section 'Round 3: logs cleared'
wevtutil cl 'Windows PowerShell'
WaitFor '104 log cleared (windows-system.core)' { $_.rule_id -eq 'windows-system.core' -and $_.fields.System.EventID -eq 104 } | Out-Null
wevtutil cl Security
WaitFor '1102 Security log cleared (windows-security.policy)' { $_.rule_id -eq 'windows-security.policy' -and $_.fields.System.EventID -eq 1102 } | Out-Null

Section 'No loss, no duplicates'
Start-Sleep -Seconds 5
$all = @(Events)
foreach ($word in 'zero', 'one', 'two', 'three') {
    $n = @($all | Where-Object { $_.rule_id -eq 'app' -and $_.fields.EventData.Data[0] -eq "wt-e2e-$run $word" }).Count
    if ($word -eq 'zero') { if ($n -ne 0) { throw 'an event from before the first start was sent' } ; continue }
    if ($n -ne 1) { throw "'$word' was received $n times" }
}
$dups = @($all | Group-Object { "$($_.rule_id)|$($_.fields.System.Channel)|$($_.fields.System.EventRecordID)" } | Where-Object Count -gt 1)
if ($dups.Count -gt 0) { $dups | Format-Table Count, Name; throw "$($dups.Count) events were sent more than once" }
foreach ($line in $all) {
    $s = $line.fields.System
    if ($line.source_type -ne 'windows.eventlog' -or $null -ne $line.body -or -not $s.EventID -or -not $s.Computer -or -not $s.Channel -or -not $s.Provider.Name -or -not $s.TimeCreated.SystemTime -or -not $s.EventRecordID) {
        $line | ConvertTo-Json -Depth 5; throw 'event is not in the WEF shape'
    }
}
$all | Group-Object rule_id | Sort-Object Name | Format-Table Count, Name -AutoSize
Write-Host "PASS $($all.Count) events, every one once, all in the WEF shape"

Stop-Service WedgetailAgent
Stop-Process -Id $server.Id -Force
Get-ChildItem Cert:\LocalMachine\Root | Where-Object Subject -like "*Wedgetail CI test root $run*" | Remove-Item
