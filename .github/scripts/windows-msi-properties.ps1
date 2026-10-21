# MSI public properties end to end, for CI only (runs on a GitHub Windows runner after the
# presets end-to-end test; never run it on a real host).
#
#   .github/scripts/windows-msi-properties.ps1 <path to the msi>
#
# 1. Uninstall and wipe %ProgramData%\Wedgetail, take LOCAL SERVICE out of Event Log Readers.
# 2. A mock ingest endpoint (mock-ingest.py) on https://localhost:8444 with a CI-only root.
# 3. msiexec /i ENDPOINT=... PRESETS=... ENROLTOKEN=...: agent.toml has the endpoint and
#    presets and keeps its access list, the host is enrolled, LOCAL SERVICE is in Event Log
#    Readers, the service runs and sends, and the token is nowhere in the installer log.
# 4. The same command again (a maintenance run): presets change, the token is not used again.
# 5. An invalid ENDPOINT fails the install and leaves agent.toml as it was.

param([Parameter(Mandatory)] [string] $Msi)

$ErrorActionPreference = 'Stop'
$Msi = (Resolve-Path $Msi).Path
$exe = "$env:ProgramFiles\Wedgetail Agent\wedgetail-agent.exe"
$data = "$env:ProgramData\Wedgetail"
$toml = "$data\agent.toml"
$work = Join-Path $env:RUNNER_TEMP 'wt-msi-props'
$received = Join-Path $work 'received.ndjson'
$run = [guid]::NewGuid().ToString('N').Substring(0, 8)
$token = 'wge_0123456789az_' + ('B' * 43)
$endpoint = 'https://localhost:8444'
New-Item -ItemType Directory -Force $work | Out-Null
Set-Content -Path $received -Value $null

function Section($text) { Write-Host "`n=== $text" }
function Msiexec([string[]] $arguments, [string] $log) {
    $p = Start-Process msiexec -ArgumentList (@('/i', "`"$Msi`"", '/qn', '/l*v', "`"$log`"") + $arguments) -Wait -PassThru
    $p.ExitCode
}
function AssertNoToken([string] $path) {
    if (Select-String -Path $path -Pattern ('B' * 43) -SimpleMatch -Quiet) {
        throw "the enrolment token is in $path"
    }
    Write-Host "PASS the token is not in $(Split-Path $path -Leaf)"
}
function AssertConfigAcl {
    # Only SYSTEM and Administrators may change agent.toml (as for a plain install); in
    # particular not LOCAL SERVICE (the service) or Users.
    $acl = Get-Acl $toml
    Write-Host "agent.toml owner: $($acl.Owner)"
    $acl.Access | Format-Table IdentityReference, FileSystemRights, AccessControlType, IsInherited -AutoSize | Out-String | Write-Host
    # Only the bits that change the file (Modify and FullControl include the read bits too).
    $write = [Security.AccessControl.FileSystemRights]'WriteData, AppendData, WriteExtendedAttributes, WriteAttributes, Delete, ChangePermissions, TakeOwnership'
    foreach ($ace in $acl.Access) {
        $who = $ace.IdentityReference.Value
        if ($ace.AccessControlType -ne 'Allow') { continue }
        if ($who -in 'NT AUTHORITY\SYSTEM', 'BUILTIN\Administrators') { continue }
        if (($ace.FileSystemRights -band $write) -ne 0) { throw "agent.toml is writable by $who ($($ace.FileSystemRights))" }
    }
    Write-Host 'PASS agent.toml is writable only by SYSTEM and Administrators'
}
function EventLogReaders {
    @(Get-LocalGroupMember -SID 'S-1-5-32-573' | Where-Object { $_.SID.Value -eq 'S-1-5-19' }).Count -gt 0
}

Section 'Start from a clean host'
Stop-Service WedgetailAgent -ErrorAction SilentlyContinue
$p = Start-Process msiexec -ArgumentList '/x', "`"$Msi`"", '/qn' -Wait -PassThru
if ($p.ExitCode -ne 0) { throw "uninstall failed: $($p.ExitCode)" }
Remove-Item -Recurse -Force $data -ErrorAction SilentlyContinue
Remove-LocalGroupMember -SID 'S-1-5-32-573' -Member 'NT AUTHORITY\LOCAL SERVICE' -ErrorAction SilentlyContinue
if (EventLogReaders) { throw 'LOCAL SERVICE is still in Event Log Readers' }

Section 'Mock ingest endpoint'
$openssl = (Get-Command openssl -ErrorAction SilentlyContinue).Source
if (-not $openssl) { $openssl = "$env:ProgramFiles\Git\usr\bin\openssl.exe" }
$env:MSYS_NO_PATHCONV = '1'
Set-Content "$work\ca.cnf" "[req]`nprompt = no`ndistinguished_name = dn`nx509_extensions = v3_ca`n[dn]`nCN = Wedgetail CI MSI test root $run`n[v3_ca]`nbasicConstraints = critical, CA:TRUE`nkeyUsage = critical, keyCertSign, cRLSign`nsubjectKeyIdentifier = hash`n"
Set-Content "$work\leaf.cnf" "[req]`nprompt = no`ndistinguished_name = dn`n[dn]`nCN = localhost`n[ext]`nbasicConstraints = critical, CA:FALSE`nkeyUsage = critical, digitalSignature, keyEncipherment`nextendedKeyUsage = serverAuth`nsubjectAltName = DNS:localhost`nauthorityKeyIdentifier = keyid`n"
& $openssl req -x509 -new -newkey rsa:2048 -nodes -keyout "$work\ca.key" -out "$work\ca.pem" -days 2 -config "$work\ca.cnf"
& $openssl req -new -newkey rsa:2048 -nodes -keyout "$work\leaf.key" -out "$work\leaf.csr" -config "$work\leaf.cnf"
& $openssl x509 -req -in "$work\leaf.csr" -CA "$work\ca.pem" -CAkey "$work\ca.key" -CAcreateserial -out "$work\leaf.pem" -days 2 -extfile "$work\leaf.cnf" -extensions ext
if ($LASTEXITCODE -ne 0) { throw 'certificate generation failed' }
Import-Certificate -FilePath "$work\ca.pem" -CertStoreLocation Cert:\LocalMachine\Root | Out-Null
$server = Start-Process python -ArgumentList "$PSScriptRoot\mock-ingest.py", 8444, "$work\leaf.pem", "$work\leaf.key", $received `
    -PassThru -NoNewWindow -RedirectStandardError "$work\mock.log"
$deadline = (Get-Date).AddSeconds(60)
while ($true) {
    if ($server.HasExited) { Get-Content "$work\mock.log"; throw 'mock ingest did not start' }
    try { [Net.Sockets.TcpClient]::new('localhost', 8444).Close(); break } catch {}
    if ((Get-Date) -gt $deadline) { Get-Content "$work\mock.log"; throw 'mock ingest is not listening' }
    Start-Sleep -Milliseconds 500
}

try {
    Section 'Install with ENDPOINT, PRESETS and ENROLTOKEN'
    $log = "$work\install-props.log"
    $code = Msiexec @("ENDPOINT=$endpoint", 'PRESETS=windows-system,windows-security', "ENROLTOKEN=$token") $log
    if ($code -ne 0) { Get-Content $log -Tail 80; throw "install with properties failed: $code" }
    Select-String -Path $log -Pattern 'Wedgetail:' | ForEach-Object { Write-Host $_.Line }
    AssertNoToken $log
    Get-Content $toml
    $text = Get-Content $toml -Raw
    if ($text -notmatch "(?m)^endpoint = `"$([regex]::Escape($endpoint))`"\r?$") { throw 'agent.toml has no endpoint line' }
    if ($text -notmatch '(?m)^presets = \["windows-system", "windows-security"\]\r?$') { throw 'agent.toml has no presets line' }
    if ($text -notmatch '(?m)^buffer_max_mb = 256') { throw 'the rest of agent.toml was not kept' }
    AssertConfigAcl
    & $exe check-config
    if ($LASTEXITCODE -ne 0) { throw 'check-config failed' }
    $enrolment = Get-Content "$data\state\enrolment.json" -Raw | ConvertFrom-Json
    if ($enrolment.host_id -ne 'h0st0000ci01') { throw "not enrolled: $($enrolment | ConvertTo-Json -Compress)" }
    if (-not (Test-Path "$data\state\credential.dpapi")) { throw 'no credential' }
    if (-not (EventLogReaders)) { throw 'LOCAL SERVICE was not added to Event Log Readers' }
    Write-Host 'PASS enrolled, LOCAL SERVICE in Event Log Readers'

    # The installer starts the service when ENDPOINT is given.
    $deadline = (Get-Date).AddSeconds(30)
    while ((Get-Service WedgetailAgent).Status -ne 'Running' -and (Get-Date) -lt $deadline) { Start-Sleep -Seconds 1 }
    if ((Get-Service WedgetailAgent).Status -ne 'Running') { throw "service is $((Get-Service WedgetailAgent).Status)" }
    Start-Sleep -Seconds 10
    & $exe status
    $status = & $exe status --json | ConvertFrom-Json
    if (-not $status.enrolment.enrolled) { throw 'status does not show the enrolment' }
    $rules = @($status.collectors.rule_id)
    if (-not ($rules | Where-Object { $_ -like 'windows-security.*' })) { throw "no windows-security rules: $rules" }
    $security = $status.collectors | Where-Object rule_id -like 'windows-security.*' | Select-Object -First 1
    if ($security.state -ne 'running') { throw "the Security log is not readable: $($security.state) $($security.last_error)" }
    $deadline = (Get-Date).AddSeconds(120)
    while ((Get-Item $received).Length -eq 0 -and (Get-Date) -lt $deadline) { Start-Sleep -Seconds 2 }
    if ((Get-Item $received).Length -eq 0) { Get-Content "$work\mock.log"; throw 'nothing received by the mock endpoint' }
    Write-Host 'PASS the service runs, reads the Security log and sends'

    Section 'The same install again: presets change, the token is not used again'
    $log = "$work\install-props-again.log"
    $code = Msiexec @("ENDPOINT=$endpoint", 'PRESETS=windows-system', "ENROLTOKEN=$token") $log
    if ($code -ne 0) { Get-Content $log -Tail 80; throw "second install failed: $code" }
    Select-String -Path $log -Pattern 'Wedgetail:' | ForEach-Object { Write-Host $_.Line }
    AssertNoToken $log
    if (-not (Select-String -Path $log -Pattern 'already enrolled; ENROLTOKEN was not used' -Quiet)) { throw 'the token was used again' }
    $text = Get-Content $toml -Raw
    if (([regex]::Matches($text, '(?m)^endpoint = ')).Count -ne 1) { throw "agent.toml has more than one endpoint line:`n$text" }
    if ($text -notmatch '(?m)^presets = \["windows-system"\]\r?$') { throw "presets not updated:`n$text" }
    AssertConfigAcl
    # The installer asked the running service to reload.
    $deadline = (Get-Date).AddSeconds(30)
    do {
        Start-Sleep -Seconds 2
        $rules = @((& $exe status --json | ConvertFrom-Json).collectors.rule_id)
    } while (($rules | Where-Object { $_ -like 'windows-security.*' }) -and (Get-Date) -lt $deadline)
    if ($rules | Where-Object { $_ -like 'windows-security.*' }) { throw "reload not applied: $rules" }
    Write-Host 'PASS presets changed and reloaded, enrolment kept'

    Section 'An invalid ENDPOINT fails the install and leaves agent.toml alone'
    $before = Get-Content $toml -Raw
    $log = "$work\install-bad.log"
    $code = Msiexec @('ENDPOINT=http://plain.example.com') $log
    if ($code -eq 0) { throw 'an http:// ENDPOINT was accepted' }
    Select-String -Path $log -Pattern 'Wedgetail:' | ForEach-Object { Write-Host $_.Line }
    if ((Get-Content $toml -Raw) -ne $before) { throw 'agent.toml changed' }
    if (Test-Path "$toml.msi-new") { throw 'the candidate file was left behind' }
    Write-Host "PASS refused with $code"
} finally {
    Stop-Process -Id $server.Id -Force -ErrorAction SilentlyContinue
    Get-ChildItem Cert:\LocalMachine\Root | Where-Object Subject -like "*Wedgetail CI MSI test root $run*" | Remove-Item
}
