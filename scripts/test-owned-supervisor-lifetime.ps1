$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
$source=Join-Path $PSScriptRoot 'owned-supervisor-lifetime.ps1'
$sha=(Get-FileHash -LiteralPath $source).Hash.ToLowerInvariant()
$sandbox=Join-Path $env:TEMP ('owned-supervisor-pure-'+[guid]::NewGuid().ToString('N'));[void][IO.Directory]::CreateDirectory($sandbox)
[IO.File]::Copy($source,(Join-Path $sandbox 'owned-supervisor-lifetime.ps1'))
foreach($name in @('generic-supervisor-fixture-owner.ps1','opaque-private-supervisor-owner.ps1')){[IO.File]::WriteAllText((Join-Path $sandbox $name),'throw ''SYNTHETIC_PLACEHOLDER_NEVER_EXECUTED''')}
. (Join-Path $sandbox 'owned-supervisor-lifetime.ps1')
$actualWriter=${function:Write-OwnedSupervisorObservation};$rows=@()
$ctx=[pscustomobject]@{Nonce=('a'*32);SourceHead=('b'*40);Run='1'}
function Read-OwnedSupervisorContext($Context,$Kind){return [pscustomobject]@{Root=$script:caseRoot;Context=$Context}}
function Write-OwnedSupervisorObservation($Root,$Name,$Value){
 if($script:mode -ceq 'pid-write' -and $Name -ceq 'launch-pid-observed.json'){throw 'INJECTED_PID_IO_FAILURE'}
 if($script:mode -ceq 'descriptor-write' -and $Name -ceq 'supervisor.json'){throw 'INJECTED_DESCRIPTOR_IO_FAILURE'}
 & $actualWriter $Root $Name $Value
 if($script:mode -ceq 'descriptor-readback' -and $Name -ceq 'supervisor.json'){throw 'INJECTED_CLOSED_DESCRIPTOR_READBACK_FAILURE'}
}
function Start-Process($FilePath,$ArgumentList,$WindowStyle,[switch]$PassThru){
 $script:starts++
 if(-not (Test-Path -LiteralPath (Join-Path $script:caseRoot 'launch-intent-UNKNOWN.json'))){throw 'LAUNCH_WITHOUT_DURABLE_INTENT'}
 if($WindowStyle -cne 'Hidden' -or -not $PassThru -or $ArgumentList -contains '-NoNewWindow' -or $env:SYNTHETIC_FORBIDDEN -or $env:RUNNER_TRACKING_ID){throw 'UNSAFE_PROCESS_VECTOR_OR_ENV'}
 if($script:mode -ceq 'start-unknown'){throw 'INJECTED_START_OUTCOME_UNKNOWN'}
 $obj=[pscustomobject]@{Id=123456}
 $obj|Add-Member ScriptProperty Handle {if($script:mode -ceq 'handle'){throw 'INJECTED_HANDLE_FAILURE'};return [IntPtr]1}
 $obj|Add-Member ScriptProperty StartTime {if($script:mode -ceq 'start-time'){throw 'INJECTED_START_TIME_FAILURE'};return [datetime]'2026-11-13T00:00:00Z'}
 $obj|Add-Member ScriptMethod Dispose {$script:disposals++;if($script:mode -ceq 'dispose'){throw 'INJECTED_DISPOSE_FAILURE'}}
 return $obj
}
$oldForbidden=$env:SYNTHETIC_FORBIDDEN;$oldTracking=$env:RUNNER_TRACKING_ID;$oldPacket=$env:OWNED_RUNNER_PACKET
try{
 $env:SYNTHETIC_FORBIDDEN='SYNTHETIC_NO_SECRET';$env:RUNNER_TRACKING_ID='SYNTHETIC_TRACKING'
 foreach($script:mode in @('clean','start-unknown','handle','start-time','pid-write','descriptor-write','descriptor-readback','dispose')){
  $script:caseRoot=Join-Path $sandbox $script:mode;[void][IO.Directory]::CreateDirectory($script:caseRoot);$script:starts=0;$script:disposals=0
  $env:OWNED_RUNNER_PACKET='SYNTHETIC_PACKET_NOT_A_CREDENTIAL';$failed=$false;$result=$null
  try{$result=Start-OwnedDetachedSupervisor $ctx 'private'}catch{$failed=$true}
  if($failed -cne ($script:mode -cne 'clean') -or $script:starts -ne 1 -or -not [string]::IsNullOrEmpty($env:OWNED_RUNNER_PACKET) -or $env:SYNTHETIC_FORBIDDEN -cne 'SYNTHETIC_NO_SECRET' -or $env:RUNNER_TRACKING_ID -cne 'SYNTHETIC_TRACKING'){throw ('BAD_FIRST_OUTCOME_'+$script:mode)}
  $claim=Get-Content -LiteralPath (Join-Path $script:caseRoot 'launch-intent-UNKNOWN.json') -Raw|ConvertFrom-Json
  if($claim.Outcome -cne 'UNKNOWN_NO_REPLAY'){throw 'NONREPLAY_INTENT_LOST'}
  if($script:mode -cne 'start-unknown' -and $script:disposals -ne 1){throw 'STARTED_HANDLE_DISPOSAL_MISSING'}
  if($script:mode -notin @('clean','dispose')){
   $failure=Get-Content -LiteralPath (Join-Path $script:caseRoot 'launch-failure-UNKNOWN.json') -Raw|ConvertFrom-Json
   if(-not $failure.NoReplay -or $failure.TeardownPermitted -or ($script:mode -cne 'start-unknown' -and $failure.PID -ne 123456)){throw 'PARTIAL_RECONCILIATION_LOST'}
  }
  if($script:mode -ceq 'dispose' -and -not (Test-Path -LiteralPath (Join-Path $script:caseRoot 'launch-restore-UNKNOWN.json'))){throw 'RESTORE_RECONCILIATION_LOST'}
  if($script:mode -ceq 'clean' -and ($result.PrivateJobAccepted -or $result.CanonicalAccepted)){throw 'UNEXPECTED_ACCEPTANCE'}
  $rows+=[pscustomobject]@{mode=$script:mode;pass=$true;starts=$script:starts;unknown=$failed;realProcesses=0}
  $env:OWNED_RUNNER_PACKET='SYNTHETIC_PACKET_NOT_A_CREDENTIAL';$replayRejected=$false
  try{[void](Start-OwnedDetachedSupervisor $ctx 'private')}catch{$replayRejected=$true}
  if(-not $replayRejected -or $script:starts -ne 1 -or -not [string]::IsNullOrEmpty($env:OWNED_RUNNER_PACKET)){throw ('REPLAY_OR_PACKET_RETENTION_WAS_POSSIBLE_'+$script:mode)}
  $rows+=[pscustomobject]@{mode=('nonreplay-'+$script:mode);pass=$true;starts=$script:starts;realProcesses=0}
  [Environment]::SetEnvironmentVariable('OWNED_RUNNER_PACKET',[Management.Automation.Language.NullString]::Value,'Process')
 }
 $script:caseRoot=Join-Path $sandbox 'fixture-refuses-packet';[void][IO.Directory]::CreateDirectory($script:caseRoot);$script:starts=0;$env:OWNED_RUNNER_PACKET='SYNTHETIC_PACKET_NOT_A_CREDENTIAL';$rejected=$false
 try{[void](Start-OwnedDetachedSupervisor $ctx 'fixture')}catch{$rejected=$true}
 if(-not $rejected -or $script:starts -ne 0 -or (Test-Path -LiteralPath (Join-Path $script:caseRoot 'launch-intent-UNKNOWN.json'))){throw 'FIXTURE_PACKET_GUARD_FAILED'}
 $rows+=[pscustomobject]@{mode='fixture-refuses-packet-before-intent';pass=$true;starts=0;realProcesses=0}
 $proof=[ordered]@{schema=1;scope='PURE_LAUNCH_NONREPLAY_AND_FAILURE_RECONCILIATION_ONLY';sourceSHA=$sha;controls=$rows.Count;allPass=$true;rows=$rows;actualFilesystem=$true;processStartMocked=$true;handleAndEnvironmentFailureInjected=$true;actualDetachedProcess=0;realPackets=0;network=0;canonicalAccepted=$false;executionArmed=$false}
 $proof|ConvertTo-Json -Depth 6|Set-Content -LiteralPath (Join-Path $PSScriptRoot 'pure-supervisor-lifetime-controls.json') -Encoding UTF8
 [pscustomobject]@{controls=$rows.Count;allPass=$true;sourceSHA=$sha}|ConvertTo-Json -Compress
}finally{
 foreach($entry in @(@('SYNTHETIC_FORBIDDEN',$oldForbidden),@('RUNNER_TRACKING_ID',$oldTracking),@('OWNED_RUNNER_PACKET',$oldPacket))){$v=if($null -eq $entry[1]){[Management.Automation.Language.NullString]::Value}else{$entry[1]};[Environment]::SetEnvironmentVariable($entry[0],$v,'Process')}
}
