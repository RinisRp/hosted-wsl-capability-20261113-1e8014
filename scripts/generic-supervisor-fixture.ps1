param([Parameter(Mandatory=$true)][ValidateSet('Start','Sign','Wait','Cleanup')][string]$Mode,[Parameter(Mandatory=$true)][ValidateSet('zero','seven')][string]$Case)
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'generic-fixture-records.ps1')
$Mode=ConvertTo-FixtureMode $Mode;$Case=$Case.ToLowerInvariant()
if($PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSEdition -cne 'Desktop'){throw 'WINDOWS_POWERSHELL5_FIXTURE_REQUIRED'}
if(-not [string]::IsNullOrEmpty($env:OWNED_RUNNER_PACKET)){throw 'PRIVATE_PACKET_REFUSED_IN_HARMLESS_FIXTURE'}
if($env:GITHUB_ACTIONS -cne 'true' -or $env:GITHUB_REPOSITORY -cne 'RinisRp/hosted-wsl-capability-20261113-1e8014' -or $env:GITHUB_ACTOR -cne 'RinisRp' -or $env:GITHUB_REF -cne 'refs/heads/codex/ack-supervisor-6e8c4a' -or $env:GITHUB_SHA -cnotmatch '\A[a-f0-9]{40}\z' -or $env:GITHUB_RUN_ID -cnotmatch '\A[1-9][0-9]{0,18}\z' -or $env:GITHUB_RUN_ATTEMPT -cne '1' -or $env:RUNNER_ENVIRONMENT -cne 'github-hosted' -or $env:RUNNER_ARCH -cne 'X64' -or $env:ImageOS -cne 'win25-vs2026' -or $env:PROBE_NONCE -cnotmatch '\A[a-f0-9]{32}\z'){throw 'EXACT_GENERIC_HOSTED_FIXTURE_REQUIRED'}
. (Join-Path $PSScriptRoot 'generic-terminal-ack.ps1')
. (Join-Path $PSScriptRoot 'private-directory-helper.ps1')
. (Join-Path $PSScriptRoot 'owned-supervisor-lifetime.ps1')
$sha=[Security.Cryptography.SHA256]::Create();try{$nonce=([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::ASCII.GetBytes($env:PROBE_NONCE+'/'+$Case))).Replace('-','').ToLowerInvariant()).Substring(0,32)}finally{$sha.Dispose()}
$keyName='OWNED_ACK_FIXTURE_'+$nonce
$keyRoot=Join-Path $env:RUNNER_TEMP ('owned-fixture-key-'+$nonce)
function Write-FixtureJson($Path,$Value){
 $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($Value|ConvertTo-Json -Depth 5 -Compress));if($bytes.Length -gt 4096){throw 'BOUNDED_FIXTURE_JSON_REQUIRED'}
 Write-FixtureClosedBytes $Path $bytes
}
function Read-FixtureJson($Path){
 $item=Get-Item -LiteralPath $Path -Force;if($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $item.Length -gt 4096){throw 'BOUNDED_REGULAR_FIXTURE_JSON_REQUIRED'}
 return ([IO.File]::ReadAllText($Path)|ConvertFrom-Json)
}
function Assert-Keys($Value,$Names){if($Value -isnot [pscustomobject] -or (@($Value.PSObject.Properties.Name|Sort-Object) -join '|') -cne (@($Names|Sort-Object) -join '|')){throw 'EXACT_SYNTHETIC_RECORD_REQUIRED'}}
function New-Context($Fingerprint){return [pscustomobject]@{PublicRepository=$env:GITHUB_REPOSITORY;Nonce=$nonce;SourceHead=$env:GITHUB_SHA;Run=$env:GITHUB_RUN_ID;Attempt=1;KeyFingerprint=$Fingerprint}}
function Read-Context{
 $path=Join-Path $env:RUNNER_TEMP ('owned-supervisor-'+$nonce+'\public-context.json');$data=Read-FixtureJson $path
 $ctx=New-Context $data.Context.KeyFingerprint
 $public=Read-OwnedSupervisorContext $ctx 'fixture'
 return $public
}

if($Mode -ceq 'start'){
 $key=$null;$rsa=$null;$created=$false;$started=$false;$primaryFailed=$false
 try{
  if([Security.Cryptography.CngKey]::Exists($keyName)){throw 'EXCLUSIVE_SYNTHETIC_KEY_REQUIRED'}
  New-OwnedPrivateDirectory $keyRoot ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value)
  Write-FixtureJson (Join-Path $keyRoot 'creation-intent-UNKNOWN.json') ([ordered]@{Schema=1;Scope='SYNTHETIC_KEY_CREATION_UNKNOWN_NO_REPLAY';Nonce=$nonce;KeyName=$keyName;SourceHead=$env:GITHUB_SHA;PublicRun=$env:GITHUB_RUN_ID;Attempt=1})
  $parameters=[Security.Cryptography.CngKeyCreationParameters]::new();$parameters.ExportPolicy=[Security.Cryptography.CngExportPolicies]::None;$parameters.KeyUsage=[Security.Cryptography.CngKeyUsages]::Signing
  $parameters.Parameters.Add([Security.Cryptography.CngProperty]::new('Length',[BitConverter]::GetBytes(3072),[Security.Cryptography.CngPropertyOptions]::None))
  $key=[Security.Cryptography.CngKey]::Create([Security.Cryptography.CngAlgorithm]::Rsa,$keyName,$parameters);$created=$true;$rsa=[Security.Cryptography.RSACng]::new($key)
  $pub=$rsa.ExportParameters($false);$wire=New-Object byte[] 387;[Array]::Copy($pub.Modulus,0,$wire,0,384);[Array]::Copy($pub.Exponent,0,$wire,384,3)
  Write-FixtureJson (Join-Path $keyRoot 'key-created.json') ([ordered]@{Schema=1;Scope='OWNED_SYNTHETIC_KEY_CREATED_ONLY';Nonce=$nonce;KeyName=$keyName;SourceHead=$env:GITHUB_SHA;PublicRun=$env:GITHUB_RUN_ID;Attempt=1;KeyFingerprint=(Get-GenericAckKeyFingerprint $wire)})
  $ctx=New-Context (Get-GenericAckKeyFingerprint $wire);$root=New-OwnedSupervisorContext $ctx $wire 'fixture'
  Write-FixtureJson (Join-Path $root 'fixture-plan.json') ([ordered]@{Schema=1;Case=$Case;KeyName=$keyName})
  # Failure evidence must remain collectible even if the owner never becomes
  # ready. This output is an owned path only and grants no readiness authority.
  [IO.File]::AppendAllText($env:GITHUB_OUTPUT,('out_path='+$root+[Environment]::NewLine),[Text.UTF8Encoding]::new($false))
  $launch=Start-OwnedDetachedSupervisor $ctx 'fixture';$held=Hold-OwnedSupervisorGeneration $ctx 'fixture'
  try{
   $clock=[Diagnostics.Stopwatch]::StartNew();$marker=Join-Path $root 'owner-started.json'
   while(-not (Test-Path -LiteralPath $marker) -and $clock.Elapsed.TotalSeconds -lt 90){if($held.Process.HasExited){throw 'SYNTHETIC_OWNER_EXITED_BEFORE_READY'};Start-Sleep -Milliseconds 200}
   if($clock.Elapsed.TotalSeconds -ge 90 -or $held.Process.HasExited){throw 'LIVE_OWNER_READY_DEADLINE_REQUIRED'}
   $ready=Read-FixtureJson $marker
   Assert-FixtureReady $ready $held
   if($clock.Elapsed.TotalSeconds -ge 90 -or $held.Process.HasExited){throw 'READY_VALIDATION_DEADLINE_REQUIRED'}
   $started=$true
  }finally{$held.Process.Dispose()}
  Write-Output 'SYNTHETIC_DETACHED_OWNER_STARTED_NO_PRIVATE_JOB'
 }catch{$primaryFailed=$true;throw}finally{
  $cleanupFailed=$false
  if($created -and -not $started -and $null -ne $key){try{$key.Delete()}catch{$cleanupFailed=$true}}
  if($null -ne $rsa){try{$rsa.Dispose()}catch{$cleanupFailed=$true}}
  if($null -ne $key){try{$key.Dispose()}catch{$cleanupFailed=$true}}
  if($cleanupFailed -and -not $primaryFailed){throw 'SYNTHETIC_START_CLEANUP_UNACCEPTED'}
 }
 exit 0
}
if($Mode -ceq 'cleanup'){
 $ownedKey=Read-FixtureJson (Join-Path $keyRoot 'key-created.json')
 Assert-FixtureTypedRecord $ownedKey @('Schema','Scope','Nonce','KeyName','SourceHead','PublicRun','Attempt','KeyFingerprint') @('Schema','Attempt') @('Scope','Nonce','KeyName','SourceHead','PublicRun','KeyFingerprint') @() @()
 if($ownedKey.Schema -ne 1 -or $ownedKey.Scope -cne 'OWNED_SYNTHETIC_KEY_CREATED_ONLY' -or $ownedKey.Nonce -cne $nonce -or $ownedKey.KeyName -cne $keyName -or $ownedKey.SourceHead -cne $env:GITHUB_SHA -or $ownedKey.PublicRun -cne $env:GITHUB_RUN_ID -or $ownedKey.Attempt -ne 1 -or $ownedKey.KeyFingerprint -cnotmatch '\A[a-f0-9]{64}\z'){throw 'INDEPENDENT_OWNED_SYNTHETIC_KEY_RECEIPT_REQUIRED'}
 if([Security.Cryptography.CngKey]::Exists($keyName)){
  $key=[Security.Cryptography.CngKey]::Open($keyName);$rsa=$null;$cleanupFailed=$false;$primaryFailed=$false
  try{$rsa=[Security.Cryptography.RSACng]::new($key);$p=$rsa.ExportParameters($false);$wire=New-Object byte[] 387;[Array]::Copy($p.Modulus,0,$wire,0,384);[Array]::Copy($p.Exponent,0,$wire,384,3);if((Get-GenericAckKeyFingerprint $wire) -cne $ownedKey.KeyFingerprint){throw 'OWNED_SYNTHETIC_KEY_IDENTITY_REQUIRED'};$key.Delete()}catch{$primaryFailed=$true;throw}finally{if($null -ne $rsa){try{$rsa.Dispose()}catch{$cleanupFailed=$true}};try{$key.Dispose()}catch{$cleanupFailed=$true};if($cleanupFailed -and -not $primaryFailed){throw 'SYNTHETIC_CLEANUP_HANDLE_UNACCEPTED'}}
 }
 if([Security.Cryptography.CngKey]::Exists($keyName)){throw 'OWNED_SYNTHETIC_KEY_CLEANUP_UNACCEPTED'}
 $public=Read-Context;$ctx=$public.Context;$root=$public.Root
 if(-not (Test-Path -LiteralPath (Join-Path $root 'cross-step-accepted.json'))){
  # An intervening step failure must not silently abandon the detached owner.
  # This is a failure reconciliation only, never a substitute acceptance.
  $remaining=Hold-OwnedSupervisorGeneration $ctx 'fixture'
  try{if(-not $remaining.Process.WaitForExit(250000)){throw 'SYNTHETIC_FAILURE_HOLD_UNCLOSED'};$remaining.Process.WaitForExit()}finally{$remaining.Process.Dispose()}
  throw 'SYNTHETIC_FAILURE_RECONCILED_NOT_ACCEPTED'
 }
 Write-Output 'OWNED_SYNTHETIC_KEY_ABSENT';exit 0
}
$public=Read-Context;$ctx=$public.Context;$root=$public.Root
$held=Hold-OwnedSupervisorGeneration $ctx 'fixture'
try{
 if($Mode -ceq 'sign'){
  $clock=[Diagnostics.Stopwatch]::StartNew();$path=Join-Path $root 'worker-terminal.json'
  while(-not (Test-Path -LiteralPath $path) -and $clock.Elapsed.TotalSeconds -lt 45){if($held.Process.HasExited){throw 'SYNTHETIC_OWNER_EXITED_BEFORE_TERMINAL'};Start-Sleep -Milliseconds 200}
  $terminal=Read-FixtureJson $path;Assert-Terminal $terminal $held
  $key=$null;$rsa=$null;$primaryFailed=$false
  try{
   $key=[Security.Cryptography.CngKey]::Open($keyName);if($key.ExportPolicy -ne [Security.Cryptography.CngExportPolicies]::None){throw 'NONEXPORTABLE_SYNTHETIC_KEY_REQUIRED'};$rsa=[Security.Cryptography.RSACng]::new($key)
   $payload=Get-GenericAckContextPayload $ctx;$signature=$rsa.SignData($payload,[Security.Cryptography.HashAlgorithmName]::SHA256,[Security.Cryptography.RSASignaturePadding]::Pss)
   $bytes=[Text.Encoding]::ASCII.GetBytes([Text.Encoding]::ASCII.GetString($payload)+'signature='+[Convert]::ToBase64String($signature)+[char]10)
   [void](Assert-GenericTerminalAck $bytes $ctx $public.PublicKeyBytes)
   Write-FixtureClosedBytes (Join-Path $root 'fixture-terminal-ack.txt') $bytes
   $key.Delete()
  }catch{$primaryFailed=$true;throw}finally{$cleanupFailed=$false;if($null -ne $rsa){try{$rsa.Dispose()}catch{$cleanupFailed=$true}};if($null -ne $key){try{$key.Dispose()}catch{$cleanupFailed=$true}};if($cleanupFailed -and -not $primaryFailed){throw 'SYNTHETIC_SIGNER_HANDLE_CLEANUP_UNACCEPTED'}}
  if([Security.Cryptography.CngKey]::Exists($keyName)){throw 'SYNTHETIC_SIGNER_KEY_STILL_PRESENT'}
  Write-Output 'SYNTHETIC_ACK_SIGNED_ONLY_AFTER_KNOWN_WORKER_TERMINAL';exit 0
 }
 if($Mode -ceq 'wait'){
  $terminal=Read-FixtureJson (Join-Path $root 'worker-terminal.json');Assert-Terminal $terminal $held
  [void](Assert-GenericTerminalAck ([IO.File]::ReadAllBytes((Join-Path $root 'fixture-terminal-ack.txt'))) $ctx $public.PublicKeyBytes)
  Write-FixtureJson (Join-Path $root 'observer-attached.json') ([ordered]@{Nonce=$nonce;PID=$held.Descriptor.PID;CreatedUTC=$held.Descriptor.CreatedUTC})
  if(-not $held.Process.WaitForExit(30000)){throw 'NATURAL_SYNTHETIC_OWNER_EXIT_REQUIRED'};$held.Process.WaitForExit()
  if(-not $held.Process.HasExited -or $held.Process.ExitCode -ne 0){throw 'SYNTHETIC_OWNER_UNACCEPTED'}
  $final=Read-FixtureJson (Join-Path $root 'fixture-final.json')
  Assert-FixtureFinal $final $terminal $held
  if([Security.Cryptography.CngKey]::Exists($keyName)){throw 'SYNTHETIC_KEY_MUST_BE_ABSENT'}
  Write-FixtureJson (Join-Path $root 'cross-step-accepted.json') ([ordered]@{Schema=1;Scope='GENERIC_SYNTHETIC_CROSS_STEP_ONLY';Case=$Case;Nonce=$nonce;SourceHead=$ctx.SourceHead;PublicRun=$ctx.Run;Attempt=1;SameGenerationHeld=$true;OwnerNaturalExit=0;WorkerExit=$terminal.Exit;WorkerSuccess=($terminal.Exit -eq 0);TerminalAckVerified=$true;SyntheticKeyAbsent=$true;RealPrivateJob=$false;CanonicalAccepted=$false;RemoteAckTransportProved=$false})
  Write-Output 'SYNTHETIC_CROSS_STEP_GENERATION_AND_SIGNED_TERMINAL_ACK_ACCEPTED';exit 0
 }
}finally{$held.Process.Dispose()}
throw 'FIXTURE_MODE_DID_NOT_COMPLETE'
