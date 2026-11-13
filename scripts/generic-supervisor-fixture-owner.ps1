param([Parameter(Mandatory=$true)][string]$Nonce,[Parameter(Mandatory=$true)][string]$LeaseRoot)
$hadPacket=-not [string]::IsNullOrEmpty($env:OWNED_RUNNER_PACKET)
[Environment]::SetEnvironmentVariable('OWNED_RUNNER_PACKET',[Management.Automation.Language.NullString]::Value,'Process')
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
$clock=[Diagnostics.Stopwatch]::StartNew();$success=$false;$ctx=$null;$rootVerified=$false;$stage='IMPORT'
function Write-FixtureJson($Path,$Value){
 $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($Value|ConvertTo-Json -Depth 4 -Compress));if($bytes.Length -gt 4096){throw 'BOUNDED_FIXTURE_JSON_REQUIRED'}
 Write-FixtureClosedBytes $Path $bytes
}
function Read-FixtureJson($Path){
 $item=Get-Item -LiteralPath $Path -Force;if($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $item.Length -gt 4096){throw 'BOUNDED_REGULAR_FIXTURE_JSON_REQUIRED'}
 return ([IO.File]::ReadAllText($Path)|ConvertFrom-Json)
}
function Assert-FixtureBootstrapRoot($Nonce,$LeaseRoot,$RunnerTemp){
 if($Nonce -isnot [string] -or $Nonce -cnotmatch '\A[a-f0-9]{32}\z' -or $RunnerTemp -isnot [string] -or $RunnerTemp -cnotmatch '\A[A-Z]:\\[A-Za-z0-9_\\-]+\z' -or $LeaseRoot -isnot [string] -or $LeaseRoot -cne (Join-Path $RunnerTemp ('owned-supervisor-'+$Nonce))){throw 'EXACT_BOOTSTRAP_ROOT_REQUIRED'}
 $item=Get-Item -LiteralPath $LeaseRoot -Force
 if(-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'EXISTING_ORDINARY_BOOTSTRAP_ROOT_REQUIRED'}
}
function Write-FixtureBootstrap($Name,$Stage,$ExceptionKind){
 Assert-FixtureBootstrapRoot $Nonce $LeaseRoot $env:RUNNER_TEMP
 if($Name -cnotin @('bootstrap-started.json','fixture-failure.json') -or $Stage -cnotin @('PRE_IMPORT','IMPORT_ACK','IMPORT_LIFETIME','IMPORT_GATE','IMPORT_RECORDS','CONTEXT','CONTEXT_READ','PLAN','READY_WRITE','NATIVE_IMPORT','WORKER','ACK','OBSERVER') -or $ExceptionKind -cnotin @('NONE','PS_ERROR','IO_ERROR','CRYPTO_ERROR','OTHER_ERROR')){throw 'FIXED_SYNTHETIC_BOOTSTRAP_CODES_REQUIRED'}
 $record=[ordered]@{Schema=1;Scope='SYNTHETIC_BOOTSTRAP_DIAGNOSTIC_ONLY';Nonce=$Nonce;PID=$PID;Stage=$Stage;ExceptionKind=$ExceptionKind;RealPrivateJob=$false;CanonicalAccepted=$false}
 $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($record|ConvertTo-Json -Compress));if($bytes.Length -gt 1024){throw 'BOUNDED_BOOTSTRAP_RECORD_REQUIRED'}
 $path=Join-Path $LeaseRoot $Name;$pending=$path+'.closed-pending';$f=[IO.File]::Open($pending,'CreateNew','Write','None');try{$f.Write($bytes,0,$bytes.Length);$f.Flush($true)}finally{$f.Dispose()};[IO.File]::Move($pending,$path)
}
try{
 if($hadPacket -or $Nonce -cnotmatch '\A[a-f0-9]{32}\z'){throw 'HARMLESS_FIXTURE_ONLY'}
 Assert-FixtureBootstrapRoot $Nonce $LeaseRoot $env:RUNNER_TEMP
 $rootVerified=$true;$stage='PRE_IMPORT';Write-FixtureBootstrap 'bootstrap-started.json' $stage 'NONE'
 $stage='IMPORT_ACK'
 . (Join-Path $PSScriptRoot 'generic-terminal-ack.ps1')
 $stage='IMPORT_LIFETIME'
 . (Join-Path $PSScriptRoot 'owned-supervisor-lifetime.ps1')
 $stage='IMPORT_GATE'
 . (Join-Path $PSScriptRoot 'terminal-ack-gate.ps1')
 $stage='IMPORT_RECORDS'
 . (Join-Path $PSScriptRoot 'generic-fixture-records.ps1')
 $stage='CONTEXT_READ'
 $raw=[IO.File]::ReadAllText((Join-Path $LeaseRoot 'public-context.json'))|ConvertFrom-Json;$ctx=$raw.Context
 if($ctx.Nonce -cne $Nonce -or (Get-OwnedSupervisorRoot $ctx) -cne $LeaseRoot){throw 'EXACT_FIXTURE_ROOT_REQUIRED'}
 $rootVerified=$true;$stage='CONTEXT'
 $public=Read-OwnedSupervisorContext $ctx 'fixture'
 $stage='PLAN'
 $plan=Read-FixtureJson (Join-Path $LeaseRoot 'fixture-plan.json')
 if($plan.Schema -ne 1 -or $plan.Case -cnotin @('zero','seven') -or $plan.KeyName -cne ('OWNED_ACK_FIXTURE_'+$Nonce)){throw 'EXACT_SYNTHETIC_PLAN_REQUIRED'}
 $self=[Diagnostics.Process]::GetCurrentProcess();try{$created=$self.StartTime.ToUniversalTime().ToString('o')}finally{$self.Dispose()}
 $stage='READY_WRITE'
 Write-FixtureJson (Join-Path $LeaseRoot 'owner-started.json') ([ordered]@{Schema=1;Scope='SYNTHETIC_OWNER_STARTED_ONLY';Nonce=$Nonce;PID=$PID;CreatedUTC=$created;RealPrivateJob=$false})
 $stage='NATIVE_IMPORT'
 $tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'probe-wsl.ps1'),[ref]$tokens,[ref]$errors)
 if($errors.Count){throw 'ACTUAL_NATIVE_SOURCE_REQUIRED'}
 $f=@($ast.FindAll({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'Native'},$false));if($f.Count -ne 1){throw 'ONE_ACTUAL_NATIVE_REQUIRED'}
 . ([scriptblock]::Create($f[0].Extent.Text))
 $root=$LeaseRoot;$raw=Join-Path $LeaseRoot 'raw';$out=Join-Path $LeaseRoot 'public-native';[void][IO.Directory]::CreateDirectory($raw);[void][IO.Directory]::CreateDirectory($out)
 $env:OWNED_ACK_FIXTURE_NONCE=$Nonce
 $stage='WORKER'
 $worker=Join-Path $PSScriptRoot 'generic-supervisor-fixture-worker.ps1';$exe=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
 $native=Native $exe @('-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',$worker,'-Nonce',$Nonce,'-Case',$plan.Case) 30 'worker'
 $expected=if($plan.Case -ceq 'zero'){0}else{7}
 if($native.exitCode -ne $expected -or $native.timedOut -or $native.onlyOwnStartedRootStopped -or -not $native.closed -or $null -ne $native.nativeError -or $null -ne $native.cleanupError -or $native.stdout -cne '' -or $native.stderr -cne ''){throw 'KNOWN_NATURAL_SYNTHETIC_WORKER_TERMINAL_REQUIRED'}
 Write-FixtureJson (Join-Path $LeaseRoot 'worker-terminal.json') ([ordered]@{Schema=1;Scope='SYNTHETIC_KNOWN_WORKER_TERMINAL_ONLY';Nonce=$Nonce;Case=$plan.Case;Exit=$native.exitCode;Closed=$true;Forced=$false;TimedOut=$false;OwnerPID=$PID;OwnerCreatedUTC=$created;RealPrivateJob=$false;PrivateJobAccepted=$false})
 $stage='ACK'
 # This override exists only in this named harmless fixture process. Production
 # Invoke-OwnedGenericAckRead remains the fixed-URL owned HTTP process reader.
 function Invoke-OwnedGenericAckRead($Context,$Index){
  $path=Join-Path $LeaseRoot 'fixture-terminal-ack.txt';$bytes=[byte[]]@();$has=Test-Path -LiteralPath $path
  if($has){$item=Get-Item -LiteralPath $path -Force;if($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $item.Length -gt 2048){throw 'BOUNDED_LOCAL_SYNTHETIC_ACK_REQUIRED'};$bytes=[IO.File]::ReadAllBytes($path)}
  return [pscustomobject]@{Scope='OWNED_ACK_QUERY_ONLY_NOT_AUTHORITY';HasAck=[bool]$has;RetryAllowed=$true;Unknown=$false;Bytes=$bytes}
 }
 $gate=Wait-VerifiedGenericTerminalAck $ctx $public.PublicKeyBytes ([int](240-$clock.Elapsed.TotalSeconds))
 if(-not $gate.Verified){throw 'SYNTHETIC_ACK_UNACCEPTED'}
 $stage='OBSERVER'
 # Stay alive until a DIFFERENT workflow step holds this exact generation.
 $observed=$false
 while($clock.Elapsed.TotalSeconds -lt 240){
  $path=Join-Path $LeaseRoot 'observer-attached.json'
  if(Test-Path -LiteralPath $path){$o=Read-FixtureJson $path;if($o.Nonce -cne $Nonce -or $o.PID -ne $PID -or $o.CreatedUTC -cne $created){throw 'EXACT_OBSERVER_GENERATION_REQUIRED'};$observed=$true;break}
  Start-Sleep -Milliseconds 200
 }
 if(-not $observed){throw 'OBSERVER_NOT_ATTACHED'}
 Write-FixtureJson (Join-Path $LeaseRoot 'fixture-final.json') ([ordered]@{Schema=1;Scope='GENERIC_SYNTHETIC_CROSS_STEP_ONLY';Nonce=$Nonce;Case=$plan.Case;WorkerExit=$native.exitCode;WorkerNaturallyClosed=$true;TerminalAckVerified=$true;ObserverAttached=$true;OwnerPID=$PID;OwnerCreatedUTC=$created;RealPrivateJob=$false;PrivateJobAccepted=$false;CanonicalAccepted=$false;MemoryErasureClaimed=$false})
 $success=$true
}catch{
 $kind=if($_.Exception -is [IO.IOException]){'IO_ERROR'}elseif($_.Exception -is [Security.Cryptography.CryptographicException]){'CRYPTO_ERROR'}elseif($_.Exception -is [Management.Automation.RuntimeException]){'PS_ERROR'}else{'OTHER_ERROR'}
 if($rootVerified){try{Write-FixtureBootstrap 'fixture-failure.json' $stage $kind}catch{}}
 # Failure never becomes success. Keep this harmless host alive to the fixed
 # hard expiry, matching the future private caller's required failure hold.
 while($clock.Elapsed.TotalSeconds -lt 240){Start-Sleep -Milliseconds 200}
}finally{[Environment]::SetEnvironmentVariable('OWNED_ACK_FIXTURE_NONCE',[Management.Automation.Language.NullString]::Value,'Process')}
if($success){exit 0};exit 81
