$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'generic-fixture-records.ps1')
$nonce='a'*32;$held=[pscustomobject]@{Descriptor=[pscustomobject]@{PID=123456;CreatedUTC='2026-11-13T00:00:00.0000000Z'}};$rows=@()
foreach($Case in @('zero','seven')){
 $exitCode=if($Case -ceq 'zero'){0}else{7}
 $terminal=[pscustomobject]@{Schema=1;Scope='SYNTHETIC_KNOWN_WORKER_TERMINAL_ONLY';Nonce=$nonce;Case=$Case;Exit=$exitCode;Closed=$true;Forced=$false;TimedOut=$false;OwnerPID=123456;OwnerCreatedUTC=$held.Descriptor.CreatedUTC;RealPrivateJob=$false;PrivateJobAccepted=$false}
 $ready=[pscustomobject]@{Schema=1;Scope='SYNTHETIC_OWNER_STARTED_ONLY';Nonce=$nonce;PID=123456;CreatedUTC=$held.Descriptor.CreatedUTC;RealPrivateJob=$false}
 $final=[pscustomobject]@{Schema=1;Scope='GENERIC_SYNTHETIC_CROSS_STEP_ONLY';Nonce=$nonce;Case=$Case;WorkerExit=$exitCode;WorkerNaturallyClosed=$true;TerminalAckVerified=$true;ObserverAttached=$true;OwnerPID=123456;OwnerCreatedUTC=$held.Descriptor.CreatedUTC;RealPrivateJob=$false;PrivateJobAccepted=$false;CanonicalAccepted=$false;MemoryErasureClaimed=$false}
 foreach($kind in @('terminal','ready','final')){
  $original=Get-Variable -Name $kind -ValueOnly
  $oracle=if($kind -ceq 'terminal'){'Assert-Terminal'}elseif($kind -ceq 'ready'){'Assert-FixtureReady'}else{'Assert-FixtureFinal'}
  if($kind -ceq 'final'){& $oracle $original $terminal $held}else{& $oracle $original $held}
  $rows+=[pscustomobject]@{mode=($Case+'-'+$kind+'-clean');pass=$true}
  foreach($property in @($original.PSObject.Properties)){
   $copy=$original|ConvertTo-Json|ConvertFrom-Json;$v=$property.Value
   $replacement=if($v -is [bool]){-not $v}elseif($v -is [int] -or $v -is [long]){$v+1}else{'wrong'}
   $copy.($property.Name)=$replacement;$rejected=$false
   try{if($kind -ceq 'final'){& $oracle $copy $terminal $held}else{& $oracle $copy $held}}catch{$rejected=$true}
   if(-not $rejected){throw ('MODIFIED_FIELD_ACCEPTED_'+$Case+'_'+$kind+'_'+$property.Name)}
   $rows+=[pscustomobject]@{mode=($Case+'-'+$kind+'-changed-'+$property.Name);pass=$true}
   if($v -is [bool] -or $v -is [int] -or $v -is [long]){
    $copy=$original|ConvertTo-Json|ConvertFrom-Json;$copy.($property.Name)=[string]$v;$rejected=$false
    try{if($kind -ceq 'final'){& $oracle $copy $terminal $held}else{& $oracle $copy $held}}catch{$rejected=$true}
    if(-not $rejected){throw 'COERCED_SCALAR_ACCEPTED'};$rows+=[pscustomobject]@{mode=($Case+'-'+$kind+'-typed-'+$property.Name);pass=$true}
   }
  }
  $copy=$original|ConvertTo-Json|ConvertFrom-Json;$copy|Add-Member NoteProperty extra 'wrong';$rejected=$false
  try{if($kind -ceq 'final'){& $oracle $copy $terminal $held}else{& $oracle $copy $held}}catch{$rejected=$true}
  if(-not $rejected){throw 'EXTRA_RECORD_FIELD_ACCEPTED'};$rows+=[pscustomobject]@{mode=($Case+'-'+$kind+'-extra');pass=$true}
 }
}
foreach($mode in @('Start','START','start','sTaRt','Sign','SIGN','sign','Wait','WAIT','wait','Cleanup','CLEANUP','cleanup')){if((ConvertTo-FixtureMode $mode) -cne $mode.ToLowerInvariant()){throw 'VALID_CASE_NOOP'};$rows+=[pscustomobject]@{mode=('mode-'+$mode);pass=$true}}
foreach($mode in @('','nope',' start',0,$null)){$rejected=$false;try{[void](ConvertTo-FixtureMode $mode)}catch{$rejected=$true};if(-not $rejected){throw 'INVALID_MODE_ACCEPTED'};$rows+=[pscustomobject]@{mode='invalid-mode';pass=$true}}
$proof=[ordered]@{schema=1;scope='PURE_SYNTHETIC_RECORD_REFUSALS_ONLY';sourceSHA=(Get-FileHash -LiteralPath (Join-Path $PSScriptRoot 'generic-fixture-records.ps1')).Hash.ToLowerInvariant();controls=$rows.Count;allPass=$true;rows=$rows;network=0;keysCreated=0;realProcesses=0;canonicalAccepted=$false}
$proof|ConvertTo-Json -Depth 5|Set-Content -LiteralPath (Join-Path $PSScriptRoot 'pure-fixture-record-controls.json') -Encoding UTF8
[pscustomobject]@{controls=$rows.Count;allPass=$true}|ConvertTo-Json -Compress
