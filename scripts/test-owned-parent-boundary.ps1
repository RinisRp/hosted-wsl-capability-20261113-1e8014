# Generic hosted-only fixture. Never starts Runner.Listener/Worker or reads a packet.
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
try{
if($env:GITHUB_ACTIONS -cne 'true' -or $env:RUNNER_ENVIRONMENT -cne 'github-hosted' -or $env:GITHUB_REPOSITORY -cne 'RinisRp/hosted-wsl-capability-20261113-1e8014' -or $env:GITHUB_ACTOR -cne 'RinisRp' -or $env:GITHUB_REF -cne 'refs/heads/codex/wsl-npipe-6f3465' -or $env:ImageOS -cne 'win25-vs2026' -or $env:RUNNER_ARCH -cne 'X64' -or $env:PROBE_NONCE -cnotmatch '\A[0-9a-f]{32}\z'){throw 'EXACT_GENERIC_HOSTED_BOUNDARY_CONTEXT_REQUIRED'}
. (Join-Path $PSScriptRoot 'private-directory-helper.ps1')
function Import-ExactFunction([string]$Path,[string]$Name){
 $t=$null;$e=$null;$a=[Management.Automation.Language.Parser]::ParseFile($Path,[ref]$t,[ref]$e)
 $f=@($a.FindAll({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq $Name},$true))
 if($e.Count -or $f.Count -ne 1){throw 'ONE_EXACT_BOUNDARY_FUNCTION_REQUIRED'}
 return $f[0].Extent.Text
}
$nativeText=Import-ExactFunction (Join-Path $PSScriptRoot 'probe-wsl.ps1') 'Native'
. ([scriptblock]::Create($nativeText))
. ([scriptblock]::Create((Import-ExactFunction (Join-Path $PSScriptRoot 'probe-windows-bridge.ps1') 'CleanNative')))
$base=Join-Path $env:RUNNER_TEMP ('session-owner-control-'+$env:PROBE_NONCE)
$owner=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
New-OwnedPrivateDirectory $base $owner
$grandchildSource=@'
param([string]$Root,[string]$Nonce)
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
if($Nonce -cne $env:PROBE_NONCE -or $Root -cnotmatch '\\session-owner-control-[0-9a-f]{32}\\case-[01]\z'){throw 'SYNTHETIC_GRANDCHILD_CONTEXT_REQUIRED'}
$stop=Join-Path $Root 'stop.txt';$ready=Join-Path $Root 'grandchild-ready.txt'
$file=[IO.File]::Open($ready,'CreateNew','Write','None');try{$bytes=[Text.Encoding]::ASCII.GetBytes($Nonce);$file.Write($bytes,0,$bytes.Length);$file.Flush($true)}finally{$file.Dispose()}
$clock=[Diagnostics.Stopwatch]::StartNew()
while($clock.Elapsed.TotalSeconds -lt 45){
 if(Test-Path -LiteralPath $stop){if([IO.File]::ReadAllText($stop) -cne $Nonce){exit 19};exit 0}
 Start-Sleep -Milliseconds 100
}
exit 20
'@
$childSource=@'
param([string]$Root,[string]$Nonce,[string]$Mode)
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
if($Nonce -cne $env:PROBE_NONCE -or $Root -cnotmatch '\\session-owner-control-[0-9a-f]{32}\\case-[01]\z' -or $Mode -cnotin @('timeout-stall','early-failure')){throw 'SYNTHETIC_CHILD_CONTEXT_REQUIRED'}
$info=[Diagnostics.ProcessStartInfo]::new();$info.FileName=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$info.Arguments='-NoProfile -NonInteractive -ExecutionPolicy Bypass -File '+(Join-Path $Root 'grandchild.ps1')+' -Root '+$Root+' -Nonce '+$Nonce
$info.UseShellExecute=$false;$info.CreateNoWindow=$true;$info.WindowStyle='Hidden';$info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true
# The grandchild never writes stdout/stderr. Its own bounded stop protocol
# remains usable if this fixture parent exits without draining those pipes.
$p=[Diagnostics.Process]::Start($info);$handle=$p.Handle
if($null -eq $handle -or $handle -eq [IntPtr]::Zero){throw 'SYNTHETIC_HELD_GRANDCHILD_HANDLE_REQUIRED'}
$clock=[Diagnostics.Stopwatch]::StartNew();$ready=Join-Path $Root 'grandchild-ready.txt'
while(-not (Test-Path -LiteralPath $ready) -and $clock.Elapsed.TotalSeconds -lt 4){Start-Sleep -Milliseconds 50}
if(-not (Test-Path -LiteralPath $ready) -or [IO.File]::ReadAllText($ready) -cne $Nonce){throw 'SYNTHETIC_GRANDCHILD_NOT_READY'}
$descriptor=@{nonce=$Nonce;id=$p.Id;createdUTC=$p.StartTime.ToUniversalTime().ToString('o')}
$bytes=[Text.UTF8Encoding]::new($false).GetBytes(($descriptor|ConvertTo-Json -Compress));$file=[IO.File]::Open((Join-Path $Root 'grandchild.json'),'CreateNew','Write','None');try{$file.Write($bytes,0,$bytes.Length);$file.Flush($true)}finally{$file.Dispose()}
if($Mode -ceq 'early-failure'){exit 17}
$clock=[Diagnostics.Stopwatch]::StartNew()
while($clock.Elapsed.TotalSeconds -lt 45){Start-Sleep -Milliseconds 100}
exit 18
'@
$rows=@();$ownerClock=[Diagnostics.Stopwatch]::StartNew()
function Remaining-OwnerWait([int]$Maximum){return [int][math]::Max(0,[math]::Min($Maximum,90000-$ownerClock.ElapsedMilliseconds))}
for($case=0;$case -lt 2;$case++){
 if((Remaining-OwnerWait 90000) -lt 40000){throw 'SYNTHETIC_OWNER_AGGREGATE_BUDGET_EXHAUSTED'}
 $root=Join-Path $base ('case-'+$case);New-OwnedPrivateDirectory $root $owner
 $raw=Join-Path $root 'raw';$out=Join-Path $root 'out';[void][IO.Directory]::CreateDirectory($raw);[void][IO.Directory]::CreateDirectory($out)
 foreach($fixture in @(@{name='child.ps1';text=$childSource},@{name='grandchild.ps1';text=$grandchildSource})){
  $bytes=[Text.UTF8Encoding]::new($false).GetBytes($fixture.text);$file=[IO.File]::Open((Join-Path $root $fixture.name),'CreateNew','Write','None');try{$file.Write($bytes,0,$bytes.Length);$file.Flush($true)}finally{$file.Dispose()}
 }
 $expectedNonce=$env:PROBE_NONCE;$mode=if($case -eq 0){'timeout-stall'}else{'early-failure'};$descendant=$null;$held=$false;$stopped=$false
 $stop=Join-Path $root 'stop.txt';$descriptorPath=Join-Path $root 'grandchild.json';$elapsed=[Diagnostics.Stopwatch]::StartNew();$caseFailure=$null;$cleanupFaults=@();$row=$null
 try{
  $file=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
  $result=Native $file @('-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',(Join-Path $root 'child.ps1'),'-Root',$root,'-Nonce',$expectedNonce,'-Mode',$mode) 5 'synthetic-owner'
  if(CleanNative $result){throw 'FAILED_PARENT_FALSELY_ACCEPTED'}
  if(-not $result.closed -or $null -ne $result.nativeError -or $null -ne $result.cleanupError -or $result.stdout -cne '' -or $result.stderr -cne '' -or $elapsed.Elapsed.TotalSeconds -gt 25){throw 'BOUNDED_SYNTHETIC_PARENT_RESULT_REQUIRED'}
  if($case -eq 0){if(-not $result.timedOut -or -not $result.onlyOwnStartedRootStopped){throw 'PARENT_TIMEOUT_NOT_OBSERVED'}}
  elseif($result.timedOut -or $result.onlyOwnStartedRootStopped -or $result.exitCode -ne 17){throw 'EARLY_PARENT_FAILURE_NOT_OBSERVED'}
  $item=Get-Item -LiteralPath $descriptorPath -Force
  if($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $item.Length -gt 4096){throw 'BOUNDED_OWNED_DESCRIPTOR_REQUIRED'}
  $descriptor=[IO.File]::ReadAllText($descriptorPath)|ConvertFrom-Json
  if($descriptor.nonce -cne $expectedNonce -or ($descriptor.id -isnot [int] -and $descriptor.id -isnot [long]) -or $descriptor.id -lt 1 -or $descriptor.id -eq $result.pid){throw 'EXACT_DISTINCT_OWNED_GRANDCHILD_REQUIRED'}
  $descendant=[Diagnostics.Process]::GetProcessById($descriptor.id);$handle=$descendant.Handle
  if($null -eq $handle -or $handle -eq [IntPtr]::Zero -or $descendant.StartTime.ToUniversalTime().Ticks -ne ([datetime]$descriptor.createdUTC).ToUniversalTime().Ticks){throw 'EXACT_HELD_GRANDCHILD_GENERATION_REQUIRED'}
  $held=$true
  if($descendant.HasExited){throw 'PARENT_EXIT_DOES_NOT_PROVE_EXPECTED_LIVE_DESCENDANT'}
  $bytes=[Text.Encoding]::ASCII.GetBytes($expectedNonce);$file=[IO.File]::Open($stop,'CreateNew','Write','None');try{$file.Write($bytes,0,$bytes.Length);$file.Flush($true)}finally{$file.Dispose()}
  $wait=Remaining-OwnerWait 15000
  if($wait -eq 0 -or -not $descendant.WaitForExit($wait) -or $descendant.ExitCode -ne 0){throw 'INDEPENDENT_SYNTHETIC_CHILD_STOP_UNPROVED'}
  $stopped=$true
  $row=@{mode=$mode;failedParentRefused=$true;parentClosed=$true;knownDescendantOutlivedParent=$true;independentStopNatural0=$true}
 }catch{$caseFailure=$_}
 finally{
  # A fixed nonce-owned file asks only these bounded fixture children to stop.
  # No PID-based termination or global process enumeration is performed.
  try{
   if(-not (Test-Path -LiteralPath $stop)){$bytes=[Text.Encoding]::ASCII.GetBytes($expectedNonce);$file=[IO.File]::Open($stop,'CreateNew','Write','None');try{$file.Write($bytes,0,$bytes.Length);$file.Flush($true)}finally{$file.Dispose()}}
   else{$item=Get-Item -LiteralPath $stop -Force;if($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $item.Length -ne 32 -or [IO.File]::ReadAllText($stop) -cne $expectedNonce){throw 'EXACT_SYNTHETIC_STOP_REQUIRED'}}
  }catch{$cleanupFaults+=@('SYNTHETIC_STOP_PUBLICATION_UNKNOWN')}
  if($null -ne $descendant){
   try{
    if(-not $held){throw 'UNVERIFIED_DESCENDANT_NOT_WAITED'}
    if(-not $stopped){$wait=Remaining-OwnerWait 15000;if($wait -eq 0 -or -not $descendant.WaitForExit($wait) -or $descendant.ExitCode -ne 0){throw 'OWNED_FIXTURE_CHILD_CLOSURE_UNKNOWN'}}
   }catch{$cleanupFaults+=@('SYNTHETIC_CHILD_CLOSURE_UNKNOWN')}
   try{$descendant.Dispose()}catch{$cleanupFaults+=@('SYNTHETIC_CHILD_HANDLE_DISPOSE_UNKNOWN')}
  }
 }
 if($null -ne $caseFailure){throw $caseFailure}
 if($cleanupFaults.Count -ne 0){throw ('SYNTHETIC_FIXTURE_CLEANUP_UNACCEPTED:'+($cleanupFaults -join ';'))}
 if($null -eq $row){throw 'SYNTHETIC_CASE_SUCCESS_UNPROVED'};$rows+=@($row)
}
if($ownerClock.Elapsed.TotalSeconds -ge 90){throw 'SYNTHETIC_OWNER_AGGREGATE_DEADLINE'}
@{Scope='GENERIC_PARENT_BOUND_AND_INDEPENDENT_CHILD_STOP_ONLY';Cases=$rows.Count;AllPass=$true;KnownParentRootsClosed=2;KnownGrandchildrenNatural0=2;DirectDescendantContainmentClaimed=$false;GlobalProcessCensusClaimed=$false;RealPrivateSession=$false;RealCredentials=0;NetworkCalls=0;CanonicalAccepted=$false;ProviderRetirement='inference only; fixture files retained on owned temporary VM'}|ConvertTo-Json -Compress
}catch{Write-Output 'GENERIC_PARENT_BOUNDARY_WITNESS_FAILED';exit 1}
