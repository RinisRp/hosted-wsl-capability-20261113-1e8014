$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'private-job-admission-core.ps1')
$passed=0
function Assert($Value,[string]$Name){if(-not $Value){throw ('PRIVATE_ADMISSION_CONTROL_FAILED:'+ $Name)}}
function Clone($Data){return ($Data|ConvertTo-Json -Depth 8 -Compress|ConvertFrom-Json)}
$descriptor=[pscustomobject]@{Schema=1;Scope='PRIVATE_ONE_JOB_ADMISSION_ONLY';Nonce=('4'*32);Repository='RinisRp/synthetic-target';ExpectedJob=[pscustomobject]@{runId=11;jobId=22;attempt=1;headSHA=('b'*40);mergeSHA=('c'*40);workflowPath='.github/workflows/synthetic.yml';jobKey='synthetic_job'}}
$context=@{GITHUB_RUN_ID='11';GITHUB_RUN_ATTEMPT='1';GITHUB_REPOSITORY='RinisRp/synthetic-target';GITHUB_SHA=('c'*40);GITHUB_JOB='synthetic_job';RUNNER_NAME=('OWNED-WINDOWS-'+('4'*8));GITHUB_REF='refs/pull/1/merge';GITHUB_WORKFLOW_REF='RinisRp/synthetic-target/.github/workflows/synthetic.yml@refs/pull/1/merge'}
Assert-OwnedPrivateJobAdmission $descriptor $context;$passed++
foreach($name in @('GITHUB_RUN_ID','GITHUB_RUN_ATTEMPT','GITHUB_REPOSITORY','GITHUB_SHA','GITHUB_JOB','RUNNER_NAME','GITHUB_REF','GITHUB_WORKFLOW_REF')){
 foreach($mode in @('wrong','missing','array')){
  $copy=$context.Clone()
  switch($mode){'wrong'{$copy[$name]='wrong'} 'missing'{$copy.Remove($name)} 'array'{$copy[$name]=@($context[$name],$context[$name])}}
  $failed=$false;try{Assert-OwnedPrivateJobAdmission $descriptor $copy}catch{$failed=$true};Assert $failed ('context-'+$name+'-'+$mode);$passed++
 }
}
foreach($mode in @('run-string','jobkey-missing','jobkey-array','path-escape','foreign-owner','extra-field','job-array')){
 $d=Clone $descriptor
 switch($mode){'run-string'{$d.ExpectedJob.runId='11'} 'jobkey-missing'{$d.ExpectedJob.PSObject.Properties.Remove('jobKey')} 'jobkey-array'{$d.ExpectedJob.jobKey=@('a','b')} 'path-escape'{$d.ExpectedJob.workflowPath='.github/workflows/../../outside.yml'} 'foreign-owner'{$d.Repository='other/target'} 'extra-field'{$d|Add-Member NoteProperty Extra 'x'} 'job-array'{$d.ExpectedJob=@($d.ExpectedJob,$d.ExpectedJob)}}
 $failed=$false;try{Assert-OwnedPrivateJobAdmission $d $context}catch{$failed=$true};Assert $failed ('descriptor-'+$mode);$passed++
}
# The hook cannot observe REST jobId or PR headSHA. Those remain controller duties.
$d=Clone $descriptor;$d.ExpectedJob.jobId=23;$d.ExpectedJob.headSHA='d'*40
Assert-OwnedPrivateJobAdmission $d $context;$passed++
# These definitions are inlined in the test harness, not dot-sourced at runtime.
function New-OwnedFixtureDiagnostic([string]$Case){
 return [pscustomobject][ordered]@{Schema=1;Scope='SYNTHETIC_HOOK_FIXTURE_DIAGNOSTIC';Case=$Case;Stage='case-start';FailureStage=$null;ParentPID=$PID;ChildPID=0;ChildCreatedUTC=$null;ChildGenerationFileTime=0L;ChildStarted=$false;BuiltinPS5Modules=$true;WaitDrainBudgetMs=10000;CleanupBudgetMs=2000;WaitDrainElapsedMs=0L;CleanupElapsedMs=0L;ExitObserved=$false;StdoutArmed=$false;StderrArmed=$false;StdoutEOF=$false;StderrEOF=$false;StdoutChars=0;StderrChars=0;StdoutDisposed=$false;StderrDisposed=$false;ProcessDisposed=$false;DirectChildClosureVerified=$false;DescendantClosureProved=$false;KillRaceObserved=$false;PrimaryCode=$null;SecondaryCodes=@();CaseAccepted=$false}
}
function Write-OwnedFixtureDiagnostic($Diagnostic){
 $line=$Diagnostic|ConvertTo-Json -Depth 4 -Compress
 if($line.Length -gt 3072){throw 'OWNED_HOOK_FIXTURE_DIAGNOSTIC_BOUND'}
 [Console]::Out.WriteLine($line);[Console]::Out.Flush()
}
function Publish-OwnedFixtureDiagnostic($Diagnostic,$Primary,[scriptblock]$Write){
 $written=$false
 try{[void](& $Write $Diagnostic);$written=$true}catch{
  $Diagnostic.SecondaryCodes=@($Diagnostic.SecondaryCodes)+@('diagnostic-write-failed')
  if($null -eq $Primary){$Primary=$_;$Diagnostic.PrimaryCode='OWNED_HOOK_FIXTURE_DIAGNOSTIC_WRITE_FAILED';$Diagnostic.FailureStage='diagnostic'}
  else{try{$Primary.Exception.Data['OwnedFixtureDiagnosticWriteFailed']='diagnostic-write-failed'}catch{}}
 }
 return [pscustomobject]@{Primary=$Primary;Written=$written}
}
function Get-OwnedFixtureTick($State,[scriptblock]$Now){
 $values=@(& $Now)
 if($values.Count -ne 1 -or ($values[0] -isnot [int] -and $values[0] -isnot [long]) -or $values[0] -lt $State.LastTick -or $values[0] -lt 0){throw 'OWNED_HOOK_FIXTURE_CLOCK'}
 $State.LastTick=[long]$values[0];$State.Diagnostic.WaitDrainElapsedMs=$State.LastTick
 return $State.LastTick
}
function Invoke-OwnedFixtureWaitDrain($State,[scriptblock]$Now,[scriptblock]$Pump,[scriptblock]$Exited,[scriptblock]$WaitSlice){
 if(-not $State.Diagnostic.StdoutArmed -or -not $State.Diagnostic.StderrArmed){throw 'OWNED_HOOK_FIXTURE_CAPTURE_NOT_ARMED'}
 while($true){
  $tick=Get-OwnedFixtureTick $State $Now;if($tick -gt 10000){throw 'OWNED_HOOK_FIXTURE_DEADLINE'}
  & $Pump
  $values=@(& $Exited);if($values.Count -ne 1 -or $values[0] -isnot [bool]){throw 'OWNED_HOOK_FIXTURE_EXIT_STATE'}
  $State.Diagnostic.ExitObserved=$values[0];$State.Diagnostic.StdoutEOF=$State.Out.EOF;$State.Diagnostic.StderrEOF=$State.Err.EOF
  $tick=Get-OwnedFixtureTick $State $Now;if($tick -gt 10000){throw 'OWNED_HOOK_FIXTURE_DEADLINE'}
  if($values[0] -and $State.Out.EOF -and $State.Err.EOF){return}
  $State.Diagnostic.Stage=if($values[0]){'drain'}else{'wait'}
  $left=10000-$tick;if($left -le 0){throw 'OWNED_HOOK_FIXTURE_DEADLINE'}
  & $WaitSlice ([int][Math]::Min(20,$left))
 }
}
function New-OwnedFixtureStream($Reader,[string]$Name){
 return [pscustomobject]@{Reader=$Reader;Name=$Name;Buffer=[char[]]::new(512);Text=[Text.StringBuilder]::new();Task=$null;EOF=$false;Count=0}
}
function Read-OwnedFixtureStreams($State){
 foreach($stream in @($State.Out,$State.Err)){
  if($stream.EOF){continue}
  if($null -eq $stream.Task){throw 'OWNED_HOOK_FIXTURE_CAPTURE_NOT_ARMED'}
  if(-not $stream.Task.IsCompleted){continue}
  if($stream.Task.IsFaulted){$observed=$stream.Task.Exception;throw 'OWNED_HOOK_FIXTURE_STREAM_READ'}
  if($stream.Task.IsCanceled){throw 'OWNED_HOOK_FIXTURE_STREAM_READ'}
  $count=[int]$stream.Task.Result
  if($count -eq 0){$stream.EOF=$true;continue}
  if($count -lt 0 -or $count -gt 512 -or $stream.Count+$count -gt 4096){throw 'OWNED_HOOK_FIXTURE_STREAM_BOUND'}
  [void]$stream.Text.Append($stream.Buffer,0,$count);$stream.Count+=$count
  if([Text.Encoding]::UTF8.GetByteCount($stream.Text.ToString()) -gt 4096){throw 'OWNED_HOOK_FIXTURE_STREAM_BOUND'}
  if($stream.Name -ceq 'stdout'){$State.Diagnostic.StdoutChars=$stream.Count}else{$State.Diagnostic.StderrChars=$stream.Count}
  $stream.Task=$stream.Reader.ReadAsync($stream.Buffer,0,$stream.Buffer.Length)
 }
}
function Complete-OwnedFixtureCleanup($State,$Primary,$Actions,[scriptblock]$Now){
 $codes=[Collections.Generic.List[string]]::new();$exited=$false;$killFailed=$false
 try{$exited=[bool](& $Actions.ProbeExit)}catch{$codes.Add('exit-probe-failed')}
 if(-not $exited){
  try{& $Actions.Kill}catch{$killFailed=$true}
  try{$elapsed=[long](& $Now);$left=[int][Math]::Max(0,2000-$elapsed);if($left -gt 0){& $Actions.Wait $left}}catch{$codes.Add('cleanup-wait-failed')}
  try{$exited=[bool](& $Actions.ProbeExit)}catch{$codes.Add('final-exit-probe-failed')}
  if($killFailed){if($exited){$State.Diagnostic.KillRaceObserved=$true}else{$codes.Add('kill-failed')}}
 }
 # Each owned disposal is attempted even when every earlier operation failed.
 try{& $Actions.DisposeOut;$State.Diagnostic.StdoutDisposed=$true}catch{$codes.Add('stdout-dispose-failed')}
 try{& $Actions.DisposeErr;$State.Diagnostic.StderrDisposed=$true}catch{$codes.Add('stderr-dispose-failed')}
 try{& $Actions.DisposeProcess;$State.Diagnostic.ProcessDisposed=$true}catch{$codes.Add('process-dispose-failed')}
 try{$elapsed=[long](& $Now);if($elapsed -lt 0){throw 'CLOCK'};$State.Diagnostic.CleanupElapsedMs=$elapsed;if($elapsed -gt 2000){$codes.Add('cleanup-budget-exceeded')}}catch{$State.Diagnostic.CleanupElapsedMs=-1;$codes.Add('cleanup-clock-unavailable')}
 $closed=$State.Diagnostic.ChildStarted -and $exited -and $State.Diagnostic.StdoutDisposed -and $State.Diagnostic.StderrDisposed -and $State.Diagnostic.ProcessDisposed
 if(-not $closed){$codes.Add('direct-child-closure-unconfirmed')}
 $State.Diagnostic.DirectChildClosureVerified=$closed;$State.Diagnostic.SecondaryCodes=@($codes)
 if($null -ne $Primary){if($codes.Count){try{$Primary.Exception.Data['OwnedFixtureCleanupCodes']=($codes -join ',')}catch{}}}
 elseif($codes.Count){$Primary=[Management.Automation.ErrorRecord]::new([InvalidOperationException]::new('OWNED_HOOK_FIXTURE_CLEANUP_UNCONFIRMED'),'OWNED_HOOK_FIXTURE_CLEANUP_UNCONFIRMED',[Management.Automation.ErrorCategory]::OperationStopped,$null)}
 return [pscustomobject]@{Primary=$Primary;Codes=@($codes);Closed=$closed}
}
function Invoke-OwnedHookFixture {
 param($Start,[ValidateSet('correct','wrong-run','wrong-merge','wrong-jobkey','wrong-runner','wrong-workflow','bad-env-path','preexisting-env','ignored-selector')][string]$Case)
 $clock=[Diagnostics.Stopwatch]::StartNew();$diag=New-OwnedFixtureDiagnostic $Case
 $state=@{Diagnostic=$diag;LastTick=0L;Out=$null;Err=$null};$process=$null;$primary=$null;$stdout=$null;$stderr=$null;$exitCode=$null
 Write-OwnedFixtureDiagnostic $diag
 try{
  $image=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe';$modules=Join-Path ([IO.Path]::GetDirectoryName($image)) 'Modules'
  if(-not [StringComparer]::OrdinalIgnoreCase.Equals([IO.Path]::GetFullPath($Start.FileName),[IO.Path]::GetFullPath($image)) -or $Start.EnvironmentVariables['PSModulePath'] -cne $modules -or $Start.UseShellExecute -or -not $Start.RedirectStandardOutput -or -not $Start.RedirectStandardError){throw 'OWNED_HOOK_FIXTURE_START_CONTRACT'}
  $diag.Stage='start';$process=[Diagnostics.Process]::Start($Start);$heldHandle=$process.Handle
  if($heldHandle -eq [IntPtr]::Zero){throw 'OWNED_HOOK_FIXTURE_PROCESS_IDENTITY'}
  $diag.ChildStarted=$true;$diag.ChildPID=$process.Id;$created=$process.StartTime.ToUniversalTime();$diag.ChildCreatedUTC=$created.ToString('o');$diag.ChildGenerationFileTime=$created.ToFileTimeUtc()
  $state.Out=New-OwnedFixtureStream $process.StandardOutput 'stdout';$state.Err=New-OwnedFixtureStream $process.StandardError 'stderr'
  $state.Out.Task=$state.Out.Reader.ReadAsync($state.Out.Buffer,0,$state.Out.Buffer.Length);$diag.StdoutArmed=$true
  $state.Err.Task=$state.Err.Reader.ReadAsync($state.Err.Buffer,0,$state.Err.Buffer.Length);$diag.StderrArmed=$true;$diag.Stage='capture-armed'
  $now={$clock.ElapsedMilliseconds}.GetNewClosure();$pump={Read-OwnedFixtureStreams $state}.GetNewClosure();$exited={$process.HasExited}.GetNewClosure();$wait={param($ms)[void]$process.WaitForExit($ms)}.GetNewClosure()
  Invoke-OwnedFixtureWaitDrain $state $now $pump $exited $wait
  $stdout=$state.Out.Text.ToString();$stderr=$state.Err.Text.ToString();$exitCode=$process.ExitCode
 }catch{
  $primary=$_;$diag.FailureStage=$diag.Stage
  $known=@('OWNED_HOOK_FIXTURE_DEADLINE','OWNED_HOOK_FIXTURE_CLOCK','OWNED_HOOK_FIXTURE_EXIT_STATE','OWNED_HOOK_FIXTURE_STREAM_BOUND','OWNED_HOOK_FIXTURE_STREAM_READ','OWNED_HOOK_FIXTURE_CAPTURE_NOT_ARMED','OWNED_HOOK_FIXTURE_START_CONTRACT','OWNED_HOOK_FIXTURE_PROCESS_IDENTITY')
  $diag.PrimaryCode=if($_.Exception.Message -cin $known){$_.Exception.Message}else{'OWNED_HOOK_FIXTURE_RUNTIME_FAILURE'}
 }
 $cleanupClock=[Diagnostics.Stopwatch]::StartNew()
 $actions=@{
  ProbeExit={if($null -eq $process){return $false};return $process.HasExited}.GetNewClosure()
  Kill={if($null -ne $process){$process.Kill()}}.GetNewClosure()
  Wait={param($ms)if($null -ne $process){[void]$process.WaitForExit($ms)}}.GetNewClosure()
  DisposeOut={if($null -ne $state.Out){$state.Out.Reader.Dispose()}}.GetNewClosure()
  DisposeErr={if($null -ne $state.Err){$state.Err.Reader.Dispose()}}.GetNewClosure()
  DisposeProcess={if($null -ne $process){$process.Dispose()}}.GetNewClosure()
 }
 $verdict=Complete-OwnedFixtureCleanup $state $primary $actions {$cleanupClock.ElapsedMilliseconds}.GetNewClosure()
 $cleanupClock.Stop();$clock.Stop();$diag.Stage=if($verdict.Closed){'child-closed'}else{'cleanup-unconfirmed'}
 if($null -ne $verdict.Primary -and $null -eq $diag.PrimaryCode){$diag.PrimaryCode='OWNED_HOOK_FIXTURE_CLEANUP_UNCONFIRMED';$diag.FailureStage='cleanup'}
 $publication=Publish-OwnedFixtureDiagnostic $diag $verdict.Primary {param($d)Write-OwnedFixtureDiagnostic $d}
 if($null -ne $publication.Primary){throw $publication.Primary}
 return [pscustomobject]@{Stdout=$stdout;Stderr=$stderr;ExitCode=$exitCode;Diagnostic=$diag}
}

$root=Join-Path ([IO.Path]::GetTempPath()) ('private-admission-fixture-'+[Guid]::NewGuid().ToString('N'))
$guard=Join-Path $root 'job-admission';$config=Join-Path $root 'empty-docker-config';$commandDirectory=Join-Path $root 'agent\_work\_temp\_runner_file_commands'
foreach($dir in @($root,$guard,$config,$commandDirectory)){[void][IO.Directory]::CreateDirectory($dir)}
foreach($name in @('private-job-admission-core.ps1','owned-private-job-hook.ps1')){[IO.File]::WriteAllBytes((Join-Path $guard $name),[IO.File]::ReadAllBytes((Join-Path $PSScriptRoot $name)))}
[IO.File]::WriteAllText((Join-Path $guard 'expected-job.json'),($descriptor|ConvertTo-Json -Depth 6 -Compress),[Text.UTF8Encoding]::new($false))
$processCount=0
foreach($mode in @('correct','wrong-run','wrong-merge','wrong-jobkey','wrong-runner','wrong-workflow','bad-env-path','preexisting-env','ignored-selector')){
 $envFile=Join-Path $commandDirectory ('set_env_'+[Guid]::NewGuid().ToString())
 if($mode -ceq 'bad-env-path'){$envFile=Join-Path $root ('set_env_'+[Guid]::NewGuid().ToString())}
 $before=if($mode -ceq 'preexisting-env'){'KEEP-SYNTHETIC-SENTINEL'}else{''};[IO.File]::WriteAllText($envFile,$before,[Text.UTF8Encoding]::new($false))
 $start=[Diagnostics.ProcessStartInfo]::new();$start.FileName=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
 $hook=Join-Path $guard 'owned-private-job-hook.ps1';if($hook -match '[\s"&|<>]'){throw 'OWNED_FIXTURE_PATH_REQUIRED'}
 $start.Arguments='-NoProfile -NonInteractive -ExecutionPolicy Bypass -File '+$hook;$start.UseShellExecute=$false;$start.CreateNoWindow=$true;$start.WindowStyle='Hidden';$start.RedirectStandardOutput=$true;$start.RedirectStandardError=$true;$start.EnvironmentVariables.Clear()
 foreach($name in @('SystemRoot','WINDIR','COMSPEC','SystemDrive','PATH','PATHEXT','TEMP','TMP','USERPROFILE','APPDATA','LOCALAPPDATA')){$value=[Environment]::GetEnvironmentVariable($name,'Process');if($value){$start.EnvironmentVariables[$name]=$value}}
 $start.EnvironmentVariables['PSModulePath']=Join-Path ([IO.Path]::GetDirectoryName($start.FileName)) 'Modules'
 foreach($name in $context.Keys){$start.EnvironmentVariables[$name]=$context[$name]};$start.EnvironmentVariables['GITHUB_ENV']=$envFile
 switch($mode){'wrong-run'{$start.EnvironmentVariables['GITHUB_RUN_ID']='12'} 'wrong-merge'{$start.EnvironmentVariables['GITHUB_SHA']='d'*40} 'wrong-jobkey'{$start.EnvironmentVariables['GITHUB_JOB']='foreign_job'} 'wrong-runner'{$start.EnvironmentVariables['RUNNER_NAME']='foreign'} 'wrong-workflow'{$start.EnvironmentVariables['GITHUB_WORKFLOW_REF']='foreign'} 'ignored-selector'{$start.EnvironmentVariables['OWNED_PRIVATE_JOB_GUARD']='C:\must-not-be-used\expected.json'}}
 $result=Invoke-OwnedHookFixture $start $mode;$processCount++
 $stdout=$result.Stdout;$stderr=$result.Stderr;$allowed=$mode -cin @('correct','ignored-selector')
 try{
  if($allowed){
   $expected='DOCKER_HOST=npipe:////./pipe/hosted_wsl_'+$descriptor.Nonce+[Environment]::NewLine+'DOCKER_CONFIG='+$config+[Environment]::NewLine
   Assert ($result.ExitCode -eq 0 -and $stdout.Trim() -ceq 'OWNED_PRIVATE_JOB_ADMISSION_OK' -and $stderr.Length -eq 0 -and [IO.File]::ReadAllText($envFile) -ceq $expected) ('actual-hook-'+$mode)
  }else{Assert ($result.ExitCode -ne 0 -and $stdout.Trim() -ceq 'OWNED_PRIVATE_JOB_ADMISSION_REFUSED' -and $stderr.Length -eq 0 -and [IO.File]::ReadAllText($envFile) -ceq $before) ('rejection-never-writes-env-'+$mode)}
  $passed++;$result.Diagnostic.CaseAccepted=$true;$result.Diagnostic.Stage='case-accepted';Write-OwnedFixtureDiagnostic $result.Diagnostic
 }catch{$oraclePrimary=$_;$result.Diagnostic.CaseAccepted=$false;$result.Diagnostic.Stage='oracle-failed';$result.Diagnostic.PrimaryCode='OWNED_HOOK_FIXTURE_ORACLE';$publication=Publish-OwnedFixtureDiagnostic $result.Diagnostic $oraclePrimary {param($d)Write-OwnedFixtureDiagnostic $d};throw $publication.Primary}
}
[pscustomobject]@{Scope='SYNTHETIC_PRIVATE_ADMISSION_CORE_AND_REAL_HOOK_CONTROLS';Passed=$passed;OwnedHookProcesses=$processCount;PrivateJobStarted=$false;CanonicalAccepted=$false;FixtureRoot=$root}|ConvertTo-Json -Compress
