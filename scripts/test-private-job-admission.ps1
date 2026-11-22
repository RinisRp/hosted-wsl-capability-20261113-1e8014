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
 foreach($name in $context.Keys){$start.EnvironmentVariables[$name]=$context[$name]};$start.EnvironmentVariables['GITHUB_ENV']=$envFile
 switch($mode){'wrong-run'{$start.EnvironmentVariables['GITHUB_RUN_ID']='12'} 'wrong-merge'{$start.EnvironmentVariables['GITHUB_SHA']='d'*40} 'wrong-jobkey'{$start.EnvironmentVariables['GITHUB_JOB']='foreign_job'} 'wrong-runner'{$start.EnvironmentVariables['RUNNER_NAME']='foreign'} 'wrong-workflow'{$start.EnvironmentVariables['GITHUB_WORKFLOW_REF']='foreign'} 'ignored-selector'{$start.EnvironmentVariables['OWNED_PRIVATE_JOB_GUARD']='C:\must-not-be-used\expected.json'}}
 $p=$null
 try{
  $p=[Diagnostics.Process]::Start($start);$handle=$p.Handle;$processCount++
  if($handle -eq [IntPtr]::Zero -or -not $p.WaitForExit(10000)){throw 'OWNED_HOOK_FIXTURE_DEADLINE'}
  $stdout=$p.StandardOutput.ReadToEnd();$stderr=$p.StandardError.ReadToEnd();$allowed=$mode -cin @('correct','ignored-selector')
  if($allowed){
   $expected='DOCKER_HOST=npipe:////./pipe/hosted_wsl_'+$descriptor.Nonce+[Environment]::NewLine+'DOCKER_CONFIG='+$config+[Environment]::NewLine
   Assert ($p.ExitCode -eq 0 -and $stdout.Trim() -ceq 'OWNED_PRIVATE_JOB_ADMISSION_OK' -and $stderr.Length -eq 0 -and [IO.File]::ReadAllText($envFile) -ceq $expected) ('actual-hook-'+$mode)
  }else{Assert ($p.ExitCode -ne 0 -and $stdout.Trim() -ceq 'OWNED_PRIVATE_JOB_ADMISSION_REFUSED' -and $stderr.Length -eq 0 -and [IO.File]::ReadAllText($envFile) -ceq $before) ('rejection-never-writes-env-'+$mode)}
  $passed++
 }finally{if($null -ne $p){if(-not $p.HasExited){$p.Kill();[void]$p.WaitForExit(5000)};$p.StandardOutput.Dispose();$p.StandardError.Dispose();$p.Dispose()}}
}
[pscustomobject]@{Scope='SYNTHETIC_PRIVATE_ADMISSION_CORE_AND_REAL_HOOK_CONTROLS';Passed=$passed;OwnedHookProcesses=$processCount;PrivateJobStarted=$false;CanonicalAccepted=$false;FixtureRoot=$root}|ConvertTo-Json -Compress