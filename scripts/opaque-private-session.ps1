# LOCAL DRAFT ONLY: not in the public payload and never invoked with a real packet.
# Exact target-job authority, VM lifecycle and lease acquire/close/controller
# must be supplied by a separate reviewed owner before any private execution.
. (Join-Path $PSScriptRoot 'private-directory-helper.ps1')
function Read-OpaqueRunnerPacket([string]$Encoded,[string]$Nonce,[string]$ExpectedPublicHead){
 try{
  if($Nonce -cnotmatch '\A[0-9a-f]{32}\z' -or $ExpectedPublicHead -cnotmatch '\A[0-9a-f]{40}\z' -or $Encoded.Length -gt 49152 -or $Encoded -cnotmatch '\A[A-Za-z0-9+/=]+\z'){throw 'INVALID'}
  $packet=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($Encoded))|ConvertFrom-Json
  $keys=@('schema','nonce','runnerName','runnerId','repositoryUrl','publicSourceHead','expectedJob','expectedLabels','encodedJitConfig')
  if($packet -isnot [pscustomobject] -or (@($packet.PSObject.Properties.Name|Sort-Object) -join '|') -cne (@($keys|Sort-Object) -join '|')){throw 'INVALID'}
  if(($packet.schema -isnot [int] -and $packet.schema -isnot [long]) -or $packet.schema -ne 2 -or ($packet.runnerId -isnot [int] -and $packet.runnerId -isnot [long]) -or $packet.runnerId -lt 1){throw 'INVALID'}
  foreach($key in @('nonce','runnerName','repositoryUrl','publicSourceHead','encodedJitConfig')){if($packet.$key -isnot [string]){throw 'INVALID'}}
  if($packet.nonce -cne $Nonce -or $packet.runnerName -cne ('OWNED-WINDOWS-'+$Nonce.Substring(0,8)) -or $packet.repositoryUrl -cnotmatch '\Ahttps://github\.com/RinisRp/[A-Za-z0-9_.-]{1,100}\z' -or $packet.publicSourceHead -cne $ExpectedPublicHead -or $packet.encodedJitConfig -cnotmatch '\A[A-Za-z0-9+/=]+\z'){throw 'INVALID'}
  $job=$packet.expectedJob;$jobKeys=@('runId','jobId','attempt','headSHA','mergeSHA','workflowPath')
  if($job -isnot [pscustomobject] -or (@($job.PSObject.Properties.Name|Sort-Object) -join '|') -cne (@($jobKeys|Sort-Object) -join '|')){throw 'INVALID'}
  foreach($key in @('runId','jobId','attempt')){if(($job.$key -isnot [int] -and $job.$key -isnot [long]) -or $job.$key -lt 1){throw 'INVALID'}}
  foreach($key in @('headSHA','mergeSHA')){if($job.$key -isnot [string] -or $job.$key -cnotmatch '\A[0-9a-f]{40}\z'){throw 'INVALID'}}
  if($job.workflowPath -isnot [string] -or $job.workflowPath -cnotmatch '\A\.github/workflows/[A-Za-z0-9_-][A-Za-z0-9_.-]{0,99}\.ya?ml\z'){throw 'INVALID'}
  if($packet.expectedLabels -isnot [array] -or $packet.expectedLabels.Count -lt 1 -or $packet.expectedLabels.Count -gt 100){throw 'INVALID'}
  $labels=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  foreach($label in $packet.expectedLabels){if($label -isnot [string] -or $label -cnotmatch '\A[A-Za-z0-9_.-]{1,100}\z' -or -not $labels.Add($label)){throw 'INVALID'}}
  $jit=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($packet.encodedJitConfig))|ConvertFrom-Json
  $jitKeys=@('.runner','.credentials','.credentials_rsaparams')
  if($jit -isnot [pscustomobject] -or (@($jit.PSObject.Properties.Name|Sort-Object) -join '|') -cne (@($jitKeys|Sort-Object) -join '|')){throw 'INVALID'}
  foreach($key in $jitKeys){if($jit.$key -isnot [string] -or $jit.$key -cnotmatch '\A[A-Za-z0-9+/=]+\z'){throw 'INVALID'}}
  $config=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($jit.'.runner'))|ConvertFrom-Json
  if($config -isnot [pscustomobject] -or $config.agentName -isnot [string] -or $config.agentName -cne $packet.runnerName -or $config.gitHubUrl -isnot [string] -or $config.gitHubUrl -cne $packet.repositoryUrl -or $config.ephemeral -isnot [bool] -or $config.ephemeral -cne $true -or $config.workFolder -isnot [string] -or $config.workFolder -cne '_work' -or ($config.agentId -isnot [int] -and $config.agentId -isnot [long]) -or $config.agentId -ne $packet.runnerId){throw 'INVALID'}
  return [pscustomobject]@{Nonce=$Nonce;RunnerName=$packet.runnerName;RepositoryUrl=$packet.repositoryUrl;AgentId=$config.agentId;EncodedJitConfig=$packet.encodedJitConfig;ExpectedJob=$job;ExpectedLabels=$packet.expectedLabels;PublicSourceHead=$ExpectedPublicHead}
 }catch{throw [InvalidOperationException]::new('OPAQUE_RUNNER_PACKET_INVALID')}
}
function Invoke-OpaquePrivateRunnerSession([string]$Nonce,[string]$Endpoint,[string]$RunnerArchive,[string]$LeaseRoot){
 $ErrorActionPreference='Stop';Set-StrictMode -Version Latest
 $encoded=[Environment]::GetEnvironmentVariable('OWNED_RUNNER_PACKET','Process')
 [Environment]::SetEnvironmentVariable('OWNED_RUNNER_PACKET',[System.Management.Automation.Language.NullString]::Value,'Process')
 $packet=$null;$start=$null;$process=$null;$held=$false;$privateRoot=$null;$privateRootOwned=$false;$receiptWritten=$false;$channels=@()
 $receipt=[ordered]@{Schema=1;Scope='PRIVATE_AGENT_SESSION_ONLY_NOT_JOB_ACCEPTANCE';Nonce=$Nonce;RunnerName=$null;AgentId=$null;RepositoryUrl=$null;PID=$null;CreatedUTC=$null;ListeningObserved=$false;AfterAgentFreeMiB=$null;NaturalExit=$false;ExitCode=$null;Forced=$false;Closed=$false;AllStreamsEOF=$false;CredentialFilesAbsent=$false;PrivateLogsRemain=$true;Failure=$null;Faults=@();DispositionBasis='official ephemeral exit and provider contract; exact private terminal job evidence required';DirectDescendantCensus=$false;MemoryErasureClaimed=$false;CanonicalAccepted=$false}
 function SessionFault([string]$Code){if($null -eq $receipt.Failure){$receipt.Failure=$Code};$receipt.Faults+=@($Code)}
 try{
  if($env:GITHUB_ACTIONS -cne 'true' -or $env:RUNNER_ENVIRONMENT -cne 'github-hosted' -or $env:GITHUB_REPOSITORY -cne 'RinisRp/hosted-wsl-capability-20261113-1e8014' -or $env:GITHUB_ACTOR -cne 'RinisRp' -or $env:GITHUB_REF -cne 'refs/heads/codex/wsl-npipe-6f3465' -or $env:ImageOS -cne 'win25-vs2026' -or $env:RUNNER_ARCH -cne 'X64' -or $env:PROBE_NONCE -cne $Nonce){throw 'EXACT_OWNED_SESSION_CONTEXT_REQUIRED'}
  if($Nonce -cnotmatch '\A[0-9a-f]{32}\z' -or $Endpoint -cne ('npipe:////./pipe/hosted_wsl_'+$Nonce) -or $LeaseRoot -cne (Join-Path $env:RUNNER_TEMP ('hosted-wsl-'+$Nonce))){throw 'EXACT_OWNED_SESSION_LEASE_REQUIRED'}
  $packet=Read-OpaqueRunnerPacket $encoded $Nonce $env:GITHUB_SHA;$encoded=$null
  $receipt.RunnerName=$packet.RunnerName;$receipt.AgentId=$packet.AgentId;$receipt.RepositoryUrl=$packet.RepositoryUrl;$receipt['ExpectedJob']=$packet.ExpectedJob;$receipt['ExpectedLabels']=$packet.ExpectedLabels;$receipt['PublicSourceHead']=$packet.PublicSourceHead
  if((Get-FileHash -LiteralPath $RunnerArchive).Hash.ToLowerInvariant() -cne 'a1f17aa987fc8158bc7521d284912267a0d01b7c2c4684b33c86783b5e8221cc'){throw 'OFFICIAL_RUNNER_ARCHIVE_REQUIRED'}
  $privateRoot=Join-Path $env:RUNNER_TEMP ('private-agent-'+$Nonce)
  $owner=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
  New-OwnedPrivateDirectory $privateRoot $owner
  $privateRootOwned=$true
  $agent=Join-Path $privateRoot 'agent';[void][IO.Directory]::CreateDirectory($agent)
  Add-Type -AssemblyName System.IO.Compression.FileSystem
  [IO.Compression.ZipFile]::ExtractToDirectory($RunnerArchive,$agent)
  $listener=Join-Path $agent 'bin\Runner.Listener.exe'
  if(-not (Test-Path -LiteralPath $listener -PathType Leaf)){throw 'OFFICIAL_LISTENER_MISSING'}
  $listenerHash=(Get-FileHash -LiteralPath $listener).Hash.ToLowerInvariant()
  $config=Join-Path $privateRoot 'empty-docker-config';[void][IO.Directory]::CreateDirectory($config)
  $start=[Diagnostics.ProcessStartInfo]::new();$start.FileName=$listener;$start.Arguments='run';$start.WorkingDirectory=$agent;$start.UseShellExecute=$false;$start.CreateNoWindow=$true;$start.WindowStyle='Hidden';$start.RedirectStandardOutput=$true;$start.RedirectStandardError=$true
  $start.EnvironmentVariables.Clear()
  foreach($key in @('SystemRoot','WINDIR','COMSPEC','SystemDrive','PATH','PATHEXT','TEMP','TMP','USERPROFILE','APPDATA','LOCALAPPDATA','ProgramFiles','ProgramFiles(x86)','ProgramData','CommonProgramFiles','CommonProgramFiles(x86)','NUMBER_OF_PROCESSORS','PROCESSOR_ARCHITECTURE','USERNAME','USERDOMAIN','HOMEDRIVE','HOMEPATH')){
   $value=[Environment]::GetEnvironmentVariable($key,'Process');if(-not [string]::IsNullOrEmpty($value)){$start.EnvironmentVariables[$key]=$value}
  }
  $start.EnvironmentVariables['DOCKER_HOST']=$Endpoint;$start.EnvironmentVariables['DOCKER_CONFIG']=$config
  $start.EnvironmentVariables['ACTIONS_RUNNER_INPUT_JITCONFIG']=$packet.EncodedJitConfig
  foreach($name in @('stdout','stderr')){
   $file=[IO.FileStream]::new((Join-Path $privateRoot ('listener.'+$name+'.log')),'CreateNew','Write','Read',1,$true)
   $channels+=@([pscustomobject]@{Name=$name;File=$file;Stream=$null;Buffer=(New-Object byte[] 16384);Pending=$null;Bytes=0L;EOF=$false;Closed=$false})
  }
  $process=[Diagnostics.Process]::Start($start)
  $handle=$process.Handle;if($null -eq $handle -or $handle -eq [IntPtr]::Zero){throw 'HELD_PRIVATE_SESSION_HANDLE_REQUIRED'};$held=$true
  $receipt.PID=$process.Id;$receipt.CreatedUTC=$process.StartTime.ToUniversalTime().ToString('o')
  $channels[0].Stream=$process.StandardOutput.BaseStream;$channels[1].Stream=$process.StandardError.BaseStream
  foreach($channel in $channels){$channel.Pending=$channel.Stream.ReadAsync($channel.Buffer,0,$channel.Buffer.Length)}
  $start.EnvironmentVariables['ACTIONS_RUNNER_INPUT_JITCONFIG']='';$packet.EncodedJitConfig='';$packet=$null
  $clock=[Diagnostics.Stopwatch]::StartNew();$terminalClock=$null;$startup=[Text.StringBuilder]::new()
  while($true){
   if($clock.Elapsed.TotalMinutes -ge 100){throw 'PRIVATE_SESSION_PARENT_DEADLINE'}
   if(-not $receipt.ListeningObserved -and $clock.Elapsed.TotalSeconds -ge 90){throw 'PRIVATE_SESSION_CONNECTION_DEADLINE'}
   foreach($channel in $channels){
    if(-not $channel.EOF -and $channel.Pending.IsCompleted){
     $count=$channel.Pending.GetAwaiter().GetResult()
     if($count -eq 0){$channel.EOF=$true}
     else{
      if($channel.Bytes+$count -gt 8388608){throw 'PRIVATE_SESSION_HARD_LOG_BOUND'}
      $channel.File.Write($channel.Buffer,0,$count);$channel.Bytes+=$count
      if($channel.Name -ceq 'stdout' -and -not $receipt.ListeningObserved){
       if($startup.Length+$count -gt 131072){throw 'PRIVATE_SESSION_STARTUP_BUFFER_BOUND'}
       [void]$startup.Append([Text.Encoding]::UTF8.GetString($channel.Buffer,0,$count))
       if($startup.ToString().Contains('Listening for Jobs')){
        $receipt.ListeningObserved=$true;$startup.Clear()|Out-Null
        $receipt.AfterAgentFreeMiB=[math]::Floor((Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory/1024)
        if($receipt.AfterAgentFreeMiB -lt 6144){throw 'PRIVATE_SESSION_UNCHANGED_6144_REQUIRED'}
       }
      }
      $channel.Pending=$channel.Stream.ReadAsync($channel.Buffer,0,$channel.Buffer.Length)
     }
    }
   }
   if($process.WaitForExit(100)){
    $process.WaitForExit();$receipt.Closed=$process.HasExited;$receipt.ExitCode=$process.ExitCode;$receipt.NaturalExit=($process.ExitCode -eq 0)
    if(@($channels|Where-Object {-not $_.EOF}).Count -eq 0){$receipt.AllStreamsEOF=$true;break}
    if($null -eq $terminalClock){$terminalClock=[Diagnostics.Stopwatch]::StartNew()}
    if($terminalClock.Elapsed.TotalSeconds -ge 15){throw 'PRIVATE_SESSION_TERMINAL_PIPE_EOF_UNKNOWN'}
   }
  }
  if(-not $receipt.ListeningObserved -or -not $receipt.NaturalExit){throw 'PRIVATE_SESSION_NATURAL_EXIT_REQUIRED'}
 }catch{SessionFault 'OPAQUE_PRIVATE_SESSION_FAILED'}
 finally{
  if($null -ne $start){try{$start.EnvironmentVariables.Clear()}catch{SessionFault 'PRIVATE_CHILD_ENV_CLEAR_FAILED'}}
  $encoded=$null;if($null -ne $packet){$packet.EncodedJitConfig='';$packet=$null}
  if($null -ne $process){
   try{
    if(-not $process.HasExited){
     if(-not $held){throw 'NO_HELD_HANDLE_NO_TERMINATION'}
     $receipt.Forced=$true;SessionFault 'PRIVATE_OWN_ROOT_FORCED'
     $process.Kill();if(-not $process.WaitForExit(15000)){throw 'PRIVATE_ROOT_CLOSURE_UNKNOWN'}
    }
    $receipt.Closed=$process.HasExited
    if($null -eq $receipt.ExitCode){$receipt.ExitCode=$process.ExitCode}
   }catch{SessionFault 'PRIVATE_OWN_ROOT_CLOSURE_FAILED'}
  }
  foreach($channel in $channels){
   if($null -ne $channel.Stream){try{$channel.Stream.Dispose();$channel.Closed=$true}catch{SessionFault 'PRIVATE_READ_STREAM_CLOSE_FAILED'}}
  }
  foreach($channel in $channels){
   if($null -ne $channel.Pending){try{if(-not $channel.Pending.Wait(15000)){throw 'PENDING_READ_UNKNOWN'}}catch{if(-not $channel.EOF){SessionFault 'PRIVATE_PENDING_READ_TERMINAL_UNKNOWN'}}}
  }
  foreach($channel in $channels){
   try{$channel.File.Flush($true)}catch{SessionFault 'PRIVATE_LOG_FLUSH_FAILED'}
   try{$channel.File.Dispose()}catch{SessionFault 'PRIVATE_LOG_DISPOSE_FAILED'}
  }
  if($null -ne $process){try{$process.Dispose()}catch{SessionFault 'PRIVATE_PROCESS_DISPOSE_FAILED'}}
  if($privateRootOwned){
   try{
    if($receipt.NaturalExit -and (Get-FileHash -LiteralPath (Join-Path $privateRoot 'agent\bin\Runner.Listener.exe')).Hash.ToLowerInvariant() -cne $listenerHash){SessionFault 'PRIVATE_LISTENER_BINARY_CHANGED'}
    $receipt.CredentialFilesAbsent=@(@('.runner','.credentials','.credentials_rsaparams')|Where-Object {Test-Path -LiteralPath (Join-Path $privateRoot ('agent\'+$_))}).Count -eq 0
    if(-not $receipt.CredentialFilesAbsent){SessionFault 'PRIVATE_CONFIG_OR_CREDENTIAL_FILES_REMAIN'}
    $receipt['LogBytes']=@($channels|ForEach-Object {@{Name=$_.Name;Bytes=$_.Bytes;EOF=$_.EOF;StreamClosed=$_.Closed}})
    $data=[Text.UTF8Encoding]::new($false).GetBytes(($receipt|ConvertTo-Json -Depth 8))
    if($data.Length -gt 131072){throw 'PRIVATE_RECEIPT_BOUND'}
    $file=[IO.File]::Open((Join-Path $privateRoot 'private-session-receipt.json'),'CreateNew','Write','None')
    try{$file.Write($data,0,$data.Length);$file.Flush($true);$receiptWritten=$true}finally{try{$file.Dispose()}catch{$receiptWritten=$false;SessionFault 'PRIVATE_RECEIPT_DISPOSE_FAILED'}}
   }catch{SessionFault 'OPAQUE_PRIVATE_RECEIPT_FAILED'}
  }
 }
 if($null -ne $receipt.Failure -or -not $receipt.Closed -or $receipt.Forced -or -not $receipt.NaturalExit -or -not $receipt.AllStreamsEOF -or -not $receipt.CredentialFilesAbsent -or -not $receiptWritten){throw [InvalidOperationException]::new('OPAQUE_PRIVATE_SESSION_NOT_ACCEPTED')}
 # The caller must independently accept exact private-job terminal/cleanup
 # evidence. Provider retirement is inference, not a direct census or erasure.
 return [pscustomobject]@{Scope='HOST_EXIT_IS_NOT_PROJECT_JOB_ACCEPTANCE';Finished=$true;NaturalExit=$true;PrivateReceiptStored=$true;CanonicalAccepted=$false}
}
