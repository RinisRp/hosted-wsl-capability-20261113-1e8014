# Generic generation and cross-step lifetime helpers. No agent/network starts
# on import. Callers bind the public context and preserve their own ACK hold.
function Get-OwnedSupervisorRoot($Context){
 [void](Get-GenericAckContextPayload $Context)
 if($env:RUNNER_TEMP -cnotmatch '\A[A-Z]:\\[A-Za-z0-9_\\-]+\z'){throw 'OWNED_SUPERVISOR_TEMP_REQUIRED'}
 return (Join-Path $env:RUNNER_TEMP ('owned-supervisor-'+$Context.Nonce))
}
function New-OwnedSupervisorContext($Context,$PublicKeyBytes,$Kind){
 if($Kind -isnot [string] -or $Kind -cnotin @('fixture','private') -or (Get-GenericAckKeyFingerprint $PublicKeyBytes) -cne $Context.KeyFingerprint){throw 'EXACT_SUPERVISOR_CONTEXT_REQUIRED'}
 $root=Get-OwnedSupervisorRoot $Context
 New-OwnedPrivateDirectory $root ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value)
 $data=[ordered]@{Schema=1;Kind=$Kind;Context=$Context;PublicKeyB64=[Convert]::ToBase64String($PublicKeyBytes)}
 $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($data|ConvertTo-Json -Depth 4 -Compress));if($bytes.Length -gt 4096){throw 'BOUNDED_PUBLIC_SUPERVISOR_CONTEXT_REQUIRED'}
 $path=Join-Path $root 'public-context.json';$f=[IO.File]::Open($path,'CreateNew','Write','None');try{$f.Write($bytes,0,$bytes.Length);$f.Flush($true)}finally{$f.Dispose()}
 if([Convert]::ToBase64String([IO.File]::ReadAllBytes($path)) -cne [Convert]::ToBase64String($bytes)){throw 'SUPERVISOR_CONTEXT_READBACK_FAILED'}
 return $root
}
function Read-OwnedSupervisorContext($Context,$Kind){
 $root=Get-OwnedSupervisorRoot $Context;$path=Join-Path $root 'public-context.json';$item=Get-Item -LiteralPath $path -Force
 if($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $item.Length -gt 4096){throw 'BOUNDED_OWNED_SUPERVISOR_CONTEXT_REQUIRED'}
 $data=[IO.File]::ReadAllText($path)|ConvertFrom-Json
 if($data -isnot [pscustomobject] -or (@($data.PSObject.Properties.Name|Sort-Object) -join '|') -cne 'Context|Kind|PublicKeyB64|Schema' -or ($data.Schema -isnot [int] -and $data.Schema -isnot [long]) -or $data.Schema -ne 1 -or $data.Kind -isnot [string] -or $data.Kind -cne $Kind -or $Kind -cnotin @('fixture','private') -or $data.PublicKeyB64 -isnot [string] -or $data.PublicKeyB64 -cnotmatch '\A[A-Za-z0-9+/]{516}\z'){throw 'EXACT_SUPERVISOR_PUBLIC_CONTEXT_REQUIRED'}
 $key=[Convert]::FromBase64String($data.PublicKeyB64)
 if((Get-GenericAckKeyFingerprint $key) -cne $Context.KeyFingerprint -or [Convert]::ToBase64String((Get-GenericAckContextPayload $data.Context)) -cne [Convert]::ToBase64String((Get-GenericAckContextPayload $Context))){throw 'SUPERVISOR_PUBLIC_CONTEXT_MISMATCH'}
 return [pscustomobject]@{Root=$root;Context=$data.Context;PublicKeyBytes=$key;Kind=$Kind}
}
function Start-OwnedDetachedSupervisor($Context,$Kind){
 try{
 $public=Read-OwnedSupervisorContext $Context $Kind;$root=$public.Root
 $name=if($Kind -ceq 'fixture'){'generic-supervisor-fixture-owner.ps1'}else{'opaque-private-supervisor-owner.ps1'}
 $scriptFile=Join-Path $PSScriptRoot $name;$scriptItem=Get-Item -LiteralPath $scriptFile -Force
 if($scriptItem.PSIsContainer -or ($scriptItem.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'REGULAR_REVIEWED_SUPERVISOR_REQUIRED'}
 $scriptHash=(Get-FileHash -LiteralPath $scriptFile).Hash.ToLowerInvariant()
 $exe=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe';$vector=@('-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',$scriptFile,'-Nonce',$Context.Nonce,'-LeaseRoot',$root)
 foreach($arg in $vector){if($arg -match '[\s"&|<>]'){throw 'FIXED_SUPERVISOR_VECTOR_REQUIRED'}}
 $saved=[ordered]@{};foreach($entry in [Environment]::GetEnvironmentVariables('Process').GetEnumerator()){$saved[[string]$entry.Key]=[string]$entry.Value}
 $allow=@('SystemRoot','WINDIR','COMSPEC','SystemDrive','PATH','PATHEXT','TEMP','TMP','USERPROFILE','APPDATA','LOCALAPPDATA','ProgramFiles','ProgramFiles(x86)','ProgramData','CommonProgramFiles','CommonProgramFiles(x86)','NUMBER_OF_PROCESSORS','PROCESSOR_ARCHITECTURE','USERNAME','USERDOMAIN','HOMEDRIVE','HOMEPATH','PSModulePath','GITHUB_ACTIONS','GITHUB_REPOSITORY','GITHUB_ACTOR','GITHUB_REF','GITHUB_SHA','GITHUB_RUN_ID','GITHUB_RUN_ATTEMPT','RUNNER_ENVIRONMENT','RUNNER_ARCH','RUNNER_TEMP','ImageOS','ImageVersion','PROBE_NONCE')
 if($Kind -ceq 'private'){if([string]::IsNullOrEmpty($env:OWNED_RUNNER_PACKET)){throw 'PRIVATE_PACKET_MISSING'};$allow+=@('OWNED_RUNNER_PACKET')}
 elseif(-not [string]::IsNullOrEmpty($env:OWNED_RUNNER_PACKET)){throw 'PRIVATE_PACKET_REFUSED_IN_FIXTURE'}
 # CreateNew BEFORE launch is the non-replay boundary. It remains UNKNOWN on
 # any ambiguous Start failure; neither an exception nor a missing descriptor
 # licenses another launch. All observations contain public ownership data only.
 $intent=[ordered]@{Schema=1;Scope='OWNED_SUPERVISOR_LAUNCH_INTENT_NOT_ACCEPTANCE';Outcome='UNKNOWN_NO_REPLAY';Kind=$Kind;Nonce=$Context.Nonce;PublicSourceHead=$Context.SourceHead;PublicRun=$Context.Run;Attempt=1;ScriptSHA256=$scriptHash;UTC=[datetime]::UtcNow.ToString('o')}
 Write-OwnedSupervisorObservation $root 'launch-intent-UNKNOWN.json' $intent
 $p=$null;$restoreFailed=$false;$descriptor=$null;$launchFailed=$false;$stage='BEFORE_START';$startedPID=$null;$createdUTC=$null;$observationFailed=$false
 try{
  foreach($key in $saved.Keys){if($key -notin $allow){[Environment]::SetEnvironmentVariable($key,[Management.Automation.Language.NullString]::Value,'Process')}}
  # No redirects/NoNewWindow/credential option: Windows ShellExecute creates an
  # independent hidden console. The owner manages its own bounded private I/O.
  $stage='START_OUTCOME_UNKNOWN'
  $p=Start-Process -FilePath $exe -ArgumentList $vector -WindowStyle Hidden -PassThru
  [Environment]::SetEnvironmentVariable('OWNED_RUNNER_PACKET',[Management.Automation.Language.NullString]::Value,'Process')
  $stage='START_RETURNED';$startedPID=$p.Id
  Write-OwnedSupervisorObservation $root 'launch-pid-observed.json' ([ordered]@{Schema=1;Scope='PUBLIC_PARTIAL_GENERATION_ONLY_NOT_ACCEPTANCE';Nonce=$Context.Nonce;PID=$startedPID})
  $handle=$p.Handle;if($null -eq $handle -or $handle -eq [IntPtr]::Zero){throw 'HELD_STARTED_SUPERVISOR_REQUIRED'}
  $createdUTC=$p.StartTime.ToUniversalTime().ToString('o');$stage='HELD_GENERATION_OBSERVED'
  Write-OwnedSupervisorObservation $root 'launch-generation-observed.json' ([ordered]@{Schema=1;Scope='PUBLIC_PARTIAL_GENERATION_ONLY_NOT_ACCEPTANCE';Nonce=$Context.Nonce;PID=$startedPID;CreatedUTC=$createdUTC;Executable=$exe;ScriptSHA256=$scriptHash})
  $descriptor=[ordered]@{Schema=1;Scope='OWNED_DETACHED_SUPERVISOR_GENERATION_ONLY';Kind=$Kind;Nonce=$Context.Nonce;PublicSourceHead=$Context.SourceHead;PublicRun=$Context.Run;Attempt=1;PID=$startedPID;CreatedUTC=$createdUTC;Executable=$exe;ScriptSHA256=$scriptHash}
  Write-OwnedSupervisorObservation $root 'supervisor.json' $descriptor
  $stage='DESCRIPTOR_CLOSED_AND_READ_BACK'
 }catch{
  $launchFailed=$true
  # Do not kill an owner that could be holding an active private job. The
  # caller must preserve its ACK/failure hold and reconcile this spent intent.
  try{Write-OwnedSupervisorObservation $root 'launch-failure-UNKNOWN.json' ([ordered]@{Schema=1;Scope='UNKNOWN_LAUNCH_RECONCILIATION_ONLY_NOT_ACCEPTANCE';Nonce=$Context.Nonce;Stage=$stage;PID=$startedPID;CreatedUTC=$createdUTC;NoReplay=$true;TeardownPermitted=$false})}catch{$observationFailed=$true}
 }finally{
  foreach($key in @([Environment]::GetEnvironmentVariables('Process').Keys)){try{if(-not $saved.Contains([string]$key) -or $key -ieq 'OWNED_RUNNER_PACKET'){[Environment]::SetEnvironmentVariable([string]$key,[Management.Automation.Language.NullString]::Value,'Process')}}catch{$restoreFailed=$true}}
  foreach($key in $saved.Keys){try{if($key -ine 'OWNED_RUNNER_PACKET'){[Environment]::SetEnvironmentVariable($key,$saved[$key],'Process')}}catch{$restoreFailed=$true}}
  if($null -ne $p){try{$p.Dispose()}catch{$restoreFailed=$true}}
 }
 if($restoreFailed){try{Write-OwnedSupervisorObservation $root 'launch-restore-UNKNOWN.json' ([ordered]@{Schema=1;Scope='UNKNOWN_LAUNCH_RECONCILIATION_ONLY_NOT_ACCEPTANCE';Nonce=$Context.Nonce;Stage='ENVIRONMENT_OR_HANDLE_DISPOSAL';PID=$startedPID;CreatedUTC=$createdUTC;NoReplay=$true;TeardownPermitted=$false})}catch{$observationFailed=$true}}
 if($launchFailed -or $restoreFailed -or $observationFailed -or $null -eq $descriptor){throw 'SUPERVISOR_START_OR_ENV_RESTORATION_UNKNOWN_NO_REPLAY_ACK_HOLD_REQUIRED'}
 return [pscustomobject]@{Root=$root;Descriptor=$descriptor;PrivateJobAccepted=$false;CanonicalAccepted=$false}
 }finally{
  # Covers validation/claim refusal as well as every post-start failure.
  # The injected packet is never restored to the initiating process.
  [Environment]::SetEnvironmentVariable('OWNED_RUNNER_PACKET',[Management.Automation.Language.NullString]::Value,'Process')
 }
}
function Write-OwnedSupervisorObservation($Root,$Name,$Value){
 if($Name -cnotin @('launch-intent-UNKNOWN.json','launch-pid-observed.json','launch-generation-observed.json','supervisor.json','launch-failure-UNKNOWN.json','launch-restore-UNKNOWN.json')){throw 'FIXED_SUPERVISOR_OBSERVATION_REQUIRED'}
 $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($Value|ConvertTo-Json -Depth 4 -Compress));if($bytes.Length -gt 4096){throw 'BOUNDED_SUPERVISOR_OBSERVATION_REQUIRED'}
 $path=Join-Path $Root $Name;$f=[IO.File]::Open($path,'CreateNew','Write','None');try{$f.Write($bytes,0,$bytes.Length);$f.Flush($true)}finally{$f.Dispose()}
 if([Convert]::ToBase64String([IO.File]::ReadAllBytes($path)) -cne [Convert]::ToBase64String($bytes)){throw 'SUPERVISOR_OBSERVATION_READBACK_FAILED'}
}
function Hold-OwnedSupervisorGeneration($Context,$Kind){
 $public=Read-OwnedSupervisorContext $Context $Kind;$path=Join-Path $public.Root 'supervisor.json';$item=Get-Item -LiteralPath $path -Force
 if($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $item.Length -gt 4096){throw 'BOUNDED_SUPERVISOR_DESCRIPTOR_REQUIRED'}
 $d=[IO.File]::ReadAllText($path)|ConvertFrom-Json
 foreach($field in @('Scope','Kind','Nonce','PublicSourceHead','PublicRun','CreatedUTC','Executable','ScriptSHA256')){if($d.$field -isnot [string]){throw 'STRICT_SUPERVISOR_DESCRIPTOR_STRINGS_REQUIRED'}}
 foreach($field in @('Schema','Attempt')){if($d.$field -isnot [int] -and $d.$field -isnot [long]){throw 'STRICT_SUPERVISOR_DESCRIPTOR_INTEGERS_REQUIRED'}}
 $keys=@('Schema','Scope','Kind','Nonce','PublicSourceHead','PublicRun','Attempt','PID','CreatedUTC','Executable','ScriptSHA256')
 if($d -isnot [pscustomobject] -or (@($d.PSObject.Properties.Name|Sort-Object) -join '|') -cne (@($keys|Sort-Object) -join '|') -or $d.Schema -ne 1 -or $d.Scope -cne 'OWNED_DETACHED_SUPERVISOR_GENERATION_ONLY' -or $d.Kind -cne $Kind -or $d.Nonce -cne $Context.Nonce -or $d.PublicSourceHead -cne $Context.SourceHead -or $d.PublicRun -cne $Context.Run -or $d.Attempt -ne 1 -or ($d.PID -isnot [int] -and $d.PID -isnot [long]) -or $d.PID -lt 1 -or $d.PID -eq $PID){throw 'EXACT_SUPERVISOR_GENERATION_DESCRIPTOR_REQUIRED'}
 $exe=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe';$name=if($Kind -ceq 'fixture'){'generic-supervisor-fixture-owner.ps1'}else{'opaque-private-supervisor-owner.ps1'}
 if($d.Executable -isnot [string] -or $d.Executable -cne $exe -or $d.CreatedUTC -isnot [string] -or $d.ScriptSHA256 -isnot [string] -or $d.ScriptSHA256 -cne (Get-FileHash (Join-Path $PSScriptRoot $name)).Hash.ToLowerInvariant()){throw 'EXACT_SUPERVISOR_IMAGE_AND_SOURCE_REQUIRED'}
 $created=[datetime]::ParseExact($d.CreatedUTC,'o',[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::RoundtripKind).ToUniversalTime()
 $p=$null;$returned=$false
 try{
  $p=[Diagnostics.Process]::GetProcessById($d.PID);$handle=$p.Handle
  if($null -eq $handle -or $handle -eq [IntPtr]::Zero -or $p.StartTime.ToUniversalTime().Ticks -ne $created.Ticks -or $p.MainModule.FileName -cne $exe -or $p.HasExited){throw 'EXACT_LIVE_HELD_SUPERVISOR_GENERATION_REQUIRED'}
  $returned=$true;return [pscustomobject]@{Process=$p;Descriptor=$d;Root=$public.Root;PublicKeyBytes=$public.PublicKeyBytes;Context=$Context}
 }finally{if(-not $returned -and $null -ne $p){$p.Dispose()}}
}
