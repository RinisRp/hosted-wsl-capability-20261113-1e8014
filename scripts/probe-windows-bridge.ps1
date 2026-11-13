function Invoke-WindowsBridgeProbe([string]$Root,[string]$Out,[string]$Nonce,[string]$Distribution,[string]$ExpectedEngine){
 $r=[ordered]@{Schema=1;Nonce=$Nonce;Scope='GENERIC_WINDOWS_CLI_NPIPE_BINARY_LOOPBACK_ONLY';Qualified=$false;Failure=$null;Endpoint=('npipe:////./pipe/hosted_wsl_'+$Nonce);BinarySHA256=$null;SourceQualification=$false;Native=@();Containers=@();InitialNetworks=@();FinalNetworks=@();BinaryBytes=262144;BinarySHA256Expected=$null;BinaryRoundTrip=$false;LoopbackHTTP=$false;LoopbackListeners=@();FinalPortAbsent=$false;InitialContainersEmpty=$false;FinalContainersEmpty=$false;AfterFreeMiB=$null;MemoryMeasuredUTC=$null;SameEngineAfterMemory=$false;Ready=$null;BridgeReport=$null;BridgeProcess=$null;PrivateProjectAccess=$false;JITGranted=$false;CanonicalAccepted=$false}
 $saved=[ordered]@{};$p=$null;$held=$false;$ready=Join-Path $Root 'bridge-ready.json';$stop=Join-Path $Root 'bridge-stop.txt';$report=Join-Path $Root 'bridge-report.json';$docker=$null;$prefix=@();$bridgeStarted=$false
 $objects=[Collections.Generic.List[object]]::new()
 function Latch([string]$Message){$r.Failure=if($null -eq $r.Failure){$Message}else{$r.Failure+';'+$Message}}
 function CleanNative($x){return ($null -ne $x -and $x.exitCode -eq 0 -and $x.closed -and -not $x.timedOut -and -not $x.onlyOwnStartedRootStopped -and $null -eq $x.nativeError -and $null -eq $x.cleanupError)}
 function DockerCall([string[]]$Arguments,[int]$Seconds,[string]$Stem){
  $x=Native $docker ($prefix+$Arguments) $Seconds ('bridge-'+$Stem)
  $r.Native+=@{Name=$Stem;Result=$x}
  if(-not (CleanNative $x)){throw ('OWN_ENDPOINT_NATIVE_FAILED_'+$Stem)}
  return $x.stdout.Trim()
 }
 function ReadBoundedJSON([string]$Path){if((Get-Item -LiteralPath $Path).Length -gt 131072){throw 'BOUNDED_BRIDGE_JSON_REQUIRED'};return ([IO.File]::ReadAllText($Path)|ConvertFrom-Json)}
 function Fields($Data,[string[]]$Keys){return ($null -ne $Data -and $Data -is [pscustomobject] -and (@($Data.PSObject.Properties.Name|Sort-Object) -join '|') -ceq (@($Keys|Sort-Object) -join '|'))}
 function Integer($Value){return ($Value -is [int] -or $Value -is [long])}
 function SourceManifestValid($Data){
  $keys=@('.gitattributes','.github/workflows/capability.yml','README.md','scripts/probe-wsl.ps1','scripts/probe-linux-engine.sh','go.mod','go.sum','scripts/wsl_npipe_bridge_windows.go','scripts/wsl_npipe_bridge_windows_test.go','scripts/qualify-bridge-source.ps1','scripts/probe-windows-bridge.ps1')
  if(-not (Fields $Data $keys)){return $false}
  foreach($key in $keys){if($Data.$key -isnot [string] -or $Data.$key -cnotmatch '\A[0-9a-f]{64}\z'){return $false}}
  return $true
 }
 function ReadyValid($Data,[string]$Owner,[int]$PIDValue){
  if(-not (Fields $Data @('Schema','Nonce','Endpoint','OwnerSID','PID','PayloadLogged'))){return $false}
  return ((Integer $Data.Schema) -and $Data.Schema -eq 1 -and (Integer $Data.PID) -and $Data.PID -eq $PIDValue -and $PIDValue -gt 0 -and $Data.Nonce -is [string] -and $Data.Nonce -ceq $Nonce -and $Data.Endpoint -is [string] -and $Data.Endpoint -ceq $r.Endpoint -and $Data.OwnerSID -is [string] -and $Data.OwnerSID -ceq $Owner -and $Data.PayloadLogged -is [bool] -and $Data.PayloadLogged -ceq $false)
 }
 function ReportValid($Data){
  $keys=@('UnknownRoots','UnknownPumps','UnknownConnectionCloses','Schema','Nonce','Endpoint','OwnerSID','SDK','Accepted','Completed','Active','ListenerCloseCompleted','AcceptLoopFinished','EndpointAbsentObserved','SDKKernelCloseErrorsChecked','PayloadLogged','Qualified','Records','Faults')
  if(-not (Fields $Data $keys)){return $false}
  foreach($key in @('UnknownRoots','UnknownPumps','UnknownConnectionCloses','Schema','Accepted','Completed','Active')){if(-not (Integer $Data.$key)){return $false}}
  foreach($key in @('Nonce','Endpoint','OwnerSID','SDK')){if($Data.$key -isnot [string]){return $false}}
  foreach($key in @('ListenerCloseCompleted','AcceptLoopFinished','EndpointAbsentObserved','Qualified')){if($Data.$key -isnot [bool] -or $Data.$key -cne $true){return $false}}
  foreach($key in @('SDKKernelCloseErrorsChecked','PayloadLogged')){if($Data.$key -isnot [bool] -or $Data.$key -cne $false){return $false}}
  if($Data.Schema -ne 1 -or $Data.Nonce -cne $Nonce -or $Data.Endpoint -cne $r.Endpoint -or $Data.OwnerSID -cne $r.Ready.OwnerSID -or $Data.SDK -cne 'github.com/Microsoft/go-winio@v0.6.4' -or $Data.Accepted -lt 1 -or $Data.Accepted -gt 128 -or $Data.Accepted -ne $Data.Completed -or $Data.Completed -ne @($Data.Records).Count -or $Data.Active -ne 0 -or $Data.UnknownRoots -ne 0 -or $Data.UnknownPumps -ne 0 -or $Data.UnknownConnectionCloses -ne 0 -or ($null -ne $Data.Faults -and @($Data.Faults).Count -ne 0)){return $false}
  $ids=@()
  foreach($record in $Data.Records){
   $recordKeys=@('Cancelled','ContextValidAtStart','ContextValidAtCompletion','ID','PID','ExitCode','RootStarted','RootWaitObserved','InputFinished','OutputFinished','StderrFinished','SDKCloseCompleted','FilesClosed','Forced','TimedOut','StderrOverflow','Qualified','StartedBeforeUTC','InputBytes','OutputBytes','StderrBytes','Faults')
   if(-not (Fields $record $recordKeys)){return $false}
   if($record.StartedBeforeUTC -isnot [string]){return $false}
   foreach($key in @('ContextValidAtStart','ContextValidAtCompletion','RootStarted','RootWaitObserved','InputFinished','OutputFinished','StderrFinished','SDKCloseCompleted','FilesClosed','Qualified')){if($record.$key -isnot [bool] -or $record.$key -cne $true){return $false}}
   foreach($key in @('Cancelled','Forced','TimedOut','StderrOverflow')){if($record.$key -isnot [bool] -or $record.$key -cne $false){return $false}}
   foreach($key in @('ID','PID','ExitCode','InputBytes','OutputBytes','StderrBytes')){if(-not (Integer $record.$key)){return $false}}
   if($record.ID -lt 1 -or $record.PID -lt 1 -or $record.ExitCode -ne 0 -or $record.InputBytes -lt 0 -or $record.OutputBytes -lt 0 -or $record.StderrBytes -lt 0 -or $record.StderrBytes -gt 16384 -or $record.ID -in $ids -or ($null -ne $record.Faults -and @($record.Faults).Count -ne 0)){return $false}
   $ids+=@($record.ID)
  }
  return $true
 }
 function PortListeners{return @(Get-NetTCPConnection -State Listen -ErrorAction Stop|Where-Object {$_.LocalPort -eq 55321})}
 function HTTPBytes([string]$Path,[int]$Length,[Diagnostics.Stopwatch]$Clock){
  $response=$null;$stream=$null;$memory=$null
  try{
   $remaining=[int][math]::Floor((45-$Clock.Elapsed.TotalSeconds)*1000);if($remaining -le 0){throw 'HTTP_TOTAL_DEADLINE_EXCEEDED'}
   $request=[Net.HttpWebRequest]::Create('http://127.0.0.1:55321/'+$Path);$request.Proxy=$null;$request.Credentials=$null;$request.UseDefaultCredentials=$false;$request.Timeout=[math]::Min(3000,$remaining);$request.ReadWriteTimeout=[math]::Min(3000,$remaining);$request.AllowAutoRedirect=$false;$request.KeepAlive=$false
   $response=$request.GetResponse();if([int]$response.StatusCode -ne 200 -or $response.ContentLength -ne $Length){throw 'EXACT_HTTP_RESPONSE_REQUIRED'}
   $stream=$response.GetResponseStream();if(-not $stream.CanTimeout){throw 'DEADLINE_CAPABLE_HTTP_STREAM_REQUIRED'}
   $memory=[IO.MemoryStream]::new();$buffer=New-Object byte[] 16384;$total=0
   while($true){
    $remaining=[int][math]::Floor((45-$Clock.Elapsed.TotalSeconds)*1000);if($remaining -le 0){throw 'HTTP_TOTAL_DEADLINE_EXCEEDED'}
    $stream.ReadTimeout=[math]::Min(3000,$remaining);$read=$stream.Read($buffer,0,$buffer.Length)
    if($read -eq 0){break};$total+=$read;if($total -gt $Length){throw 'HTTP_RESPONSE_BOUND_EXCEEDED'};$memory.Write($buffer,0,$read)
   }
   if($Clock.Elapsed.TotalSeconds -ge 45 -or $total -ne $Length){throw 'COMPLETE_HTTP_RESPONSE_WITHIN_TOTAL_DEADLINE_REQUIRED'}
   return ,$memory.ToArray()
  }catch [Net.WebException]{if($null -ne $_.Exception.Response){$_.Exception.Response.Dispose()};throw}
  finally{if($null -ne $stream){$stream.Dispose()};if($null -ne $response){$response.Dispose()};if($null -ne $memory){$memory.Dispose()}}
 }
 function InspectOwned($Object,[string]$Stem){
  $target=if($null -eq $Object.ID){$Object.Name}else{$Object.ID}
  $data=DockerCall @('container','inspect',$target) 20 $Stem
  $items=@($data|ConvertFrom-Json)
  if($items.Count -ne 1){throw 'ONE_OWNED_CONTAINER_REQUIRED'}
  $c=$items[0]
  if($c.Id -cnotmatch '\A[0-9a-f]{64}\z' -or $c.Name -cne ('/'+$Object.Name) -or $c.Config.Labels.capabilityNonce -cne $Nonce -or $c.Config.Image -cne $image -or ($null -ne $Object.ID -and $c.Id -cne $Object.ID)){throw 'EXACT_OWNED_CONTAINER_IDENTITY_REQUIRED'}
  $Object.ID=$c.Id
  return $c
 }
 function RemoveOwned($Object,[string]$Stem){
  if($Object.Removed){return}
  $c=InspectOwned $Object ($Stem+'-inspect')
  if($c.State.Running){
   if($Object.StopAttempted){throw 'OWN_STOP_ALREADY_ATTEMPTED_NO_RETRY'}
   $Object.StopAttempted=$true
   [void](DockerCall @('container','stop','--timeout=-1',$Object.ID) 20 ($Stem+'-stop'))
   $c=InspectOwned $Object ($Stem+'-stopped')
  }
  if($c.State.Running -or $c.State.OOMKilled -or $c.State.ExitCode -notin @(0,143)){throw 'OWN_STOPPED_NONFORCED_CONTAINER_REQUIRED'}
  if($Object.RemoveAttempted){throw 'OWN_REMOVE_ALREADY_ATTEMPTED_NO_RETRY'}
  $Object.RemoveAttempted=$true
  [void](DockerCall @('container','rm',$Object.ID) 20 ($Stem+'-remove'))
  $Object.Removed=$true
 }
 try{
  if($Nonce -cnotmatch '\A[0-9a-f]{32}\z' -or $Distribution -cne ('hosted-wsl-'+$Nonce) -or $ExpectedEngine -cnotmatch '\A[0-9A-Za-z:._-]{1,128}\z' -or $Root -ine (Join-Path $env:RUNNER_TEMP ('hosted-wsl-'+$Nonce))){throw 'EXACT_OWNED_BRIDGE_CONTEXT_REQUIRED'}
  $qroot=Join-Path $env:RUNNER_TEMP ('bridge-source-'+$Nonce)
  $q=ReadBoundedJSON (Join-Path $qroot 'outputs\source-result.json')
  $binary=Join-Path $qroot 'bridge-source-only.exe'
  $r.BinarySHA256=(Get-FileHash -LiteralPath $binary).Hash.ToLowerInvariant()
  $r.SourceQualification=($q -is [pscustomobject] -and $q.Nonce -is [string] -and $q.Nonce -ceq $Nonce -and $q.SourceHead -is [string] -and $q.SourceHead -ceq $env:GITHUB_SHA -and $q.SourceQualified -is [bool] -and $q.SourceQualified -ceq $true -and $q.ResultFilePublished -is [bool] -and $q.ResultFilePublished -ceq $true -and $q.OriginalSourceUnchanged -is [bool] -and $q.OriginalSourceUnchanged -ceq $true -and $q.RequiresFormatting -is [bool] -and $q.RequiresFormatting -ceq $false -and $null -eq $q.Failure -and $q.BinarySHA256 -is [string] -and $q.BinarySHA256 -ceq $r.BinarySHA256 -and (SourceManifestValid $q.SourceManifest))
  if(-not $r.SourceQualification){throw 'EXACT_SUCCESSFUL_FORMATTED_SOURCE_AND_BINARY_REQUIRED'}
  foreach($key in $q.SourceManifest.PSObject.Properties.Name){if((Get-FileHash -LiteralPath (Join-Path (Split-Path -Parent $PSScriptRoot) $key)).Hash.ToLowerInvariant() -cne $q.SourceManifest.$key){throw 'SOURCE_CHANGED_AFTER_BUILD'}}
  foreach($key in @([Environment]::GetEnvironmentVariables('Process').Keys|Where-Object {$_ -like 'DOCKER*'})){$saved[$key]=[Environment]::GetEnvironmentVariable($key,'Process');[Environment]::SetEnvironmentVariable($key,$null,'Process')}
  $config=Join-Path $Root 'empty-docker-config';if(Test-Path -LiteralPath $config){throw 'FRESH_EMPTY_DOCKER_CONFIG_REQUIRED'};[void][IO.Directory]::CreateDirectory($config)
  $docker=(Get-Command docker.exe -ErrorAction Stop).Source;$prefix=@('--config',$config,'--host',$r.Endpoint)
  if(@(PortListeners).Count){throw 'UNUSED_WINDOWS_LOOPBACK_PORT_REQUIRED'}
  $p=Start-Process -FilePath $binary -ArgumentList @('--nonce',$Nonce,'--distribution',$Distribution,'--ready',$ready,'--stop',$stop,'--report',$report) -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $Root 'bridge-main.stdout') -RedirectStandardError (Join-Path $Root 'bridge-main.stderr')
  $bridgeStarted=$true
  $r.BridgeProcess=[ordered]@{PID=$null;CreatedUTC=$null;Closed=$false;ExitCode=$null;Forced=$false;CleanupError=$null}
  $handle=$p.Handle;if($null -eq $handle -or $handle -eq [IntPtr]::Zero){throw 'HELD_OWN_BRIDGE_PROCESS_HANDLE_REQUIRED'};$held=$true
  $r.BridgeProcess.PID=$p.Id;$r.BridgeProcess.CreatedUTC=$p.StartTime.ToUniversalTime().ToString('o')
  $limit=[Diagnostics.Stopwatch]::StartNew()
  while($null -eq $r.Ready){
   if($p.HasExited -or $limit.Elapsed.TotalSeconds -ge 20){throw 'OWN_BRIDGE_READY_TIMEOUT'}
   if(Test-Path -LiteralPath $ready){if((Get-Item -LiteralPath $ready).Length -gt 131072){throw 'BOUNDED_BRIDGE_JSON_REQUIRED'};try{$r.Ready=ReadBoundedJSON $ready}catch{$r.Ready=$null}}
   if($null -eq $r.Ready){Start-Sleep -Milliseconds 100}
  }
  $owner=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
  if(-not (ReadyValid $r.Ready $owner $p.Id)){throw 'EXACT_OWN_BRIDGE_READY_REQUIRED'}
  $info=DockerCall @('info','--format','{{.ID}}/{{.OSType}}/{{.ServerVersion}}') 30 'initial-info'
  if($info -cne ($ExpectedEngine+'/linux/29.9.3')){throw 'SAME_NEW_LINUX_ENGINE_REQUIRED_BEFORE_MUTATION'}
  $r.InitialContainersEmpty=((DockerCall @('container','ls','--all','--quiet') 20 'initial-census') -ceq '')
  if(-not $r.InitialContainersEmpty){throw 'FRESH_BRIDGE_ENGINE_REQUIRED'}
  $r.InitialNetworks=@((DockerCall @('network','ls','--no-trunc','--format','{{.ID}}/{{.Name}}/{{.Driver}}') 20 'initial-networks') -split '\r?\n'|Sort-Object)
  if($r.InitialNetworks.Count -ne 3 -or @($r.InitialNetworks|Where-Object {$_ -cnotmatch '\A[0-9a-f]{64}/(bridge/bridge|host/host|none/null)\z'}).Count){throw 'THREE_GENUINE_BUILTIN_NETWORKS_REQUIRED'}
  $image='busybox@sha256:66a6306db78bf2dbf3487f293aa8d6990d8e506fdffab9cc43fe422becf886e4'
  $fixture=New-Object byte[] 262144;for($i=0;$i -lt $fixture.Length;$i++){$fixture[$i]=[byte]($i%256)}
  $inputFile=Join-Path $Root 'binary-input.bin';$outputFile=Join-Path $Root 'binary-output.bin';[IO.File]::WriteAllBytes($inputFile,$fixture)
  $r.BinarySHA256Expected=(Get-FileHash -LiteralPath $inputFile).Hash.ToLowerInvariant()
  $bin=[ordered]@{Name=('bridge-bin-'+$Nonce);ID=$null;CreateAttempted=$true;StopAttempted=$false;RemoveAttempted=$false;Removed=$false};$objects.Add($bin)
  $created=DockerCall @('container','create','--name',$bin.Name,'--label',('capabilityNonce='+$Nonce),'--network','none',$image,'/bin/echo',$Nonce) 30 'binary-create'
  if($created -cnotmatch '\A[0-9a-f]{64}\z'){throw 'EXACT_BINARY_CONTAINER_ID_REQUIRED'};$bin.ID=$created
  [void](InspectOwned $bin 'binary-before-copy')
  [void](DockerCall @('cp',$inputFile,($bin.ID+':/capability.bin')) 30 'binary-copy-in')
  [void](DockerCall @('cp',($bin.ID+':/capability.bin'),$outputFile) 30 'binary-copy-out')
  $r.BinaryRoundTrip=((Get-Item -LiteralPath $outputFile).Length -eq $fixture.Length -and (Get-FileHash -LiteralPath $outputFile).Hash.ToLowerInvariant() -ceq $r.BinarySHA256Expected)
  if(-not $r.BinaryRoundTrip){throw 'BINARY_NUL_ROUND_TRIP_REQUIRED'}
  if((DockerCall @('container','start','--attach',$bin.ID) 20 'binary-start') -cne $Nonce){throw 'OWN_BINARY_CONTAINER_OUTPUT_REQUIRED'}
  RemoveOwned $bin 'binary-cleanup'
  $http=[ordered]@{Name=('bridge-http-'+$Nonce);ID=$null;CreateAttempted=$true;StopAttempted=$false;RemoveAttempted=$false;Removed=$false};$objects.Add($http)
  $created=DockerCall @('container','create','--name',$http.Name,'--hostname',('probe-'+$Nonce),'--label',('capabilityNonce='+$Nonce),'--network','bridge','--publish','127.0.0.1:55321:8080',$image,'/bin/busybox','httpd','-f','-p','8080','-h','/') 30 'http-create'
  if($created -cnotmatch '\A[0-9a-f]{64}\z'){throw 'EXACT_HTTP_CONTAINER_ID_REQUIRED'};$http.ID=$created
  $c=InspectOwned $http 'http-before-start'
  $binding=@($c.HostConfig.PortBindings.'8080/tcp')
  if($binding.Count -ne 1 -or $binding[0].HostIp -cne '127.0.0.1' -or $binding[0].HostPort -cne '55321'){throw 'EXACT_EXPLICIT_LOOPBACK_BINDING_REQUIRED'}
  [void](DockerCall @('cp',$inputFile,($http.ID+':/capability.bin')) 30 'http-copy-in')
  [void](DockerCall @('container','start',$http.ID) 20 'http-start')
  $httpLimit=[Diagnostics.Stopwatch]::StartNew();$httpBody=$null
  while($null -eq $httpBody -and $httpLimit.Elapsed.TotalSeconds -lt 45){
   try{$httpBody=HTTPBytes 'capability.bin' 262144 $httpLimit}catch [Net.WebException]{if($httpLimit.Elapsed.TotalSeconds -ge 45){throw 'WINDOWS_LOOPBACK_HTTP_UNREACHABLE'};Start-Sleep -Milliseconds 200}
  }
  if($null -eq $httpBody){throw 'WINDOWS_LOOPBACK_HTTP_UNREACHABLE'}
  $sha=[Security.Cryptography.SHA256]::Create();try{$actualHash=([BitConverter]::ToString($sha.ComputeHash($httpBody))).Replace('-','').ToLowerInvariant()}finally{$sha.Dispose()}
  if($actualHash -cne $r.BinarySHA256Expected){throw 'WINDOWS_HTTP_BINARY_HASH_REQUIRED'}
  $nonceBody=HTTPBytes 'etc/hostname' 39 $httpLimit
  if([Text.Encoding]::UTF8.GetString($nonceBody) -cne ('probe-'+$Nonce+"`n")){throw 'EXACT_HTTP_NONCE_REQUIRED'}
  $r.LoopbackListeners=@(PortListeners|Select-Object LocalAddress,LocalPort,OwningProcess)
  if($r.LoopbackListeners.Count -lt 1 -or @($r.LoopbackListeners|Where-Object {$_.LocalAddress -notin @('127.0.0.1','::1')}).Count){throw 'WINDOWS_LOCALHOST_ONLY_LISTENER_REQUIRED'}
  $r.LoopbackHTTP=$true
  RemoveOwned $http 'http-cleanup'
 }catch{Latch $_.Exception.Message}
 finally{
  foreach($obj in $objects){if(-not $obj.Removed){try{RemoveOwned $obj ('failure-cleanup-'+($objects.IndexOf($obj)))}catch{Latch $_.Exception.Message}}}
  $r.Containers=@($objects.ToArray())
  if($null -ne $docker -and $null -ne $r.Ready){
   try{
    $r.FinalContainersEmpty=((DockerCall @('container','ls','--all','--quiet') 20 'final-census') -ceq '')
    if(-not $r.FinalContainersEmpty){throw 'NO_FINAL_CONTAINERS_REQUIRED'}
    $r.FinalNetworks=@((DockerCall @('network','ls','--no-trunc','--format','{{.ID}}/{{.Name}}/{{.Driver}}') 20 'final-networks') -split '\r?\n'|Sort-Object)
    if(($r.InitialNetworks -join '|') -cne ($r.FinalNetworks -join '|')){throw 'BUILTIN_NETWORK_IDENTITIES_MUST_REMAIN_UNCHANGED'}
    $r.AfterFreeMiB=[math]::Floor((Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory/1024);$r.MemoryMeasuredUTC=[datetime]::UtcNow.ToString('o')
    $r.SameEngineAfterMemory=((DockerCall @('info','--format','{{.ID}}/{{.OSType}}/{{.ServerVersion}}') 30 'after-memory') -ceq ($ExpectedEngine+'/linux/29.9.3'))
    if(-not $r.SameEngineAfterMemory -or $r.AfterFreeMiB -lt 6144){throw 'SAME_LIVE_LINUX_ENGINE_AND_UNCHANGED_6144_REQUIRED'}
   }catch{Latch $_.Exception.Message}
  }
  if($bridgeStarted -and $null -ne $p){
   try{if(-not $p.HasExited){$bytes=[Text.Encoding]::UTF8.GetBytes($Nonce);$f=[IO.File]::Open($stop,'CreateNew','Write','None');try{$f.Write($bytes,0,$bytes.Length);$f.Flush($true)}finally{$f.Dispose()}}}catch{Latch ('OWN_STOP_PUBLICATION_FAILED:'+ $_.Exception.GetType().FullName)}
   try{
    if(-not $p.WaitForExit(20000)){
     Latch 'OWN_BRIDGE_PARENT_TIMEOUT'
     if(-not $held){throw 'NO_VERIFIED_HELD_HANDLE_NO_FORCED_TERMINATION'}
     $r.BridgeProcess.Forced=$true;$p.Kill();if(-not $p.WaitForExit(10000)){throw 'OWN_BRIDGE_ROOT_CLOSURE_UNPROVED'}
    }
    $p.WaitForExit();$r.BridgeProcess.Closed=$p.HasExited;$r.BridgeProcess.ExitCode=$p.ExitCode
   }catch{Latch $_.Exception.Message;$r.BridgeProcess.CleanupError=$_.Exception.Message}
   try{
    foreach($path in @((Join-Path $Root 'bridge-main.stdout'),(Join-Path $Root 'bridge-main.stderr'))){if((Get-Item -LiteralPath $path).Length -gt 16384){throw 'BRIDGE_DIAGNOSTIC_BOUND_EXCEEDED'}}
    $r.BridgeReport=ReadBoundedJSON $report
    $b=$r.BridgeReport
    if($p.ExitCode -ne 0 -or -not (ReportValid $b)){throw 'ALL_OWN_BRIDGE_ROOTS_PUMPS_CLOSES_AND_NAMESPACE_REQUIRED'}
    Copy-Item -LiteralPath $ready -Destination (Join-Path $Out 'bridge-ready.json');Copy-Item -LiteralPath $report -Destination (Join-Path $Out 'bridge-report.json')
   }catch{Latch $_.Exception.Message;$r.BridgeProcess.CleanupError=$_.Exception.Message}
   finally{try{$p.Dispose()}catch{Latch 'OWN_BRIDGE_PROCESS_DISPOSE_FAILED'}}
  }
  foreach($key in $saved.Keys){try{[Environment]::SetEnvironmentVariable($key,$saved[$key],'Process')}catch{Latch 'PROCESS_DOCKER_ENVIRONMENT_RESTORE_FAILED'}}
  try{$r.FinalPortAbsent=(@(PortListeners).Count -eq 0);if(-not $r.FinalPortAbsent){throw 'WINDOWS_HTTP_LISTENER_CLEANUP_UNPROVED'}}catch{Latch $_.Exception.Message}
 }
 $r.Qualified=($null -eq $r.Failure -and $r.SourceQualification -and $r.BinaryRoundTrip -and $r.LoopbackHTTP -and $r.InitialContainersEmpty -and $r.FinalContainersEmpty -and $r.FinalPortAbsent -and $r.SameEngineAfterMemory -and $r.AfterFreeMiB -ge 6144 -and $null -ne $r.BridgeReport -and $r.BridgeReport.Qualified)
 return $r
}
