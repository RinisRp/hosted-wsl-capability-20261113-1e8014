$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$env:PSModulePath='C:\Windows\System32\WindowsPowerShell\v1.0\Modules'
$nonce='d1e1522826b64651a632e610e43a060b'
if($env:GITHUB_ACTIONS -cne 'true' -or $env:RUNNER_ENVIRONMENT -cne 'github-hosted' -or $env:GITHUB_REPOSITORY -cne 'RinisRp/hosted-wsl-capability-20261113-1e8014' -or $env:GITHUB_ACTOR -cne 'RinisRp' -or $env:GITHUB_REF -cne 'refs/heads/codex/wsl-npipe-6f3465' -or $env:PROBE_NONCE -cne $nonce -or $env:ImageOS -cne 'win25-vs2026' -or $env:RUNNER_ARCH -cne 'X64'){throw 'EXACT_GENERIC_SOURCE_QUALIFICATION_CONTEXT_REQUIRED'}
if($env:RUNNER_TEMP -cnotmatch '\A[A-Z]:\\[A-Za-z0-9_\\-]+\z'){throw 'OWNED_TEMP_PATH_REQUIRED'}
$root=Join-Path $env:RUNNER_TEMP ('bridge-source-'+$nonce)
if(Test-Path -LiteralPath $root){throw 'FRESH_SOURCE_QUALIFICATION_ROOT_REQUIRED'}
[void][IO.Directory]::CreateDirectory($root)
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
$acl=[Security.AccessControl.DirectorySecurity]::new();$acl.SetAccessRuleProtection($true,$false);$acl.SetOwner($identity.User)
foreach($sid in @($identity.User.Value,'S-1-5-18','S-1-5-32-544')){[void]$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid),'FullControl','ContainerInherit,ObjectInherit','None','Allow'))}
Set-Acl -LiteralPath $root -AclObject $acl
$out=Join-Path $root 'outputs';$raw=Join-Path $root 'raw-native'
[void][IO.Directory]::CreateDirectory($out);[void][IO.Directory]::CreateDirectory($raw)
[IO.File]::AppendAllText($env:GITHUB_OUTPUT,'out_path='+$out+[Environment]::NewLine)
function Native([string]$File,[string[]]$Arguments,[int]$Seconds,[string]$Stem){
 foreach($a in $Arguments){if($a -match '[\s"&|<>]'){throw 'FIXED_NATIVE_ARGUMENTS_ONLY'}}
 $stdout=Join-Path $raw ($Stem+'.stdout.txt');$stderr=Join-Path $raw ($Stem+'.stderr.txt')
 $p=$null;$timedOut=$false;$exitCode=$null;$closed=$false;$ownRootStopped=$false;$created=$null;$childId=$null;$nativeError=$null;$cleanupError=$null
 try{
  $p=Start-Process -FilePath $File -ArgumentList $Arguments -WindowStyle Hidden -PassThru -RedirectStandardOutput $stdout -RedirectStandardError $stderr
  $childId=$p.Id;$handle=$p.Handle;if($null -eq $handle -or $handle -eq [IntPtr]::Zero){throw 'OWN_STARTED_CLIENT_HANDLE_REQUIRED'};$created=$p.StartTime.ToUniversalTime().ToString('o')
  if($p.WaitForExit($Seconds*1000)){$p.WaitForExit();$exitCode=$p.ExitCode;$closed=$p.HasExited}else{$timedOut=$true}
 }catch{$nativeError=$_.Exception.GetType().FullName}
 finally{
  if($null -ne $p){
   try{
    if(-not $p.HasExited){$p.Kill();$ownRootStopped=$true}
    if(-not $p.WaitForExit(15000)){throw 'OWN_STARTED_NATIVE_ROOT_DID_NOT_CLOSE'}
    $p.WaitForExit();$closed=$p.HasExited
    if($null -eq $exitCode){$exitCode=$p.ExitCode}
   }catch{$cleanupError=$_.Exception.GetType().FullName;$closed=$false}
   finally{try{$p.Dispose()}catch{$cleanupError=if($null -eq $cleanupError){'OWN_CLIENT_DISPOSE_FAILED'}else{$cleanupError+';OWN_CLIENT_DISPOSE_FAILED'}}}
  }
 }
 $stdoutText='';$stderrText=''
 try{
  foreach($path in @($stdout,$stderr)){if((Get-Item -LiteralPath $path).Length -gt 131072){throw 'NATIVE_OUTPUT_BOUND_EXCEEDED'}}
  $stdoutText=[IO.File]::ReadAllText($stdout).Replace([string][char]0,[string]::Empty)
  $stderrText=[IO.File]::ReadAllText($stderr).Replace([string][char]0,[string]::Empty)
  $copies=@(@{name=($Stem+'.stdout.txt');value=$stdoutText},@{name=($Stem+'.stderr.txt');value=$stderrText})
  foreach($copy in $copies){if([Text.Encoding]::UTF8.GetByteCount($copy.value) -gt 131072){throw 'NORMALIZED_PUBLIC_OUTPUT_BOUND_EXCEEDED'}}
  foreach($copy in $copies){
   $bytes=[Text.Encoding]::UTF8.GetBytes($copy.value)
   $stream=[IO.File]::Open((Join-Path $out $copy.name),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
   try{$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
  }
 }catch{$stdoutText='';$stderrText='';$nativeError=if($null -eq $nativeError){'NATIVE_OUTPUT_READ_OR_PUBLICATION_FAILED'}else{$nativeError+';NATIVE_OUTPUT_READ_OR_PUBLICATION_FAILED'}}
 return [ordered]@{pid=$childId;createdUtc=$created;exitCode=$exitCode;timedOut=$timedOut;closed=$closed;onlyOwnStartedRootStopped=$ownRootStopped;nativeError=$nativeError;cleanupError=$cleanupError;stdout=$stdoutText;stderr=$stderrText}
}
$repo=Split-Path -Parent $PSScriptRoot
$paths=@('.gitattributes','.github/workflows/capability.yml','README.md','scripts/probe-wsl.ps1','scripts/probe-linux-engine.sh','go.mod','go.sum','scripts/wsl_npipe_bridge_windows.go','scripts/wsl_npipe_bridge_windows_test.go','scripts/qualify-bridge-source.ps1','scripts/probe-windows-bridge.ps1','scripts/capability-http.sh','scripts/capability-exec.sh')
function SourceManifest{$m=[ordered]@{};foreach($rel in $paths){$m[$rel]=(Get-FileHash -LiteralPath (Join-Path $repo $rel)).Hash.ToLowerInvariant()};return $m}
$result=[ordered]@{Schema=1;Scope='GENERIC_BRIDGE_SOURCE_QUALIFICATION_ONLY';Nonce=$nonce;SourceHead=$env:GITHUB_SHA;SourceManifest=(SourceManifest);CompilerVersion='go1.26.11';CompilerArchiveSHA256='71ae086f0137e665f855a811cc119152b6a783e0bbc1b906e709f46d80141eb0';Phases=@();OriginalSourceUnchanged=$false;RequiresFormatting=$null;BinarySHA256=$null;SourceQualified=$false;WSLCalls=0;DockerCalls=0;ProductionBridgeMainExecuted=$false;PrivateProjectAccess=$false;JITGranted=$false;CanonicalAccepted=$false;Failure=$null;ResultFilePublished=$false;FinishedUTC=$null}
$saved=[ordered]@{}
$names=@('GOTOOLCHAIN','GOPROXY','GOSUMDB','GOMODCACHE','GOCACHE','GOPATH','GOENV','GOWORK','CGO_ENABLED','GOOS','GOARCH','GOAMD64','GOFLAGS','GOEXPERIMENT')
foreach($key in $names){$saved[$key]=[Environment]::GetEnvironmentVariable($key,'Process')}
$located=$false
try{
 $archive=Join-Path $root 'go1.26.11.windows-amd64.zip'
 Invoke-WebRequest -UseBasicParsing -Uri 'https://go.dev/dl/go1.26.11.windows-amd64.zip' -OutFile $archive
 if((Get-Item -LiteralPath $archive).Length -ne 75074581 -or (Get-FileHash -LiteralPath $archive).Hash.ToLowerInvariant() -cne $result.CompilerArchiveSHA256){throw 'OFFICIAL_COMPILER_ARCHIVE_REFUSED'}
 $runtime=Join-Path $root 'compiler';[void][IO.Directory]::CreateDirectory($runtime)
 Add-Type -AssemblyName System.IO.Compression.FileSystem
 [IO.Compression.ZipFile]::ExtractToDirectory($archive,$runtime)
 $go=Join-Path $runtime 'go\bin\go.exe';$fmt=Join-Path $runtime 'go\bin\gofmt.exe'
 $env:GOTOOLCHAIN='local';$env:GOPROXY='https://proxy.golang.org';$env:GOSUMDB='sum.golang.org';$env:GOENV='off';$env:GOWORK='off';$env:CGO_ENABLED='0';$env:GOOS='windows';$env:GOARCH='amd64';$env:GOAMD64='v1'
 $env:GOMODCACHE=Join-Path $root 'module-cache';$env:GOCACHE=Join-Path $root 'build-cache';$env:GOPATH=Join-Path $root 'go-path'
 [Environment]::SetEnvironmentVariable('GOFLAGS',$null,'Process');[Environment]::SetEnvironmentVariable('GOEXPERIMENT',$null,'Process')
 Push-Location $repo;$located=$true
 $vectors=@(
  @{name='compiler-version';file=$go;args=@('version');seconds=20},
  @{name='formatted-main';file=$fmt;args=@((Join-Path $repo 'scripts/wsl_npipe_bridge_windows.go'));seconds=20},
  @{name='formatted-tests';file=$fmt;args=@((Join-Path $repo 'scripts/wsl_npipe_bridge_windows_test.go'));seconds=20},
  @{name='unit-tests';file=$go;args=@('test','-mod=readonly','-count=1','-timeout=60s','-json','./scripts');seconds=120},
  @{name='build-only';file=$go;args=@('build','-mod=readonly','-trimpath','-buildvcs=false','-o',(Join-Path $root 'bridge-source-only.exe'),'./scripts');seconds=120},
  @{name='module-verify';file=$go;args=@('mod','verify');seconds=60}
 )
 foreach($v in $vectors){
  $p=Native $v.file $v.args $v.seconds $v.name
  $result.Phases+=@{Name=$v.name;Result=$p}
  if($p.exitCode -ne 0 -or -not $p.closed -or $p.timedOut -or $p.onlyOwnStartedRootStopped -or $null -ne $p.nativeError -or $null -ne $p.cleanupError){throw ('SOURCE_PHASE_FAILED_'+$v.name)}
 }
 if($result.Phases[0].Result.stdout.Trim() -cne 'go version go1.26.11 windows/amd64'){throw 'EXACT_COMPILER_VERSION_REQUIRED'}
 $result.RequiresFormatting=([IO.File]::ReadAllText((Join-Path $out 'formatted-main.stdout.txt')) -cne [IO.File]::ReadAllText((Join-Path $repo 'scripts/wsl_npipe_bridge_windows.go')) -or [IO.File]::ReadAllText((Join-Path $out 'formatted-tests.stdout.txt')) -cne [IO.File]::ReadAllText((Join-Path $repo 'scripts/wsl_npipe_bridge_windows_test.go')))
 $result.BinarySHA256=(Get-FileHash -LiteralPath (Join-Path $root 'bridge-source-only.exe')).Hash.ToLowerInvariant()
 $result.SourceQualified=$true
}catch{$result.Failure=$_.Exception.Message}
finally{
 try{
  $after=SourceManifest
  $result.OriginalSourceUnchanged=(($after|ConvertTo-Json -Compress) -ceq ($result.SourceManifest|ConvertTo-Json -Compress))
  if(-not $result.OriginalSourceUnchanged){$result.SourceQualified=$false;$result.Failure=if($null -eq $result.Failure){'SOURCE_INPUTS_MUTATED'}else{$result.Failure+';SOURCE_INPUTS_MUTATED'}}
 }catch{$result.SourceQualified=$false;$result.Failure=if($null -eq $result.Failure){'SOURCE_MANIFEST_READBACK_FAILED'}else{$result.Failure+';SOURCE_MANIFEST_READBACK_FAILED'}}
 if($located){Pop-Location}
 foreach($key in $names){[Environment]::SetEnvironmentVariable($key,$saved[$key],'Process')}
 $result.FinishedUTC=[datetime]::UtcNow.ToString('o')
 try{$result.ResultFilePublished=$true;[IO.File]::WriteAllText((Join-Path $out 'source-result.json'),($result|ConvertTo-Json -Depth 25),[Text.UTF8Encoding]::new($false))}catch{$result.ResultFilePublished=$false;$result.Failure=if($null -eq $result.Failure){'SOURCE_RESULT_PUBLICATION_FAILED'}else{$result.Failure+';SOURCE_RESULT_PUBLICATION_FAILED'}}
 Write-Output ('GENERIC_BRIDGE_SOURCE_JSON='+($result|ConvertTo-Json -Depth 25 -Compress))
}
if(-not $result.SourceQualified -or -not $result.ResultFilePublished -or $null -ne $result.Failure){throw 'GENERIC_BRIDGE_SOURCE_NOT_QUALIFIED'}
