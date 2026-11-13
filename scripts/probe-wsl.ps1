param([switch]$OpaquePrivateHost)
$opaquePacket=[Environment]::GetEnvironmentVariable('OWNED_RUNNER_PACKET','Process')
[Environment]::SetEnvironmentVariable('OWNED_RUNNER_PACKET',[System.Management.Automation.Language.NullString]::Value,'Process')
if($OpaquePrivateHost -and [string]::IsNullOrWhiteSpace($opaquePacket)){throw 'OPAQUE_PRIVATE_PACKET_REQUIRED'}
if(-not $OpaquePrivateHost -and -not [string]::IsNullOrWhiteSpace($opaquePacket)){$opaquePacket=$null;throw 'OPAQUE_PACKET_REFUSED_IN_GENERIC_PROBE'}
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$env:PSModulePath='C:\Windows\System32\WindowsPowerShell\v1.0\Modules'
$expectedNonce='90e620c965b847819f8a4b4205cf8027'
$contextChecks=[ordered]@{
 githubActions=($env:GITHUB_ACTIONS -ceq 'true')
 hostedEnvironment=($env:RUNNER_ENVIRONMENT -ceq 'github-hosted')
 exactRepository=($env:GITHUB_REPOSITORY -ceq 'RinisRp/hosted-wsl-capability-20261113-1e8014')
 exactActor=($env:GITHUB_ACTOR -ceq 'RinisRp')
 exactImage=($env:ImageOS -ceq 'win25-vs2026')
 exactArchitecture=($env:RUNNER_ARCH -ceq 'X64')
 exactRef=($env:GITHUB_REF -ceq 'refs/heads/codex/wsl-npipe-6f3465')
 exactNonce=($env:PROBE_NONCE -ceq $expectedNonce)
}
$imageEnum=switch -CaseSensitive ($env:ImageOS){'win25'{'WIN25'} 'win25-vs2026'{'WIN25_VS2026'} $null{'MISSING'} default{'OTHER'}}
Write-Output ('HOSTED_WSL_CONTEXT_GUARDS_JSON='+([ordered]@{checks=$contextChecks;imageEnum=$imageEnum}|ConvertTo-Json -Depth 4 -Compress))
if(@($contextChecks.Values|Where-Object {$_ -cne $true}).Count){throw 'EXACT_ISOLATED_WIN25_PROBE_CONTEXT_REQUIRED'}
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
$principal=[Security.Principal.WindowsPrincipal]::new($identity)
$machine=Get-CimInstance Win32_ComputerSystem
if($machine.Model -cne 'Virtual Machine' -or -not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'HOSTED_ADMIN_VM_REQUIRED'}
if($env:RUNNER_TEMP -cnotmatch '\A[A-Z]:\\[A-Za-z0-9_\\-]+\z'){throw 'OWNED_TEMP_WITHOUT_ARGUMENT_METACHARACTERS_REQUIRED'}
$root=Join-Path $env:RUNNER_TEMP ('hosted-wsl-'+$expectedNonce)
if(Test-Path -LiteralPath $root){throw 'FRESH_PROBE_ROOT_REQUIRED'}
[void][IO.Directory]::CreateDirectory($root)
$acl=[Security.AccessControl.DirectorySecurity]::new();$acl.SetAccessRuleProtection($true,$false);$acl.SetOwner($identity.User)
foreach($sidText in @($identity.User.Value,'S-1-5-18','S-1-5-32-544')){
 $rule=[Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sidText),'FullControl','ContainerInherit,ObjectInherit','None','Allow')
 [void]$acl.AddAccessRule($rule)
}
Set-Acl -LiteralPath $root -AclObject $acl
$out=Join-Path $root $(if($OpaquePrivateHost){'private-diagnostics'}else{'outputs'});[void][IO.Directory]::CreateDirectory($out)
$raw=Join-Path $root 'raw-native';[void][IO.Directory]::CreateDirectory($raw)
$genericDispositionPath=$null
$script:opaqueReconciliationHeld=$false
function Wait-OpaqueReconciliation{
 if($script:opaqueReconciliationHeld){return}
 $script:opaqueReconciliationHeld=$true
 Write-Output 'OWNED_OPAQUE_HOST_FAILED_REQUIRES_PRIVATE_RECONCILIATION'
 # Allow the exact private-job controller to cancel/reconcile its target
 # before owned engine teardown. Expiry is failure, never cleanup acceptance.
 $reconcileClock=[Diagnostics.Stopwatch]::StartNew()
 while($reconcileClock.Elapsed.TotalSeconds -lt 600){Start-Sleep -Seconds 1}
}
if($OpaquePrivateHost){
 $genericDirectory=Join-Path $root 'generic-disposition';[void][IO.Directory]::CreateDirectory($genericDirectory)
 $genericDispositionPath=Join-Path $genericDirectory 'generic-host-disposition.json'
}else{[IO.File]::AppendAllText($env:GITHUB_OUTPUT,'out_path='+$out+[Environment]::NewLine)}
$name='hosted-wsl-'+$expectedNonce;$install=Join-Path $root 'distribution'
$wsl=Join-Path $env:SystemRoot 'System32\wsl.exe'
function Native([string]$File,[string[]]$Arguments,[int]$Seconds,[string]$Stem,[string]$InputFile){
 foreach($a in $Arguments){if($a -match '[\s"&|<>]'){throw 'FIXED_NATIVE_ARGUMENTS_ONLY'}}
 if(-not [string]::IsNullOrEmpty($InputFile)){
  $expectedInput=Join-Path $root 'exec-input.txt'
  if($InputFile -cne $expectedInput){throw 'EXACT_OWNED_ASCII_INPUT_PATH_REQUIRED'}
  $inputItem=Get-Item -LiteralPath $InputFile -Force
  if($inputItem.PSIsContainer -or ($inputItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $inputItem.Length -ne 32 -or [IO.File]::ReadAllText($InputFile) -cne $expectedNonce){throw 'EXACT_OWNED_ASCII_NONCE_INPUT_REQUIRED'}
 }
 $stdout=Join-Path $raw ($Stem+'.stdout.txt');$stderr=Join-Path $raw ($Stem+'.stderr.txt')
 $p=$null;$timedOut=$false;$exitCode=$null;$closed=$false;$ownRootStopped=$false;$created=$null;$childId=$null;$nativeError=$null;$cleanupError=$null
 try{
  $start=@{FilePath=$File;ArgumentList=$Arguments;WindowStyle='Hidden';PassThru=$true;RedirectStandardOutput=$stdout;RedirectStandardError=$stderr}
  if(-not [string]::IsNullOrEmpty($InputFile)){$start.RedirectStandardInput=$InputFile}
  $p=Start-Process @start
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
function Test-LinuxEngineResult($Data,[string]$Nonce){
 if($null -eq $Data -or $Data -isnot [pscustomobject]){return $false}
 $keys=@('schema','nonce','ostype','endpoint','engineId','dockerVersion','image','containerId','containerExitCode','containerOutput','initialContainers','finalContainers','containerRemoved','onlyOwnedContainerTouched')
 if((@($Data.PSObject.Properties.Name|Sort-Object) -join '|') -cne (@($keys|Sort-Object) -join '|')){return $false}
 foreach($key in @('schema','containerExitCode','initialContainers','finalContainers')){if($Data.$key -isnot [int] -and $Data.$key -isnot [long]){return $false}}
 foreach($key in @('nonce','ostype','endpoint','engineId','dockerVersion','image','containerId','containerOutput')){if($Data.$key -isnot [string]){return $false}}
 foreach($key in @('containerRemoved','onlyOwnedContainerTouched')){if($Data.$key -isnot [bool] -or $Data.$key -cne $true){return $false}}
 return ($Data.schema -eq 1 -and $Data.nonce -ceq $Nonce -and $Data.ostype -ceq 'linux' -and $Data.endpoint -ceq 'unix:///var/run/docker.sock' -and $Data.engineId -cmatch '\A[0-9A-Za-z:._-]{1,128}\z' -and $Data.containerId -cmatch '\A[0-9a-f]{64}\z' -and $Data.containerExitCode -eq 0 -and $Data.containerOutput -ceq $Nonce -and $Data.initialContainers -eq 0 -and $Data.finalContainers -eq 0 -and $Data.dockerVersion -ceq '29.9.3' -and $Data.image -ceq 'busybox@sha256:66a6306db78bf2dbf3487f293aa8d6990d8e506fdffab9cc43fe422becf886e4')
}
function OwnRegistration{
 $key='HKCU:\Software\Microsoft\Windows\CurrentVersion\Lxss'
 if(-not (Test-Path -LiteralPath $key)){return @()}
 return @(Get-ChildItem -LiteralPath $key|ForEach-Object {Get-ItemProperty -LiteralPath $_.PSPath}|Where-Object {$_.DistributionName -ceq $name})
}
$result=[ordered]@{schema=1;scope='GENERIC_HOSTED_WSL2_LINUX_DOCKER_CAPABILITY_ONLY';nonce=$expectedNonce;sourceHead=$env:GITHUB_SHA;sourceScriptSHA256=(Get-FileHash -LiteralPath $PSCommandPath).Hash.ToLowerInvariant();imageOS=$env:ImageOS;imageVersion=$env:ImageVersion;runnerEnvironment=$env:RUNNER_ENVIRONMENT;machineModel=$machine.Model;totalPhysicalBytes=$machine.TotalPhysicalMemory;beforeFreeMiB=[math]::Floor((Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory/1024);features=$null;cpu=$null;wslVersion=$null;dockerInfo=$null;linuxDocker=$null;linuxEngine=$null;linuxDockerProved=$false;windowsBridge=$null;windowsBridgeQualified=$false;linuxScriptSHA256=$null;engineAfterMemory=$null;engineLiveAfterMemory=$false;memoryMeasuredUtc=$null;importAttempted=$false;import=$null;uname=$null;registeredVersion=$null;afterKernelFreeMiB=$null;cleanup=$null;cleanupVerified=$false;kernelStarted=$false;candidateHeadroom6144=$false;databaseCapabilityGranted=$false;canonicalAccepted=$false;projectRunnerRegistrationPerformed=$false;externalRepositoryChanged=$false;securitySettingsChanged=$false;globalWslShutdownUsed=$false;importOperationClosureProved=$false;resultFilePublished=$false;failure=$null;finishedUtc=$null}
try{
 $result.cpu=@(Get-CimInstance Win32_Processor|Select-Object VMMonitorModeExtensions,VirtualizationFirmwareEnabled,SecondLevelAddressTranslationExtensions)
 $result.features=@(foreach($feature in @('Microsoft-Windows-Subsystem-Linux','VirtualMachinePlatform')){$f=Get-WindowsOptionalFeature -Online -FeatureName $feature;[ordered]@{name=$feature;state=[string]$f.State}})
 $result.wslVersion=Native $wsl @('--version') 20 'wsl-version'
 $docker=(Get-Command docker.exe -ErrorAction Stop).Source
 $result.dockerInfo=Native $docker @('info','--format','{{.OSType}}') 20 'docker-info'
 if(@($result.features|Where-Object {$_.state -cne 'Enabled'}).Count){throw 'WSL_OR_VIRTUAL_MACHINE_PLATFORM_NOT_ENABLED_NO_SETTING_CHANGE'}
 if(@(OwnRegistration).Count){throw 'OWN_DISTRO_NAME_ALREADY_EXISTS_NO_IMPORT_OR_DELETE'}
 $archive=Join-Path $root 'alpine-minirootfs-3.24.4-x86_64.tar.gz'
 Invoke-WebRequest -UseBasicParsing -Uri 'https://dl-cdn.alpinelinux.org/alpine/v3.24/releases/x86_64/alpine-minirootfs-3.24.4-x86_64.tar.gz' -OutFile $archive
 if((Get-FileHash -LiteralPath $archive).Hash.ToLowerInvariant() -cne 'cdaa38cb8de3537967ee5b6c9b6cd00cc962da2b018e6eea48696bb274923012'){throw 'OFFICIAL_ALPINE_ROOTFS_DIGEST_MISMATCH'}
 $result.importAttempted=$true
 $result.import=Native $wsl @('--import',$name,$install,$archive,'--version','2') 120 'wsl-import'
 if($result.import.timedOut -or $result.import.exitCode -ne 0 -or -not $result.import.closed -or $null -ne $result.import.nativeError -or $null -ne $result.import.cleanupError){throw 'ONE_WSL2_IMPORT_FAILED_NO_RETRY'}
 $reg=@(OwnRegistration)
 if($reg.Count -ne 1 -or [int]$reg[0].Version -ne 2){throw 'ACTUAL_OWN_VERSION2_REGISTRATION_REQUIRED'}
 $result.registeredVersion=[int]$reg[0].Version
 $result.uname=Native $wsl @('--distribution',$name,'--exec','/bin/uname','-a') 60 'wsl-uname'
 $result.kernelStarted=($result.uname.exitCode -eq 0 -and -not $result.uname.timedOut -and $result.uname.closed -and $null -eq $result.uname.nativeError -and $null -eq $result.uname.cleanupError -and $result.uname.stdout -match '(?i)microsoft.*WSL2')
 if(-not $result.kernelStarted){throw 'ACTUAL_VERSION2_KERNEL_START_NOT_PROVED'}
 if(-not [string]::IsNullOrWhiteSpace($env:WSLENV)){throw 'NO_CUSTOM_WINDOWS_TO_LINUX_ENVIRONMENT_FORWARDING_ALLOWED'}
 $linuxSource=Join-Path $PSScriptRoot 'probe-linux-engine.sh'
 $linuxCopy=Join-Path $root 'probe-linux-engine.sh'
 Copy-Item -LiteralPath $linuxSource -Destination $linuxCopy -ErrorAction Stop
 $result.linuxScriptSHA256=(Get-FileHash -LiteralPath $linuxCopy).Hash.ToLowerInvariant()
 $linuxPath='/mnt/'+$linuxCopy.Substring(0,1).ToLowerInvariant()+'/'+$linuxCopy.Substring(3).Replace('\','/')
 $result.linuxDocker=Native $wsl @('--distribution',$name,'--exec','/usr/bin/env','-i','PATH=/usr/sbin:/usr/bin:/sbin:/bin','/bin/ash',$linuxPath,$expectedNonce) 300 'linux-engine'
 if($result.linuxDocker.exitCode -ne 0 -or $result.linuxDocker.timedOut -or -not $result.linuxDocker.closed -or $null -ne $result.linuxDocker.nativeError -or $null -ne $result.linuxDocker.cleanupError -or $result.linuxDocker.onlyOwnStartedRootStopped){throw 'OWN_LINUX_DOCKER_PROBE_FAILED_NO_RETRY'}
 $engineMatches=[regex]::Matches($result.linuxDocker.stdout,'(?m)^HOSTED_LINUX_ENGINE_JSON=(\{[^\r\n]+\})\r?$')
 if($engineMatches.Count -ne 1){throw 'ONE_BOUNDED_LINUX_ENGINE_RESULT_REQUIRED'}
 $result.linuxEngine=$engineMatches[0].Groups[1].Value|ConvertFrom-Json
 $e=$result.linuxEngine
 $result.linuxDockerProved=Test-LinuxEngineResult $e $expectedNonce
 if(-not $result.linuxDockerProved){throw 'ACTUAL_PINNED_LINUX_ENGINE_AND_CONTAINER_CLEANUP_REQUIRED'}
 . (Join-Path $PSScriptRoot 'probe-windows-bridge.ps1')
 $runnerArchive=$null
 if($OpaquePrivateHost){
  $runnerArchive=Join-Path $root 'official-runner.zip'
  Invoke-WebRequest -UseBasicParsing -Uri 'https://github.com/actions/runner/releases/download/v2.338.2/actions-runner-win-x64-2.338.2.zip' -OutFile $runnerArchive
  if((Get-FileHash -LiteralPath $runnerArchive).Hash.ToLowerInvariant() -cne 'a1f17aa987fc8158bc7521d284912267a0d01b7c2c4684b33c86783b5e8221cc'){throw 'OFFICIAL_RUNNER_ARCHIVE_REQUIRED'}
 }
 $result.windowsBridge=Invoke-WindowsBridgeProbe $root $out $expectedNonce $name $result.linuxEngine.engineId $opaquePacket $runnerArchive
 $opaquePacket=$null
 $result.windowsBridgeQualified=($null -ne $result.windowsBridge -and $result.windowsBridge.Qualified -ceq $true)
 if(-not $result.windowsBridgeQualified){throw 'WINDOWS_CLI_NPIPE_BINARY_LOOPBACK_NOT_QUALIFIED'}
 $result.afterKernelFreeMiB=[math]::Floor((Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory/1024)
 $result.memoryMeasuredUtc=[datetime]::UtcNow.ToString('o')
 $result.engineAfterMemory=Native $wsl @('--distribution',$name,'--exec','/usr/bin/env','-i','PATH=/usr/sbin:/usr/bin:/sbin:/bin','DOCKER_HOST=unix:///var/run/docker.sock','/usr/bin/docker','info','--format','{{.ID}}/{{.OSType}}/{{.ServerVersion}}') 30 'linux-after-memory'
 $n=$result.engineAfterMemory
 $result.engineLiveAfterMemory=($n.exitCode -eq 0 -and $n.closed -and -not $n.timedOut -and -not $n.onlyOwnStartedRootStopped -and $null -eq $n.nativeError -and $null -eq $n.cleanupError -and $n.stdout.Trim() -ceq ($result.linuxEngine.engineId+'/linux/29.9.3'))
 if(-not $result.engineLiveAfterMemory){throw 'SAME_LINUX_ENGINE_MUST_BE_ALIVE_AFTER_RAM_MEASUREMENT'}
 $result.candidateHeadroom6144=($result.kernelStarted -and $result.linuxDockerProved -and $result.windowsBridgeQualified -and $result.engineLiveAfterMemory -and $result.afterKernelFreeMiB -ge 6144)
 if(-not $result.kernelStarted){throw 'ACTUAL_VERSION2_KERNEL_START_NOT_PROVED'}
 if(-not $result.candidateHeadroom6144){throw 'UNCHANGED6144_NOT_AVAILABLE_AFTER_KERNEL'}
}catch{$result.failure=$_.Exception.Message;if($OpaquePrivateHost){Wait-OpaqueReconciliation}}
finally{
 try{
  $result.importOperationClosureProved=(-not $result.importAttempted -or ($null -ne $result.import -and $result.import.exitCode -eq 0 -and $result.import.closed -and -not $result.import.timedOut -and -not $result.import.onlyOwnStartedRootStopped -and $null -eq $result.import.nativeError -and $null -eq $result.import.cleanupError))
  $reg=@(OwnRegistration)
  if($result.importAttempted -and $reg.Count -eq 1){
   $basePath=[string]$reg[0].BasePath
   if($basePath.StartsWith('\\?\',[StringComparison]::Ordinal)){$basePath=$basePath.Substring(4)}
   if([IO.Path]::GetFullPath($basePath).TrimEnd('\') -ine [IO.Path]::GetFullPath($install).TrimEnd('\')){throw 'UNREGISTER_OWN_EXACT_INSTALL_PATH_REQUIRED'}
   if((Get-Item -LiteralPath $install -Force).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'OWN_INSTALL_REPARSE_REFUSED'}
   $result.cleanup=Native $wsl @('--unregister',$name) 45 'wsl-unregister'
   $result.cleanupVerified=($result.cleanup.exitCode -eq 0 -and -not $result.cleanup.timedOut -and $result.cleanup.closed -and $null -eq $result.cleanup.nativeError -and $null -eq $result.cleanup.cleanupError -and @(OwnRegistration).Count -eq 0 -and $result.importOperationClosureProved)
  }elseif($reg.Count -eq 0){$result.cleanupVerified=$result.importOperationClosureProved}
  if(-not $result.cleanupVerified){throw 'OWN_DISTRO_CLEANUP_UNPROVED'}
 }catch{$result.failure=if($null -eq $result.failure){$_.Exception.Message}else{$result.failure+';'+$_.Exception.Message}}
 $result.finishedUtc=[datetime]::UtcNow.ToString('o')
 try{$result.resultFilePublished=$true;[IO.File]::WriteAllText((Join-Path $out 'probe-result.json'),($result|ConvertTo-Json -Depth 20),[Text.UTF8Encoding]::new($false))}catch{$result.resultFilePublished=$false;$result.failure=if($null -eq $result.failure){'RESULT_FILE_PUBLICATION_FAILED'}else{$result.failure+';RESULT_FILE_PUBLICATION_FAILED'}}
 if($OpaquePrivateHost){
  try{
   . (Join-Path $PSScriptRoot 'generic-host-disposition.ps1')
   $safeDisposition=New-GenericHostDisposition $result $expectedNonce $env:GITHUB_SHA
   Write-GenericHostDisposition $safeDisposition $genericDispositionPath
   [IO.File]::AppendAllText($env:GITHUB_OUTPUT,'generic_disposition_file='+$genericDispositionPath+[Environment]::NewLine)
   Write-Output ('GENERIC_OPAQUE_HOST_DISPOSITION_JSON='+($safeDisposition|ConvertTo-Json -Compress))
  }catch{$result.failure=if($null -eq $result.failure){'GENERIC_DISPOSITION_PUBLICATION_FAILED'}else{$result.failure+';GENERIC_DISPOSITION_PUBLICATION_FAILED'};Write-Output 'GENERIC_OPAQUE_HOST_DISPOSITION_UNAVAILABLE'}
 }else{Write-Output ('HOSTED_WSL_CAPABILITY_JSON='+($result|ConvertTo-Json -Depth 20 -Compress))}
}
if($null -ne $result.failure -or -not $result.kernelStarted -or -not $result.linuxDockerProved -or -not $result.windowsBridgeQualified -or -not $result.engineLiveAfterMemory -or -not $result.candidateHeadroom6144 -or -not $result.cleanupVerified -or -not $result.resultFilePublished){throw 'HOSTED_CAPABILITY_NOT_QUALIFIED_SEE_PRESERVED_RESULT'}
