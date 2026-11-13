# Explicit harmless diagnostic: never qualifies source, transport or a private job.
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
$env:PSModulePath='C:\Windows\System32\WindowsPowerShell\v1.0\Modules'
$nonce='6566f2cbfb624edcb50ca54f6bc7a2ca'
if($env:GITHUB_ACTIONS -cne 'true' -or $env:RUNNER_ENVIRONMENT -cne 'github-hosted' -or $env:GITHUB_REPOSITORY -cne 'RinisRp/hosted-wsl-capability-20261113-1e8014' -or $env:GITHUB_ACTOR -cne 'RinisRp' -or $env:GITHUB_REF -cne 'refs/heads/codex/wsl-npipe-6f3465' -or $env:ImageOS -cne 'win25-vs2026' -or $env:RUNNER_ARCH -cne 'X64' -or $env:PROBE_NONCE -cne $nonce -or $env:PARENT_DIAGNOSTIC -cne 'true' -or $env:GITHUB_SHA -cnotmatch '\A[0-9a-f]{40}\z'){throw 'EXACT_EXPLICIT_GENERIC_DIAGNOSTIC_CONTEXT_REQUIRED'}
if($env:RUNNER_TEMP -cnotmatch '\A[A-Z]:\\[A-Za-z0-9_\\-]+\z'){throw 'OWNED_DIAGNOSTIC_TEMP_PATH_REQUIRED'}
. (Join-Path $PSScriptRoot 'private-directory-helper.ps1')
$root=Join-Path $env:RUNNER_TEMP ('parent-diagnostic-'+$nonce)
New-OwnedPrivateDirectory $root ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value)
$raw=Join-Path $root 'raw';$out=Join-Path $root 'out'
[void][IO.Directory]::CreateDirectory($raw);[void][IO.Directory]::CreateDirectory($out)
[IO.File]::AppendAllText($env:GITHUB_OUTPUT,'out_path='+$out+[Environment]::NewLine)
$t=$null;$e=$null;$a=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'qualify-bridge-source.ps1'),[ref]$t,[ref]$e)
$f=@($a.FindAll({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'Native'},$true))
if($e.Count -or $f.Count -ne 1){throw 'EXACT_QUALIFIER_NATIVE_REQUIRED'}
. ([scriptblock]::Create($f[0].Extent.Text))
$repo=Split-Path -Parent $PSScriptRoot
$paths=@('.gitattributes','.github/workflows/capability.yml','README.md','scripts/probe-wsl.ps1','scripts/probe-linux-engine.sh','go.mod','go.sum','scripts/wsl_npipe_bridge_windows.go','scripts/wsl_npipe_bridge_windows_test.go','scripts/qualify-bridge-source.ps1','scripts/probe-windows-bridge.ps1','scripts/capability-http.sh','scripts/capability-exec.sh','scripts/generic-host-disposition.ps1','scripts/opaque-private-session.ps1','scripts/private-directory-helper.ps1','scripts/run-opaque-private-session.ps1','scripts/test-generic-host-disposition.ps1','scripts/test-opaque-lifecycle-controls.ps1','scripts/test-opaque-packet-controls.ps1','scripts/test-owned-private-directory.ps1','scripts/test-opaque-deadline-controls.ps1','scripts/test-owned-parent-boundary.ps1','scripts/diagnose-owned-parent-boundary.ps1')
function SourceManifest{$m=[ordered]@{};foreach($rel in $paths){$m[$rel]=(Get-FileHash -LiteralPath (Join-Path $repo $rel)).Hash.ToLowerInvariant()};return $m}
function WitnessValid($Data){
 $keys=@('Scope','Cases','AllPass','ParentOutputReadUnacceptedCount','KnownParentRootsClosed','KnownGrandchildrenNatural0','DirectDescendantContainmentClaimed','GlobalProcessCensusClaimed','RealPrivateSession','RealCredentials','NetworkCalls','CanonicalAccepted','ProviderRetirement')
 if($Data -isnot [pscustomobject] -or (@($Data.PSObject.Properties.Name|Sort-Object) -join '|') -cne (@($keys|Sort-Object) -join '|')){return $false}
 foreach($key in @('Cases','ParentOutputReadUnacceptedCount','KnownParentRootsClosed','KnownGrandchildrenNatural0','RealCredentials','NetworkCalls')){if($Data.$key -isnot [int] -and $Data.$key -isnot [long]){return $false}}
 foreach($key in @('AllPass','DirectDescendantContainmentClaimed','GlobalProcessCensusClaimed','RealPrivateSession','CanonicalAccepted')){if($Data.$key -isnot [bool]){return $false}}
 if($Data.Scope -isnot [string] -or $Data.Scope -cne 'GENERIC_PARENT_BOUND_AND_INDEPENDENT_CHILD_STOP_ONLY' -or $Data.ProviderRetirement -isnot [string] -or $Data.ProviderRetirement -cne 'inference only; fixture files retained on owned temporary VM'){return $false}
 return ($Data.Cases -eq 2 -and $Data.AllPass -ceq $true -and $Data.ParentOutputReadUnacceptedCount -eq 0 -and $Data.KnownParentRootsClosed -eq 2 -and $Data.KnownGrandchildrenNatural0 -eq 2 -and $Data.DirectDescendantContainmentClaimed -ceq $false -and $Data.GlobalProcessCensusClaimed -ceq $false -and $Data.RealPrivateSession -ceq $false -and $Data.RealCredentials -eq 0 -and $Data.NetworkCalls -eq 0 -and $Data.CanonicalAccepted -ceq $false)
}
$result=[ordered]@{Schema=2;Scope='THREE_ALL_REQUIRED_PARENT_TRIALS_SOURCE_ENVIRONMENT_ONLY';Nonce=$nonce;SourceHead=$env:GITHUB_SHA;SourceManifest=(SourceManifest);Phase=$null;Witness=$null;Trial=$null;TrialNonce=$null;Trials=@();RequiredTrials=3;OriginalSourceUnchanged=$false;DiagnosticPassed=$false;FailureSidecarPublished=$false;SourceQualified=$false;TransportQualified=$false;PrivateProjectAccess=$false;RealCredentials=0;JITGranted=$false;CanonicalAccepted=$false;Failure=$null}
$savedEnvironment=[ordered]@{}
foreach($key in @('GOTOOLCHAIN','GOPROXY','GOSUMDB','GOENV','GOWORK','CGO_ENABLED','GOOS','GOARCH','GOAMD64','GOMODCACHE','GOCACHE','GOPATH','GOFLAGS','GOEXPERIMENT','PROBE_NONCE')){$savedEnvironment[$key]=[Environment]::GetEnvironmentVariable($key,'Process')}
$diagnosticClock=[Diagnostics.Stopwatch]::StartNew()
try{
 $env:GOTOOLCHAIN='local';$env:GOPROXY='https://proxy.golang.org';$env:GOSUMDB='sum.golang.org';$env:GOENV='off';$env:GOWORK='off';$env:CGO_ENABLED='0';$env:GOOS='windows';$env:GOARCH='amd64';$env:GOAMD64='v1'
 $env:GOMODCACHE=Join-Path $root 'module-cache';$env:GOCACHE=Join-Path $root 'build-cache';$env:GOPATH=Join-Path $root 'go-path'
 [Environment]::SetEnvironmentVariable('GOFLAGS',[Management.Automation.Language.NullString]::Value,'Process');[Environment]::SetEnvironmentVariable('GOEXPERIMENT',[Management.Automation.Language.NullString]::Value,'Process')
 for($trial=0;$trial -lt 3;$trial++){
  if(240-$diagnosticClock.Elapsed.TotalSeconds -lt 165){throw 'DIAGNOSTIC_AGGREGATE_RESERVE_EXHAUSTED'}
  $result.Trial=$trial;$result.TrialNonce=[guid]::NewGuid().ToString('N');$result.Phase=$null;$result.Witness=$null
  $env:PROBE_NONCE=$result.TrialNonce
  # Exactly the source phase's PowerShell vector and environment. No Go/WSL/
  # Docker runs here; three successes are required, never retry-until-green.
  $result.Phase=Native (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') @('-NoProfile','-ExecutionPolicy','Bypass','-File',(Join-Path $PSScriptRoot 'test-owned-parent-boundary.ps1')) 150 ('parent-boundary-'+$trial)
  $p=$result.Phase
  if($p.exitCode -ne 0 -or -not $p.closed -or $p.timedOut -or $p.onlyOwnStartedRootStopped -or $null -ne $p.nativeError -or $null -ne $p.cleanupError -or $p.stderr -cne ''){throw 'PARENT_DIAGNOSTIC_NATIVE_UNACCEPTED'}
  $w=$p.stdout.Trim()|ConvertFrom-Json
  if(-not (WitnessValid $w)){throw 'PARENT_DIAGNOSTIC_WITNESS_UNACCEPTED'}
  $result.Witness=$w;$result.Trials+=@{Trial=$trial;Nonce=$result.TrialNonce;Phase=$p;Witness=$w}
 }
 if($result.Trials.Count -ne 3 -or $diagnosticClock.Elapsed.TotalSeconds -ge 240){throw 'ALL_THREE_BOUNDED_TRIALS_REQUIRED'}
 $result.DiagnosticPassed=$true
}catch{$result.Failure='HARMLESS_PARENT_DIAGNOSTIC_FAILED'}
finally{
 if(-not $result.DiagnosticPassed){
  try{
   $sidecar=Join-Path $env:RUNNER_TEMP ('session-owner-control-'+$result.TrialNonce+'\failure-status.json')
   $item=Get-Item -LiteralPath $sidecar -Force
   if($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $item.Length -lt 1 -or $item.Length -gt 8192){throw 'BOUNDED_SYNTHETIC_SIDECAR_REQUIRED'}
   $bytes=[IO.File]::ReadAllBytes($sidecar);if($bytes.Length -gt 8192){throw 'BOUNDED_SYNTHETIC_SIDECAR_REQUIRED'}
   $file=[IO.File]::Open((Join-Path $out 'failure-status.json'),'CreateNew','Write','None');try{$file.Write($bytes,0,$bytes.Length);$file.Flush($true)}finally{$file.Dispose()}
   $result.FailureSidecarPublished=$true
  }catch{}
 }
 foreach($key in $savedEnvironment.Keys){[Environment]::SetEnvironmentVariable($key,$savedEnvironment[$key],'Process')}
 $after=SourceManifest;$result.OriginalSourceUnchanged=(($after|ConvertTo-Json -Compress) -ceq ($result.SourceManifest|ConvertTo-Json -Compress))
 if(-not $result.OriginalSourceUnchanged){$result.DiagnosticPassed=$false;$result.Failure='DIAGNOSTIC_SOURCE_MUTATED'}
 $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($result|ConvertTo-Json -Depth 20));$file=[IO.File]::Open((Join-Path $out 'parent-diagnostic-result.json'),'CreateNew','Write','None');try{$file.Write($bytes,0,$bytes.Length);$file.Flush($true)}finally{$file.Dispose()}
}
if(-not $result.DiagnosticPassed -or $null -ne $result.Failure){throw 'HARMLESS_PARENT_DIAGNOSTIC_UNACCEPTED'}
