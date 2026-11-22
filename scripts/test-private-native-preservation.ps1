$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
$sourcePath=Join-Path $PSScriptRoot 'probe-wsl.ps1';$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($sourcePath,[ref]$tokens,[ref]$errors)
if(@($errors).Count){throw 'NATIVE_SOURCE_PARSE_FAILED'}
$native=@($ast.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Native'},$true))
if($native.Count -ne 1){throw 'ONE_ACTUAL_NATIVE_DEFINITION_REQUIRED'}
. ([scriptblock]::Create($native[0].Extent.Text))
$root=Join-Path ([IO.Path]::GetTempPath()) ('native-private-boundary-'+[Guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($root);$raw=Join-Path $root 'raw';$out=Join-Path $root 'out';[void][IO.Directory]::CreateDirectory($raw);[void][IO.Directory]::CreateDirectory($out)
$script:fake=$null;$script:starts=0;$script:kills=0
function Start-Process {
 param($FilePath,$ArgumentList,$WindowStyle,[switch]$PassThru,$RedirectStandardOutput,$RedirectStandardError,$RedirectStandardInput)
 if($FilePath -cne 'inert-owned-native-fixture'){throw 'NO_REAL_EXECUTABLE_ALLOWED'}
 [IO.File]::WriteAllText($RedirectStandardOutput,'');[IO.File]::WriteAllText($RedirectStandardError,'')
 $script:starts++;$p=[pscustomobject]@{Id=1234;Handle=[IntPtr]1;StartTime=[datetime]::UtcNow;HasExited=$false;ExitCode=0;Disposed=$false}
 $p|Add-Member ScriptMethod WaitForExit {param($Milliseconds);if($null -eq $Milliseconds){return};return $this.HasExited}
 $p|Add-Member ScriptMethod Kill {$script:kills++;$this.HasExited=$true;$this.ExitCode=143}
 $p|Add-Member ScriptMethod Dispose {$this.Disposed=$true}
 $script:fake=$p;return $p
}
$passed=0
try{
 $q=Native 'inert-owned-native-fixture' @('safe') 6750 'opaque-session-owner'
 if($script:kills -ne 0 -or $q.closed -or -not $q.timedOut -or $q.onlyOwnStartedRootStopped -or $q.nativeError -cne 'PRIVATE_OWNER_TIMEOUT_PRESERVED_NO_FORCE' -or -not $script:fake.Disposed){throw 'ACTUAL_PRIVATE_NATIVE_TIMEOUT_MUST_NOT_KILL'};$passed++
 $q=Native 'inert-owned-native-fixture' @('safe') 5 'generic-owner'
 if($script:kills -ne 1 -or -not $q.closed -or -not $q.timedOut -or -not $q.onlyOwnStartedRootStopped){throw 'GENERIC_OWNER_CLEANUP_MUST_REMAIN_UNCHANGED'};$passed++
 $q=Native 'inert-owned-native-fixture' @('safe') 5 'opaque-session-owner-suffix'
 if($script:kills -ne 2 -or -not $q.closed -or -not $q.onlyOwnStartedRootStopped){throw 'ONLY_EXACT_PRIVATE_STEM_MAY_PRESERVE'};$passed++
}finally{
 foreach($dir in @($raw,$out)){foreach($file in [IO.Directory]::GetFiles($dir)){[IO.File]::Delete($file)};[IO.Directory]::Delete($dir,$false)}
 [IO.Directory]::Delete($root,$false)
}
[pscustomobject]@{Scope='ACTUAL_NATIVE_AST_WITH_INERT_PROCESS_FIXTURE';Passed=$passed;InertStartCalls=$script:starts;RealProcessesStarted=0;PrivateExecutionStarted=$false;CanonicalAccepted=$false}|ConvertTo-Json -Compress