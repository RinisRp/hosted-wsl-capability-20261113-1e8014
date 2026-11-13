$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
$source=Join-Path $PSScriptRoot 'generic-supervisor-fixture-owner.ps1';$t=$null;$e=$null;$ast=[Management.Automation.Language.Parser]::ParseFile($source,[ref]$t,[ref]$e);if($e.Count){throw 'BOOTSTRAP_SOURCE_PARSE_FAILED'}
foreach($name in @('Assert-FixtureBootstrapRoot','Write-FixtureBootstrap')){$f=@($ast.FindAll({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq $name},$false));if($f.Count -ne 1){throw 'EXACT_BOOTSTRAP_FUNCTION_REQUIRED'};. ([scriptblock]::Create($f[0].Extent.Text))}
function Select-BootstrapControlBase($RunnerTemp,$ProcessTemp,$Hosted){
 if($Hosted -isnot [bool]){throw 'STRICT_HOSTED_CONTROL_FLAG_REQUIRED'}
 if($Hosted -and [string]::IsNullOrEmpty($RunnerTemp)){throw 'HOSTED_RUNNER_TEMP_CONTROL_BASE_REQUIRED'}
 if(-not [string]::IsNullOrEmpty($RunnerTemp)){
  if($RunnerTemp -isnot [string] -or $RunnerTemp -cnotmatch '\A[A-Z]:\\[A-Za-z0-9_\\-]+\z' -or -not (Test-Path -LiteralPath $RunnerTemp -PathType Container)){throw 'VALID_RUNNER_TEMP_CONTROL_BASE_REQUIRED'}
  return $RunnerTemp
 }
 if($ProcessTemp -isnot [string] -or $ProcessTemp -cnotmatch '\A[A-Z]:\\[A-Za-z0-9_\\-]+\z' -or -not (Test-Path -LiteralPath $ProcessTemp -PathType Container)){throw 'VALID_STANDALONE_CONTROL_BASE_REQUIRED'}
 return $ProcessTemp
}
function Assert-SourceTokenOrder($Text,$Tokens){$prior=-1;foreach($needle in $Tokens){$index=$Text.IndexOf($needle,[StringComparison]::Ordinal);if($index -lt 0 -or $index -le $prior -or $Text.LastIndexOf($needle,[StringComparison]::Ordinal) -ne $index){throw 'EVERY_UNIQUE_ORDERED_SOURCE_TOKEN_REQUIRED'};$prior=$index}}
$saved=$env:RUNNER_TEMP;$base=Select-BootstrapControlBase $saved $env:TEMP ($env:GITHUB_ACTIONS -ceq 'true')
@{scope='SYNTHETIC_BASE_PATH_SHAPE_ONLY';runnerTempMatches=($saved -cmatch '\A[A-Z]:\\[A-Za-z0-9_\\-]+\z');processTempMatches=($env:TEMP -cmatch '\A[A-Z]:\\[A-Za-z0-9_\\-]+\z');selectedBaseMatches=($base -cmatch '\A[A-Z]:\\[A-Za-z0-9_\\-]+\z')}|ConvertTo-Json -Compress
$testRoot=Join-Path $base ('fixture_bootstrap_'+[guid]::NewGuid().ToString('N'));[void][IO.Directory]::CreateDirectory($testRoot);$env:RUNNER_TEMP=$testRoot
$Nonce='a'*32;$LeaseRoot=Join-Path $testRoot ('owned-supervisor-'+$Nonce);[void][IO.Directory]::CreateDirectory($LeaseRoot);$rows=@()
try{
 if((Select-BootstrapControlBase $base 'C:\Users\RUNNER~1\AppData\Local\Temp' $true) -cne $base){throw 'VALID_RUNNER_TEMP_MUST_BE_PREFERRED'};$rows+=@{mode='valid-runner-base-with-8dot3-process-temp';pass=$true}
 if((Select-BootstrapControlBase $null $base $false) -cne $base){throw 'STANDALONE_FALLBACK_REQUIRED'};$rows+=@{mode='strict-standalone-fallback';pass=$true}
 foreach($entry in @(@('invalid',$base,$true),@($null,'C:\Users\RUNNER~1\AppData\Local\Temp',$false),@($null,$base,$true),@($base,$base,'true'))){$reject=$false;try{[void](Select-BootstrapControlBase $entry[0] $entry[1] $entry[2])}catch{$reject=$true};if(-not $reject){throw 'INVALID_CONTROL_BASE_ACCEPTED'};$rows+=@{mode='invalid-or-missing-hosted-base-refusal';pass=$true}}
 Assert-FixtureBootstrapRoot $Nonce $LeaseRoot $testRoot;$rows+=@{mode='exact-ordinary-root';pass=$true}
 foreach($v in @(@(('A'*32),$LeaseRoot,$testRoot),@('wrong',$LeaseRoot,$testRoot),@($null,$LeaseRoot,$testRoot),@($Nonce,($LeaseRoot+'x'),$testRoot),@($Nonce,$LeaseRoot,'relative'),@($Nonce,$LeaseRoot,($testRoot+'\..')))){$reject=$false;try{Assert-FixtureBootstrapRoot $v[0] $v[1] $v[2]}catch{$reject=$true};if(-not $reject){throw 'BAD_ROOT_ACCEPTED'};$rows+=@{mode='bad-root';pass=$true}}
 $fileTemp=Join-Path $testRoot 'file_case';[void][IO.Directory]::CreateDirectory($fileTemp);$file=Join-Path $fileTemp ('owned-supervisor-'+$Nonce);[IO.File]::WriteAllText($file,'synthetic');$reject=$false;try{Assert-FixtureBootstrapRoot $Nonce $file $fileTemp}catch{$reject=$true};if(-not $reject){throw 'FILE_ROOT_ACCEPTED'};$rows+=@{mode='file-root';pass=$true}
 $junctionTemp=Join-Path $testRoot 'junction_case';[void][IO.Directory]::CreateDirectory($junctionTemp);$target=Join-Path $testRoot 'owned_junction_target';[void][IO.Directory]::CreateDirectory($target);$junction=Join-Path $junctionTemp ('owned-supervisor-'+$Nonce);$null=New-Item -ItemType Junction -Path $junction -Target $target -ErrorAction Stop;$reject=$false;try{Assert-FixtureBootstrapRoot $Nonce $junction $junctionTemp}catch{$reject=$true};if(-not $reject){throw 'JUNCTION_ROOT_ACCEPTED'};$rows+=@{mode='junction-root';pass=$true}
 Write-FixtureBootstrap 'bootstrap-started.json' 'PRE_IMPORT' 'NONE';$record=Get-Content -LiteralPath (Join-Path $LeaseRoot 'bootstrap-started.json') -Raw|ConvertFrom-Json
 if($record.Stage -cne 'PRE_IMPORT' -or $record.Nonce -cne $Nonce -or $record.PID -ne $PID -or $record.RealPrivateJob -isnot [bool] -or $record.RealPrivateJob -or $record.CanonicalAccepted -isnot [bool] -or $record.CanonicalAccepted -or @($record.PSObject.Properties).Count -ne 8){throw 'EXACT_PUBLIC_BOOTSTRAP_RECORD_REQUIRED'};$rows+=@{mode='actual-closed-bootstrap-publication';pass=$true}
 $reject=$false;try{Write-FixtureBootstrap 'bootstrap-started.json' 'PRE_IMPORT' 'NONE'}catch{$reject=$true};if(-not $reject){throw 'BOOTSTRAP_COLLISION_OVERWROTE'};$rows+=@{mode='bootstrap-collision';pass=$true}
 foreach($v in @(@('other.json','PRE_IMPORT','NONE'),@('../outside.json','PRE_IMPORT','NONE'),@('fixture-failure.json','arbitrary error','NONE'),@('fixture-failure.json','CONTEXT_READ','arbitrary exception text'),@('fixture-failure.json','context_read','PS_ERROR'))){$reject=$false;try{Write-FixtureBootstrap $v[0] $v[1] $v[2]}catch{$reject=$true};if(-not $reject){throw 'ARBITRARY_DIAGNOSTIC_ACCEPTED'};$rows+=@{mode='fixed-code-refusal';pass=$true}}
 Write-FixtureBootstrap 'fixture-failure.json' 'IMPORT_RECORDS' 'PS_ERROR';$record=Get-Content -LiteralPath (Join-Path $LeaseRoot 'fixture-failure.json') -Raw|ConvertFrom-Json;if($record.Stage -cne 'IMPORT_RECORDS' -or $record.ExceptionKind -cne 'PS_ERROR'){throw 'FIXED_FAILURE_DIAGNOSTIC_LOST'};$rows+=@{mode='preimport-failure-independent-of-dependencies';pass=$true}
 $coordinator=[IO.File]::ReadAllText((Join-Path $PSScriptRoot 'generic-supervisor-fixture.ps1'))
 $output="[IO.File]::AppendAllText(`$env:GITHUB_OUTPUT,('out_path='+`$root+";$launch='$launch=Start-OwnedDetachedSupervisor';$plan='Write-FixtureJson (Join-Path $root ''fixture-plan.json'')';$context='$root=New-OwnedSupervisorContext'
 if(([regex]::Matches($coordinator,[regex]::Escape($output))).Count -ne 1){throw 'ONE_OWNED_EVIDENCE_OUTPUT_REQUIRED'}
 Assert-SourceTokenOrder $coordinator @($context,$plan,$output,$launch);$rows+=@{mode='source-bound-evidence-output-order';pass=$true}
 foreach($missing in @($context,$plan,$output,$launch)){$reject=$false;try{Assert-SourceTokenOrder ($coordinator.Replace($missing,'')) @($context,$plan,$output,$launch)}catch{$reject=$true};if(-not $reject){throw 'MISSING_SOURCE_TOKEN_ACCEPTED'};$rows+=@{mode='missing-coordinator-token-refusal';pass=$true}}
 $owner=[IO.File]::ReadAllText($source)
 $ownerTokens=@("Write-FixtureBootstrap 'bootstrap-started.json'",". (Join-Path `$PSScriptRoot 'generic-terminal-ack.ps1')");Assert-SourceTokenOrder $owner $ownerTokens
 if(-not $owner.Contains('$clock.Elapsed.TotalSeconds -lt 240') -or -not $coordinator.Contains('$clock.Elapsed.TotalSeconds -lt 20')){throw 'BOOTSTRAP_DEADLINE_CHANGED'};$rows+=@{mode='source-bound-bootstrap-order-and-unchanged-deadlines';pass=$true}
 foreach($missing in $ownerTokens){$reject=$false;try{Assert-SourceTokenOrder ($owner.Replace($missing,'')) $ownerTokens}catch{$reject=$true};if(-not $reject){throw 'MISSING_OWNER_TOKEN_ACCEPTED'};$rows+=@{mode='missing-owner-token-refusal';pass=$true}}
 $reject=$false;try{Assert-SourceTokenOrder 'B A' @('A','B')}catch{$reject=$true};if(-not $reject){throw 'REVERSED_SOURCE_ORDER_ACCEPTED'};$rows+=@{mode='reversed-source-order-refusal';pass=$true}
 $reject=$false;try{Assert-SourceTokenOrder 'A B A' @('A','B')}catch{$reject=$true};if(-not $reject){throw 'DUPLICATE_SOURCE_TOKEN_ACCEPTED'};$rows+=@{mode='duplicate-source-order-refusal';pass=$true}
 $proof=[ordered]@{schema=1;scope='ACTUAL_SYNTHETIC_BOOTSTRAP_FILESYSTEM_AND_ENUM_CONTROLS';sourceSHA=(Get-FileHash -LiteralPath $source).Hash.ToLowerInvariant();controls=$rows.Count;allPass=$true;rows=$rows;actualProcesses=0;network=0;realKeys=0;entryPointNotExecuted=$true;noArbitraryExceptionText=$true;canonicalAccepted=$false}
 $proof|ConvertTo-Json -Depth 5|Set-Content -LiteralPath (Join-Path $PSScriptRoot 'pure-fixture-bootstrap-controls.json') -Encoding UTF8
 @{controls=$rows.Count;allPass=$true}|ConvertTo-Json -Compress
}finally{[Environment]::SetEnvironmentVariable('RUNNER_TEMP',$(if($null -eq $saved){[Management.Automation.Language.NullString]::Value}else{$saved}),'Process')}
