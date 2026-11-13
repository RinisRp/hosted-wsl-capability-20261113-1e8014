$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
$source=Join-Path $PSScriptRoot 'generic-fixture-records.ps1';. $source
$root=Join-Path $env:TEMP ('fixture-publication-controls-'+[guid]::NewGuid().ToString('N'));[void][IO.Directory]::CreateDirectory($root);$rows=@()
$bytes=[Text.Encoding]::ASCII.GetBytes('{"synthetic":true}')
$target=Join-Path $root 'actual-closed.json';Write-FixtureClosedBytes $target $bytes
if([Convert]::ToBase64String([IO.File]::ReadAllBytes($target)) -cne [Convert]::ToBase64String($bytes) -or (Test-Path -LiteralPath ($target+'.closed-pending'))){throw 'ACTUAL_PUBLICATION_FAILED'}
$rows+=@{mode='real-closed-rename';pass=$true}
$rejected=$false;try{Write-FixtureClosedBytes $target ([Text.Encoding]::ASCII.GetBytes('wrong'))}catch{$rejected=$true}
if(-not $rejected -or [Convert]::ToBase64String([IO.File]::ReadAllBytes($target)) -cne [Convert]::ToBase64String($bytes)){throw 'FINAL_COLLISION_OVERWROTE'};$rows+=@{mode='final-collision';pass=$true}
$target=Join-Path $root 'pending-collision.json';[IO.File]::WriteAllText(($target+'.closed-pending'),'collision');$rejected=$false;try{Write-FixtureClosedBytes $target $bytes}catch{$rejected=$true}
if(-not $rejected -or (Test-Path -LiteralPath $target) -or [IO.File]::ReadAllText(($target+'.closed-pending')) -cne 'collision'){throw 'PENDING_COLLISION_OVERWROTE'};$rows+=@{mode='pending-collision';pass=$true}
foreach($bad in @('string',(New-Object byte[] 4097),$null)){$rejected=$false;try{Write-FixtureClosedBytes (Join-Path $root 'bad') $bad}catch{$rejected=$true};if(-not $rejected){throw 'BAD_BYTES_ACCEPTED'};$rows+=@{mode='bad-bytes';pass=$true}}
$tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseFile($source,[ref]$tokens,[ref]$errors);$fn=@($ast.FindAll({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'Write-FixtureClosedBytes'},$false));if($errors.Count -or $fn.Count -ne 1){throw 'EXACT_PUBLICATION_AST_REQUIRED'}
$text=$fn[0].Extent.Text;$needle='[IO.File]::Move($pending,$Path)';if(([regex]::Matches($text,[regex]::Escape($needle))).Count -ne 1){throw 'ONLY_SINGLE_MOVE_MAPPING_REQUIRED'}
function Invoke-PublicationMoveWitness($Pending,$Target){
 if(Test-Path -LiteralPath $Target){throw 'FINAL_VISIBLE_BEFORE_MOVE'}
 $f=[IO.File]::Open($Pending,'Open','Read','None');try{if($f.Length -ne $bytes.Length){throw 'INCOMPLETE_PENDING'}}finally{$f.Dispose()}
 $script:closedBeforeVisible=$true;[IO.File]::Move($Pending,$Target)
}
. ([scriptblock]::Create($text.Replace($needle,'Invoke-PublicationMoveWitness $pending $Path')))
$script:closedBeforeVisible=$false;Write-FixtureClosedBytes (Join-Path $root 'witness.json') $bytes;if(-not $script:closedBeforeVisible){throw 'CLOSED_BEFORE_VISIBLE_UNPROVED'};$rows+=@{mode='closed-and-complete-before-final-visible';pass=$true}
$proof=[ordered]@{schema=1;scope='ACTUAL_SYNTHETIC_FILESYSTEM_PUBLICATION_ONLY';sourceSHA=(Get-FileHash -LiteralPath $source).Hash.ToLowerInvariant();controls=$rows.Count;allPass=$true;rows=$rows;mapping='Only exact single File.Move call wrapped to inspect closed pending and absent final';realFilesystem=$true;actualNetwork=0;actualProcesses=0;actualKeys=0;canonicalAccepted=$false}
$proof|ConvertTo-Json -Depth 4|Set-Content -LiteralPath (Join-Path $PSScriptRoot 'pure-fixture-publication-controls.json') -Encoding UTF8
[pscustomobject]@{controls=$rows.Count;allPass=$true}|ConvertTo-Json -Compress
