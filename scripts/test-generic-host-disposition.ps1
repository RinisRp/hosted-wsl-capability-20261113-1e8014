$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'generic-host-disposition.ps1')
$nonce='0123456789abcdef0123456789abcdef';$head='a'*40
$sentinels=@('SYNTHETIC_PRIVATE_URL_7f3e','SYNTHETIC_SECRET_8a2d','SYNTHETIC_JOB_9c1b','C:\synthetic-private-path')
$base=[ordered]@{failure=$null;resultFilePublished=$true;cleanupVerified=$true;privateURL=$sentinels[0];secret=$sentinels[1];job=$sentinels[2];path=$sentinels[3];windowsBridge=@{PrivateSessionAccepted=$true;BridgeReport=@{Qualified=$true;Records=@{stdout=$sentinels[1]}};BridgeProcess=@{Closed=$true;Forced=$false;ExitCode=0};Native=@{stdout=($sentinels -join '|');stderr=($sentinels -join '|')}}}
$root=Join-Path ([IO.Path]::GetTempPath()) ('disposition-control-'+[guid]::NewGuid().ToString('N'));[void][IO.Directory]::CreateDirectory($root)
$count=0
foreach($mode in @('success','private-failure','bridge-unknown','wsl-unknown','forced','early-failure')){
 $data=($base|ConvertTo-Json -Depth 10 -Compress)|ConvertFrom-Json
 switch($mode){'private-failure'{$data.failure=$sentinels[1];$data.windowsBridge.PrivateSessionAccepted=$false}'bridge-unknown'{$data.windowsBridge.BridgeReport.Qualified=$false}'wsl-unknown'{$data.cleanupVerified=$false}'forced'{$data.windowsBridge.BridgeProcess.Forced=$true}'early-failure'{$data.failure=$sentinels[0];$data.windowsBridge=$null}}
 $safe=New-GenericHostDisposition $data $nonce $head;$json=$safe|ConvertTo-Json -Compress
 foreach($value in $sentinels){if($json.Contains($value)){throw 'PRIVATE_SENTINEL_IN_GENERIC_OUTPUT'}}
 if($safe.HostQualified -ne ($mode -ceq 'success') -or $safe.CanonicalAccepted -or $safe.PrivateJobAccepted -or $safe.MemoryErasureClaimed -or $safe.DirectDescendantCensus){throw 'GENERIC_OUTPUT_FALSE_ACCEPTANCE'}
 $caseRoot=Join-Path $root $mode;[void][IO.Directory]::CreateDirectory($caseRoot);$path=Join-Path $caseRoot 'generic-host-disposition.json'
 Write-GenericHostDisposition $safe $path
 $bytes=[IO.File]::ReadAllText($path);foreach($value in $sentinels){if($bytes.Contains($value)){throw 'PRIVATE_SENTINEL_IN_ARTIFACT'}}
 $before=(Get-FileHash -LiteralPath $path).Hash;$refused=$false;try{Write-GenericHostDisposition $safe $path}catch{$refused=$true}
 if(-not $refused -or (Get-FileHash -LiteralPath $path).Hash -cne $before){throw 'GENERIC_OUTPUT_COLLISION_OVERWRITTEN'}
 $count+=3
}
foreach($mode in @('scope-array','extra-private-field','string-boolean','overclaim','inconsistent')){
 $safe=New-GenericHostDisposition (($base|ConvertTo-Json -Depth 10 -Compress)|ConvertFrom-Json) $nonce $head
 switch($mode){'scope-array'{$safe.Scope=@($safe.Scope,$safe.Scope)}'extra-private-field'{$safe|Add-Member NoteProperty private $sentinels[0]}'string-boolean'{$safe.HostQualified='true'}'overclaim'{$safe.CanonicalAccepted=$true}'inconsistent'{$safe.OwnedBridgeQualified=$false}}
 $refused=$false;try{Write-GenericHostDisposition $safe (Join-Path $root 'generic-host-disposition.json')}catch{$refused=$true};if(-not $refused){throw 'INVALID_GENERIC_SCHEMA_ACCEPTED'};$count++
}
$probe=Join-Path $PSScriptRoot 'probe-wsl.ps1';$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($probe,[ref]$tokens,[ref]$errors)
$publication=@($ast.FindAll({param($n)$n -is [Management.Automation.Language.IfStatementAst] -and $n.Extent.Text.StartsWith('if($OpaquePrivateHost){') -and $n.Extent.Text.Contains('Write-GenericHostDisposition $safeDisposition')},$true))
if($errors.Count -or $publication.Count -ne 1){throw 'ONE_EXACT_PUBLICATION_BLOCK_REQUIRED'}
$publicationText=$publication[0].Extent.Text.Replace(". (Join-Path `$PSScriptRoot 'generic-host-disposition.ps1')",'# helper dependency already loaded above')
if($publicationText -ceq $publication[0].Extent.Text){throw 'EXACT_HELPER_IMPORT_REQUIRED'}
$block=[scriptblock]::Create($publicationText);$savedOutput=$env:GITHUB_OUTPUT;$savedHead=$env:GITHUB_SHA
try{
 $OpaquePrivateHost=$true;$expectedNonce=$nonce;$env:GITHUB_SHA=$head
 foreach($mode in @('publish-success','publish-collision','publish-reparse-refused')){
  $caseRoot=Join-Path $root $mode;[void][IO.Directory]::CreateDirectory($caseRoot)
  $genericDispositionPath=Join-Path $caseRoot 'generic-host-disposition.json';$env:GITHUB_OUTPUT=Join-Path $caseRoot 'github-output.txt';[IO.File]::WriteAllText($env:GITHUB_OUTPUT,'')
  $result=($base|ConvertTo-Json -Depth 10 -Compress)|ConvertFrom-Json
  if($mode -ceq 'publish-collision'){[IO.File]::WriteAllText($genericDispositionPath,$sentinels[1])}
  if($mode -ceq 'publish-reparse-refused'){
   # Simulate readback observing substitution after CreateNew. No real link
   # or privileges are needed; the exact production refusal branch executes.
   function Get-Item {param($LiteralPath,[switch]$Force);return [pscustomobject]@{PSIsContainer=$false;Attributes=[IO.FileAttributes]::ReparsePoint;Length=0}}
  }
  try{$messages=@(. $block) -join "`n"}finally{if($mode -ceq 'publish-reparse-refused'){Remove-Item Function:\Get-Item}}
  $output=[IO.File]::ReadAllText($env:GITHUB_OUTPUT)
  foreach($value in $sentinels){if($messages.Contains($value) -or $output.Contains($value)){throw 'PRIVATE_SENTINEL_IN_PUBLICATION_CHANNEL'}}
  if($mode -ceq 'publish-success'){
   if($null -ne $result.failure -or $output -cne ('generic_disposition_file='+$genericDispositionPath+[Environment]::NewLine)){throw 'VERIFIED_PUBLICATION_NOT_ADVERTISED'}
  }elseif($null -eq $result.failure -or $output.Length -ne 0 -or $messages -cne 'GENERIC_OPAQUE_HOST_DISPOSITION_UNAVAILABLE'){throw 'FAILED_PUBLICATION_ADVERTISED'}
  if($mode -ceq 'publish-collision' -and [IO.File]::ReadAllText($genericDispositionPath) -cne $sentinels[1]){throw 'COLLISION_SENTINEL_OVERWRITTEN'}
  $count++
 }
}finally{[Environment]::SetEnvironmentVariable('GITHUB_OUTPUT',$savedOutput,'Process');[Environment]::SetEnvironmentVariable('GITHUB_SHA',$savedHead,'Process')}
Write-Output ('SYNTHETIC_GENERIC_DISPOSITION_CONTROLS_PASS='+$count)
