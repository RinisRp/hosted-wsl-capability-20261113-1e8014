$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
$draftRoot=Join-Path ([IO.Path]::GetTempPath()) ('opaque-packet-controls-'+[guid]::NewGuid().ToString('N'));[void][IO.Directory]::CreateDirectory($draftRoot);$source=Join-Path $PSScriptRoot 'opaque-private-session.ps1'
$tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseFile($source,[ref]$tokens,[ref]$errors)
$function=@($ast.FindAll({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'Read-OpaqueRunnerPacket'},$false))
if($errors.Count -or $function.Count -ne 1){throw 'ONE_PURE_PACKET_VALIDATOR_REQUIRED'}
. ([scriptblock]::Create($function[0].Extent.Text))
function Encode($Data){return [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($Data|ConvertTo-Json -Depth 10 -Compress)))}
$nonce='0123456789abcdef0123456789abcdef';$rows=@()
foreach($mode in @('valid','wrong-public-head','runner-id-mismatch','job-array','job-head-array','job-id-string','job-path-escape','labels-duplicate','labels-string','wrong-nonce','foreign-host','foreign-owner','extra-field','packet-array','config-array','name-array','wrong-name','ephemeral-string','ephemeral-false','workdir-escape','unknown-jit-file','nonbase64','oversize')){
 $config=[ordered]@{agentName=('OWNED-WINDOWS-'+$nonce.Substring(0,8));gitHubUrl='https://github.com/RinisRp/synthetic-target';ephemeral=$true;workFolder='_work';agentId=123}
 switch($mode){'config-array'{$config=@($config,$config)}'name-array'{$config.agentName=@($config.agentName,$config.agentName)}'wrong-name'{$config.agentName='wrong'}'ephemeral-string'{$config.ephemeral='true'}'ephemeral-false'{$config.ephemeral=$false}'workdir-escape'{$config.workFolder='../outside'}}
 $jit=[ordered]@{'.runner'=(Encode $config);'.credentials'=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes('synthetic-noncredential'));'.credentials_rsaparams'=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes('synthetic-noncredential'))}
 if($mode -ceq 'unknown-jit-file'){$jit['unknown']='eA=='}
 $packet=[ordered]@{schema=2;nonce=$nonce;runnerId=123;publicSourceHead=('a'*40);expectedJob=@{runId=11;jobId=22;attempt=1;headSHA=('b'*40);mergeSHA=('c'*40);workflowPath='.github/workflows/synthetic.yml'};expectedLabels=@('synthetic-stage');runnerName=('OWNED-WINDOWS-'+$nonce.Substring(0,8));repositoryUrl='https://github.com/RinisRp/synthetic-target';encodedJitConfig=(Encode $jit)}
 switch($mode){'wrong-public-head'{$packet.publicSourceHead='d'*40}'runner-id-mismatch'{$packet.runnerId=124}'job-array'{$packet.expectedJob=@($packet.expectedJob,$packet.expectedJob)}'job-head-array'{$packet.expectedJob.headSHA=@(('b'*40),('b'*40))}'job-id-string'{$packet.expectedJob.jobId='22'}'job-path-escape'{$packet.expectedJob.workflowPath='.github/workflows/../../outside.yml'}'labels-duplicate'{$packet.expectedLabels=@('stage','STAGE')}'labels-string'{$packet.expectedLabels='stage'}'wrong-nonce'{$packet.nonce='f'*32}'foreign-host'{$packet.repositoryUrl='https://example.invalid/RinisRp/synthetic-target'}'foreign-owner'{$packet.repositoryUrl='https://github.com/unrelated/synthetic-target'}'extra-field'{$packet.extra='synthetic'}'packet-array'{$packet=@($packet,$packet)}}
 $encoded=Encode $packet;if($mode -ceq 'nonbase64'){$encoded='!synthetic!'};if($mode -ceq 'oversize'){$encoded='A'*49153}
 $failure=$null;$result=$null
 try{$result=Read-OpaqueRunnerPacket $encoded $nonce ('a'*40)}catch{$failure=$_.Exception.Message}
 if(($null -eq $failure) -ne ($mode -ceq 'valid')){throw ('PACKET_FALSE_ACCEPTANCE_'+$mode)}
 if($null -ne $failure -and $failure -cne 'OPAQUE_RUNNER_PACKET_INVALID'){throw 'UNSANITIZED_PACKET_FAILURE'}
 if($mode -ceq 'valid' -and ($result.Nonce -cne $nonce -or $result.AgentId -ne 123)){throw 'SYNTHETIC_PACKET_BINDING_LOST'}
 $rows+=@{mode=$mode;accepted=($null -eq $failure);sanitizedFailure=$failure;pass=$true}
}
$proof=@{SourceSHA=(Get-FileHash -LiteralPath $source).Hash.ToLowerInvariant();Controls=$rows.Count;Rows=$rows;AllPass=$true;SyntheticOnly=$true;RealCredentialsCreated=$false;RealPacketRead=$false;SessionEntryExecuted=$false;ProcessesStarted=0;NetworkCalls=0;ProviderMutations=0}
$path=Join-Path $draftRoot 'synthetic-packet-controls.json';[IO.File]::WriteAllText($path,($proof|ConvertTo-Json -Depth 8),[Text.UTF8Encoding]::new($false))
@{controls=$rows.Count;allPass=$true;syntheticOnly=$true;processes=0;network=0;proofSHA=(Get-FileHash -LiteralPath $path).Hash.ToLowerInvariant()}|ConvertTo-Json -Compress
