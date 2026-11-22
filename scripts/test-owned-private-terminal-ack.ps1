$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'owned-private-terminal-ack.ps1')
. (Join-Path $PSScriptRoot 'private-directory-helper.ps1')
$script:passed=0;$script:queries=0;$roots=[Collections.Generic.List[string]]::new();$rsa=$null
$envNames=@('RUNNER_TEMP','GITHUB_REPOSITORY','GITHUB_SHA','GITHUB_RUN_ID','GITHUB_RUN_ATTEMPT','OWNED_ACK_PUBLIC_KEY');$saved=@{}
function Assert($Value,[string]$Name){if(-not $Value){throw ('TERMINAL_AUTHORITY_CONTROL_FAILED:'+ $Name)}}
function Must-Fail([scriptblock]$Action,[string]$Name){$failed=$false;try{& $Action}catch{$failed=$true};Assert $failed $Name;$script:passed++}
function Fresh-Authority {
 $nonce=[Guid]::NewGuid().ToString('N');$root=Join-Path $env:RUNNER_TEMP ('hosted-wsl-'+$nonce)
 New-OwnedPrivateDirectory $root ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value);$roots.Add($root)
 return (New-OwnedTerminalAuthority $nonce $root ([Diagnostics.Stopwatch]::GetTimestamp()))
}
function Signed-Body($Authority){
 $payload=Get-GenericAckContextPayload $Authority.Context
 $sig=$rsa.SignData($payload,[Security.Cryptography.HashAlgorithmName]::SHA256,[Security.Cryptography.RSASignaturePadding]::Pss)
 return ,([Text.Encoding]::ASCII.GetBytes([Text.Encoding]::ASCII.GetString($payload)+'signature='+[Convert]::ToBase64String($sig)+[char]10))
}
function Invoke-OwnedGenericAckRead($Context,$Index){
 $script:queries++
 if($script:queryUnknown){return [pscustomobject]@{Scope='OWNED_ACK_QUERY_ONLY_NOT_AUTHORITY';HasAck=$false;RetryAllowed=$false;Unknown=$true;Bytes=[byte[]]@()}}
 return [pscustomobject]@{Scope='OWNED_ACK_QUERY_ONLY_NOT_AUTHORITY';HasAck=$true;RetryAllowed=$true;Unknown=$false;Bytes=[byte[]]$script:queryBody}
}
try{
 foreach($name in $envNames){$saved[$name]=[Environment]::GetEnvironmentVariable($name,'Process')}
 $env:RUNNER_TEMP=[IO.Path]::GetTempPath().TrimEnd('\');$env:GITHUB_REPOSITORY='RinisRp/hosted-wsl-capability-20261113-1e8014';$env:GITHUB_SHA='a'*40;$env:GITHUB_RUN_ID='1';$env:GITHUB_RUN_ATTEMPT='1'
 $rsa=[Security.Cryptography.RSACng]::new(3072);$p=$rsa.ExportParameters($false);$public=New-Object byte[] 387
 [Array]::Copy($p.Modulus,0,$public,0,384);[Array]::Copy($p.Exponent,0,$public,384,3);$env:OWNED_ACK_PUBLIC_KEY=[Convert]::ToBase64String($public)
 $a=Fresh-Authority;Assert ((Get-OwnedTerminalRemaining $a) -ge 6870 -and $a.Context.Nonce -cmatch '\A[0-9a-f]{32}\z') 'fresh-monotonic-authority';$script:passed++
 Assert-OwnedPrivateStartBudget $a ([Diagnostics.Stopwatch]::GetTimestamp());$script:passed++
 Must-Fail {Assert-OwnedPrivateStartBudget $a ([Diagnostics.Stopwatch]::GetTimestamp()-31L*[Diagnostics.Stopwatch]::Frequency)} 'wrapper-setup-counted-before-start'
 Must-Fail {Read-OwnedTerminalAuthority $a.Context.Nonce $a.Root 0} 'trusted-bridge-origin-mandatory'
 $short=$a.PSObject.Copy();$short.ExpiresTick=[Diagnostics.Stopwatch]::GetTimestamp()+6869L*[Diagnostics.Stopwatch]::Frequency
 Must-Fail {Assert-OwnedPrivateStartBudget $short ([Diagnostics.Stopwatch]::GetTimestamp())} 'insufficient-before-start'
 $extended=$a.PSObject.Copy();$extended.ExpiresTick=[Diagnostics.Stopwatch]::GetTimestamp()+7202L*[Diagnostics.Stopwatch]::Frequency
 Must-Fail {Get-OwnedTerminalRemaining $extended} 'lease-extension-refused'
 $script:queryBody=Signed-Body $a;$script:queryUnknown=$false;$script:queries=0
 $verdict=Confirm-OwnedTerminalAck $a
 Assert ($verdict.Verified -and $script:queries -eq 1 -and -not $verdict.PrivateJobAccepted -and -not $verdict.CanonicalAccepted) 'first-signed-proof';$script:passed++
 $script:queryUnknown=$true;$memo=Confirm-OwnedTerminalAck $a
 Assert ($memo.Verified -and $script:queries -eq 1) 'memo-reverifies-without-query';$script:passed++
 $changed=$a.PSObject.Copy();$changed.Context=$a.Context.PSObject.Copy();$changed.Context.Run='2'
 Assert (-not (Confirm-OwnedTerminalAck $changed).Verified -and $script:queries -eq 1) 'memo-bound-to-context';$script:passed++
 $expired=$a.PSObject.Copy();$expired.ExpiresTick=[Diagnostics.Stopwatch]::GetTimestamp()-1
 Assert (-not (Confirm-OwnedTerminalAck $expired).Verified -and $script:queries -eq 1) 'expired-memo-refused';$script:passed++
 Assert ((Wait-OwnedTerminalHardExpiry $expired) -ceq $false) 'expiry-does-not-accept';$script:passed++
 $b=Fresh-Authority;$script:queries=0;$script:queryUnknown=$true
 Assert (-not (Confirm-OwnedTerminalAck $b).Verified -and $script:queries -eq 1) 'unknown-spends-intent';$script:passed++
 $script:queryUnknown=$false;$script:queryBody=Signed-Body $b
 Assert (-not (Confirm-OwnedTerminalAck $b).Verified -and $script:queries -eq 1) 'spent-unknown-not-retried';$script:passed++
 $c=Fresh-Authority;$script:queries=0
 Write-OwnedAckBytes $c.Root 'verified-terminal-ack.txt' (Signed-Body $c)
 Assert (-not (Confirm-OwnedTerminalAck $c).Verified -and $script:queries -eq 0) 'unowned-proof-collision-no-query';$script:passed++
 Must-Fail {New-OwnedTerminalAuthority $c.Context.Nonce $c.Root ([Diagnostics.Stopwatch]::GetTimestamp())} 'context-create-collision'
 $d=Fresh-Authority;$contextPath=Join-Path $d.Root 'owned-terminal-ack-context.json';$data=[IO.File]::ReadAllText($contextPath)|ConvertFrom-Json
 $data.Frequency=1;[IO.File]::WriteAllText($contextPath,($data|ConvertTo-Json -Depth 4 -Compress),[Text.UTF8Encoding]::new($false))
 Must-Fail {Read-OwnedTerminalAuthority $d.Context.Nonce $d.Root $d.LeaseStartedTick} 'foreign-monotonic-frequency'
 $e=Fresh-Authority;$contextPath=Join-Path $e.Root 'owned-terminal-ack-context.json';$data=[IO.File]::ReadAllText($contextPath)|ConvertFrom-Json
 $data.Context.Run='2';[IO.File]::WriteAllText($contextPath,($data|ConvertTo-Json -Depth 4 -Compress),[Text.UTF8Encoding]::new($false))
 Must-Fail {Read-OwnedTerminalAuthority $e.Context.Nonce $e.Root $e.LeaseStartedTick} 'foreign-public-run'
 Must-Fail {Read-OwnedTerminalAuthority $e.Context.Nonce (Join-Path $env:RUNNER_TEMP 'outside-ack-root') $e.LeaseStartedTick} 'root-escape-before-read'
 $g=Fresh-Authority;$contextPath=Join-Path $g.Root 'owned-terminal-ack-context.json';$data=[IO.File]::ReadAllText($contextPath)|ConvertFrom-Json
 $data.ExpiresTick+=$data.Frequency;[IO.File]::WriteAllText($contextPath,($data|ConvertTo-Json -Depth 4 -Compress),[Text.UTF8Encoding]::new($false))
 Must-Fail {Read-OwnedTerminalAuthority $g.Context.Nonce $g.Root $g.LeaseStartedTick} 'shifted-expiry-cannot-renew-lease'
 $other=[Security.Cryptography.RSACng]::new(3072)
 try{
  $op=$other.ExportParameters($false);$otherPublic=New-Object byte[] 387;[Array]::Copy($op.Modulus,0,$otherPublic,0,384);[Array]::Copy($op.Exponent,0,$otherPublic,384,3)
  $h=Fresh-Authority;$contextPath=Join-Path $h.Root 'owned-terminal-ack-context.json';$data=[IO.File]::ReadAllText($contextPath)|ConvertFrom-Json
  $data.PublicKeyBase64=[Convert]::ToBase64String($otherPublic);$data.Context.KeyFingerprint=Get-GenericAckKeyFingerprint $otherPublic
  [IO.File]::WriteAllText($contextPath,($data|ConvertTo-Json -Depth 4 -Compress),[Text.UTF8Encoding]::new($false))
  Must-Fail {Read-OwnedTerminalAuthority $h.Context.Nonce $h.Root $h.LeaseStartedTick} 'consistent-substituted-key-does-not-select-trust'
 }finally{$other.Dispose()}
 $f=Fresh-Authority;$script:queries=0;Write-OwnedAckBytes $f.Root 'terminal-ack-attempt.txt' (Get-GenericAckContextPayload $f.Context)
 Write-OwnedAckBytes $f.Root 'verified-terminal-ack.txt' ([Text.Encoding]::ASCII.GetBytes('unsigned-teardown=true'))
 Assert (-not (Confirm-OwnedTerminalAck $f).Verified -and $script:queries -eq 0) 'unsigned-proof-no-authority';$script:passed++
 # A valid memo may later prove external terminal truth, but never repair the
 # first failed publication/host operation. Exercise a post-write I/O fault.
 $i=Fresh-Authority;$j=Fresh-Authority;$script:queryUnknown=$false;$script:queryBody=Signed-Body $i;$script:queries=0
 $script:realWriter=(Get-Command Write-OwnedAckBytes).ScriptBlock
 function Write-OwnedAckBytes([string]$Root,[string]$Name,[byte[]]$Bytes){
  & $script:realWriter $Root $Name $Bytes
  if($Name -ceq 'verified-terminal-ack.txt'){throw 'SYNTHETIC_LATE_MEMO_IO_FAILURE'}
 }
 try{
  $failedPublication=Confirm-OwnedTerminalAck $i
  Assert (-not $failedPublication.Verified -and -not $failedPublication.OperationAccepted -and $script:queries -eq 1) 'late-memo-io-cannot-pass-first-operation';$script:passed++
 }finally{Set-Item Function:Write-OwnedAckBytes -Value $script:realWriter}
 $terminalOnly=Confirm-OwnedTerminalAck $i
 Assert ($terminalOnly.Verified -and $terminalOnly.Scope -ceq 'EXTERNAL_TERMINAL_TRUTH_ONLY_NOT_OPERATION_ACCEPTANCE' -and -not $terminalOnly.OperationAccepted -and -not $terminalOnly.PrivateJobAccepted -and $script:queries -eq 1) 'memo-reconciliation-does-not-rehabilitate-operation';$script:passed++
 $script:realRemaining=(Get-Command Get-OwnedTerminalRemaining).ScriptBlock
 $script:remainingValues=[Collections.Generic.Queue[int]]::new()
 function Get-OwnedTerminalRemaining($Authority){if($script:remainingValues.Count){return $script:remainingValues.Dequeue()};return 119}
 try{
  $script:remainingValues.Enqueue(200);$script:remainingValues.Enqueue(119)
  Assert (-not (Confirm-OwnedTerminalAck $i).Verified) 'memo-reserve-rechecked-after-signature-and-read';$script:passed++
  $script:queryBody=Signed-Body $j
  $script:remainingValues.Enqueue(200);$script:remainingValues.Enqueue(7200);$script:remainingValues.Enqueue(119)
  Assert (-not (Confirm-OwnedTerminalAck $j).Verified -and $script:remainingValues.Count -eq 0) 'fresh-reserve-rechecked-after-memo-close-and-readback';$script:passed++
 }finally{Set-Item Function:Get-OwnedTerminalRemaining -Value $script:realRemaining}
}finally{
 if($null -ne $rsa){$rsa.Dispose()}
 foreach($root in $roots){
  $full=[IO.Path]::GetFullPath($root);$expectedParent=[IO.Path]::GetFullPath($env:RUNNER_TEMP).TrimEnd('\')+'\'
  if(-not $full.StartsWith($expectedParent,[StringComparison]::OrdinalIgnoreCase) -or [IO.Path]::GetFileName($full) -cnotmatch '\Ahosted-wsl-[0-9a-f]{32}\z'){throw 'FIXTURE_CLEANUP_SCOPE_REFUSED'}
  foreach($name in @('owned-terminal-ack-context.json','terminal-ack-attempt.txt','verified-terminal-ack.txt')){$path=Join-Path $full $name;if(Test-Path -LiteralPath $path){[IO.File]::Delete($path)}}
  [IO.Directory]::Delete($full,$false)
 }
 foreach($name in $envNames){[Environment]::SetEnvironmentVariable($name,$saved[$name],'Process')}
}
[pscustomobject]@{Scope='SYNTHETIC_TERMINAL_AUTHORITY_CONTROLS_ONLY';Passed=$script:passed;PrivateExecutionStarted=$false;PrivateJobAccepted=$false;CanonicalAccepted=$false}|ConvertTo-Json -Compress