$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'generic-terminal-ack.ps1')
. (Join-Path $PSScriptRoot 'terminal-ack-gate.ps1')
$rsa=$null;$rows=@()
try{
 $rsa=[Security.Cryptography.RSACng]::new(3072);$pub=$rsa.ExportParameters($false);$key=New-Object byte[] 387;[Array]::Copy($pub.Modulus,0,$key,0,384);[Array]::Copy($pub.Exponent,0,$key,384,3)
 $ctx=[pscustomobject]@{PublicRepository='RinisRp/hosted-wsl-capability-20261113-1e8014';Nonce='0123456789abcdef0123456789abcdef';SourceHead=('a'*40);Run='1';Attempt=1;KeyFingerprint=(Get-GenericAckKeyFingerprint $key)}
 function SignFixture($c){$p=Get-GenericAckContextPayload $c;$sig=$rsa.SignData($p,[Security.Cryptography.HashAlgorithmName]::SHA256,[Security.Cryptography.RSASignaturePadding]::Pss);return ,([Text.Encoding]::ASCII.GetBytes([Text.Encoding]::ASCII.GetString($p)+'signature='+[Convert]::ToBase64String($sig)+[char]10))}
 $valid=SignFixture $ctx;$other=$ctx|ConvertTo-Json|ConvertFrom-Json;$other.Run='2';$wrongRun=SignFixture $other
 function Invoke-OwnedGenericAckRead($Context,$Index){
  if($Index -ne $script:calls){throw 'ACK_COUNTER_WAS_RESET'};$script:calls++
  $q=[pscustomobject]@{Scope='OWNED_ACK_QUERY_ONLY_NOT_AUTHORITY';HasAck=$true;RetryAllowed=$true;Unknown=$false;Bytes=$valid}
  switch($script:mode){'absent-then-valid'{if($script:calls -eq 1){$q.HasAck=$false;$q.Bytes=[byte[]]@()}};'unknown'{$q.Unknown=$true};'no-retry'{$q.RetryAllowed=$false};'typed'{$q.HasAck='true'};'malformed'{$q.Bytes=[Text.Encoding]::ASCII.GetBytes('abc')};'cross-run'{$q.Bytes=$wrongRun};'negative-with-bytes'{$q.HasAck=$false};'wrong-scope'{$q.Scope='wrong'};'typed-bytes'{$q.Bytes='string'};'oversized'{$q.Bytes=New-Object byte[] 2049}}
  return $q
 }
 foreach($script:mode in @('clean','absent-then-valid','unknown','no-retry','typed','malformed','cross-run','negative-with-bytes','wrong-scope','typed-bytes','oversized')){
  $script:calls=0;$r=Wait-VerifiedGenericTerminalAck $ctx $key 7200;$want=$script:mode -in @('clean','absent-then-valid');$wantCalls=if($script:mode -ceq 'absent-then-valid'){2}else{1}
  if($r.Verified -isnot [bool] -or $r.Verified -cne $want -or $script:calls -ne $wantCalls -or $r.PrivateJobAccepted -cne $false -or $r.CanonicalAccepted -cne $false -or ($want -and ($r.Receipt.TeardownPermitted -cne $true -or $r.Receipt.PrivateJobAccepted -cne $false))){throw ('ACK_GATE_ORACLE_'+$script:mode)}
  $rows+=@{mode=$script:mode;verified=$r.Verified;calls=$script:calls;pass=$true}
 }
 foreach($lease in @(-1,164,7201,'7200',@($true))){$script:mode='clean';$script:calls=0;$r=Wait-VerifiedGenericTerminalAck $ctx $key $lease;if($r.Verified -or $script:calls -ne 0){throw 'LEASE_WITHOUT_RESERVE_QUERIED_OR_GRANTED'};$rows+=@{mode='lease-refusal';verified=$false;calls=0;pass=$true}}
 $tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'terminal-ack-gate.ps1'),[ref]$tokens,[ref]$errors);$fn=@($ast.FindAll({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'Wait-VerifiedGenericTerminalAck'},$true));if($errors.Count -or $fn.Count -ne 1){throw 'ONE_REAL_ACK_GATE_REQUIRED'}
 $clockText=$fn[0].Extent.Text;if(([regex]::Matches($clockText,[regex]::Escape('[Diagnostics.Stopwatch]::StartNew()'))).Count -ne 1){throw 'ONE_MONOTONIC_CLOCK_REQUIRED'}
 . ([scriptblock]::Create($clockText.Replace('function Wait-VerifiedGenericTerminalAck','function Wait-InjectedAckClock').Replace('[Diagnostics.Stopwatch]::StartNew()','$testClock')))
 foreach($late in @('initial','after-query')){
  $script:mode='clean';$script:calls=0;$script:late=$late;$testClock=[pscustomobject]@{};$testClock|Add-Member ScriptProperty Elapsed {return @{TotalSeconds=$(if($script:late -ceq 'initial' -or $script:calls -gt 0){601}else{0})}}
  $r=Wait-InjectedAckClock $ctx $key 7200;if($r.Verified -or $script:calls -ne $(if($late -ceq 'initial'){0}else{1})){throw 'LATE_ACK_FALSELY_GRANTED'};$rows+=@{mode=('monotonic-'+$late);verified=$false;calls=$script:calls;pass=$true}
 }
 $proof=@{schema=1;scope='SYNTHETIC_SIGNED_ACK_GATE_ONLY_NO_PRIVATE_AUTHORITY';sourceSHA=(Get-FileHash (Join-Path $PSScriptRoot 'terminal-ack-gate.ps1')).Hash.ToLowerInvariant();controls=$rows.Count;allPass=$true;rows=$rows;actualNetwork=0;realKeys=0;syntheticEphemeralKeyOnly=$true;privateKeyExported=$false;actualPrivateSessions=0;canonicalAccepted=$false;injectedClockMapping='Only the single Stopwatch constructor in retained production AST'};$p=Join-Path $PSScriptRoot 'pure-terminal-ack-gate-controls.json';[IO.File]::WriteAllText($p,($proof|ConvertTo-Json -Depth 8),[Text.UTF8Encoding]::new($false));@{controls=$rows.Count;pass=$true;sha=(Get-FileHash $p).Hash.ToLowerInvariant()}|ConvertTo-Json -Compress
}finally{if($null -ne $rsa){$rsa.Dispose()}}
