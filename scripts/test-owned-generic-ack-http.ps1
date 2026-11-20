$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
Add-Type -AssemblyName System.Net.Http
. (Join-Path $PSScriptRoot 'generic-terminal-ack.ps1')
. (Join-Path $PSScriptRoot 'generic-ack-http-core.ps1')
. (Join-Path $PSScriptRoot 'terminal-ack-gate.ps1')
$script:passed=0
if((Get-OwnedAckHttpBudgetMilliseconds) -ne 25000){throw 'PRODUCTION_25S_BUDGET_CHANGED'}
function Get-OwnedAckHttpBudgetMilliseconds{return $script:state.Budget}
function Assert($Value,[string]$Name){if(-not $Value){throw ('ACK_HTTP_CONTROL_FAILED:'+ $Name)}}
$actualHandler=New-OwnedAckHttpHandler
try{Assert (-not $actualHandler.AllowAutoRedirect -and -not $actualHandler.UseProxy -and -not $actualHandler.UseCookies -and -not $actualHandler.UseDefaultCredentials -and $null -eq $actualHandler.Credentials -and -not $actualHandler.PreAuthenticate -and $actualHandler.AutomaticDecompression -eq [Net.DecompressionMethods]::None) 'production-handler-policy';$script:passed++}finally{$actualHandler.Dispose()}
function New-TestTask($Value){
 $o=[pscustomobject]@{Value=$Value}
 $o|Add-Member ScriptMethod GetAwaiter {return $this}
 $o|Add-Member ScriptMethod GetResult {return $this.Value}
 return $o
}
function New-TestResource([string]$Kind){
 $o=[pscustomobject]@{Kind=$Kind}
 $o|Add-Member ScriptMethod Dispose {
  $script:state.Disposed[$this.Kind]=$true
  if($this.Kind -in $script:state.CloseFaults){throw ('SYNTHETIC_CLOSE_FAULT_'+$this.Kind)}
 }
 return $o
}
function New-OwnedAckHttpHandler {$script:state.HandlerCalls++;return (New-TestResource 'handler')}
function New-OwnedAckHttpClient($Handler){
 $o=New-TestResource 'client';$o|Add-Member NoteProperty Timeout ([Threading.Timeout]::InfiniteTimeSpan)
 $o|Add-Member ScriptMethod SendAsync {
  param($Request,$Completion,$Token)
    $script:state.Requests++;$script:state.Uri=[string]$Request.Uri
  if($script:state.HeaderDelay -gt 0){Start-Sleep -Milliseconds $script:state.HeaderDelay}
  $response=New-TestResource 'response';$response|Add-Member NoteProperty StatusCode $script:state.Status
  $stream=New-TestResource 'stream'
  $stream|Add-Member ScriptMethod ReadAsync {
   param($Buffer,$Offset,$Count,$Token)
   $Token.ThrowIfCancellationRequested()
   if($script:state.ReadFault){throw 'SYNTHETIC_READ_FAILURE'}
      $remaining=$script:state.Body.Length-$script:state.Position
   if($remaining -eq 0 -and $script:state.EOFDelay -gt 0){Start-Sleep -Milliseconds $script:state.EOFDelay}
   if($remaining -gt 0 -and $script:state.BodyDelay -gt 0){Start-Sleep -Milliseconds $script:state.BodyDelay}
   $take=[Math]::Min($remaining,[Math]::Min($Count,$script:state.Chunk))
   if($take -gt 0){[Array]::Copy($script:state.Body,$script:state.Position,$Buffer,$Offset,$take);$script:state.Position+=$take}
   return (New-TestTask $take)
  }
  $content=[pscustomobject]@{Headers=[pscustomobject]@{ContentEncoding=@($script:state.Encoding);ContentLength=$script:state.Declared};Stream=$stream}
  $content|Add-Member ScriptMethod ReadAsStreamAsync {return (New-TestTask $this.Stream)}
  $response|Add-Member NoteProperty Content $content
  return (New-TestTask $response)
 }
 return $o
}
function New-OwnedAckHttpRequest([uri]$Uri){
 $o=New-TestResource 'request';$o|Add-Member NoteProperty Uri $Uri
 $headers=[pscustomobject]@{}
 $headers|Add-Member ScriptMethod TryAddWithoutValidation {param($Name,$Value);Assert ($Name -ceq 'Accept-Encoding' -and $Value -ceq 'identity') 'only-identity-header';return $true}
 $o|Add-Member NoteProperty Headers $headers;return $o
}
$context=[pscustomobject]@{PublicRepository='RinisRp/hosted-wsl-capability-20261113-1e8014';Nonce=('1'*32);SourceHead=('a'*40);Run='1';Attempt=1;KeyFingerprint=('f'*64)}
function Reset-State([int]$Status,[byte[]]$Body){
 $script:state=[ordered]@{Status=$Status;Body=$Body;Position=0;Chunk=2049;Declared=$null;Encoding=@();ReadFault=$false;CloseFaults=@();Disposed=@{};Requests=0;HandlerCalls=0;Uri=$null;Budget=25000;HeaderDelay=0;BodyDelay=0;EOFDelay=0}
}
function Check-Query([string]$Name,[bool]$ExpectedAck,[bool]$ExpectedUnknown){
 $q=Invoke-OwnedAckHttpCore $context
 Assert ($q.Scope -ceq 'OWNED_ACK_QUERY_ONLY_NOT_AUTHORITY' -and $q.Unknown -ceq $ExpectedUnknown -and $q.HasAck -ceq $ExpectedAck -and $q.RetryAllowed -ceq (-not $ExpectedUnknown) -and $q.Bytes -is [byte[]]) ($Name+'-result')
 if($ExpectedUnknown -or -not $ExpectedAck){Assert ($q.Bytes.Length -eq 0) ($Name+'-no-bytes')}
 if($ExpectedAck){Assert ([Convert]::ToBase64String($q.Bytes) -ceq [Convert]::ToBase64String($script:state.Body)) ($Name+'-exact-bytes')}
 foreach($kind in @('response','request','client','handler')){Assert $script:state.Disposed.ContainsKey($kind) ($Name+'-close-'+$kind)}
 Assert ($script:state.Requests -eq 1 -and $script:state.Uri -ceq ('https://raw.githubusercontent.com/'+$context.PublicRepository+'/owned-terminal-ack-'+$context.Nonce+'/terminal-ack.txt')) ($Name+'-one-fixed-uri')
 $script:passed++
}
Reset-State 200 ([Text.Encoding]::ASCII.GetBytes('ack'));Check-Query '200-small' $true $false
Reset-State 200 (New-Object byte[] 2048);$script:state.Chunk=1;$script:state.Declared=2048;Check-Query '200-boundary-partial-reads' $true $false
Reset-State 404 ([Text.Encoding]::ASCII.GetBytes('Not Found'));Check-Query '404-closed-absence' $false $false
foreach($code in @(301,302,307,308,401,403,429,500)) {Reset-State $code ([byte[]]@());Check-Query ('status-'+$code) $false $true}
Reset-State 200 ([byte[]]@());Check-Query 'empty-200' $false $true
Reset-State 200 (New-Object byte[] 2049);Check-Query 'chunked-oversize' $false $true
Reset-State 200 ([byte[]]@(1));$script:state.Declared=2049;Check-Query 'declared-oversize' $false $true
Reset-State 200 ([byte[]]@(1));$script:state.Declared=2;Check-Query 'truncated-declared' $false $true
Reset-State 200 ([byte[]]@(1));$script:state.Declared=0;Check-Query 'extra-body' $false $true
Reset-State 200 ([byte[]]@(1));$script:state.Encoding=@('gzip');Check-Query 'compressed-refusal' $false $true
Reset-State 200 ([byte[]]@(1));$script:state.ReadFault=$true;Check-Query 'read-failure' $false $true
foreach($code in @(200,404)){
 foreach($kind in @('stream','response','request','client','handler')){
  Reset-State $code ([Text.Encoding]::ASCII.GetBytes('ack'));$script:state.CloseFaults=@($kind)
  Check-Query ('close-fault-'+$code+'-'+$kind) $false $true
  Assert $script:state.Disposed.ContainsKey('stream') 'remaining-stream-close-attempted'
 }
}
foreach($bad in @('nonce','repository','run','fingerprint')){
 $invalid=$context.PSObject.Copy()
 switch($bad){'nonce'{$invalid.Nonce='../x'} 'repository'{$invalid.PublicRepository='other/repo'} 'run'{$invalid.Run='01'} 'fingerprint'{$invalid.KeyFingerprint='bad'}}
 Reset-State 200 ([byte[]]@(1));$q=Invoke-OwnedAckHttpCore $invalid
 Assert ($q.Unknown -and -not $q.RetryAllowed -and $q.Bytes.Length -eq 0 -and $script:state.HandlerCalls -eq 0) ('invalid-context-'+$bad)
 $script:passed++
}
foreach($phase in @('HeaderDelay','BodyDelay','EOFDelay')){
 Reset-State 200 ([byte[]]@(1));$script:state.Budget=100;$script:state[$phase]=200
 Check-Query ('aggregate-deadline-'+$phase) $false $true
}
foreach($budget in @(0,25001,$true)){
 Reset-State 200 ([byte[]]@(1));$script:state.Budget=$budget;$q=Invoke-OwnedAckHttpCore $context
 Assert ($q.Unknown -and -not $q.RetryAllowed -and $script:state.HandlerCalls -eq 0) 'invalid-budget-before-io';$script:passed++
}
$rsa=[Security.Cryptography.RSACng]::new(3072)
try{
 $p=$rsa.ExportParameters($false);$public=New-Object byte[] 387
 Assert ($p.Modulus.Length -eq 384 -and $p.Exponent.Length -eq 3) 'synthetic-public-key-shape'
 [Array]::Copy($p.Modulus,0,$public,0,384);[Array]::Copy($p.Exponent,0,$public,384,3)
 $context.KeyFingerprint=Get-GenericAckKeyFingerprint $public
 $payload=Get-GenericAckContextPayload $context
 $signature=$rsa.SignData($payload,[Security.Cryptography.HashAlgorithmName]::SHA256,[Security.Cryptography.RSASignaturePadding]::Pss)
 $signed=[Text.Encoding]::ASCII.GetBytes([Text.Encoding]::ASCII.GetString($payload)+'signature='+[Convert]::ToBase64String($signature)+[char]10)
 function Invoke-OwnedGenericAckRead($Context,$Index){return (Invoke-OwnedAckHttpCore $Context)}
 Reset-State 200 $signed;$gate=Wait-VerifiedGenericTerminalAck $context $public 7200
 Assert ($gate.Verified -and $gate.Receipt.TeardownPermitted -and -not $gate.CanonicalAccepted -and $script:state.Requests -eq 1) 'real-core-and-signature-gate';$script:passed++
 Reset-State 200 $signed;$script:state.CloseFaults=@('stream');$gate=Wait-VerifiedGenericTerminalAck $context $public 7200
 Assert (-not $gate.Verified -and $script:state.Requests -eq 1) 'valid-signature-close-fault-cannot-grant';$script:passed++
 Reset-State 404 ([byte[]]@());$script:state.CloseFaults=@('response');$gate=Wait-VerifiedGenericTerminalAck $context $public 7200
 Assert (-not $gate.Verified -and $script:state.Requests -eq 1) '404-close-fault-cannot-retry';$script:passed++
 Reset-State 200 $signed;$context.Nonce='2'*32;$gate=Wait-VerifiedGenericTerminalAck $context $public 7200
 Assert (-not $gate.Verified -and $script:state.Requests -eq 1) 'wrong-nonce-signature-stops';$script:passed++
}finally{$rsa.Dispose()}
[pscustomobject]@{Scope='SYNTHETIC_ACK_HTTP_CORE_CONTROLS_NOT_PRIVATE_ACCEPTANCE';Passed=$script:passed;RealNetworkCalls=0;PrivateJobAccepted=$false;CanonicalAccepted=$false}|ConvertTo-Json -Compress