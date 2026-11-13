# Generic signature verifier only. No network, real credentials or job acceptance.
function Get-GenericAckContextPayload($Context){
 $keys=@('PublicRepository','Nonce','SourceHead','Run','Attempt','KeyFingerprint')
 if($Context -isnot [pscustomobject] -or (@($Context.PSObject.Properties.Name|Sort-Object) -join '|') -cne (@($keys|Sort-Object) -join '|')){throw 'EXACT_GENERIC_ACK_CONTEXT_REQUIRED'}
 if($Context.PublicRepository -isnot [string] -or $Context.PublicRepository -cne 'RinisRp/hosted-wsl-capability-20261113-1e8014' -or $Context.Nonce -isnot [string] -or $Context.Nonce -cnotmatch '\A[0-9a-f]{32}\z' -or $Context.SourceHead -isnot [string] -or $Context.SourceHead -cnotmatch '\A[0-9a-f]{40}\z' -or $Context.Run -isnot [string] -or $Context.Run -cnotmatch '\A[1-9][0-9]{0,18}\z' -or ($Context.Attempt -isnot [int] -and $Context.Attempt -isnot [long]) -or $Context.Attempt -ne 1 -or $Context.KeyFingerprint -isnot [string] -or $Context.KeyFingerprint -cnotmatch '\A[0-9a-f]{64}\z'){throw 'INVALID_GENERIC_ACK_CONTEXT'}
 $runNumber=0L
 if(-not [long]::TryParse($Context.Run,[Globalization.NumberStyles]::None,[Globalization.CultureInfo]::InvariantCulture,[ref]$runNumber) -or $runNumber -lt 1 -or $runNumber.ToString([Globalization.CultureInfo]::InvariantCulture) -cne $Context.Run){throw 'CANONICAL_POSITIVE_INT64_RUN_REQUIRED'}
 $lines=@('purpose=owned-private-terminal-ack','schema=1',('publicRepo='+$Context.PublicRepository),('nonce='+$Context.Nonce),('publicSourceHead='+$Context.SourceHead),('publicRunId='+$Context.Run),'publicAttempt=1','privateTargetTerminal=true',('keyFingerprintSHA256='+$Context.KeyFingerprint))
 return ,([Text.Encoding]::ASCII.GetBytes(($lines -join [string][char]10)+[string][char]10))
}
function Get-GenericAckKeyFingerprint($PublicKeyBytes){
 if($PublicKeyBytes -isnot [byte[]] -or $PublicKeyBytes.Length -ne 387 -or $PublicKeyBytes[0] -lt 128 -or ($PublicKeyBytes[383] -band 1) -ne 1 -or $PublicKeyBytes[384] -ne 1 -or $PublicKeyBytes[385] -ne 0 -or $PublicKeyBytes[386] -ne 1){throw 'FIXED_GENERIC_RSA3072_KEY_REQUIRED'}
 $sha=[Security.Cryptography.SHA256]::Create();try{$fingerprint=([BitConverter]::ToString($sha.ComputeHash($PublicKeyBytes))).Replace('-','').ToLowerInvariant()}finally{$sha.Dispose()};return $fingerprint
}
function Assert-GenericTerminalAck($Bytes,$Context,$PublicKeyBytes){
 $ErrorActionPreference='Stop';Set-StrictMode -Version Latest
 $rsa=$null;$publicHandle=$null;$verdict=$null;$valid=$false;$cleanupFailed=$false
 try{
  $expected=Get-GenericAckContextPayload $Context
  if((Get-GenericAckKeyFingerprint $PublicKeyBytes) -cne $Context.KeyFingerprint){throw 'PINNED_ACK_KEY_REQUIRED'}
  if($Bytes -isnot [byte[]] -or $Bytes.Length -lt 1 -or $Bytes.Length -gt 2048){throw 'BOUNDED_ASCII_ACK_REQUIRED'}
  foreach($b in $Bytes){if($b -gt 127 -or $b -eq 0 -or $b -eq 13){throw 'CANONICAL_ASCII_LF_ACK_REQUIRED'}}
  $text=[Text.Encoding]::ASCII.GetString($Bytes);$lines=$text.Split([char]10)
  if($lines.Length -ne 11 -or $lines[10] -cne '' -or $lines[9] -cnotmatch '\Asignature=[A-Za-z0-9+/]{512}\z'){throw 'EXACT_ACK_ENVELOPE_REQUIRED'}
  $payload=[Text.Encoding]::ASCII.GetBytes(($lines[0..8] -join [string][char]10)+[string][char]10)
  if([Convert]::ToBase64String($payload) -cne [Convert]::ToBase64String($expected)){throw 'EXACT_ACK_OPERATION_REQUIRED'}
  $signatureText=$lines[9].Substring(10);$signature=[Convert]::FromBase64String($signatureText);if($signature.Length -ne 384 -or [Convert]::ToBase64String($signature) -cne $signatureText){throw 'CANONICAL_ACK_SIGNATURE_REQUIRED'}
  # Import only a BCRYPT_RSAPUBLIC_BLOB; the verifier generates no private key.
  $memory=[IO.MemoryStream]::new();$writer=[IO.BinaryWriter]::new($memory)
  try{
   foreach($value in @([uint32]0x31415352,[uint32]3072,[uint32]3,[uint32]384,[uint32]0,[uint32]0)){$writer.Write($value)}
   $writer.Write($PublicKeyBytes,384,3);$writer.Write($PublicKeyBytes,0,384);$writer.Flush();$blob=$memory.ToArray()
  }finally{$writer.Dispose();$memory.Dispose()}
  $publicHandle=[Security.Cryptography.CngKey]::Import($blob,[Security.Cryptography.CngKeyBlobFormat]::GenericPublicBlob)
  $rsa=[Security.Cryptography.RSACng]::new($publicHandle)
  if(-not $rsa.VerifyData($payload,$signature,[Security.Cryptography.HashAlgorithmName]::SHA256,[Security.Cryptography.RSASignaturePadding]::Pss)){throw 'INVALID_ACK_SIGNATURE'}
  $verdict=[pscustomobject][ordered]@{Schema=1;Scope='VERIFIED_TERMINAL_ACK_PERMITS_OWNED_TEARDOWN_ONLY';Nonce=$Context.Nonce;PublicSourceHead=$Context.SourceHead;PublicRun=$Context.Run;Attempt=1;PrivateTargetTerminal=$true;TeardownPermitted=$true;PrivateJobAccepted=$false;CanonicalAccepted=$false;MemoryErasureClaimed=$false}
  $valid=$true
 }catch{$valid=$false}
 finally{
  if($null -ne $rsa){try{$rsa.Dispose()}catch{$cleanupFailed=$true}}
  if($null -ne $publicHandle){try{$publicHandle.Dispose()}catch{$cleanupFailed=$true}}
 }
 if(-not $valid -or $cleanupFailed){throw [InvalidOperationException]::new('GENERIC_TERMINAL_ACK_UNACCEPTED')}
 return $verdict
}
