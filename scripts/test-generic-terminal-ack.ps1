$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'generic-terminal-ack.ps1')
$rsa=$null;$rows=@()
function Case([string]$Name,[scriptblock]$Block,[bool]$Accept){
 $threw=$false;$receipt=$null;try{$receipt=& $Block}catch{$threw=$true}
 if($Accept){if($threw -or $receipt.PrivateJobAccepted -isnot [bool] -or $receipt.PrivateJobAccepted -cne $false -or $receipt.CanonicalAccepted -cne $false -or $receipt.MemoryErasureClaimed -cne $false -or $receipt.TeardownPermitted -cne $true){throw ('ACK_POSITIVE_CONTROL_FAILED_'+$Name)}}
 elseif(-not $threw){throw ('ACK_REFUSAL_CONTROL_FAILED_'+$Name)}
 $script:rows+=@{name=$Name;accepted=(-not $threw);pass=$true}
}
try{
 $rsa=[Security.Cryptography.RSACng]::new(3072);$public=$rsa.ExportParameters($false)
 $key=New-Object byte[] 387;[Array]::Copy($public.Modulus,0,$key,0,384);[Array]::Copy($public.Exponent,0,$key,384,3)
 $context=[pscustomobject]@{PublicRepository='RinisRp/hosted-wsl-capability-20261113-1e8014';Nonce='0123456789abcdef0123456789abcdef';SourceHead=('a'*40);Run='123456789';Attempt=1;KeyFingerprint=(Get-GenericAckKeyFingerprint $key)}
 $payload=Get-GenericAckContextPayload $context;$signature=$rsa.SignData($payload,[Security.Cryptography.HashAlgorithmName]::SHA256,[Security.Cryptography.RSASignaturePadding]::Pss)
 $text=[Text.Encoding]::ASCII.GetString($payload)+'signature='+[Convert]::ToBase64String($signature)+[string][char]10;$bytes=[Text.Encoding]::ASCII.GetBytes($text)
 Case 'valid-terminal-ack' {Assert-GenericTerminalAck $bytes $context $key} $true
 function CopyContext{return ($context|ConvertTo-Json|ConvertFrom-Json)}
 foreach($field in $context.PSObject.Properties.Name){foreach($value in @($null,@($context.$field),'coerced')){$bad=CopyContext;$bad.$field=$value;Case ('typed-'+$field) {Assert-GenericTerminalAck $bytes $bad $key} $false};$bad=CopyContext;$bad.PSObject.Properties.Remove($field);Case ('missing-'+$field) {Assert-GenericTerminalAck $bytes $bad $key} $false}
 foreach($pair in @(@{key='Nonce';value=('f'*32)},@{key='SourceHead';value=('b'*40)},@{key='Run';value='123456790'},@{key='Attempt';value=2},@{key='KeyFingerprint';value=('0'*64)})){$bad=CopyContext;$bad.($pair.key)=$pair.value;Case ('replay-'+$pair.key) {Assert-GenericTerminalAck $bytes $bad $key} $false}
 $bad=CopyContext;$bad|Add-Member NoteProperty Extra 'refuse';Case 'extra-context' {Assert-GenericTerminalAck $bytes $bad $key} $false
 foreach($badText in @($text.Replace([string][char]10,[string][char]13+[char]10),$text.TrimEnd([char]10),($text+[string][char]10),($text.Replace('schema=1','schema=2')),($text.Replace('privateTargetTerminal=true','privateTargetTerminal=false')),($text+'duplicate=value'+[char]10),('x'*2049))){$badBytes=[Text.Encoding]::ASCII.GetBytes($badText);Case 'noncanonical-envelope' {Assert-GenericTerminalAck $badBytes $context $key} $false}
 $tampered=[byte[]]$bytes.Clone();$tampered[$tampered.Length-2]=if($tampered[$tampered.Length-2] -eq 65){66}else{65};Case 'altered-signature' {Assert-GenericTerminalAck $tampered $context $key} $false
 $pkcs=$rsa.SignData($payload,[Security.Cryptography.HashAlgorithmName]::SHA256,[Security.Cryptography.RSASignaturePadding]::Pkcs1);$wrongPadding=[Text.Encoding]::ASCII.GetBytes([Text.Encoding]::ASCII.GetString($payload)+'signature='+[Convert]::ToBase64String($pkcs)+[char]10);Case 'pkcs1-downgrade' {Assert-GenericTerminalAck $wrongPadding $context $key} $false
 $badKey=[byte[]]$key.Clone();$badKey[386]=3;Case 'nonfixed-exponent' {Assert-GenericTerminalAck $bytes $context $badKey} $false
 $bom=[byte[]](@(239,187,191)+$bytes);Case 'utf8-bom-refused' {Assert-GenericTerminalAck $bom $context $key} $false
 Case 'string-instead-of-bytes' {Assert-GenericTerminalAck $text $context $key} $false
 function SignedEnvelope([byte[]]$Payload){$sig=$rsa.SignData($Payload,[Security.Cryptography.HashAlgorithmName]::SHA256,[Security.Cryptography.RSASignaturePadding]::Pss);return ,([Text.Encoding]::ASCII.GetBytes([Text.Encoding]::ASCII.GetString($Payload)+'signature='+[Convert]::ToBase64String($sig)+[char]10))}
 $max=CopyContext;$max.Run='9223372036854775807';$maxBytes=SignedEnvelope (Get-GenericAckContextPayload $max);Case 'positive-int64-maximum' {Assert-GenericTerminalAck $maxBytes $max $key} $true
 foreach($value in @('9223372036854775808','10000000000000000000','0','01','+1','1.0')){$bad=CopyContext;$bad.Run=$value;Case ('noncanonical-run-'+$value) {Assert-GenericTerminalAck $bytes $bad $key} $false}
 $payloadLines=[Text.Encoding]::ASCII.GetString($payload).TrimEnd([char]10).Split([char]10)
 foreach($index in 0..8){$changed=[string[]]$payloadLines.Clone();$changed[$index]+='x';$badPayload=[Text.Encoding]::ASCII.GetBytes(($changed -join [string][char]10)+[char]10);$badEnvelope=SignedEnvelope $badPayload;Case ('resigned-field-'+$index) {Assert-GenericTerminalAck $badEnvelope $context $key} $false}
 $badPayloads=@()
 $badPayloads+=@((($payloadLines[1..8]+$payloadLines[0]) -join [string][char]10)+[char]10)
 $badPayloads+=@((($payloadLines+$payloadLines[0]) -join [string][char]10)+[char]10)
 $badPayloads+=@([Text.Encoding]::ASCII.GetString($payload).Replace('privateTargetTerminal=true','privateTargetTerminal=false'))
 if($badPayloads.Count -ne 3){throw 'THREE_DISTINCT_RESIGNED_SHAPES_REQUIRED'}
 $shape=0;foreach($badPayloadText in $badPayloads){$badEnvelope=SignedEnvelope ([Text.Encoding]::ASCII.GetBytes($badPayloadText));Case ('resigned-noncanonical-or-false-'+$shape) {Assert-GenericTerminalAck $badEnvelope $context $key} $false;$shape++}
 $other=$null;try{$other=[Security.Cryptography.RSACng]::new(3072);$wrongSig=$other.SignData($payload,[Security.Cryptography.HashAlgorithmName]::SHA256,[Security.Cryptography.RSASignaturePadding]::Pss);$wrongEnvelope=[Text.Encoding]::ASCII.GetBytes([Text.Encoding]::ASCII.GetString($payload)+'signature='+[Convert]::ToBase64String($wrongSig)+[char]10);Case 'otherwise-exact-wrong-key' {Assert-GenericTerminalAck $wrongEnvelope $context $key} $false}finally{if($null -ne $other){$other.Dispose()}}
 foreach($badLength in @(0,386,388)){$lengthKey=New-Object byte[] $badLength;Case 'public-key-length' {Assert-GenericTerminalAck $bytes $context $lengthKey} $false}
 foreach($byteValue in @(0,255)){$badBytes=[byte[]]$bytes.Clone();$badBytes[0]=$byteValue;Case 'nul-or-nonascii' {Assert-GenericTerminalAck $badBytes $context $key} $false}
 $even=[byte[]]$key.Clone();$even[383]=$even[383] -band 254;Case 'even-modulus-format' {[void](Get-GenericAckKeyFingerprint $even);Assert-GenericTerminalAck $bytes $context $key} $false
 foreach($size in @(0,2049)){$badBytes=New-Object byte[] $size;Case 'ack-byte-boundary' {Assert-GenericTerminalAck $badBytes $context $key} $false}
 Case 'null-context' {Assert-GenericTerminalAck $bytes $null $key} $false
 $tok=$null;$err=$null;$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'generic-terminal-ack.ps1'),[ref]$tok,[ref]$err)
 $fn=@($ast.FindAll({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'Assert-GenericTerminalAck'},$true))[0]
 $tr=@($fn.FindAll({param($n)$n -is [Management.Automation.Language.TryStatementAst] -and $null -ne $n.Finally -and $n.Finally.Extent.Text.Contains('$publicHandle.Dispose()')},$true))
 $ret=@($fn.FindAll({param($n)$n -is [Management.Automation.Language.ReturnStatementAst]},$true))
 if($err.Count -or $tr.Count -ne 1 -or $ret.Count -ne 1 -or $ret[0].Extent.StartOffset -lt $tr[0].Extent.EndOffset){throw 'VERDICT_MUST_FOLLOW_OWNED_CLEANUP'}
 $cleanupBlock=[scriptblock]::Create(($tr[0].Finally.Statements|ForEach-Object {$_.Extent.Text}) -join [Environment]::NewLine)
 foreach($faults in @('none','rsa','public','both')){
  $scope={
   param($Mode,$Code)
   $cleanupFailed=$false
   $rsa=[pscustomobject]@{Calls=0;Fail=($Mode -in @('rsa','both'))};$publicHandle=[pscustomobject]@{Calls=0;Fail=($Mode -in @('public','both'))}
   foreach($handle in @($rsa,$publicHandle)){$handle|Add-Member ScriptMethod Dispose {$this.Calls++;if($this.Fail){throw 'SYNTHETIC_DISPOSE_FAULT'}}}
   . $Code
   if($rsa.Calls -ne 1 -or $publicHandle.Calls -ne 1 -or $cleanupFailed -cne ($Mode -cne 'none')){throw 'INDEPENDENT_ACK_CLEANUP_ORACLE_FAILED'}
  }; & $scope $faults $cleanupBlock
  $rows+=@{name=('independent-dispose-'+$faults);accepted=($faults -ceq 'none');pass=$true}
 }
 $proof=@{schema=1;scope='SYNTHETIC_EPHEMERAL_RSA3072_ACK_CONTROLS_ONLY';controls=$rows.Count;allPass=$true;sourceSHA=(Get-FileHash -LiteralPath (Join-Path $PSScriptRoot 'generic-terminal-ack.ps1')).Hash.ToLowerInvariant();rows=$rows;realKeysCreated=0;syntheticEphemeralKeyOnly=$true;privateKeyExported=$false;networkCalls=0;refsWritten=0;realSession=$false;canonicalAccepted=$false}
 $p=Join-Path $PSScriptRoot 'pure-ack-controls.json';[IO.File]::WriteAllText($p,($proof|ConvertTo-Json -Depth 8),[Text.UTF8Encoding]::new($false));@{controls=$rows.Count;allPass=$true;sha=(Get-FileHash $p).Hash.ToLowerInvariant()}|ConvertTo-Json -Compress
}finally{if($null -ne $rsa){$rsa.Dispose()}}
