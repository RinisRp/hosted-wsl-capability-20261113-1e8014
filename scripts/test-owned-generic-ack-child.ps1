$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'generic-terminal-ack.ps1')
. (Join-Path $PSScriptRoot 'terminal-ack-gate.ps1')
. (Join-Path $PSScriptRoot 'private-directory-helper.ps1')
$sourcePath=Join-Path $PSScriptRoot 'owned-generic-ack-http.ps1'
$before=(Get-FileHash -LiteralPath $sourcePath).Hash
$fixture=Join-Path ([IO.Path]::GetTempPath()) ('ack-child-fixture-'+[Guid]::NewGuid().ToString('N'))
$owner=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
New-OwnedPrivateDirectory $fixture $owner
$copy=Join-Path $fixture 'owned-generic-ack-http.ps1'
[IO.File]::WriteAllBytes($copy,[IO.File]::ReadAllBytes($sourcePath))
. $copy
$context=[pscustomobject]@{PublicRepository='RinisRp/hosted-wsl-capability-20261113-1e8014';Nonce=('3'*32);SourceHead=('a'*40);Run='1';Attempt=1;KeyFingerprint=('f'*64)}
$script:passed=0
function Frame([bool]$Ack,[string]$Bytes){return ([ordered]@{Schema=1;Scope='OWNED_ACK_QUERY_ONLY_NOT_AUTHORITY';HasAck=$Ack;RetryAllowed=$true;Unknown=$false;BytesBase64=$Bytes}|ConvertTo-Json -Compress)}
function ChildText([string]$Text){return ('[Console]::Out.Write('''+$Text.Replace('''','''''')+''')')}
function Run-Case([string]$Name,[string]$Child,[bool]$Unknown,[bool]$Ack){
 [IO.File]::WriteAllText((Join-Path $fixture 'read-owned-generic-ack.ps1'),$Child,[Text.UTF8Encoding]::new($false))
 $q=Invoke-OwnedGenericAckRead $context 0
 if($q.Unknown -cne $Unknown -or $q.HasAck -cne $Ack -or $q.RetryAllowed -cne (-not $Unknown) -or $q.Bytes -isnot [byte[]] -or (($Unknown -or -not $Ack) -and $q.Bytes.Length -ne 0)){throw ('ACK_CHILD_CONTROL_FAILED:'+ $Name)}
 $script:passed++
}
$absence=ChildText (Frame $false '')
Run-Case 'closed-404-frame' $absence $false $false
Run-Case 'closed-200-frame' (ChildText (Frame $true 'YQ==')) $false $true
Run-Case 'stdout-overflow' '[Console]::Out.Write((''x''*5000))' $true $false
Run-Case 'stderr-one-byte' '[Console]::Error.Write(''x'')' $true $false
Run-Case 'invalid-utf8' '[Console]::OpenStandardOutput().Write([byte[]]@(255,254),0,2)' $true $false
Run-Case 'malformed-json' '[Console]::Out.Write(''{'')' $true $false
Run-Case 'nonzero-with-good-frame' ($absence+';exit 7') $true $false
Run-Case 'extra-field' (ChildText ((Frame $false '').Replace('"Schema":1','"Unexpected":0,"Schema":1'))) $true $false
Run-Case 'string-boolean' (ChildText ((Frame $false '').Replace('"HasAck":false','"HasAck":"false"'))) $true $false
Run-Case 'noncanonical-base64' (ChildText (Frame $true 'YQ')) $true $false
Run-Case 'empty-200-frame' (ChildText (Frame $true '')) $true $false
Run-Case '404-with-bytes' (ChildText (Frame $false 'YQ==')) $true $false
Run-Case 'decoded-oversize' (ChildText (Frame $true ([Convert]::ToBase64String((New-Object byte[] 2049))))) $true $false
[IO.File]::WriteAllText((Join-Path $fixture 'read-owned-generic-ack.ps1'),$absence,[Text.UTF8Encoding]::new($false))
foreach($bad in @(-1,300,'0',$true)){
 $q=Invoke-OwnedGenericAckRead $context $bad
 if(-not $q.Unknown -or $q.RetryAllowed -or $q.HasAck -or $q.Bytes.Length -ne 0){throw 'ACK_CHILD_INDEX_REJECTED_BEFORE_IO_REQUIRED'}
 $script:passed++
}
$rsa=[Security.Cryptography.RSACng]::new(3072)
try{
 $p=$rsa.ExportParameters($false);$public=New-Object byte[] 387
 [Array]::Copy($p.Modulus,0,$public,0,384);[Array]::Copy($p.Exponent,0,$public,384,3)
 $context.KeyFingerprint=Get-GenericAckKeyFingerprint $public
 $payload=Get-GenericAckContextPayload $context
 $sig=$rsa.SignData($payload,[Security.Cryptography.HashAlgorithmName]::SHA256,[Security.Cryptography.RSASignaturePadding]::Pss)
 $signed=[Text.Encoding]::ASCII.GetBytes([Text.Encoding]::ASCII.GetString($payload)+'signature='+[Convert]::ToBase64String($sig)+[char]10)
 [IO.File]::WriteAllText((Join-Path $fixture 'read-owned-generic-ack.ps1'),(ChildText (Frame $true ([Convert]::ToBase64String($signed)))),[Text.UTF8Encoding]::new($false))
 $gate=Wait-VerifiedGenericTerminalAck $context $public 7200
 if(-not $gate.Verified -or -not $gate.Receipt.TeardownPermitted -or $gate.CanonicalAccepted){throw 'ACTUAL_PARENT_AND_SIGNATURE_GATE_REQUIRED'}
 $script:passed++
}finally{$rsa.Dispose()}
Run-Case 'native-deadline-without-EOF' 'Start-Sleep -Seconds 35' $true $false
if((Get-FileHash -LiteralPath $sourcePath).Hash -cne $before){throw 'PRODUCTION_PARENT_SOURCE_CHANGED'}
[pscustomobject]@{Scope='OWNED_SYNTHETIC_ACK_CHILD_CONTROLS_NOT_PRIVATE_ACCEPTANCE';Passed=$script:passed;RealNetworkCalls=0;ProductionSourceUnchanged=$true;FixturePath=$fixture;PrivateJobAccepted=$false;CanonicalAccepted=$false}|ConvertTo-Json -Compress