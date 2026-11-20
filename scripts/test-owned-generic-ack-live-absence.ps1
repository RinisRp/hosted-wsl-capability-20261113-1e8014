$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
$root=Split-Path -Parent $PSCommandPath
. (Join-Path $root 'generic-terminal-ack.ps1')
. (Join-Path $root 'owned-generic-ack-http.ps1')
$context=[pscustomobject]@{PublicRepository='RinisRp/hosted-wsl-capability-20261113-1e8014';Nonce='7e4128c5f4954defab1180e32d59bac7';SourceHead='188e9a0af087e8036b43c0df3c7bf3fa10eb70d8';Run='1';Attempt=1;KeyFingerprint=('f'*64)}
$names=@('OWNED_RUNNER_PACKET','GITHUB_TOKEN','GH_TOKEN','HTTP_PROXY','HTTPS_PROXY','ALL_PROXY');$saved=@{}
try{
 foreach($name in $names){$saved[$name]=[Environment]::GetEnvironmentVariable($name,'Process');[Environment]::SetEnvironmentVariable($name,'SYNTHETIC_MUST_NOT_REACH_ACK_CHILD','Process')}
 $result=Invoke-OwnedGenericAckRead $context 0
 if($result.Unknown -or $result.HasAck -or -not $result.RetryAllowed -or $result.Bytes -isnot [byte[]] -or $result.Bytes.Length -ne 0){throw 'REAL_FIXED_PUBLIC_404_OR_SANITIZED_CHILD_NOT_PROVED'}
 [pscustomobject]@{Scope='REAL_FIXED_PUBLIC_404_ONLY_NOT_PRIVATE_ACCEPTANCE';ClosedAbsence=$true;PoisonedCredentialAndProxyEnvironmentNotForwarded=$true;PrivateJobAccepted=$false;CanonicalAccepted=$false}|ConvertTo-Json -Compress
}finally{foreach($name in $names){[Environment]::SetEnvironmentVariable($name,$saved[$name],'Process')}}