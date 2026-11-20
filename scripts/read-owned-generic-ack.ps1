param([string]$Nonce,[string]$SourceHead,[string]$PublicRun,[string]$KeyFingerprint)
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
$result=[pscustomobject]@{Schema=1;Scope='OWNED_ACK_QUERY_ONLY_NOT_AUTHORITY';HasAck=$false;RetryAllowed=$false;Unknown=$true;BytesBase64=''}
try{
 foreach($name in @('OWNED_RUNNER_PACKET','GITHUB_TOKEN','GH_TOKEN','HTTP_PROXY','HTTPS_PROXY','ALL_PROXY')){
  if(-not [string]::IsNullOrEmpty([Environment]::GetEnvironmentVariable($name,'Process'))){throw 'ACK_CHILD_CREDENTIAL_OR_PROXY_ENV_REFUSED'}
 }
 Add-Type -AssemblyName System.Net.Http
 . (Join-Path $PSScriptRoot 'generic-terminal-ack.ps1')
 . (Join-Path $PSScriptRoot 'generic-ack-http-core.ps1')
 $context=[pscustomobject]@{PublicRepository='RinisRp/hosted-wsl-capability-20261113-1e8014';Nonce=$Nonce;SourceHead=$SourceHead;Run=$PublicRun;Attempt=1;KeyFingerprint=$KeyFingerprint}
 $query=Invoke-OwnedAckHttpCore $context
 $result=[pscustomobject]@{Schema=1;Scope=$query.Scope;HasAck=$query.HasAck;RetryAllowed=$query.RetryAllowed;Unknown=$query.Unknown;BytesBase64=[Convert]::ToBase64String($query.Bytes)}
}catch{}
$text=$result|ConvertTo-Json -Compress
if([Text.Encoding]::UTF8.GetByteCount($text) -gt 4096){throw 'ACK_CHILD_OUTPUT_BOUND'}
[Console]::Out.WriteLine($text)