param([string]$Nonce,[string]$Endpoint,[string]$RunnerArchive,[string]$LeaseRoot,[long]$BridgeLeaseStartedTick,[long]$WrapperStartedTick)
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
try{
 . (Join-Path $PSScriptRoot 'opaque-private-session.ps1')
 $safe=Invoke-OpaquePrivateRunnerSession $Nonce $Endpoint $RunnerArchive $LeaseRoot $BridgeLeaseStartedTick $WrapperStartedTick
 if($safe.Finished -isnot [bool] -or $safe.Finished -cne $true -or $safe.NaturalExit -isnot [bool] -or $safe.NaturalExit -cne $true -or $safe.CanonicalAccepted -isnot [bool] -or $safe.CanonicalAccepted -cne $false){throw 'OPAQUE_PRIVATE_SESSION_UNACCEPTED'}
 Write-Output 'OWNED_OPAQUE_SESSION_OK'
 exit 0
}catch{
 # Never forward exception text, invocation values or private receipt/log data.
 Write-Output 'OWNED_OPAQUE_SESSION_FAILED_REQUIRES_PRIVATE_RECONCILIATION'
 exit 1
}
