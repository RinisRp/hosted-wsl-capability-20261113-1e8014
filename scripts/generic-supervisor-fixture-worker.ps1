param([Parameter(Mandatory=$true)][string]$Nonce,[Parameter(Mandatory=$true)][string]$Case)
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
if($Nonce -cnotmatch '\A[a-f0-9]{32}\z' -or $env:OWNED_ACK_FIXTURE_NONCE -cne $Nonce -or $Case -cnotin @('zero','seven') -or -not [string]::IsNullOrEmpty($env:OWNED_RUNNER_PACKET)){throw 'HARMLESS_FIXTURE_WORKER_REQUIRED'}
# No credentials, network, agent or database. Both outcomes are intentional.
Start-Sleep -Milliseconds 1500
if($Case -ceq 'seven'){exit 7};exit 0
