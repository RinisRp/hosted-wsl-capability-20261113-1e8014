$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'owned-private-terminal-ack.ps1')
$script:verified=$false;$script:holds=0;$script:kills=0
function Confirm-OwnedTerminalAck($Authority){return [pscustomobject]@{Verified=$script:verified}}
function Wait-OwnedTerminalHardExpiry($Authority){$script:holds++;return $false}
function Inert-Process([bool]$Exited){
 $p=[pscustomobject]@{HasExited=$Exited}
 $p|Add-Member ScriptMethod Kill {$script:kills++;$this.HasExited=$true}
 $p|Add-Member ScriptMethod WaitForExit {param($Milliseconds);return $this.HasExited}
 return $p
}
$passed=0
$p=Inert-Process $false;$q=Reconcile-OwnedPrivateRoot $p $true ([pscustomobject]@{})
if($q.Closed -or $q.Forced -or $script:kills -ne 0 -or $script:holds -ne 1 -or $q.Faults -notcontains 'PRIVATE_TERMINAL_ACK_UNPROVED_NO_ROOT_STOP'){throw 'ACTIVE_ROOT_WITHOUT_ACK_MUST_NOT_STOP'};$passed++
$script:verified=$true;$originalFailure='KEPT_ORIGINAL_FAILURE';$q=Reconcile-OwnedPrivateRoot $p $true ([pscustomobject]@{})
if(-not $q.Closed -or -not $q.Forced -or -not $q.TerminalVerified -or $script:kills -ne 1 -or $q.Faults -notcontains 'PRIVATE_OWN_ROOT_FORCED_AFTER_VERIFIED_TERMINAL' -or $originalFailure -cne 'KEPT_ORIGINAL_FAILURE'){throw 'ACK_PERMITS_ONLY_FAILED_RECONCILIATION'};$passed++
$p=Inert-Process $true;$q=Reconcile-OwnedPrivateRoot $p $true ([pscustomobject]@{})
if(-not $q.Closed -or $q.Forced -or $q.Faults.Count -ne 0 -or $script:kills -ne 1){throw 'NATURAL_ROOT_EXIT_MUST_NOT_FORCE'};$passed++
$p=Inert-Process $false;$q=Reconcile-OwnedPrivateRoot $p $false ([pscustomobject]@{})
if($q.Closed -or $q.Forced -or $script:kills -ne 1 -or $q.Faults -notcontains 'PRIVATE_OWN_ROOT_CLOSURE_FAILED'){throw 'UNHELD_ROOT_MUST_NOT_STOP'};$passed++
# Execute the real parent reconciliation functions and the actual final host
# predicate. A late failed memo write can leave valid signed bytes; later external
# truth permits cleanup but must never turn that original operation green.
$wslTokens=$null;$wslErrors=$null
$wslAst=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'probe-wsl.ps1'),[ref]$wslTokens,[ref]$wslErrors)
if($wslErrors.Count){throw 'PARENT_SOURCE_PARSE_FAILED'}
foreach($name in @('Wait-OpaqueReconciliation','Set-OwnedAckOperationFailure')){
 $definition=@($wslAst.FindAll({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq $name},$true))
 if($definition.Count -ne 1){throw 'ONE_ACTUAL_PARENT_FUNCTION_REQUIRED'}
 . ([scriptblock]::Create($definition[0].Extent.Text))
}
$script:confirmCalls=0
function Confirm-OwnedTerminalAck($Authority){$script:confirmCalls++;return [pscustomobject]@{Verified=($script:confirmCalls -gt 1)}}
function Get-OwnedTerminalRemaining($Authority){return 600}
function Test-Path {param($LiteralPath);return $true}
$script:OwnedPrivateLaunchMayHaveOccurred=$true;$script:OwnedPrivateAckVerified=$false;$script:OwnedPrivateAckOperationFailed=$false
$script:OwnedPrivateAuthority=[pscustomobject]@{Root=[IO.Path]::GetTempPath()}
Wait-OpaqueReconciliation
if($script:confirmCalls -ne 2 -or -not $script:OwnedPrivateAckVerified -or -not $script:OwnedPrivateAckOperationFailed -or -not (Test-OwnedPrivateCleanupAllowed $true $script:OwnedPrivateAckVerified)){throw 'LATE_MEMO_MAY_ALLOW_CLEANUP_ONLY_WITH_FAILURE_LATCHED'};$passed++
Wait-OpaqueReconciliation
if(-not $script:OwnedPrivateAckOperationFailed){throw 'REPEATED_RECONCILIATION_MUST_NOT_RESET_FAILURE'};$passed++
$r=[ordered]@{Failure=$null;Qualified=$true;SourceQualification=$true;BinaryRoundTrip=$true;LoopbackHTTP=$true;ExecStdinEOF=$true;InitialContainersEmpty=$true;FinalContainersEmpty=$true;FinalPortAbsent=$true;SameEngineAfterMemory=$true;AfterFreeMiB=8192;BridgeReport=[pscustomobject]@{Qualified=$true}}
Set-OwnedAckOperationFailure $r
$bridgeTokens=$null;$bridgeErrors=$null
$bridgeAst=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'probe-windows-bridge.ps1'),[ref]$bridgeTokens,[ref]$bridgeErrors)
$qualified=@($bridgeAst.FindAll({param($n)$n -is [Management.Automation.Language.AssignmentStatementAst] -and $n.Left.Extent.Text -ceq '$r.Qualified'},$true))
if($bridgeErrors.Count -or $qualified.Count -ne 1){throw 'ONE_ACTUAL_BRIDGE_VERDICT_REQUIRED'}
. ([scriptblock]::Create($qualified[0].Extent.Text))
if($r.Qualified -or $r.Failure -cne 'PRIVATE_TERMINAL_ACK_OPERATION_FAILED'){throw 'LATE_ACK_FAULT_MUST_FAIL_ACTUAL_BRIDGE_VERDICT'};$passed++
$result=[ordered]@{failure=$null;kernelStarted=$true;linuxDockerProved=$true;windowsBridgeQualified=$true;engineLiveAfterMemory=$true;candidateHeadroom6144=$true;cleanupVerified=$true;resultFilePublished=$true;windowsBridge=[pscustomobject]@{PrivateSessionAccepted=$true;BridgeReport=[pscustomobject]@{Qualified=$true};BridgeProcess=[pscustomobject]@{Closed=$true;Forced=$false;ExitCode=0}}}
Set-OwnedAckOperationFailure $result
. (Join-Path $PSScriptRoot 'generic-host-disposition.ps1')
$disposition=New-GenericHostDisposition $result ('a'*32) ('b'*40)
if($disposition.HostQualified){throw 'LATE_ACK_FAULT_MUST_FAIL_PUBLIC_HOST_DISPOSITION'};$passed++
$thrown=$null;try{. ([scriptblock]::Create($wslAst.EndBlock.Statements[-1].Extent.Text))}catch{$thrown=$_.Exception.Message}
if($thrown -cne 'HOSTED_CAPABILITY_NOT_QUALIFIED_SEE_PRESERVED_RESULT'){throw 'LATE_ACK_FAULT_MUST_FAIL_ACTUAL_HOST_EXIT'};$passed++
$result.failure='ORIGINAL_FAILURE';Set-OwnedAckOperationFailure $result;Set-OwnedAckOperationFailure $result
if($result.failure -cne 'ORIGINAL_FAILURE;PRIVATE_TERMINAL_ACK_OPERATION_FAILED'){throw 'PRIMARY_FAULT_MUST_SURVIVE_WITHOUT_DUPLICATE_ACK_FAULT'};$passed++
[pscustomobject]@{Scope='ACTUAL_PRIVATE_ROOT_POLICY_WITH_INERT_PROCESS';Passed=$passed;RealProcessesStarted=0;PrivateExecutionStarted=$false;CanonicalAccepted=$false}|ConvertTo-Json -Compress