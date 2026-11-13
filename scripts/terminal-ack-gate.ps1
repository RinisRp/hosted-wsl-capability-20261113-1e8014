# Returns authority only after the separate signature verifier succeeds.
# A negative result never permits owner/bridge/WSL teardown: its caller must
# hold the VM until a valid terminal ACK or an explicitly failed hard expiry.
function Wait-VerifiedGenericTerminalAck($Context,$PublicKeyBytes,$BridgeLeaseRemainingSeconds){
 $failure=[pscustomobject]@{Scope='ACK_GATE_ONLY_NOT_JOB_ACCEPTANCE';Verified=$false;RetryStopped=$true;PrivateJobAccepted=$false;CanonicalAccepted=$false;Receipt=$null}
 try{
  [void](Get-GenericAckContextPayload $Context)
  if((Get-GenericAckKeyFingerprint $PublicKeyBytes) -cne $Context.KeyFingerprint -or ($BridgeLeaseRemainingSeconds -isnot [int] -and $BridgeLeaseRemainingSeconds -isnot [long]) -or $BridgeLeaseRemainingSeconds -lt 0 -or $BridgeLeaseRemainingSeconds -gt 7200){return $failure}
  # Reserve120s for voluntary cleanup, and45s before every query for its held
  # root30s limit plus15s closure. One aggregate budget is never reset.
  $budget=[int][Math]::Min(600,$BridgeLeaseRemainingSeconds-120)
  if($budget -lt 45){return $failure}
  $clock=[Diagnostics.Stopwatch]::StartNew()
  for($index=0;$index -lt 300;$index++){
   if($budget-$clock.Elapsed.TotalSeconds -lt 45){return $failure}
   $query=Invoke-OwnedGenericAckRead $Context $index
   if($query -isnot [pscustomobject] -or $query.Scope -isnot [string] -or $query.Scope -cne 'OWNED_ACK_QUERY_ONLY_NOT_AUTHORITY'){return $failure}
   foreach($key in @('HasAck','RetryAllowed','Unknown')){if($query.$key -isnot [bool]){return $failure}}
   if($query.Unknown -or -not $query.RetryAllowed -or $query.Bytes -isnot [byte[]] -or $clock.Elapsed.TotalSeconds -ge $budget){return $failure}
   if($query.HasAck){
    if($query.Bytes.Length -lt 1 -or $query.Bytes.Length -gt 2048){return $failure}
    # A body at our immutable nonce-ref with invalid context/signature is an
    # integrity failure, not a transient absence. Do not retry it or hide a
    # verifier cleanup failure behind another attempt.
    $receipt=Assert-GenericTerminalAck $query.Bytes $Context $PublicKeyBytes
    if($receipt -isnot [pscustomobject] -or $receipt.Scope -cne 'VERIFIED_TERMINAL_ACK_PERMITS_OWNED_TEARDOWN_ONLY' -or $receipt.Nonce -cne $Context.Nonce -or $receipt.PublicSourceHead -cne $Context.SourceHead -or $receipt.PublicRun -cne $Context.Run -or $receipt.Attempt -ne 1){return $failure}
    foreach($key in @('TeardownPermitted','PrivateTargetTerminal')){if($receipt.$key -isnot [bool] -or $receipt.$key -cne $true){return $failure}}
    foreach($key in @('PrivateJobAccepted','CanonicalAccepted','MemoryErasureClaimed')){if($receipt.$key -isnot [bool] -or $receipt.$key -cne $false){return $failure}}
    if($clock.Elapsed.TotalSeconds -ge $budget -or $BridgeLeaseRemainingSeconds-$clock.Elapsed.TotalSeconds -lt 120){return $failure}
    return [pscustomobject]@{Scope='ACK_GATE_ONLY_NOT_JOB_ACCEPTANCE';Verified=$true;RetryStopped=$true;PrivateJobAccepted=$false;CanonicalAccepted=$false;Receipt=$receipt}
   }
   if($query.Bytes.Length -ne 0){return $failure}
   $sleep=[int][Math]::Min(2000,[Math]::Max(0,($budget-$clock.Elapsed.TotalSeconds-45)*1000))
   if($sleep -le 0){return $failure};Start-Sleep -Milliseconds $sleep
  }
 }catch{return $failure}
 return $failure
}
