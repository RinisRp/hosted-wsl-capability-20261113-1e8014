# Public context and signed ACK memo only. No private target/credential is stored.
. (Join-Path $PSScriptRoot 'generic-terminal-ack.ps1')
. (Join-Path $PSScriptRoot 'owned-generic-ack-http.ps1')
. (Join-Path $PSScriptRoot 'terminal-ack-gate.ps1')
function Assert-OwnedAckRoot([string]$Nonce,[string]$Root){
 if($Nonce -cnotmatch '\A[0-9a-f]{32}\z' -or $Root -cne (Join-Path $env:RUNNER_TEMP ('hosted-wsl-'+$Nonce))){throw 'EXACT_OWNED_ACK_ROOT_REQUIRED'}
 $item=Get-Item -LiteralPath $Root -Force
 if(-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'ORDINARY_OWNED_ACK_DIRECTORY_REQUIRED'}
 $current=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
 $acl=$item.GetAccessControl([Security.AccessControl.AccessControlSections]'Access,Owner')
 if(-not $acl.AreAccessRulesProtected -or $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -cne $current){throw 'OWNED_PROTECTED_ACK_ROOT_REQUIRED'}
 $allowed=@($current,'S-1-5-18','S-1-5-32-544');$rules=@($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))
 if($rules.Count -ne 3){throw 'EXACT_ACK_ROOT_RULE_COUNT_REQUIRED'}
 foreach($rule in $rules){if($rule.AccessControlType -ne 'Allow' -or $rule.IdentityReference.Value -cnotin $allowed -or $rule.FileSystemRights -ne 'FullControl'){throw 'EXACT_ACK_ROOT_ALLOWLIST_REQUIRED'}}
 $parent=Get-Item -LiteralPath ([IO.Path]::GetFullPath($env:RUNNER_TEMP)) -Force
 while($null -ne $parent){if($parent.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'ACK_ROOT_ANCESTOR_REPARSE_REFUSED'};$parent=$parent.Parent}
}
function Read-OwnedAckBytes([string]$Path,[int]$Bound){
 $item=Get-Item -LiteralPath $Path -Force
 if($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $item.Length -gt $Bound){throw 'BOUNDED_ORDINARY_ACK_FILE_REQUIRED'}
 $file=[IO.File]::Open($Path,'Open','Read','Read');$memory=$null
 try{
  if($file.Length -gt $Bound){throw 'ACK_FILE_CHANGED_SIZE'}
  $memory=[IO.MemoryStream]::new();$buffer=New-Object byte[] ($Bound+1)
  while($true){$count=$file.Read($buffer,0,$buffer.Length);if($count -eq 0){break};if($memory.Length+$count -gt $Bound){throw 'ACK_FILE_OVERFLOW'};$memory.Write($buffer,0,$count)}
  $bytes=$memory.ToArray()
 }finally{try{if($null -ne $memory){$memory.Dispose()}}finally{$file.Dispose()}}
 return ,([byte[]]$bytes)
}
function Write-OwnedAckBytes([string]$Root,[string]$Name,[byte[]]$Bytes){
 if($Name -cnotin @('owned-terminal-ack-context.json','terminal-ack-attempt.txt','verified-terminal-ack.txt','private-launch-spent.json') -or $Bytes.Length -lt 1 -or $Bytes.Length -gt 4096){throw 'FIXED_OWNED_ACK_RECORD_REQUIRED'}
 $path=Join-Path $Root $Name;$file=[IO.File]::Open($path,'CreateNew','Write','None')
 try{$file.Write($Bytes,0,$Bytes.Length);$file.Flush($true)}finally{$file.Dispose()}
 if([Convert]::ToBase64String((Read-OwnedAckBytes $path 4096)) -cne [Convert]::ToBase64String($Bytes)){throw 'OWNED_ACK_RECORD_READBACK_FAILED'}
}
function New-OwnedTerminalAuthority([string]$Nonce,[string]$Root,[long]$LeaseStartedTick){
 Assert-OwnedAckRoot $Nonce $Root
 $encoded=[Environment]::GetEnvironmentVariable('OWNED_ACK_PUBLIC_KEY','Process')
 if($encoded -cnotmatch '\A[A-Za-z0-9+/]{516}\z'){throw 'EXACT_PUBLIC_RSA3072_KEY_REQUIRED'}
 $public=[Convert]::FromBase64String($encoded)
 if([Convert]::ToBase64String($public) -cne $encoded){throw 'CANONICAL_PUBLIC_KEY_REQUIRED'}
 $context=[pscustomobject]@{PublicRepository=$env:GITHUB_REPOSITORY;Nonce=$Nonce;SourceHead=$env:GITHUB_SHA;Run=$env:GITHUB_RUN_ID;Attempt=1;KeyFingerprint=(Get-GenericAckKeyFingerprint $public)}
 [void](Get-GenericAckContextPayload $context)
 if($env:GITHUB_RUN_ATTEMPT -cne '1'){throw 'ONE_SHOT_PUBLIC_ATTEMPT_REQUIRED'}
 $frequency=[long][Diagnostics.Stopwatch]::Frequency;$now=[Diagnostics.Stopwatch]::GetTimestamp()
 if($LeaseStartedTick -lt 0 -or $LeaseStartedTick -gt $now -or ($now-$LeaseStartedTick)/[double]$frequency -gt 330){throw 'ACTUAL_BRIDGE_START_BUDGET_REQUIRED'}
 $expires=[long]($LeaseStartedTick+7200L*$frequency)
 $data=[pscustomobject]@{Schema=1;Context=$context;PublicKeyBase64=$encoded;Frequency=$frequency;ExpiresTick=$expires}
 Write-OwnedAckBytes $Root 'owned-terminal-ack-context.json' ([Text.UTF8Encoding]::new($false).GetBytes(($data|ConvertTo-Json -Depth 4 -Compress)))
 return (Read-OwnedTerminalAuthority $Nonce $Root $LeaseStartedTick)
}
function Read-OwnedTerminalAuthority([string]$Nonce,[string]$Root,[long]$TrustedLeaseStartedTick){
 Assert-OwnedAckRoot $Nonce $Root
 $data=[Text.UTF8Encoding]::new($false,$true).GetString((Read-OwnedAckBytes (Join-Path $Root 'owned-terminal-ack-context.json') 4096))|ConvertFrom-Json
 $keys=@('Schema','Context','PublicKeyBase64','Frequency','ExpiresTick')
 if($data -isnot [pscustomobject] -or (@($data.PSObject.Properties.Name|Sort-Object) -join '|') -cne (@($keys|Sort-Object) -join '|') -or ($data.Schema -isnot [int] -and $data.Schema -isnot [long]) -or $data.Schema -ne 1){throw 'EXACT_OWNED_ACK_ENVELOPE_REQUIRED'}
 [void](Get-GenericAckContextPayload $data.Context)
 if($data.Context.Nonce -cne $Nonce -or $data.Context.PublicRepository -cne $env:GITHUB_REPOSITORY -or $data.Context.SourceHead -cne $env:GITHUB_SHA -or $data.Context.Run -cne $env:GITHUB_RUN_ID -or $env:GITHUB_RUN_ATTEMPT -cne '1'){throw 'CURRENT_PUBLIC_HOST_ACK_CONTEXT_REQUIRED'}
 if($data.PublicKeyBase64 -isnot [string] -or $data.PublicKeyBase64 -cnotmatch '\A[A-Za-z0-9+/]{516}\z'){throw 'TYPED_PUBLIC_ACK_KEY_REQUIRED'}
 $public=[Convert]::FromBase64String($data.PublicKeyBase64)
 if((Get-GenericAckKeyFingerprint $public) -cne $data.Context.KeyFingerprint -or [Convert]::ToBase64String($public) -cne $data.PublicKeyBase64){throw 'OWNED_PUBLIC_KEY_FINGERPRINT_MISMATCH'}
 if($data.PublicKeyBase64 -cne [Environment]::GetEnvironmentVariable('OWNED_ACK_PUBLIC_KEY','Process')){throw 'ORIGINAL_PARENT_PUBLIC_KEY_REQUIRED'}
 $now=[Diagnostics.Stopwatch]::GetTimestamp()
 if($TrustedLeaseStartedTick -lt 1 -or $TrustedLeaseStartedTick -gt $now -or $data.ExpiresTick -ne [long]($TrustedLeaseStartedTick+7200L*[Diagnostics.Stopwatch]::Frequency)){throw 'EXACT_TRUSTED_BRIDGE_MONOTONIC_ORIGIN_REQUIRED'}
 foreach($name in @('Frequency','ExpiresTick')){if(($data.$name -isnot [int] -and $data.$name -isnot [long]) -or $data.$name -lt 1){throw 'TYPED_MONOTONIC_ACK_LEASE_REQUIRED'}}
 if($data.Frequency -ne [Diagnostics.Stopwatch]::Frequency){throw 'SAME_HOST_MONOTONIC_FREQUENCY_REQUIRED'}
 $authority=[pscustomobject]@{Root=$Root;Context=$data.Context;PublicKeyBytes=[byte[]]$public;Frequency=[long]$data.Frequency;ExpiresTick=[long]$data.ExpiresTick;LeaseStartedTick=$TrustedLeaseStartedTick}
 [void](Get-OwnedTerminalRemaining $authority)
 return $authority
}
function Get-OwnedTerminalRemaining($Authority){
 $remaining=[Math]::Floor(($Authority.ExpiresTick-[Diagnostics.Stopwatch]::GetTimestamp())/[double]$Authority.Frequency)
 if($remaining -gt 7200){throw 'ACK_LEASE_EXTENSION_REFUSED'}
 return [int][Math]::Max(0,$remaining)
}
function Confirm-OwnedTerminalAck($Authority){
 $no=[pscustomobject]@{Scope='EXTERNAL_TERMINAL_TRUTH_ONLY_NOT_OPERATION_ACCEPTANCE';Verified=$false;Receipt=$null;OperationAccepted=$false;PrivateJobAccepted=$false;CanonicalAccepted=$false}
 try{
  Assert-OwnedAckRoot $Authority.Context.Nonce $Authority.Root
  if((Get-OwnedTerminalRemaining $Authority) -lt 120){return $no}
  $intent=Join-Path $Authority.Root 'terminal-ack-attempt.txt';$proof=Join-Path $Authority.Root 'verified-terminal-ack.txt'
  $expected=Get-GenericAckContextPayload $Authority.Context
  if(Test-Path -LiteralPath $intent){
   if([Convert]::ToBase64String((Read-OwnedAckBytes $intent 2048)) -cne [Convert]::ToBase64String($expected)){return $no}
   if(-not (Test-Path -LiteralPath $proof)){return $no}
   $receipt=Assert-GenericTerminalAck (Read-OwnedAckBytes $proof 2048) $Authority.Context $Authority.PublicKeyBytes
   if((Get-OwnedTerminalRemaining $Authority) -lt 120){return $no}
   return [pscustomobject]@{Scope='EXTERNAL_TERMINAL_TRUTH_ONLY_NOT_OPERATION_ACCEPTANCE';Verified=$true;Receipt=$receipt;OperationAccepted=$false;PrivateJobAccepted=$false;CanonicalAccepted=$false}
  }
  if(Test-Path -LiteralPath $proof){return $no}
  Write-OwnedAckBytes $Authority.Root 'terminal-ack-attempt.txt' $expected
  $gate=Wait-VerifiedGenericTerminalAck $Authority.Context $Authority.PublicKeyBytes (Get-OwnedTerminalRemaining $Authority)
  if(-not $gate.Verified -or $gate.SignedBytes -isnot [byte[]] -or $gate.SignedBytes.Length -lt 1 -or $gate.SignedBytes.Length -gt 2048){return $no}
  $signed=[byte[]]($gate.SignedBytes.Clone())
  [void](Assert-GenericTerminalAck $signed $Authority.Context $Authority.PublicKeyBytes)
  Write-OwnedAckBytes $Authority.Root 'verified-terminal-ack.txt' $signed
  $readback=Read-OwnedAckBytes (Join-Path $Authority.Root 'verified-terminal-ack.txt') 2048
  if([Convert]::ToBase64String($readback) -cne [Convert]::ToBase64String($signed)){return $no}
  $receipt=Assert-GenericTerminalAck $readback $Authority.Context $Authority.PublicKeyBytes
  if((Get-OwnedTerminalRemaining $Authority) -lt 120){return $no}
  # Reconciliation truth may be reverified after an earlier writer fault.
  # It never rehabilitates that failed operation or the private/host result.
  return [pscustomobject]@{Scope='EXTERNAL_TERMINAL_TRUTH_ONLY_NOT_OPERATION_ACCEPTANCE';Verified=$true;Receipt=$receipt;OperationAccepted=$false;PrivateJobAccepted=$false;CanonicalAccepted=$false}
 }catch{return $no}
}
function Wait-OwnedTerminalHardExpiry($Authority){
 # Unknown is never retried or accepted. Keep the host until the declared hard
 # lease; expiry remains failure and does not license accepted engine cleanup.
 while((Get-OwnedTerminalRemaining $Authority) -gt 0){Start-Sleep -Milliseconds 500}
 return $false
}
function Assert-OwnedPrivateStartBudget($Authority,[long]$WrapperStartedTick){
 if((Get-OwnedTerminalRemaining $Authority) -lt 6870){throw 'PRIVATE_START_REQUIRES6870_SECONDS_INSIDE_BRIDGE_LEASE'}
 $now=[Diagnostics.Stopwatch]::GetTimestamp()
 if($WrapperStartedTick -lt 1 -or $WrapperStartedTick -gt $now -or ($now-$WrapperStartedTick)/[double][Diagnostics.Stopwatch]::Frequency -gt 30){throw 'PRIVATE_WRAPPER_SETUP30_SECONDS_BUDGET_REQUIRED'}
}
function Reconcile-OwnedPrivateRoot($Process,[bool]$Held,$Authority){
 $result=[ordered]@{Closed=$false;Forced=$false;TerminalVerified=$false;Faults=@()}
 try{
  if(-not $Process.HasExited){
   if(-not $Held){throw 'NO_HELD_PRIVATE_ROOT_NO_TERMINATION'}
   $terminal=Confirm-OwnedTerminalAck $Authority
   if(-not $terminal.Verified){
    $result.Faults+=@('PRIVATE_TERMINAL_ACK_UNPROVED_NO_ROOT_STOP')
    [void](Wait-OwnedTerminalHardExpiry $Authority)
   }else{
    $result.TerminalVerified=$true;$result.Forced=$true
    $result.Faults+=@('PRIVATE_OWN_ROOT_FORCED_AFTER_VERIFIED_TERMINAL')
    $Process.Kill()
    if(-not $Process.WaitForExit(15000)){throw 'PRIVATE_ROOT_CLOSURE_UNKNOWN'}
   }
  }
  $result.Closed=$Process.HasExited
 }catch{$result.Closed=$false;$result.Faults+=@('PRIVATE_OWN_ROOT_CLOSURE_FAILED')}
 return [pscustomobject]$result
}
function Test-OwnedPrivateCleanupAllowed([bool]$LaunchMayHaveOccurred,[bool]$TerminalVerified){return (-not $LaunchMayHaveOccurred -or $TerminalVerified)}
