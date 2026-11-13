function New-GenericHostDisposition($Result,[string]$Nonce,[string]$PublicSourceHead){
 if($Nonce -cnotmatch '\A[0-9a-f]{32}\z' -or $PublicSourceHead -cnotmatch '\A[0-9a-f]{40}\z'){throw 'EXACT_GENERIC_DISPOSITION_IDENTITY_REQUIRED'}
 function Flag($Value){return ($Value -is [bool] -and $Value -ceq $true)}
 $bridge=$Result.windowsBridge
 $privateOK=$false;$bridgeOK=$false;$naturalBridge=$false
 if($null -ne $bridge){
  $privateOK=Flag $bridge.PrivateSessionAccepted
  if($null -ne $bridge.BridgeReport){$bridgeOK=Flag $bridge.BridgeReport.Qualified}
  if($null -ne $bridge.BridgeProcess){$naturalBridge=((Flag $bridge.BridgeProcess.Closed) -and $bridge.BridgeProcess.Forced -is [bool] -and $bridge.BridgeProcess.Forced -ceq $false -and ($bridge.BridgeProcess.ExitCode -is [int] -or $bridge.BridgeProcess.ExitCode -is [long]) -and $bridge.BridgeProcess.ExitCode -eq 0)}
 }
 $wslOK=Flag $Result.cleanupVerified
 $good=($null -eq $Result.failure -and (Flag $Result.resultFilePublished) -and $privateOK -and $bridgeOK -and $naturalBridge -and $wslOK)
 # Construct only fixed-schema scalars. Never serialize a private object,
 # command, stdout/stderr, exception, name, URL, ID, path or workload timing.
 return [pscustomobject][ordered]@{Schema=1;Scope='GENERIC_OPAQUE_HOST_DISPOSITION_ONLY';Nonce=$Nonce;PublicSourceHead=$PublicSourceHead;HostQualified=$good;PrivateAgentHostQualified=$privateOK;ThreePrivateFilesAbsent=$privateOK;OwnedBridgeQualified=$bridgeOK;BridgeNaturalExit=$naturalBridge;OwnedWSLUnregistered=$wslOK;PrivateJobAccepted=$false;CanonicalAccepted=$false;DirectDescendantCensus=$false;MemoryErasureClaimed=$false;VMDispositionBasis='PROVIDER_CONTRACT_INFERENCE'}
}

function Write-GenericHostDisposition($Data,[string]$Path){
 $keys=@('Schema','Scope','Nonce','PublicSourceHead','HostQualified','PrivateAgentHostQualified','ThreePrivateFilesAbsent','OwnedBridgeQualified','BridgeNaturalExit','OwnedWSLUnregistered','PrivateJobAccepted','CanonicalAccepted','DirectDescendantCensus','MemoryErasureClaimed','VMDispositionBasis')
 if($Data -isnot [pscustomobject] -or (@($Data.PSObject.Properties.Name|Sort-Object) -join '|') -cne (@($keys|Sort-Object) -join '|')){throw 'EXACT_GENERIC_DISPOSITION_SCHEMA_REQUIRED'}
 if(($Data.Schema -isnot [int] -and $Data.Schema -isnot [long]) -or $Data.Schema -ne 1 -or $Data.Scope -isnot [string] -or $Data.Scope -cne 'GENERIC_OPAQUE_HOST_DISPOSITION_ONLY' -or $Data.Nonce -isnot [string] -or $Data.Nonce -cnotmatch '\A[0-9a-f]{32}\z' -or $Data.PublicSourceHead -isnot [string] -or $Data.PublicSourceHead -cnotmatch '\A[0-9a-f]{40}\z' -or $Data.VMDispositionBasis -isnot [string] -or $Data.VMDispositionBasis -cne 'PROVIDER_CONTRACT_INFERENCE'){throw 'INVALID_GENERIC_DISPOSITION_SCALARS'}
 foreach($key in @('HostQualified','PrivateAgentHostQualified','ThreePrivateFilesAbsent','OwnedBridgeQualified','BridgeNaturalExit','OwnedWSLUnregistered','PrivateJobAccepted','CanonicalAccepted','DirectDescendantCensus','MemoryErasureClaimed')){if($Data.$key -isnot [bool]){throw 'BOOLEAN_GENERIC_DISPOSITION_REQUIRED'}}
 foreach($key in @('PrivateJobAccepted','CanonicalAccepted','DirectDescendantCensus','MemoryErasureClaimed')){if($Data.$key -cne $false){throw 'GENERIC_DISPOSITION_OVERCLAIM_REFUSED'}}
 if($Data.HostQualified -and (-not $Data.PrivateAgentHostQualified -or -not $Data.ThreePrivateFilesAbsent -or -not $Data.OwnedBridgeQualified -or -not $Data.BridgeNaturalExit -or -not $Data.OwnedWSLUnregistered)){throw 'INCONSISTENT_GENERIC_DISPOSITION_REFUSED'}
 if([IO.Path]::GetFileName($Path) -cne 'generic-host-disposition.json'){throw 'EXACT_GENERIC_DISPOSITION_FILENAME_REQUIRED'}
 $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($Data|ConvertTo-Json -Compress))
 if($bytes.Length -gt 8192){throw 'GENERIC_DISPOSITION_BOUND_EXCEEDED'}
 $stream=[IO.File]::Open($Path,'CreateNew','Write','None')
 try{$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
 $file=Get-Item -LiteralPath $Path -Force
 if($file.PSIsContainer -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $file.Length -ne $bytes.Length){throw 'REGULAR_CLOSED_GENERIC_DISPOSITION_REQUIRED'}
 $readback=[IO.File]::ReadAllBytes($Path)
 if([Convert]::ToBase64String($readback) -cne [Convert]::ToBase64String($bytes)){throw 'GENERIC_DISPOSITION_READBACK_MISMATCH'}
}
