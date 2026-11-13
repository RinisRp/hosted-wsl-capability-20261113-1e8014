# Pure synthetic-record oracles. No process, key or network operations on import.
function Write-FixtureClosedBytes($Path,$Bytes){
 if($Path -isnot [string] -or $Bytes -isnot [byte[]] -or $Bytes.Length -gt 4096){throw 'BOUNDED_SYNTHETIC_PUBLICATION_REQUIRED'}
 $pending=$Path+'.closed-pending';$file=[IO.File]::Open($pending,'CreateNew','Write','None')
 try{$file.Write($Bytes,0,$Bytes.Length);$file.Flush($true)}finally{$file.Dispose()}
 # The final name is absent until the complete, flushed stream has closed.
 # Move refuses an existing final name; neither file is ever overwritten.
 [IO.File]::Move($pending,$Path)
}
function Assert-FixtureTypedRecord($Value,$Keys,$Integers,$Strings,$TrueFields,$FalseFields){
 if($Value -isnot [pscustomobject] -or (@($Value.PSObject.Properties.Name|Sort-Object) -join '|') -cne (@($Keys|Sort-Object) -join '|')){throw 'EXACT_SYNTHETIC_RECORD_REQUIRED'}
 foreach($n in $Integers){if($Value.$n -isnot [int] -and $Value.$n -isnot [long]){throw 'STRICT_SYNTHETIC_INTEGER_REQUIRED'}}
 foreach($n in $Strings){if($Value.$n -isnot [string]){throw 'STRICT_SYNTHETIC_STRING_REQUIRED'}}
 foreach($n in $TrueFields){if($Value.$n -isnot [bool] -or -not $Value.$n){throw 'STRICT_SYNTHETIC_TRUE_REQUIRED'}}
 foreach($n in $FalseFields){if($Value.$n -isnot [bool] -or $Value.$n){throw 'STRICT_SYNTHETIC_FALSE_REQUIRED'}}
}
function Assert-Terminal($Terminal,$Held){
 Assert-FixtureTypedRecord $Terminal @('Schema','Scope','Nonce','Case','Exit','Closed','Forced','TimedOut','OwnerPID','OwnerCreatedUTC','RealPrivateJob','PrivateJobAccepted') @('Schema','Exit','OwnerPID') @('Scope','Nonce','Case','OwnerCreatedUTC') @('Closed') @('Forced','TimedOut','RealPrivateJob','PrivateJobAccepted')
 $expected=if($Case -ceq 'zero'){0}else{7}
 if($Terminal.Schema -ne 1 -or $Terminal.Scope -cne 'SYNTHETIC_KNOWN_WORKER_TERMINAL_ONLY' -or $Terminal.Nonce -cne $nonce -or $Terminal.Case -cne $Case -or $Terminal.Exit -ne $expected -or $Terminal.OwnerPID -ne $Held.Descriptor.PID -or $Terminal.OwnerCreatedUTC -cne $Held.Descriptor.CreatedUTC){throw 'EXACT_KNOWN_WORKER_TERMINAL_REQUIRED'}
}
function Assert-FixtureReady($Ready,$Held){
 Assert-FixtureTypedRecord $Ready @('Schema','Scope','Nonce','PID','CreatedUTC','RealPrivateJob') @('Schema','PID') @('Scope','Nonce','CreatedUTC') @() @('RealPrivateJob')
 if($Ready.Schema -ne 1 -or $Ready.Scope -cne 'SYNTHETIC_OWNER_STARTED_ONLY' -or $Ready.Nonce -cne $nonce -or $Ready.PID -ne $Held.Descriptor.PID -or $Ready.CreatedUTC -cne $Held.Descriptor.CreatedUTC){throw 'HELD_SYNTHETIC_OWNER_READY_REQUIRED'}
}
function Assert-FixtureFinal($Final,$Terminal,$Held){
 Assert-FixtureTypedRecord $Final @('Schema','Scope','Nonce','Case','WorkerExit','WorkerNaturallyClosed','TerminalAckVerified','ObserverAttached','OwnerPID','OwnerCreatedUTC','RealPrivateJob','PrivateJobAccepted','CanonicalAccepted','MemoryErasureClaimed') @('Schema','WorkerExit','OwnerPID') @('Scope','Nonce','Case','OwnerCreatedUTC') @('WorkerNaturallyClosed','TerminalAckVerified','ObserverAttached') @('RealPrivateJob','PrivateJobAccepted','CanonicalAccepted','MemoryErasureClaimed')
 if($Final.Schema -ne 1 -or $Final.Scope -cne 'GENERIC_SYNTHETIC_CROSS_STEP_ONLY' -or $Final.Nonce -cne $nonce -or $Final.Case -cne $Case -or $Final.WorkerExit -ne $Terminal.Exit -or $Final.OwnerPID -ne $Held.Descriptor.PID -or $Final.OwnerCreatedUTC -cne $Held.Descriptor.CreatedUTC){throw 'EXACT_FINAL_SYNTHETIC_RECEIPT_REQUIRED'}
}
function ConvertTo-FixtureMode($Value){
 if($Value -isnot [string] -or $Value.ToLowerInvariant() -cnotin @('start','sign','wait','cleanup')){throw 'EXACT_FIXTURE_MODE_REQUIRED'}
 return $Value.ToLowerInvariant()
}
