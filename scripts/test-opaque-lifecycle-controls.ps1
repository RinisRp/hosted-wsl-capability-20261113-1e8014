$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'owned-private-terminal-ack.ps1')
$draftRoot=Join-Path ([IO.Path]::GetTempPath()) ('opaque-lifecycle-controls-'+[guid]::NewGuid().ToString('N'));[void][IO.Directory]::CreateDirectory($draftRoot);$source=Join-Path $PSScriptRoot 'opaque-private-session.ps1'
$t=$null;$e=$null;$a=[Management.Automation.Language.Parser]::ParseFile($source,[ref]$t,[ref]$e)
$session=@($a.FindAll({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'Invoke-OpaquePrivateRunnerSession'},$false))[0]
$fault=@($session.FindAll({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'SessionFault'},$true))[0]
. ([scriptblock]::Create($fault.Extent.Text))
$try=@($session.Body.EndBlock.Statements|Where-Object {$_ -is [Management.Automation.Language.TryStatementAst]})[0]
$cleanup=[scriptblock]::Create(($try.Finally.Statements|ForEach-Object {$_.Extent.Text}) -join "`n")
$pump=@($session.FindAll({param($n)$n -is [Management.Automation.Language.ForEachStatementAst] -and $n.Extent.Text.Contains('PRIVATE_SESSION_HARD_LOG_BOUND')},$true))
if($e.Count -or $pump.Count -ne 1){throw 'EXACT_SOURCE_LIFECYCLE_BLOCKS_REQUIRED'}
$pumpBlock=[scriptblock]::Create($pump[0].Extent.Text)
function MockFile([bool]$FlushFault,[bool]$DisposeFault){
 $m=[pscustomobject]@{Writes=0;Written=0;Flushes=0;Disposes=0;FlushFault=$FlushFault;DisposeFault=$DisposeFault}
 $m|Add-Member ScriptMethod Write {param($Bytes,$Offset,$Count);$this.Writes++;$this.Written+=$Count}
 $m|Add-Member ScriptMethod Flush {param($Durable);$this.Flushes++;if($this.FlushFault){throw 'MOCK_FLUSH'}}
 $m|Add-Member ScriptMethod Dispose {$this.Disposes++;if($this.DisposeFault){throw 'MOCK_DISPOSE'}}
 return $m
}
function MockStream([bool]$CloseFault){
 $m=[pscustomobject]@{Disposes=0;CloseFault=$CloseFault}
 $m|Add-Member ScriptMethod Dispose {$this.Disposes++;if($this.CloseFault){throw 'MOCK_STREAM_DISPOSE'}}
 $m|Add-Member ScriptMethod ReadAsync {param($Bytes,$Offset,$Count);return [Threading.Tasks.Task]::FromResult([int]0)}
 return $m
}
$rows=@()
foreach($mode in @('chunk-valid','exact-bound','overflow','startup-overflow','eof','faulted-read','stalled-read')){
 $receipt=@{ListeningObserved=($mode -ne 'startup-overflow');Failure=$null;Faults=@()}
 $buffer=New-Object byte[] 16384;$count=if($mode -ceq 'eof'){0}else{16};$file=MockFile $false $false
 $channel=[pscustomobject]@{Name='stdout';File=$file;Stream=(MockStream $false);Buffer=$buffer;Pending=[Threading.Tasks.Task]::FromResult([int]$count);Bytes=$(if($mode -ceq 'exact-bound'){8388592L}elseif($mode -ceq 'overflow'){8388593L}else{0L});EOF=$false;Closed=$false}
 $channels=@($channel);$startup=[Text.StringBuilder]::new();if($mode -ceq 'startup-overflow'){[void]$startup.Append(('x'*131071))}
 if($mode -cin @('faulted-read','stalled-read')){$completion=[Threading.Tasks.TaskCompletionSource[int]]::new();if($mode -ceq 'faulted-read'){$completion.SetException([InvalidOperationException]::new('SYNTHETIC_READ_FAULT'))};$channel.Pending=$completion.Task}
 $failure=$null;try{. $pumpBlock}catch{$failure=$_.Exception.Message}
 $expectedFailure=$mode -cin @('overflow','startup-overflow','faulted-read')
 if(($null -ne $failure) -ne $expectedFailure){throw ('PUMP_FALSE_ACCEPTANCE_'+$mode)}
 if($mode -ceq 'overflow' -and $file.Writes -ne 0){throw 'OVERFLOW_WRITTEN_TO_DISK'}
 if($mode -ceq 'eof' -and (-not $channel.EOF -or $file.Writes -ne 0)){throw 'EOF_NOT_RECORDED'}
 if($mode -ceq 'exact-bound' -and $channel.Bytes -ne 8388608){throw 'EXACT_BOUND_REJECTED'}
 if($mode -ceq 'stalled-read' -and ($file.Writes -ne 0 -or $channel.EOF -or $channel.Pending.IsCompleted)){throw 'STALLED_READ_WAS_CLAIMED_COMPLETE'}
 $rows+=@{mode=$mode;pass=$true;faultExpected=$expectedFailure;writes=$file.Writes;bytes=$channel.Bytes}
}
foreach($mode in @('all-clean','process-dispose-fault','file-dispose-fault','flush-fault','stream-close-fault','unowned-existing-root')){
 $receipt=@{Failure='ORIGINAL_SENTINEL';Faults=@('ORIGINAL_SENTINEL');Forced=$false;Closed=$false;ExitCode=0;CredentialFilesAbsent=$false}
 $start=$null;$encoded=$null;$packet=$null;$held=$true;$receiptWritten=$false;$privateRootOwned=$false;$terminalAuthority=$null
 $privateRoot=Join-Path $draftRoot ('lifecycle-fixture-'+[guid]::NewGuid().ToString('N'));[void][IO.Directory]::CreateDirectory($privateRoot)
 $sentinel=Join-Path $privateRoot 'private-session-receipt.json';[IO.File]::WriteAllText($sentinel,'untouched-synthetic-sentinel')
 $process=[pscustomobject]@{HasExited=$true;ExitCode=0;Disposes=0;DisposeFault=($mode -ceq 'process-dispose-fault')}
 $process|Add-Member ScriptMethod Dispose {$this.Disposes++;if($this.DisposeFault){throw 'MOCK_PROCESS_DISPOSE'}}
 $channels=@()
 foreach($i in @(0,1)){$channels+=@([pscustomobject]@{Name=('stream'+$i);File=(MockFile ($mode -ceq 'flush-fault' -and $i -eq 0) ($mode -ceq 'file-dispose-fault' -and $i -eq 0));Stream=(MockStream ($mode -ceq 'stream-close-fault' -and $i -eq 0));Pending=[Threading.Tasks.Task]::FromResult([int]0);Bytes=0L;EOF=$true;Closed=$false})}
 . $cleanup
 if($receipt.Failure -cne 'ORIGINAL_SENTINEL' -or $process.Disposes -ne 1 -or @($channels|Where-Object {$_.File.Disposes -ne 1 -or $_.File.Flushes -ne 1 -or $_.Stream.Disposes -ne 1}).Count -ne 0 -or [IO.File]::ReadAllText($sentinel) -cne 'untouched-synthetic-sentinel' -or $receiptWritten){throw ('CLEANUP_STAGE_SKIPPED_OR_FIRST_FAILURE_LOST_'+$mode)}
 $rows+=@{mode=$mode;pass=$true;firstFailurePreserved=$true;unownedRootUnwritten=$true;allDisposesAttempted=$true}
}
$credentialAssignment=@($session.FindAll({param($n)$n -is [Management.Automation.Language.AssignmentStatementAst] -and $n.Left.Extent.Text -ceq '$receipt.CredentialFilesAbsent'},$true))
$credentialIf=@($session.FindAll({param($n)$n -is [Management.Automation.Language.IfStatementAst] -and $n.Clauses[0].Item1.Extent.Text -ceq '-not $receipt.CredentialFilesAbsent'},$true))
if($credentialAssignment.Count -ne 1 -or $credentialIf.Count -ne 1){throw 'EXACT_CREDENTIAL_ABSENCE_GATE_REQUIRED'}
$credentialBlock=[scriptblock]::Create($credentialAssignment[0].Extent.Text+"`n"+$credentialIf[0].Extent.Text)
function Test-Path{param($LiteralPath);$script:absenceChecks++;return ($script:present -cne '' -and $LiteralPath.EndsWith($script:present,[StringComparison]::Ordinal))}
foreach($present in @('','.runner','.credentials','.credentials_rsaparams')){
 $script:present=$present;$script:absenceChecks=0;$privateRoot='C:\synthetic-private-root';$receipt=@{Failure=$null;Faults=@();CredentialFilesAbsent=$false}
 . $credentialBlock
 if($receipt.CredentialFilesAbsent -ne ($present -ceq '') -or $script:absenceChecks -ne 3 -or (($null -ne $receipt.Failure) -ne ($present -cne ''))){throw 'CONFIG_CREDENTIAL_ABSENCE_FALSE_ACCEPTANCE'}
 $rows+=@{mode=('credential-presence-'+$(if($present -ceq ''){'none'}else{$present}));pass=$true;checks=$script:absenceChecks;absent=$receipt.CredentialFilesAbsent}
}
$proof=@{SourceSHA=(Get-FileHash -LiteralPath $source).Hash.ToLowerInvariant();Controls=$rows.Count;Rows=$rows;AllPass=$true;EntryExecuted=$false;ActualProcessStarts=0;RealCredentials=0;NetworkCalls=0;DirectoryHelperExecuted=$false}
$path=Join-Path $draftRoot 'synthetic-lifecycle-controls.json';[IO.File]::WriteAllText($path,($proof|ConvertTo-Json -Depth 9),[Text.UTF8Encoding]::new($false))
@{controls=$rows.Count;allPass=$true;actualProcesses=0;network=0;realCredentials=0;proofSHA=(Get-FileHash -LiteralPath $path).Hash.ToLowerInvariant()}|ConvertTo-Json -Compress
