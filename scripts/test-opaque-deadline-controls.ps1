$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
$source=Join-Path $PSScriptRoot 'opaque-private-session.ps1'
$tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseFile($source,[ref]$tokens,[ref]$errors)
$loops=@($ast.FindAll({param($n)$n -is [Management.Automation.Language.WhileStatementAst] -and $n.Extent.Text.Contains('PRIVATE_SESSION_PARENT_DEADLINE')},$true))
if($errors.Count -or $loops.Count -ne 1){throw 'ONE_EXACT_SESSION_LOOP_REQUIRED'}
$body=[scriptblock]::Create($loops[0].Extent.Text)
function Get-CimInstance {param($ClassName);if($ClassName -cne 'Win32_OperatingSystem'){throw 'UNEXPECTED_MOCK_QUERY'};return @{FreePhysicalMemory=8388608}}
$rows=@()
foreach($mode in @('ready-before-90','ready-at-90','stalled-at-90','parent-before-100m','parent-at-100m','terminal-eof-at-15','terminal-complete')){
 $seconds=switch($mode){'ready-before-90'{89.999}'ready-at-90'{90}'stalled-at-90'{90}'parent-before-100m'{5999.999}'parent-at-100m'{6000}default{100}}
 $clock=@{Elapsed=@{TotalSeconds=$seconds;TotalMinutes=($seconds/60)}}
 $terminalClock=if($mode -ceq 'terminal-eof-at-15'){@{Elapsed=@{TotalSeconds=15}}}else{$null}
 $receipt=@{ListeningObserved=($mode -notin @('ready-before-90','ready-at-90','stalled-at-90'));Closed=$false;ExitCode=$null;NaturalExit=$false;AllStreamsEOF=$false;AfterAgentFreeMiB=$null}
 $startup=[Text.StringBuilder]::new();$text=[Text.Encoding]::UTF8.GetBytes('Listening for Jobs')
 $file=[pscustomobject]@{Writes=0};$file|Add-Member ScriptMethod Write {param($Bytes,$Offset,$Count);$this.Writes++}
 $stream=[pscustomobject]@{Reads=0};$stream|Add-Member ScriptMethod ReadAsync {param($Bytes,$Offset,$Count);$this.Reads++;return [Threading.Tasks.Task]::FromResult([int]0)}
 $ready=$mode -like 'ready-*';$pending=if($ready){[Threading.Tasks.Task]::FromResult([int]$text.Length)}else{[Threading.Tasks.TaskCompletionSource[int]]::new().Task}
 $channels=@([pscustomobject]@{Name='stdout';File=$file;Stream=$stream;Buffer=$text;Pending=$pending;Bytes=0L;EOF=($mode -ceq 'terminal-complete')})
 $process=[pscustomobject]@{Waits=0;Terminal=($mode -like 'terminal-*');HasExited=$true;ExitCode=0}
 $process|Add-Member ScriptMethod WaitForExit {param($Milliseconds);$this.Waits++;if($this.Waits -gt 2){throw 'UNEXPECTED_LOOP_ITERATION'};if($null -eq $Milliseconds){return};if($this.Terminal){return $true};throw 'SYNTHETIC_ITERATION_STOP'}
 $failure=$null;try{. $body}catch{$failure=$_.Exception.Message}
 $expected=switch($mode){'ready-at-90'{'PRIVATE_SESSION_CONNECTION_DEADLINE'}'stalled-at-90'{'PRIVATE_SESSION_CONNECTION_DEADLINE'}'parent-at-100m'{'PRIVATE_SESSION_PARENT_DEADLINE'}'terminal-eof-at-15'{'PRIVATE_SESSION_TERMINAL_PIPE_EOF_UNKNOWN'}'terminal-complete'{$null}default{'SYNTHETIC_ITERATION_STOP'}}
 # ScriptMethod wraps the intentional sentinel; all real source deadlines
 # must match exactly. Any other exception is a failed control.
 if($expected -ceq 'SYNTHETIC_ITERATION_STOP'){if($null -eq $failure -or -not $failure.Contains('SYNTHETIC_ITERATION_STOP')){throw ('WRONG_LOOP_RESULT_'+$mode)}}elseif($failure -cne $expected){throw ('WRONG_LOOP_RESULT_'+$mode)}
 if($mode -ceq 'ready-before-90' -and (-not $receipt.ListeningObserved -or $file.Writes -ne 1 -or $stream.Reads -ne 1)){throw 'ON_TIME_READINESS_NOT_PROCESSED'}
 if($mode -in @('ready-at-90','stalled-at-90','parent-at-100m') -and ($process.Waits -ne 0 -or $file.Writes -ne 0 -or $stream.Reads -ne 0)){throw 'DEADLINE_DID_NOT_PRECEDE_IO'}
 if($mode -ceq 'ready-at-90' -and $receipt.ListeningObserved){throw 'LATE_READINESS_ACCEPTED'}
 if($mode -ceq 'terminal-complete' -and (-not $receipt.AllStreamsEOF -or -not $receipt.NaturalExit -or -not $receipt.Closed)){throw 'JOINED_TERMINAL_NOT_ACCEPTED'}
 $rows+=@{mode=$mode;pass=$true;failure=$expected}
}
@{controls=$rows.Count;allPass=$true;sourceSHA=(Get-FileHash -LiteralPath $source).Hash.ToLowerInvariant();actualProcesses=0;network=0;realCredentials=0}|ConvertTo-Json -Compress
