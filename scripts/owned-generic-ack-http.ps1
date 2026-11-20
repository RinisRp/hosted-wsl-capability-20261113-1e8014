# Sanitized owned child; operational30s/15s enclosures do not claim blocked OS
# startup/disposal is interruptible. The caller's host/workflow deadline remains.
function Invoke-OwnedGenericAckRead($Context,$Index){
 $unknown=[pscustomobject]@{Scope='OWNED_ACK_QUERY_ONLY_NOT_AUTHORITY';HasAck=$false;RetryAllowed=$false;Unknown=$true;Bytes=[byte[]]@()}
 $process=$null;$candidate=$null;$failed=$false;$held=$false;$channels=@()
 $clock=[Diagnostics.Stopwatch]::StartNew()
 try{
  [void](Get-GenericAckContextPayload $Context)
  if(($Index -isnot [int] -and $Index -isnot [long]) -or $Index -lt 0 -or $Index -ge 300){throw 'BOUNDED_ACK_QUERY_INDEX_REQUIRED'}
  $scriptPath=Join-Path $PSScriptRoot 'read-owned-generic-ack.ps1';$item=Get-Item -LiteralPath $scriptPath -Force
  if($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'REGULAR_ACK_READER_REQUIRED'}
  $args=@('-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',$scriptPath,'-Nonce',$Context.Nonce,'-SourceHead',$Context.SourceHead,'-PublicRun',$Context.Run,'-KeyFingerprint',$Context.KeyFingerprint)
  foreach($arg in $args){if($arg -match '[\s"&|<>]'){throw 'FIXED_ACK_CHILD_VECTOR_REQUIRED'}}
  $start=[Diagnostics.ProcessStartInfo]::new();$start.FileName=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
  $start.Arguments=$args -join ' ';$start.WorkingDirectory=$PSScriptRoot;$start.UseShellExecute=$false;$start.CreateNoWindow=$true;$start.WindowStyle='Hidden'
  $start.RedirectStandardOutput=$true;$start.RedirectStandardError=$true;$start.EnvironmentVariables.Clear()
  foreach($name in @('SystemRoot','WINDIR','COMSPEC','SystemDrive','PATH','PATHEXT','TEMP','TMP','USERPROFILE','APPDATA','LOCALAPPDATA','ProgramFiles','ProgramFiles(x86)','ProgramData','CommonProgramFiles','CommonProgramFiles(x86)','NUMBER_OF_PROCESSORS','PROCESSOR_ARCHITECTURE','USERNAME','USERDOMAIN','HOMEDRIVE','HOMEPATH')){
   $value=[Environment]::GetEnvironmentVariable($name,'Process');if(-not [string]::IsNullOrEmpty($value)){$start.EnvironmentVariables[$name]=$value}
  }
  $start.EnvironmentVariables['PSModulePath']=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\Modules'
  $process=[Diagnostics.Process]::Start($start);$handle=$process.Handle
  if($null -eq $handle -or $handle -eq [IntPtr]::Zero){throw 'HELD_ACK_CHILD_REQUIRED'};$held=$true
  foreach($entry in @(@{Name='stdout';Reader=$process.StandardOutput;Stream=$process.StandardOutput.BaseStream;Limit=4096},@{Name='stderr';Reader=$process.StandardError;Stream=$process.StandardError.BaseStream;Limit=0})){
   $buffer=New-Object byte[] ($entry.Limit+1)
   $channels+=@([pscustomobject]@{Name=$entry.Name;Reader=$entry.Reader;Stream=$entry.Stream;Limit=$entry.Limit;Buffer=$buffer;Memory=[IO.MemoryStream]::new();Pending=$entry.Stream.ReadAsync($buffer,0,$buffer.Length);EOF=$false})
  }
  $closed=$false
  while($clock.ElapsedMilliseconds -lt 30000){
   foreach($channel in $channels){
    if(-not $channel.EOF -and $channel.Pending.IsCompleted){
     $count=$channel.Pending.GetAwaiter().GetResult()
     if($count -eq 0){$channel.EOF=$true}
     else{
      if($count -lt 0 -or $count -gt $channel.Buffer.Length -or $channel.Memory.Length+$count -gt $channel.Limit){throw 'ACK_CHILD_OUTPUT_BOUND'}
      $channel.Memory.Write($channel.Buffer,0,$count)
      $channel.Pending=$channel.Stream.ReadAsync($channel.Buffer,0,$channel.Buffer.Length)
     }
    }
   }
   if($process.WaitForExit(50)){
    $closed=$true
    if(@($channels|Where-Object {-not $_.EOF}).Count -eq 0){break}
   }
  }
  if(-not $closed -or $process.ExitCode -ne 0 -or @($channels|Where-Object {-not $_.EOF}).Count -ne 0 -or $clock.ElapsedMilliseconds -ge 30000){throw 'ACK_CHILD_TERMINAL_OR_STREAM_UNKNOWN'}
  $stdout=[Text.UTF8Encoding]::new($false,$true).GetString($channels[0].Memory.ToArray())
  $data=$stdout|ConvertFrom-Json;$keys=@('Schema','Scope','HasAck','RetryAllowed','Unknown','BytesBase64')
  if($data -isnot [pscustomobject] -or (@($data.PSObject.Properties.Name|Sort-Object) -join '|') -cne (@($keys|Sort-Object) -join '|') -or ($data.Schema -isnot [int] -and $data.Schema -isnot [long]) -or $data.Schema -ne 1 -or $data.Scope -isnot [string] -or $data.Scope -cne 'OWNED_ACK_QUERY_ONLY_NOT_AUTHORITY'){throw 'EXACT_ACK_CHILD_SCHEMA_REQUIRED'}
  foreach($name in @('HasAck','RetryAllowed','Unknown')){if($data.$name -isnot [bool]){throw 'TYPED_ACK_CHILD_FLAGS_REQUIRED'}}
  if($data.Unknown -or -not $data.RetryAllowed -or $data.BytesBase64 -isnot [string] -or $data.BytesBase64.Length -gt 2732){throw 'ACK_QUERY_UNKNOWN'}
  $bytes=[Convert]::FromBase64String($data.BytesBase64)
  if($bytes.Length -gt 2048 -or [Convert]::ToBase64String($bytes) -cne $data.BytesBase64 -or ($data.HasAck -and $bytes.Length -eq 0) -or (-not $data.HasAck -and $bytes.Length -ne 0)){throw 'ACK_CHILD_BYTES_REFUSED'}
  $candidate=[pscustomobject]@{Scope='OWNED_ACK_QUERY_ONLY_NOT_AUTHORITY';HasAck=$data.HasAck;RetryAllowed=$true;Unknown=$false;Bytes=[byte[]]$bytes}
 }catch{$failed=$true}
 finally{
  if($null -ne $process){
   try{
    if(-not $process.HasExited){
     $failed=$true;if(-not $held){throw 'NO_HELD_ACK_ROOT_NO_TERMINATION'}
     $process.Kill();$remaining=[int][Math]::Max(0,45000-$clock.ElapsedMilliseconds)
     if($remaining -lt 1 -or -not $process.WaitForExit($remaining)){throw 'ACK_CHILD_CLOSURE_UNKNOWN'}
    }
   }catch{$failed=$true}
  }
  foreach($channel in $channels){try{$channel.Stream.Dispose()}catch{$failed=$true};try{$channel.Reader.Dispose()}catch{$failed=$true}}
  foreach($channel in $channels){
   if($null -ne $channel.Pending -and -not $channel.Pending.IsCompleted){
    try{$remaining=[int][Math]::Max(0,45000-$clock.ElapsedMilliseconds);if($remaining -lt 1 -or -not $channel.Pending.Wait($remaining)){throw 'ACK_PENDING_READ_UNKNOWN'}}catch{$failed=$true}
   }
   try{$channel.Memory.Dispose()}catch{$failed=$true}
  }
  if($null -ne $process){try{$process.Dispose()}catch{$failed=$true}}
  if($clock.ElapsedMilliseconds -ge 45000){$failed=$true};$clock.Stop()
 }
 if($failed -or $null -eq $candidate){return $unknown};return $candidate
}