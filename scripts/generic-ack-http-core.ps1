# Fixed public ACK transport only; signature authority remains in the verifier.
function New-OwnedAckHttpHandler {
 $handler=[Net.Http.HttpClientHandler]::new()
 try {
  $handler.AllowAutoRedirect=$false;$handler.UseProxy=$false;$handler.UseCookies=$false
  $handler.UseDefaultCredentials=$false;$handler.Credentials=$null;$handler.PreAuthenticate=$false
  $handler.AutomaticDecompression=[Net.DecompressionMethods]::None
  return $handler
 }catch{try{$handler.Dispose()}finally{throw 'ACK_HANDLER_PREPARATION_FAILED'}}
}
function New-OwnedAckHttpClient($Handler){return [Net.Http.HttpClient]::new($Handler,$false)}
function New-OwnedAckHttpRequest([uri]$Uri){return [Net.Http.HttpRequestMessage]::new([Net.Http.HttpMethod]::Get,$Uri)}
function Get-OwnedAckHttpBudgetMilliseconds{return 25000}
function Invoke-OwnedAckHttpCore($Context){
 $unknown=[pscustomobject]@{Schema=1;Scope='OWNED_ACK_QUERY_ONLY_NOT_AUTHORITY';HasAck=$false;RetryAllowed=$false;Unknown=$true;Bytes=[byte[]]@()}
 $handler=$null;$client=$null;$request=$null;$response=$null;$stream=$null;$cts=$null;$memory=$null
 $candidate=$null;$failed=$false;$budget=25000;$clock=[Diagnostics.Stopwatch]::StartNew()
 try{
  [void](Get-GenericAckContextPayload $Context)
  $proposed=Get-OwnedAckHttpBudgetMilliseconds
  if(($proposed -isnot [int] -and $proposed -isnot [long]) -or $proposed -lt 1 -or $proposed -gt 25000){throw 'ACK_FINITE_BUDGET_REQUIRED'};$budget=[int]$proposed
  $uri=[uri]('https://raw.githubusercontent.com/'+$Context.PublicRepository+'/owned-terminal-ack-'+$Context.Nonce+'/terminal-ack.txt')
  if($uri.Scheme -cne 'https' -or $uri.Host -cne 'raw.githubusercontent.com' -or $uri.UserInfo -or $uri.Query -or $uri.Fragment -or -not $uri.IsDefaultPort){throw 'FIXED_ACK_URI_REQUIRED'}
  $cts=[Threading.CancellationTokenSource]::new();$cts.CancelAfter([int]$budget)
  $handler=New-OwnedAckHttpHandler;$client=New-OwnedAckHttpClient $handler
  $client.Timeout=[Threading.Timeout]::InfiniteTimeSpan
  $request=New-OwnedAckHttpRequest $uri
  [void]$request.Headers.TryAddWithoutValidation('Accept-Encoding','identity')
  $response=$client.SendAsync($request,[Net.Http.HttpCompletionOption]::ResponseHeadersRead,$cts.Token).GetAwaiter().GetResult()
  $code=[int]$response.StatusCode
  if($code -ne 200 -and $code -ne 404){throw 'ACK_RESPONSE_STATUS_NOT_RETRYABLE'}
  if($null -eq $response.Content){throw 'ACK_CONTENT_REQUIRED'}
  $encoding=@($response.Content.Headers.ContentEncoding)
  if(@($encoding|Where-Object {$_ -cne 'identity'}).Count){throw 'ACK_COMPRESSION_REFUSED'}
  $declared=$response.Content.Headers.ContentLength
  if($null -ne $declared -and ($declared -lt 0 -or $declared -gt 2048)){throw 'ACK_DECLARED_SIZE_REFUSED'}
  $stream=$response.Content.ReadAsStreamAsync().GetAwaiter().GetResult()
  $memory=[IO.MemoryStream]::new();$buffer=New-Object byte[] 2049
  while($true){
   if($clock.ElapsedMilliseconds -ge $budget){throw 'ACK_AGGREGATE_DEADLINE'}
   $count=$stream.ReadAsync($buffer,0,$buffer.Length,$cts.Token).GetAwaiter().GetResult()
   if($count -eq 0){break}
   if($count -lt 0 -or $count -gt $buffer.Length -or $memory.Length+$count -gt 2048){throw 'ACK_STREAM_SIZE_REFUSED'}
   $memory.Write($buffer,0,$count)
  }
  if($clock.ElapsedMilliseconds -ge $budget -or ($null -ne $declared -and $memory.Length -ne $declared)){throw 'ACK_EOF_OR_LENGTH_UNPROVED'}
  if($code -eq 200 -and $memory.Length -eq 0){throw 'ACK_EMPTY_SUCCESS_REFUSED'}
  $bytes=[byte[]]@();if($code -eq 200){$bytes=$memory.ToArray()}
  $candidate=[pscustomobject]@{Schema=1;Scope='OWNED_ACK_QUERY_ONLY_NOT_AUTHORITY';HasAck=($code -eq 200);RetryAllowed=$true;Unknown=$false;Bytes=[byte[]]$bytes}
 }catch{$failed=$true}
 finally{
  # Independently attempt every owned close. A clean body never erases a fault.
  foreach($resource in @($stream,$response,$request,$client,$handler,$memory,$cts)){
   if($null -ne $resource){try{$resource.Dispose()}catch{$failed=$true}}
  }
  if($clock.ElapsedMilliseconds -ge $budget){$failed=$true}
  $clock.Stop()
 }
 if($failed -or $null -eq $candidate){return $unknown}
 return $candidate
}