$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
if($env:GITHUB_ACTIONS -cne 'true' -or $env:RUNNER_ENVIRONMENT -cne 'github-hosted' -or $env:GITHUB_REPOSITORY -cne 'RinisRp/hosted-wsl-capability-20261113-1e8014' -or $env:GITHUB_ACTOR -cne 'RinisRp' -or $env:GITHUB_REF -cne 'refs/heads/codex/wsl-npipe-6f3465' -or $env:PROBE_NONCE -cnotmatch '\A[0-9a-f]{32}\z'){throw 'EXACT_SYNTHETIC_DIRECTORY_CONTEXT_REQUIRED'}
. (Join-Path $PSScriptRoot 'owned-directory-helper.ps1')
$owner=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$base=Join-Path $env:RUNNER_TEMP ('directory-control-'+$env:PROBE_NONCE)
$made=$false;$child=$null;$childMade=$false;$marker=$null
try{
 New-OwnedPrivateDirectory $base $owner;$made=$true
 $child=Join-Path $base 'child';New-OwnedPrivateDirectory $child $owner;$childMade=$true
 $marker=Join-Path $child 'synthetic-marker.txt';[IO.File]::WriteAllText($marker,'SYNTHETIC_NO_CREDENTIALS')
 $before=(Get-FileHash -LiteralPath $marker).Hash;$collision=$null
 try{New-OwnedPrivateDirectory $child $owner}catch{$collision=$_.Exception}
 $native=$collision;while($null -ne $native -and $native -isnot [ComponentModel.Win32Exception]){$native=$native.InnerException}
 if($null -eq $native -or $native.NativeErrorCode -ne 183 -or (Get-FileHash -LiteralPath $marker).Hash -cne $before){throw 'EXCLUSIVE_DIRECTORY_COLLISION_NOT_PRESERVED'}
 Write-Output 'SYNTHETIC_PRIVATE_DIRECTORY_CREATE_DACL_COLLISION_PASS'
}finally{
 if($childMade){
  $resolved=[IO.Path]::GetFullPath($child);if(-not $resolved.StartsWith([IO.Path]::GetFullPath($base)+'\',[StringComparison]::OrdinalIgnoreCase) -or ((Get-Item -LiteralPath $child -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'OWNED_SYNTHETIC_CHILD_CLEANUP_REFUSED'}
  if($null -ne $marker -and (Test-Path -LiteralPath $marker)){Remove-Item -LiteralPath $marker}
  [IO.Directory]::Delete($child,$false)
 }
 if($made){if([IO.Path]::GetFullPath($base) -cne (Join-Path $env:RUNNER_TEMP ('directory-control-'+$env:PROBE_NONCE)) -or ((Get-Item -LiteralPath $base -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'OWNED_SYNTHETIC_BASE_CLEANUP_REFUSED'};[IO.Directory]::Delete($base,$false)}
}
