$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
try{
 . (Join-Path $PSScriptRoot 'private-job-admission-core.ps1')
 $path=Join-Path $PSScriptRoot 'expected-job.json';$item=Get-Item -LiteralPath $path -Force
 if($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $item.Length -lt 1 -or $item.Length -gt 4096){throw 'BOUNDED_PRIVATE_DESCRIPTOR_REQUIRED'}
 $data=[Text.UTF8Encoding]::new($false,$true).GetString([IO.File]::ReadAllBytes($path))|ConvertFrom-Json
 $context=@{}
 foreach($name in @('GITHUB_RUN_ID','GITHUB_RUN_ATTEMPT','GITHUB_REPOSITORY','GITHUB_SHA','GITHUB_JOB','RUNNER_NAME','GITHUB_REF','GITHUB_WORKFLOW_REF')){$context[$name]=[Environment]::GetEnvironmentVariable($name,'Process')}
 Assert-OwnedPrivateJobAdmission $data $context
 $privateRoot=Split-Path -Parent $PSScriptRoot;$config=Join-Path $privateRoot 'empty-docker-config'
 $configItem=Get-Item -LiteralPath $config -Force
 if(-not $configItem.PSIsContainer -or ($configItem.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'OWNED_EMPTY_DOCKER_CONFIG_REQUIRED'}
 $commandPath=[Environment]::GetEnvironmentVariable('GITHUB_ENV','Process')
 $expectedDirectory=Join-Path $privateRoot 'agent\_work\_temp\_runner_file_commands'
 if([string]::IsNullOrEmpty($commandPath) -or -not [IO.Path]::IsPathRooted($commandPath) -or [IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($commandPath)) -ine [IO.Path]::GetFullPath($expectedDirectory) -or [IO.Path]::GetFileName($commandPath) -cnotmatch '\Aset_env_[0-9a-fA-F-]{36}\z'){throw 'EXACT_HOOK_ENV_COMMAND_FILE_REQUIRED'}
 $commandItem=Get-Item -LiteralPath $commandPath -Force
 if($commandItem.PSIsContainer -or ($commandItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $commandItem.Length -ne 0){throw 'FRESH_ORDINARY_HOOK_ENV_FILE_REQUIRED'}
 $endpoint='npipe:////./pipe/hosted_wsl_'+$data.Nonce
 $bytes=[Text.UTF8Encoding]::new($false).GetBytes('DOCKER_HOST='+$endpoint+[Environment]::NewLine+'DOCKER_CONFIG='+$config+[Environment]::NewLine)
 # File commands are processed even on hook failure. Every admission check
 # MUST precede this only write; late I/O failure remains a failed operation.
 $file=[IO.File]::Open($commandPath,'Append','Write','None')
 try{if($file.Length -ne 0){throw 'HOOK_ENV_FILE_CHANGED'};$file.Write($bytes,0,$bytes.Length);$file.Flush($true)}finally{$file.Dispose()}
 [Console]::Out.WriteLine('OWNED_PRIVATE_JOB_ADMISSION_OK')
 exit 0
}catch{
 [Console]::Out.WriteLine('OWNED_PRIVATE_JOB_ADMISSION_REFUSED')
 exit 1
}