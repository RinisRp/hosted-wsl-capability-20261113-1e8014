$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'owned-private-terminal-ack.ps1')
$repo=Split-Path -Parent $PSScriptRoot;$passed=0
function Assert($Value,[string]$Name){if(-not $Value){throw ('PRIVATE_WIRING_CONTRACT_FAILED:'+ $Name)}}
function Parse([string]$Name){$t=$null;$e=$null;$a=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot $Name),[ref]$t,[ref]$e);Assert (@($e).Count -eq 0) ('parse-'+$Name);return $a}
function Check-Workflow($w){
 Assert ((@($w.on.PSObject.Properties.Name) -join '|') -ceq 'workflow_dispatch') 'manual-only-trigger'
 Assert ($w.permissions.contents -ceq 'read' -and @($w.permissions.PSObject.Properties).Count -eq 1) 'least-privilege-token'
 Assert ((@($w.jobs.PSObject.Properties.Name) -join '|') -ceq 'qualification') 'one-exact-job-not-decoy'
 $j=$w.jobs.qualification
 Assert ($j.'runs-on' -ceq 'windows-2025-vs2026' -and $j.'timeout-minutes' -eq 210) 'exact-host-and-finite-enclosure'
 Assert ($j.if -ceq "`${{ github.actor == 'RinisRp' && github.repository == 'RinisRp/hosted-wsl-capability-20261113-1e8014' && github.ref == 'refs/heads/codex/issue-447-private-canonical-host' }}") 'exact-actor-repository-ref'
 $source=@($j.steps|Where-Object {$_.PSObject.Properties['id'] -and $_.id -ceq 'source'})
 $opaque=@($j.steps|Where-Object {$_.PSObject.Properties['id'] -and $_.id -ceq 'opaque'})
 Assert ($source.Count -eq 1 -and $opaque.Count -eq 1 -and $source[0].run.Contains('qualify-bridge-source.ps1') -and $opaque[0].run.Contains('probe-wsl.ps1 -OpaquePrivateHost')) 'exact-source-runtime-entrypoints'
 Assert ($opaque[0].if -ceq '${{ success() && inputs.private_host }}' -and $opaque[0].env.OWNED_RUNNER_PACKET -ceq '${{ secrets.OWNED_RUNNER_PACKET }}' -and $opaque[0].env.OWNED_ACK_PUBLIC_KEY -ceq '${{ inputs.ack_public_key }}') 'packet-only-opt-in-runtime'
 $packetCount=0
 foreach($step in $j.steps){
  $envProperty=$step.PSObject.Properties['env']
  if($null -ne $envProperty -and $null -ne $envProperty.Value.PSObject.Properties['OWNED_RUNNER_PACKET']){$packetCount++;Assert ([object]::ReferenceEquals($step,$opaque[0])) 'no-packet-in-other-step'}
  if($step.PSObject.Properties['uses']){
   Assert ($step.uses -cin @('actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803','actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a')) 'immutable-action-pins'
   if($step.uses.StartsWith('actions/checkout@')){Assert ($step.with.'persist-credentials' -is [bool] -and -not $step.with.'persist-credentials' -and $step.with.ref -ceq '${{ github.sha }}') 'exact-checkout-no-persist'}
   if($step.uses.StartsWith('actions/upload-artifact@')){
    Assert ($step.with.path -cin @('${{ steps.source.outputs.out_path }}','${{ steps.generic.outputs.out_path }}','${{ steps.opaque.outputs.generic_disposition_file }}')) 'only-allowlisted-generic-artifacts'
   }
  }
 }
 Assert ($packetCount -eq 1) 'one-packet-injection-only'
 $privateUpload=@($j.steps|Where-Object {$_.PSObject.Properties['with'] -and $_.with.PSObject.Properties['path'] -and $_.with.path -ceq '${{ steps.opaque.outputs.generic_disposition_file }}'})
 Assert ($privateUpload.Count -eq 1 -and $privateUpload[0].if -ceq '${{ always() && inputs.private_host && steps.opaque.outputs.generic_disposition_file != '''' }}') 'private-artifact-is-single-reconstructed-file'
}
$workflowText=[IO.File]::ReadAllText((Join-Path $repo '.github/workflows/capability.yml'));$w=$workflowText|ConvertFrom-Json
Check-Workflow $w;$passed++
foreach($mutation in @('source-secret','bad-upload','broad-trigger','wrong-ref','wrong-action','unconditional-private','wrong-job-decoy')){
 $m=$workflowText|ConvertFrom-Json
 switch($mutation){
  'source-secret'{$m.jobs.qualification.steps[1]|Add-Member NoteProperty env ([pscustomobject]@{OWNED_RUNNER_PACKET='${{ secrets.OWNED_RUNNER_PACKET }}'})}
  'bad-upload'{$m.jobs.qualification.steps[-1].with.path='private-diagnostics/**'}
  'broad-trigger'{$m.on|Add-Member NoteProperty push ([pscustomobject]@{})}
  'wrong-ref'{$m.jobs.qualification.if='${{ true }}'}
  'wrong-action'{$m.jobs.qualification.steps[0].uses='actions/checkout@main'}
  'unconditional-private'{$m.jobs.qualification.steps[4].if='${{ always() }}'}
  'wrong-job-decoy'{$m.jobs|Add-Member NoteProperty decoy $m.jobs.qualification}
 }
 $failed=$false;try{Check-Workflow $m}catch{$failed=$true};Assert $failed ('refuse-'+$mutation);$passed++
}
$exactRef='refs/heads/codex/issue-447-private-canonical-host'
foreach($name in @('probe-wsl.ps1','qualify-bridge-source.ps1','opaque-private-session.ps1','wsl_npipe_bridge_windows.go','test-owned-private-directory.ps1','test-owned-parent-boundary.ps1')){
 $text=[IO.File]::ReadAllText((Join-Path $PSScriptRoot $name))
 Assert ($text.Contains($exactRef) -and -not $text.Contains('refs/heads/codex/wsl-npipe-6f3465')) ('actual-entrypoint-ref-'+$name)
}
$passed++
$q=Parse 'qualify-bridge-source.ps1';$b=Parse 'probe-windows-bridge.ps1';$s=Parse 'opaque-private-session.ps1'
$paths=@($q.FindAll({param($n)$n -is [Management.Automation.Language.AssignmentStatementAst] -and $n.Left.Extent.Text -ceq '$paths'},$true))
$validator=@($b.FindAll({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'SourceManifestValid'},$true))
$keys=@($validator[0].FindAll({param($n)$n -is [Management.Automation.Language.AssignmentStatementAst] -and $n.Left.Extent.Text -ceq '$keys'},$true))
Assert ($paths.Count -eq 1 -and $keys.Count -eq 1) 'unique-source-manifest-definitions'
function Literal-StringArray($Node){
 $allowed=@('ArrayExpressionAst','StatementBlockAst','PipelineAst','CommandExpressionAst','ArrayLiteralAst','StringConstantExpressionAst')
 $all=@($Node.FindAll({param($n) $true},$true))
 Assert (@($all|Where-Object {$_.GetType().Name -cnotin $allowed}).Count -eq 0) 'manifest-has-only-literal-string-array-syntax'
 return @($all|Where-Object {$_ -is [Management.Automation.Language.StringConstantExpressionAst]}|ForEach-Object {$_.Value})
}
$p1=@(Literal-StringArray $paths[0].Right);$p2=@(Literal-StringArray $keys[0].Right)
Assert ($p1.Count -eq 42 -and (@($p1|Sort-Object -Unique).Count -eq 42) -and (($p1|Sort-Object) -join '|') -ceq (($p2|Sort-Object) -join '|')) 'producer-consumer-exact42-inputs'
foreach($path in $p1){Assert (Test-Path -LiteralPath (Join-Path $repo $path) -PathType Leaf) ('source-input-exists-'+$path)};$passed++
$privateNative=@($b.FindAll({param($n)$n -is [Management.Automation.Language.CommandAst] -and $n.GetCommandName() -ceq 'Native' -and $n.Extent.Text.Contains("'opaque-session-owner'")},$true))
$may=@($b.FindAll({param($n)$n -is [Management.Automation.Language.AssignmentStatementAst] -and $n.Left.Extent.Text -ceq '$script:OwnedPrivateLaunchMayHaveOccurred' -and $n.Right.Extent.Text -ceq '$true'},$true))
Assert ($privateNative.Count -eq 1 -and $may.Count -eq 1 -and $may[0].Extent.StartOffset -lt $privateNative[0].Extent.StartOffset -and $privateNative[0].CommandElements[-2].SafeGetValue() -eq 6750 -and $privateNative[0].Extent.Text.Contains("'-BridgeLeaseStartedTick'") -and $privateNative[0].Extent.Text.Contains("'-WrapperStartedTick'")) 'spent-before-native-with-shared-origins';$passed++
$starts=@($s.FindAll({param($n)$n -is [Management.Automation.Language.InvokeMemberExpressionAst] -and $n.Member.Extent.Text -ceq 'Start' -and $n.Expression.Extent.Text -ceq '[Diagnostics.Process]'},$true))
$reads=@($s.FindAll({param($n)$n -is [Management.Automation.Language.CommandAst] -and $n.GetCommandName() -ceq 'Read-OwnedTerminalAuthority'},$true))
$admission=@($s.FindAll({param($n)$n -is [Management.Automation.Language.CommandAst] -and $n.GetCommandName() -ceq 'Assert-OwnedPrivateStartBudget'},$true))
$reconcile=@($s.FindAll({param($n)$n -is [Management.Automation.Language.CommandAst] -and $n.GetCommandName() -ceq 'Reconcile-OwnedPrivateRoot'},$true))
$kills=@($s.FindAll({param($n)$n -is [Management.Automation.Language.InvokeMemberExpressionAst] -and $n.Member.Extent.Text -ceq 'Kill'},$true))
Assert ($starts.Count -eq 1 -and $reads.Count -eq 1 -and $admission.Count -eq 1 -and $reads[0].Extent.StartOffset -lt $starts[0].Extent.StartOffset -and $admission[0].Extent.StartOffset -lt $starts[0].Extent.StartOffset -and $reconcile.Count -eq 1 -and $kills.Count -eq 0) 'pinned-authority-before-start-no-ungated-root-kill';$passed++
foreach($pair in @(@($false,$false,$true),@($false,$true,$true),@($true,$false,$false),@($true,$true,$true))){Assert ((Test-OwnedPrivateCleanupAllowed $pair[0] $pair[1]) -ceq $pair[2]) 'actual-cleanup-admission-truth-table';$passed++}
[pscustomobject]@{Scope='PARSED_PRIVATE_WIRING_AND_ACTUAL_ADMISSION_CONTRACT';Passed=$passed;SourceInputs=$p1.Count;PrivateExecutionStarted=$false;CanonicalAccepted=$false}|ConvertTo-Json -Compress