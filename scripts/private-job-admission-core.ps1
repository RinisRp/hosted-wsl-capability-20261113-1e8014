# Admission before default workflow steps, not isolation from always() steps.
function Assert-OwnedPrivateJobDescriptor($Data){
 $keys=@('Schema','Scope','Nonce','Repository','ExpectedJob')
 if($Data -isnot [pscustomobject] -or (@($Data.PSObject.Properties.Name|Sort-Object) -join '|') -cne (@($keys|Sort-Object) -join '|') -or ($Data.Schema -isnot [int] -and $Data.Schema -isnot [long]) -or $Data.Schema -ne 1 -or $Data.Scope -isnot [string] -or $Data.Scope -cne 'PRIVATE_ONE_JOB_ADMISSION_ONLY'){throw 'PRIVATE_JOB_DESCRIPTOR_INVALID'}
 if($Data.Nonce -isnot [string] -or $Data.Nonce -cnotmatch '\A[0-9a-f]{32}\z' -or $Data.Repository -isnot [string] -or $Data.Repository -cnotmatch '\ARinisRp/[A-Za-z0-9_.-]{1,100}\z'){throw 'PRIVATE_JOB_DESCRIPTOR_IDENTITY_INVALID'}
 $job=$Data.ExpectedJob;$jobKeys=@('runId','jobId','attempt','headSHA','mergeSHA','workflowPath','jobKey')
 if($job -isnot [pscustomobject] -or (@($job.PSObject.Properties.Name|Sort-Object) -join '|') -cne (@($jobKeys|Sort-Object) -join '|')){throw 'PRIVATE_EXPECTED_JOB_SHAPE_INVALID'}
 foreach($name in @('runId','jobId','attempt')){if(($job.$name -isnot [int] -and $job.$name -isnot [long]) -or $job.$name -lt 1){throw 'PRIVATE_EXPECTED_JOB_NUMBER_INVALID'}}
 foreach($name in @('headSHA','mergeSHA')){if($job.$name -isnot [string] -or $job.$name -cnotmatch '\A[0-9a-f]{40}\z'){throw 'PRIVATE_EXPECTED_JOB_SOURCE_INVALID'}}
 if($job.workflowPath -isnot [string] -or $job.workflowPath -cnotmatch '\A\.github/workflows/[A-Za-z0-9_-][A-Za-z0-9_.-]{0,99}\.ya?ml\z' -or $job.jobKey -isnot [string] -or $job.jobKey -cnotmatch '\A[A-Za-z_][A-Za-z0-9_-]{0,99}\z'){throw 'PRIVATE_EXPECTED_WORKFLOW_INVALID'}
}
function Assert-OwnedPrivateJobAdmission($Data,[Collections.IDictionary]$Environment){
 Assert-OwnedPrivateJobDescriptor $Data
 $job=$Data.ExpectedJob;$invariant=[Globalization.CultureInfo]::InvariantCulture
 $expected=@{GITHUB_RUN_ID=([long]$job.runId).ToString($invariant);GITHUB_RUN_ATTEMPT=([long]$job.attempt).ToString($invariant);GITHUB_REPOSITORY=$Data.Repository;GITHUB_SHA=$job.mergeSHA;GITHUB_JOB=$job.jobKey;RUNNER_NAME=('OWNED-WINDOWS-'+$Data.Nonce.Substring(0,8))}
 foreach($name in $expected.Keys){if(-not $Environment.Contains($name) -or $Environment[$name] -isnot [string] -or $Environment[$name] -cne $expected[$name]){throw 'PRIVATE_ASSIGNED_JOB_CONTEXT_REFUSED'}}
 if(-not $Environment.Contains('GITHUB_REF') -or $Environment['GITHUB_REF'] -isnot [string] -or $Environment['GITHUB_REF'] -cnotmatch '\Arefs/(?:(?:heads|tags)/[A-Za-z0-9_][A-Za-z0-9._/-]{0,199}|pull/[1-9][0-9]*/merge)\z'){throw 'PRIVATE_ASSIGNED_JOB_REF_REFUSED'}
 $workflow=$Data.Repository+'/'+$job.workflowPath+'@'+$Environment['GITHUB_REF']
 if(-not $Environment.Contains('GITHUB_WORKFLOW_REF') -or $Environment['GITHUB_WORKFLOW_REF'] -isnot [string] -or $Environment['GITHUB_WORKFLOW_REF'] -cne $workflow){throw 'PRIVATE_ASSIGNED_WORKFLOW_REFUSED'}
 # Numeric REST jobId and queue/assignment must still be checked by controller.
}