function New-OwnedPrivateDirectory([string]$Path,[string]$OwnerSID){
 if(-not ('OwnedLease.ExclusiveDirectory' -as [type])){
  Add-Type -TypeDefinition @"
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
namespace OwnedLease {
 public static class ExclusiveDirectory {
  [StructLayout(LayoutKind.Sequential)] private struct SECURITY_ATTRIBUTES { public int nLength; public IntPtr lpSecurityDescriptor; [MarshalAs(UnmanagedType.Bool)] public bool bInheritHandle; }
  [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool CreateDirectoryW(string path, ref SECURITY_ATTRIBUTES attributes);
  public static void Create(string path, byte[] descriptor) {
   IntPtr sd=Marshal.AllocHGlobal(descriptor.Length);
   try { Marshal.Copy(descriptor,0,sd,descriptor.Length); var attributes=new SECURITY_ATTRIBUTES { nLength=Marshal.SizeOf<SECURITY_ATTRIBUTES>(), lpSecurityDescriptor=sd, bInheritHandle=false }; if(!CreateDirectoryW(path,ref attributes)) throw new Win32Exception(Marshal.GetLastWin32Error(),"Exclusive private directory creation refused"); }
   finally { Marshal.FreeHGlobal(sd); }
  }
 }
}
"@
 }
 if($Path -cnotmatch '\A[A-Z]:\\[A-Za-z0-9_\\.-]+\z' -or [IO.Path]::GetFullPath($Path) -cne $Path){throw 'EXACT_PRIVATE_DIRECTORY_PATH_REQUIRED'}
 $descriptor=[Security.AccessControl.DirectorySecurity]::new();$descriptor.SetOwner([Security.Principal.SecurityIdentifier]::new($OwnerSID));$descriptor.SetAccessRuleProtection($true,$false)
 $allowed=@($OwnerSID,'S-1-5-18','S-1-5-32-544'|Sort-Object -Unique)
 foreach($sid in $allowed){[void]$descriptor.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid),'FullControl','ContainerInherit,ObjectInherit','None','Allow'))}
 [OwnedLease.ExclusiveDirectory]::Create($Path,$descriptor.GetSecurityDescriptorBinaryForm())
 $item=Get-Item -LiteralPath $Path -Force
 if(-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or @(Get-ChildItem -LiteralPath $Path -Force).Count){throw 'ORDINARY_EMPTY_PRIVATE_DIRECTORY_REQUIRED'}
 $actual=Get-Acl -LiteralPath $Path
 if(-not $actual.AreAccessRulesProtected -or $actual.GetOwner([Security.Principal.SecurityIdentifier]).Value -cne $OwnerSID){throw 'PRIVATE_OWNER_DACL_READBACK_FAILED'}
 $rules=@($actual.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))
 if($rules.Count -ne $allowed.Count){throw 'EXACT_PRIVATE_DACL_REQUIRED'}
 foreach($rule in $rules){if($rule.IsInherited -or $rule.AccessControlType -ne 'Allow' -or $rule.IdentityReference.Value -cnotin $allowed -or $rule.FileSystemRights -ne [Security.AccessControl.FileSystemRights]::FullControl -or $rule.InheritanceFlags -ne ([Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit) -or $rule.PropagationFlags -ne [Security.AccessControl.PropagationFlags]::None){throw 'EXACT_PRIVATE_DACL_REQUIRED'}}
}
