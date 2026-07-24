param(
  [Parameter(Mandatory = $true)]
  [string]$TargetPath
)

$ErrorActionPreference = "Stop"
$acl = Get-Acl -LiteralPath $TargetPath
$currentUserSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$ownerSid = $acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
$rules = @(
  $acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]) | ForEach-Object {
    [pscustomobject]@{
      identitySid = $_.IdentityReference.Value
      accessControlType = $_.AccessControlType.ToString()
      fileSystemRights = [int64]$_.FileSystemRights
      isInherited = [bool]$_.IsInherited
    }
  }
)

[pscustomobject]@{
  protected = [bool]$acl.AreAccessRulesProtected
  currentUserSid = $currentUserSid
  ownerSid = $ownerSid
  rules = $rules
} | ConvertTo-Json -Compress -Depth 4
