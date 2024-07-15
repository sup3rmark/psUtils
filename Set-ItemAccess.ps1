function Set-ItemAccess {
    <#
.SYNOPSIS
    Sets ACLs on a specified file or folder.

.EXAMPLE
    PS> Set-ItemAccess -Grantee TestGroup -Target C:\Folder\file.txt -Rights Modify -InheritanceFlags None -PropagationFlag None -AccessType Deny

.EXAMPLE
    PS> Set-ItemAccess -Grantee testuser -Target C:\Folder -Rights CreateDirectories,CreateFiles,Write -InheritanceFlags ContainerInherit,ObjectInherit -PropagationFlag NoPropagateInherit -AccessType Allow

.LINK
    https://learn.microsoft.com/en-us/dotnet/api/system.security.accesscontrol.filesystemaccessrule
#>
    [CmdletBinding()]
    param(
        #Specifies the entity whose access we want to set
        [Parameter (Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]$Grantee,

        #Specifies the target object (file or folder) to which the Access Control Entity should be applied
        [Parameter (Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]$Target,

        #Specifies the rights to be applied for the specified Grantee on the Target: https://learn.microsoft.com/en-us/dotnet/api/system.security.accesscontrol.filesystemrights
        [Parameter (Mandatory = $true)]
        [ValidateSet('AppendData', 'ChangePermissions', 'CreateDirectories', 'CreateFiles', 'Delete', 'DeleteSubdirectoriesAndFiles', 'ExecuteFile', 'FullControl', 'ListDirectory', 'Modify', 'Read', 'ReadAndExecute', 'ReadAttributes', 'ReadData', 'ReadExtendedAttributes', 'ReadPermissions', 'Synchronize', 'TakeOwnership', 'Traverse', 'Write', 'WriteAttributes', 'WriteData', 'WriteExtendedAttributes')]
        [String[]]$Rights,

        #Specifies the inheritance values for child objects
        [Parameter (Mandatory = $true)]
        [ValidateSet('ContainerInherit', 'ObjectInherit', 'None'
        )]
        [String[]]$InheritanceFlags,

        #Specifies whether to propagate changes to existing child objects
        [Parameter (Mandatory = $true)]
        [ValidateSet('InheritOnly', 'NoPropagateInherit', 'None'
        )]
        [String]$PropagationFlag,

        #Specifies whether to allow or deny the specified access to the target object
        [Parameter (Mandatory = $true)]
        [ValidateSet('Allow', 'Deny')]
        [String]$AccessType
    )
	
    $ace = New-Object System.Security.AccessControl.FileSystemAccessRule($Grantee, ($Rights -join ','), ($InheritanceFlags -join ','), $PropagationFlag, $AccessType)

    if (Test-Path -Path $Target) {
        $objACL = Get-Acl $Target
        $objACL.AddAccessRule($ace)
        try {
            Set-Acl -Path $Target -AclObject $objACL -ErrorAction Stop
        }
        catch {
            Write-Error "Failed to set permissons on specified target. Exception: $($_.Exception.Message)"
        }
    }
    else {
        Write-Error "Specified target '$Target' not found."
    }
}