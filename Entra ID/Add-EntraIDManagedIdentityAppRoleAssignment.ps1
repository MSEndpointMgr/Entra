<#
.SYNOPSIS
    Assign Microsoft Graph Permissions to a Managed Identity.

.DESCRIPTION
    This script assigns Microsoft Graph Permissions to a Managed Identity. 
    The script requires the Managed Identity service principal display name and object ID and the permissions name (app role) to assign.

.PARAMETER TenantID
    The Entra ID tenant ID or the common name, e.g. 'tenant.onmicrosoft.com'.

.PARAMETER ManagedIdentityName
    The Managed Identity display name.

.PARAMETER ManagedIdentityObjectId
    The Managed Identity object identifier.

.PARAMETER PermissionName
    The permission name (app role) to assign to the Managed Identity.

.EXAMPLE
    .\Add-EntraIDManagedIdentityAppRoleAssignment.ps1 -TenantID "tenant.onmicrosoft.com" -ManagedIdentityName "<DisplayName>" -ManagedIdentityObjectId "<ObjectGUID>" -PermissionName "Devices.Read.All"

.NOTES
    FileName:    Add-EntraIDManagedIdentityAppRoleAssignment.ps1
    Author:      Nickolaj Andersen
    Contact:     @NickolajA
    Created:     2024-04-12
    Updated:     2024-04-12

    Version history:
    1.0.0 - (2024-04-12) Script created
#>
#Requires -Modules Microsoft.Graph.Authentication,Microsoft.Graph.Applications
[CmdletBinding(SupportsShouldProcess)]
param(
    [parameter(Mandatory = $true, HelpMessage = "Specify the Entra ID tenant ID or the common name, e.g. 'tenant.onmicrosoft.com'.")]
    [ValidateNotNullOrEmpty()]
    [string]$TenantID,

    [parameter(Mandatory = $true, HelpMessage = "Specify the Managed Identity display name.")]
    [ValidateNotNullOrEmpty()]
    [string]$ManagedIdentityName,

    [parameter(Mandatory = $true, HelpMessage = "Specify the Managed Identity object identifier.")]
    [ValidateNotNullOrEmpty()]
    [string]$ManagedIdentityObjectId,

    [parameter(Mandatory = $false, HelpMessage = "Specify the permission name (app role).")]
    [ValidateNotNullOrEmpty()]
    [string]$PermissionName
)
Process {
    # Connect to Microsoft Graph with required scopes
    Connect-MgGraph -TenantId $TenantID -Scopes "Application.ReadWrite.All", "AppRoleAssignment.ReadWrite.All", "Directory.ReadWrite.All" -NoWelcome

    # Retrieve the Managed Identity service principal
    $ManagedSystemIdentity = Get-MgServicePrincipal -Search "DisplayName:$($ManagedIdentityName)" -ConsistencyLevel "eventual"
    if ($ManagedSystemIdentity -ne $null) {
        Write-Output -InputObject "Assigning Microsoft Graph Permissions to: $($ManagedSystemIdentity.DisplayName)"

        # Retrieve the Microsoft Graph service principal
        $GraphAppId = '00000003-0000-0000-c000-000000000000'
        $GraphServicePrincipal = Get-MgServicePrincipal -Search "appId:$($GraphAppId)" -ConsistencyLevel "eventual"
        Write-Output -InputObject "Found Microsoft Graph Service Principal: $($GraphServicePrincipal.DisplayName)"
    
        # Foreach permission, assign the Microsoft Graph Permissions to the Managed Identity
        foreach ($Permission in $PermissionName) {
            Write-Output -InputObject "Assigning current permission: $($Permission)"
            $AppRole = $GraphServicePrincipal.AppRoles | Where-Object { ($PSItem.Value -eq $Permission) -and ($PSItem.AllowedMemberTypes -contains "Application") }
    
            # Check if AppRole exists
            if ($AppRole -ne $null) {
                Write-Output -InputObject "Found AppRole for current permission name: $($AppRole.DisplayName)"
                $AppRoleAssignmentExistence = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $ManagedIdentityObjectId | Where-Object { $PSItem.AppRoleId -eq $AppRole.Id }
    
                # Check if AppRoleAssignment for current permission exists
                if ($AppRoleAssignmentExistence -eq $null) {
                    Write-Output -InputObject "Assigning '$($AppRole.DisplayName)' to: $($ManagedSystemIdentity.DisplayName)"
                    $AppRoleAssignment = @{
                        "principalId" = $ManagedSystemIdentity.Id
                        "resourceId" = $GraphServicePrincipal.Id
                        "appRoleId" = $AppRole.Id
                    }
                    New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $ManagedSystemIdentity.Id -BodyParameter $AppRoleAssignment
                }
                else {
                    Write-Output "Permission '$($AppRole.DisplayName)' already exists for: $($ManagedSystemIdentity.DisplayName)"
                }
            }
            else {
                Write-Warning -Message "Could not find Approle with permission name $($Permission)"
            }
        }
    }
    else {
        Write-Warning -Message "Could not find Managed Identity with display name: $($ManagedIdentityName)"
    }
}