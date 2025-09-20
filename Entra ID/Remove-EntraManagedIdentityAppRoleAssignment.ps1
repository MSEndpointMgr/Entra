<#
.SYNOPSIS
    Remove API (including Microsoft Graph) Permissions from a Managed Identity.

.DESCRIPTION
    This script removes API permissions (app roles) from a Managed Identity in Entra ID. 
    You can specify the Managed Identity by display name or object ID, and remove one or more permissions (app roles) for Microsoft Graph or a custom API.

.PARAMETER TenantID
    The Entra ID tenant ID or the common name, e.g. 'tenant.onmicrosoft.com'.

.PARAMETER APIName
    The API name to remove permissions from. Defaults to 'Microsoft Graph'. Specify a custom API name to remove permissions for other APIs.

.PARAMETER ManagedIdentityName
    The Managed Identity display name. Use this parameter set to identify the Managed Identity by name.

.PARAMETER ManagedIdentityObjectId
    The Managed Identity object ID. Use this parameter set to identify the Managed Identity by object ID.

.PARAMETER PermissionName
    The permission name(s) (app role) to remove from the Managed Identity.

.EXAMPLE
    # Remove Microsoft Graph 'Device.Read.All' permission from a Managed Identity by name:
    .\Remove-EntraManagedIdentityAppRoleAssignment.ps1 -TenantID "tenant.onmicrosoft.com" -ManagedIdentityName "<DisplayName>" -PermissionName "Device.Read.All"

.EXAMPLE
    # Remove Microsoft Graph 'Device.Read.All' and 'User.Read.All' permissions from a Managed Identity by name:
    .\Remove-EntraManagedIdentityAppRoleAssignment.ps1 -TenantID "tenant.onmicrosoft.com" -ManagedIdentityName "<DisplayName>" -PermissionName @("Device.Read.All", "User.Read.All")

.EXAMPLE
    # Remove a custom API 'app_impersonation' permission from a Managed Identity by name:
    .\Remove-EntraManagedIdentityAppRoleAssignment.ps1 -TenantID "tenant.onmicrosoft.com" -APIName "<Custom API Name>" -ManagedIdentityName "<DisplayName>" -PermissionName "app_impersonation"

.EXAMPLE
    # Remove Microsoft Graph 'User.Read.All' permission from a Managed Identity by object ID:
    .\Remove-EntraManagedIdentityAppRoleAssignment.ps1 -TenantID "tenant.onmicrosoft.com" -ManagedIdentityObjectId "<ObjectId>" -PermissionName "User.Read.All"

.EXAMPLE
    # Remove a custom API 'custom_role' permission from a Managed Identity by object ID:
    .\Remove-EntraManagedIdentityAppRoleAssignment.ps1 -TenantID "tenant.onmicrosoft.com" -APIName "<Custom API Name>" -ManagedIdentityObjectId "<ObjectId>" -PermissionName "custom_role"

.NOTES
    FileName:    Remove-EntraManagedIdentityAppRoleAssignment.ps1
    Author:      Nickolaj Andersen
    Contact:     @NickolajA
    Created:     2024-10-04
    Updated:     2025-08-25

    Version history:
    1.0.0 - (2024-10-04) Script created
    1.0.1 - (2025-08-25) Updated script to support specifying the API name, parameter sets for managed identity identification, and fixed variable reference bugs
#>
#Requires -Modules Microsoft.Graph.Authentication,Microsoft.Graph.Applications
[CmdletBinding(SupportsShouldProcess, DefaultParameterSetName = "ByName")]
param(
    [Parameter(Mandatory = $true, HelpMessage = "Specify the Entra ID tenant ID or the common name, e.g. 'tenant.onmicrosoft.com'.")]
    [ValidateNotNullOrEmpty()]
    [string]$TenantID,

    [Parameter(Mandatory = $false, HelpMessage = "Specify the API name to remove permissions from.")]
    [ValidateNotNullOrEmpty()]
    [string]$APIName = "Microsoft Graph",

    [Parameter(Mandatory = $true, ParameterSetName = "ByName", HelpMessage = "Specify the Managed Identity display name.")]
    [ValidateNotNullOrEmpty()]
    [string]$ManagedIdentityName,

    [Parameter(Mandatory = $true, ParameterSetName = "ById", HelpMessage = "Specify the Managed Identity object ID.")]
    [ValidateNotNullOrEmpty()]
    [string]$ManagedIdentityObjectId,

    [Parameter(Mandatory = $true, HelpMessage = "Specify the permission name (app role).")]
    [ValidateNotNullOrEmpty()]
    [Alias("PermissionNames")]
    [string[]]$PermissionName
)
Process {
    # Connect to Microsoft Graph with required scopes
    Connect-MgGraph -TenantId $TenantID -Scopes "Application.ReadWrite.All", "AppRoleAssignment.ReadWrite.All", "Directory.ReadWrite.All" -NoWelcome

    # Retrieve the Managed Identity service principal based on parameter set
    if ($PSCmdlet.ParameterSetName -eq "ByName") {
        $ManagedSystemIdentity = Get-MgServicePrincipal -Filter "DisplayName eq '$($ManagedIdentityName)'"
    }
    elseif ($PSCmdlet.ParameterSetName -eq "ById") {
        $ManagedSystemIdentity = Get-MgServicePrincipal -ServicePrincipalId $ManagedIdentityObjectId
    }

    if ($ManagedSystemIdentity -ne $null) {
        # Retrieve the service principal id for specified API
        if ($APIName -like "Microsoft Graph") {
            Write-Output -InputObject "Using default API name value: Microsoft Graph"
            $AppId = '00000003-0000-0000-c000-000000000000'
        }
        else {
            Write-Output -InputObject "Using specified API name value: $($APIName)"
            $APIServicePrincipal = Get-MgServicePrincipal -Search "displayName:$($APIName)" -ConsistencyLevel "eventual"
            if ($APIServicePrincipal -ne $null) {
                $AppId = $APIServicePrincipal.AppId
            }
            else {
                Write-Warning -Message "Could not find service principal with display name: $($APIName)"
                break
            }
        }
        Write-Output -InputObject "Removing '$($APIName)' permissions from: $($ManagedSystemIdentity.DisplayName)"
        
        # Retrieve the service principal for specified API
        $ServicePrincipal = Get-MgServicePrincipal -Search "appId:$($AppId)" -ConsistencyLevel "eventual"
        Write-Output -InputObject "Found '$($APIName)' service principal: $($ServicePrincipal.DisplayName)"
    
        # Foreach permission, remove the API Permissions from the Managed Identity
        foreach ($Permission in $PermissionName) {
            Write-Output -InputObject "Removing current permission: $($Permission)"
            $AppRole = $ServicePrincipal.AppRoles | Where-Object { ($PSItem.Value -eq $Permission) -and ($PSItem.AllowedMemberTypes -contains "Application") }
    
            # Check if AppRole exists
            if ($AppRole -ne $null) {
                Write-Output -InputObject "Found AppRole for current permission name: $($AppRole.DisplayName)"
                $AppRoleAssignment = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $ManagedSystemIdentity.Id | Where-Object { $PSItem.AppRoleId -eq $AppRole.Id }
    
                # Check if AppRoleAssignment for current permission exists
                if ($AppRoleAssignment -ne $null) {
                    try {
                        Write-Output -InputObject "Removing '$($AppRole.DisplayName)' from: $($ManagedSystemIdentity.DisplayName)"
                        Remove-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $ManagedSystemIdentity.Id -AppRoleAssignmentId $AppRoleAssignment.Id -ErrorAction "Stop"
                        Write-Output -InputObject "Successfully removed permission '$($AppRole.DisplayName)' from: $($ManagedSystemIdentity.DisplayName)"
                    }
                    catch {
                        Write-Warning -Message "Failed to remove permission '$($AppRole.DisplayName)' from: $($ManagedSystemIdentity.DisplayName)"
                    }
                }
                else {
                    Write-Output "Permission '$($AppRole.DisplayName)' is not assigned to: $($ManagedSystemIdentity.DisplayName)"
                }
            }
            else {
                Write-Warning -Message "Could not find AppRole with permission name: $($Permission)"
            }
        }
    }
    else {
        if ($PSCmdlet.ParameterSetName -eq "ByName") {
            Write-Warning -Message "Could not find Managed Identity with display name: $($ManagedIdentityName)"
        }
        else {
            Write-Warning -Message "Could not find Managed Identity with object ID: $($ManagedIdentityObjectId)"
        }
    }
}