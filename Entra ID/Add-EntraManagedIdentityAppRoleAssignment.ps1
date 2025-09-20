<#
.SYNOPSIS
    Assign API (including Microsoft Graph) Permissions to a Managed Identity.

.DESCRIPTION
    This script assigns API permissions (app roles) to a Managed Identity in Entra ID. 
    You can specify the Managed Identity by display name or object ID, and assign one or more permissions (app roles) for Microsoft Graph or a custom API.

.PARAMETER TenantID
    The Entra ID tenant ID or the common name, e.g. 'tenant.onmicrosoft.com'.

.PARAMETER APIName
    The API name to assign permissions to. Defaults to 'Microsoft Graph'. Specify a custom API name to assign permissions for other APIs.

.PARAMETER ManagedIdentityName
    The Managed Identity display name. Use this parameter set to identify the Managed Identity by name.

.PARAMETER ManagedIdentityObjectId
    The Managed Identity object ID. Use this parameter set to identify the Managed Identity by object ID.

.PARAMETER PermissionName
    The permission name(s) (app role) to assign to the Managed Identity.

.EXAMPLE
    # Assign Microsoft Graph 'Device.Read.All' permission to a Managed Identity by name:
    .\Add-EntraManagedIdentityAppRoleAssignment.ps1 -TenantID "tenant.onmicrosoft.com" -ManagedIdentityName "<DisplayName>" -PermissionName "Device.Read.All"

.EXAMPLE
    # Assign Microsoft Graph 'Device.Read.All' and 'User.Read.All' permissions to a Managed Identity by name:
    .\Add-EntraManagedIdentityAppRoleAssignment.ps1 -TenantID "tenant.onmicrosoft.com" -ManagedIdentityName "<DisplayName>" -PermissionName @("Device.Read.All", "User.Read.All")

.EXAMPLE
    # Assign a custom API 'app_impersonation' permission to a Managed Identity by name:
    .\Add-EntraManagedIdentityAppRoleAssignment.ps1 -TenantID "tenant.onmicrosoft.com" -APIName "<Custom API Name>" -ManagedIdentityName "<DisplayName>" -PermissionName "app_impersonation"

.EXAMPLE
    # Assign Microsoft Graph 'User.Read.All' permission to a Managed Identity by object ID:
    .\Add-EntraManagedIdentityAppRoleAssignment.ps1 -TenantID "tenant.onmicrosoft.com" -ManagedIdentityObjectId "<ObjectId>" -PermissionName "User.Read.All"

.EXAMPLE
    # Assign a custom API 'custom_role' permission to a Managed Identity by object ID:
    .\Add-EntraManagedIdentityAppRoleAssignment.ps1 -TenantID "tenant.onmicrosoft.com" -APIName "<Custom API Name>" -ManagedIdentityObjectId "<ObjectId>" -PermissionName "custom_role"

.NOTES
    FileName:    Add-EntraManagedIdentityAppRoleAssignment.ps1
    Author:      Nickolaj Andersen
    Contact:     @NickolajA
    Created:     2024-04-12
    Updated:     2025-08-25

    Version history:
    1.0.0 - (2024-04-12) Script created
    1.0.1 - (2025-01-08) Updated script to also support specifying the API name to assign permissions to, instead of only working with Microsoft Graph
    1.0.2 - (2025-08-25) Added parameter set to support specifying the Managed Identity by object ID or display name
#>
#Requires -Modules Microsoft.Graph.Authentication,Microsoft.Graph.Applications
[CmdletBinding(SupportsShouldProcess, DefaultParameterSetName = "ByName")]
param(
    [Parameter(Mandatory = $true, HelpMessage = "Specify the Entra ID tenant ID or the common name, e.g. 'tenant.onmicrosoft.com'.")]
    [ValidateNotNullOrEmpty()]
    [string]$TenantID,

    [Parameter(Mandatory = $false, HelpMessage = "Specify the API name to assign permissions to.")]
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
        Write-Output -InputObject "Assigning '$($APIName)' permissions to: $($ManagedSystemIdentity.DisplayName)"
        
        # Retrieve the service principal for specified API
        $ServicePrincipal = Get-MgServicePrincipal -Search "appId:$($AppId)" -ConsistencyLevel "eventual"
        Write-Output -InputObject "Found service principal for app role assignment: $($ServicePrincipal.DisplayName)"
    
        # Foreach permission, assign the Microsoft Graph Permissions to the Managed Identity
        foreach ($Permission in $PermissionName) {
            Write-Output -InputObject "Assigning current permission: $($Permission)"
            $AppRole = $ServicePrincipal.AppRoles | Where-Object { ($PSItem.Value -eq $Permission) -and ($PSItem.AllowedMemberTypes -contains "Application") }
    
            # Check if AppRole exists
            if ($AppRole -ne $null) {
                Write-Output -InputObject "Found AppRole for current permission name: $($AppRole.DisplayName)"
                $AppRoleAssignmentExistence = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $ManagedSystemIdentity.Id | Where-Object { $PSItem.AppRoleId -eq $AppRole.Id }
    
                # Check if AppRoleAssignment for current permission exists
                if ($AppRoleAssignmentExistence -eq $null) {
                    Write-Output -InputObject "Assigning '$($AppRole.DisplayName)' to: $($ManagedSystemIdentity.DisplayName)"
                    $AppRoleAssignment = @{
                        "principalId" = $ManagedSystemIdentity.Id
                        "resourceId" = $ServicePrincipal.Id
                        "appRoleId" = $AppRole.Id
                    }
                    New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $ManagedSystemIdentity.Id -BodyParameter $AppRoleAssignment
                }
                else {
                    Write-Output "Permission '$($AppRole.DisplayName)' already exists for: $($ManagedSystemIdentity.DisplayName)"
                }
            }
            else {
                Write-Warning -Message "Could not find AppRole with permission name: $($Permission)"
            }
        }
    }
    else {
        Write-Warning -Message "Could not find Managed Identity with display name: $($ManagedIdentityName)"
    }
}