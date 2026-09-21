<#
.SYNOPSIS
    Weekly Nerdio/Azure Automation runbook that grants local admin rights on AVD session
    hosts to the user assigned to that host, provided they belong to an approved Entra ID
    admin group.

.DESCRIPTION
    Implements the following flow, intended to run every Monday 00:00:
      1. Read membership of the Entra ID "AVD Admin Access" group.
      2. Read the assigned users of every session host in the AVD host pool.
      3. For each session host with an assigned user, check whether that user is also a
         member of the admin group.
      4. If matched and the user does not already have the local Administrators role on
         their assigned session host, add them to it.
      5. Re-query the session host to confirm the role was applied.
      6. Repeat for every matched user, then terminate.

.PARAMETER SubscriptionId
    Azure subscription containing the host pool and session hosts.

.PARAMETER ResourceGroupName
    Resource group of the AVD host pool.

.PARAMETER HostPoolName
    Name of the AVD host pool whose session-host assignments are read.

.PARAMETER SessionHostResourceGroupName
    Resource group of the session host VMs, if different from the host pool's resource
    group. Defaults to ResourceGroupName.

.PARAMETER AdminGroupObjectId
    Object ID of the Entra ID group whose members are allowed admin access to their
    assigned AVD ("Entra ID Group for AVD Admin Access" in the diagram).

.PARAMETER UseManagedIdentity
    Connect using the Automation Account's / Nerdio runbook's managed identity instead of
    an interactive/service-principal sign-in.

.NOTES
    Requires modules: Az.Accounts, Az.Compute, Az.DesktopVirtualization,
    Microsoft.Graph.Authentication, Microsoft.Graph.Groups, Microsoft.Graph.Users.
    Assumes Entra ID joined (or hybrid joined) session hosts, so local group membership is
    granted via the "AzureAD\<UPN>" account format.
#>

#Requires -Modules Az.Accounts, Az.Compute, Az.DesktopVirtualization, Microsoft.Graph.Authentication, Microsoft.Graph.Groups, Microsoft.Graph.Users

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)]
    [string] $SubscriptionId,

    [Parameter(Mandatory)]
    [string] $ResourceGroupName,

    [Parameter(Mandatory)]
    [string] $HostPoolName,

    [string] $SessionHostResourceGroupName = $ResourceGroupName,

    [Parameter(Mandatory)]
    [string] $AdminGroupObjectId,

    [switch] $UseManagedIdentity
)

$ErrorActionPreference = 'Stop'

function Connect-Services {
    if ($UseManagedIdentity) {
        Connect-AzAccount -Identity -Subscription $SubscriptionId | Out-Null
        Connect-MgGraph -Identity | Out-Null
    }
    else {
        Connect-AzAccount -Subscription $SubscriptionId | Out-Null
        Connect-MgGraph -Scopes 'GroupMember.Read.All', 'User.Read.All' | Out-Null
    }
}

function Get-AllowedAdminUsers {
    param([string] $GroupId)

    Get-MgGroupMember -GroupId $GroupId -All |
        ForEach-Object { Get-MgUser -UserId $_.Id -Property Id, UserPrincipalName } |
        Select-Object Id, UserPrincipalName
}

function Get-AssignedSessionHosts {
    param([string] $ResourceGroupName, [string] $HostPoolName)

    Get-AzWvdSessionHost -ResourceGroupName $ResourceGroupName -HostPoolName $HostPoolName |
        Where-Object { $_.AssignedUser }
}

function Get-SessionHostVmName {
    param([string] $SessionHostName)

    # SessionHost.Name is "<hostpool>/<vmname>.<domain>"; VM run-commands need the short VM name.
    (($SessionHostName -split '/')[-1] -split '\.')[0]
}

function Test-LocalAdmin {
    param([string] $ResourceGroupName, [string] $VmName, [string] $UserPrincipalName)

    $script = @"
`$upn = '$UserPrincipalName'
`$member = Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue |
    Where-Object { `$_.Name -like "*`$upn" }
if (`$member) { Write-Output 'PRESENT' } else { Write-Output 'ABSENT' }
"@

    $result = Invoke-AzVMRunCommand -ResourceGroupName $ResourceGroupName -VMName $VmName `
        -CommandId 'RunPowerShellScript' -ScriptString $script

    return ($result.Value[0].Message -match 'PRESENT')
}

function Add-LocalAdmin {
    param([string] $ResourceGroupName, [string] $VmName, [string] $UserPrincipalName)

    $script = @"
`$upn = '$UserPrincipalName'
`$account = "AzureAD\`$upn"
`$existing = Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue |
    Where-Object { `$_.Name -like "*`$upn" }
if (-not `$existing) {
    Add-LocalGroupMember -Group 'Administrators' -Member `$account
    Write-Output 'ADDED'
} else {
    Write-Output 'ALREADY_MEMBER'
}
"@

    Invoke-AzVMRunCommand -ResourceGroupName $ResourceGroupName -VMName $VmName `
        -CommandId 'RunPowerShellScript' -ScriptString $script | Out-Null
}

# --- Main ---

Connect-Services

$allowedAdmins = Get-AllowedAdminUsers -GroupId $AdminGroupObjectId
Write-Output "Found $($allowedAdmins.Count) member(s) in the AVD admin group."

$sessionHosts = Get-AssignedSessionHosts -ResourceGroupName $ResourceGroupName -HostPoolName $HostPoolName
Write-Output "Found $($sessionHosts.Count) session host(s) with an assigned user."

foreach ($sessionHost in $sessionHosts) {
    $assignedUpn = $sessionHost.AssignedUser
    $match = $allowedAdmins | Where-Object { $_.UserPrincipalName -eq $assignedUpn }

    if (-not $match) {
        Write-Output "Skipping $($sessionHost.Name): assigned user '$assignedUpn' is not in the admin group."
        continue
    }

    $vmName = Get-SessionHostVmName -SessionHostName $sessionHost.Name
    Write-Output "Processing '$vmName' for assigned admin '$assignedUpn'..."

    try {
        if (Test-LocalAdmin -ResourceGroupName $SessionHostResourceGroupName -VmName $vmName -UserPrincipalName $assignedUpn) {
            Write-Output "  '$assignedUpn' already has the admin role on '$vmName'. No action needed."
            continue
        }

        if ($PSCmdlet.ShouldProcess($vmName, "Add '$assignedUpn' to local Administrators")) {
            Add-LocalAdmin -ResourceGroupName $SessionHostResourceGroupName -VmName $vmName -UserPrincipalName $assignedUpn

            if (Test-LocalAdmin -ResourceGroupName $SessionHostResourceGroupName -VmName $vmName -UserPrincipalName $assignedUpn) {
                Write-Output "  Confirmed: '$assignedUpn' now has the admin role on '$vmName'."
            }
            else {
                Write-Warning "  Could not confirm the admin role for '$assignedUpn' on '$vmName' after adding."
            }
        }
    }
    catch {
        Write-Warning "  Failed to process '$vmName' for '$assignedUpn': $($_.Exception.Message)"
    }
}

Write-Output 'Script complete.'
Disconnect-MgGraph | Out-Null
