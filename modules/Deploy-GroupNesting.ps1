#Requires -Modules ActiveDirectory

<#
.SYNOPSIS
    Deploys nested group privilege escalation scenarios in Active Directory.

.DESCRIPTION
    Creates a chain of nested groups that ultimately grants Domain Admins membership
    through transitive group nesting. A low-privileged user is placed in the first
    group of the chain, making them a Domain Admin through 4 hops of indirection.
    At Hard difficulty, decoy groups are added to increase analysis complexity.

    MITRE ATT&CK: T1078.002 - Valid Accounts: Domain Accounts

.PARAMETER Difficulty
    Scenario difficulty level. Hard adds decoy groups to obscure the real chain.
    Valid values: Easy, Medium, Hard.

.PARAMETER DomainDN
    The distinguished name of the domain (e.g., DC=contoso,DC=com).

.PARAMETER Domain
    The NetBIOS or FQDN of the domain (e.g., contoso.com).

.EXAMPLE
    Deploy-GroupNesting -Difficulty Medium -DomainDN 'DC=contoso,DC=com' -Domain 'contoso.com'

.EXAMPLE
    Remove-GroupNesting -DomainDN 'DC=contoso,DC=com'

.EXAMPLE
    Test-GroupNesting -DomainDN 'DC=contoso,DC=com'

.NOTES
    Module: VulnAD - Group Nesting Privilege Escalation
    Author: VulnAD Project
    Requires: ActiveDirectory module, VulnAD-Core.ps1 helpers
#>

function Deploy-GroupNesting {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('Easy', 'Medium', 'Hard')]
        [string]$Difficulty,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$DomainDN,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Domain
    )

    begin {
        Write-VulnStatus -Message "Deploying Group Nesting scenario [$Difficulty]" -Type 'Info'

        $usersOU   = "OU=Users,OU=ADMonolith,$DomainDN"
        $groupsOU  = "OU=Groups,OU=ADMonolith,$DomainDN"
        $createdObjects = [System.Collections.Generic.List[string]]::new()

        # Define the nesting chain
        $chainGroups = @(
            @{ Name = 'Support-Team';          Description = 'Customer support team members' },
            @{ Name = 'IT-Operations';         Description = 'IT operations and helpdesk staff' },
            @{ Name = 'Infrastructure-Admins'; Description = 'Infrastructure administration team' },
            @{ Name = 'Server-Operators-Priv'; Description = 'Privileged server operators group' }
        )

        # Decoy groups for Hard difficulty
        $decoyGroups = @(
            @{ Name = 'Shadow-Ops';          Description = 'Shadow operations coordination group' },
            @{ Name = 'Network-Monitoring';   Description = 'Network monitoring and alerting team' }
        )
    }

    process {
        try {
            # ---------------------------------------------------------------
            # Step 1: Create the nesting chain groups
            # ---------------------------------------------------------------
            Write-VulnStatus -Message "Creating group nesting chain" -Type 'Info'

            foreach ($groupDef in $chainGroups) {
                $group = New-VulnGroup `
                    -Name $groupDef.Name `
                    -DomainDN $DomainDN `
                    -Description $groupDef.Description

                if ($group) {
                    $createdObjects.Add("CN=$($groupDef.Name),$groupsOU")
                    Write-VulnResult -Name $groupDef.Name -Detail "Group created in VulnAD Groups OU" -Success $true
                }
                else {
                    Write-VulnResult -Name $groupDef.Name -Detail "Failed to create group" -Success $false
                }
            }

            # ---------------------------------------------------------------
            # Step 2: Establish the nesting chain
            #   Support-Team -> IT-Operations -> Infrastructure-Admins -> Server-Operators-Priv
            # ---------------------------------------------------------------
            Write-VulnStatus -Message "Establishing group nesting chain" -Type 'Info'

            $nestingPairs = @(
                @{ Child = 'Support-Team';          Parent = 'IT-Operations' },
                @{ Child = 'IT-Operations';         Parent = 'Infrastructure-Admins' },
                @{ Child = 'Infrastructure-Admins'; Parent = 'Server-Operators-Priv' }
            )

            foreach ($pair in $nestingPairs) {
                try {
                    Add-ADGroupMember -Identity $pair.Parent -Members $pair.Child -ErrorAction Stop
                    Write-VulnResult -Name "$($pair.Child) -> $($pair.Parent)" -Detail "Group nesting established" -Success $true
                }
                catch {
                    Write-VulnResult -Name "$($pair.Child) -> $($pair.Parent)" -Detail "Failed to nest groups: $_" -Success $false
                }
            }

            # ---------------------------------------------------------------
            # Step 3: Add Server-Operators-Priv to Domain Admins
            # ---------------------------------------------------------------
            Write-VulnStatus -Message "Adding Server-Operators-Priv to Domain Admins" -Type 'Info'

            try {
                Add-ADGroupMember -Identity 'Domain Admins' -Members 'Server-Operators-Priv' -ErrorAction Stop
                Write-VulnResult -Name 'Server-Operators-Priv -> Domain Admins' -Detail "Final chain link to Domain Admins established" -Success $true
            }
            catch {
                Write-VulnResult -Name 'Server-Operators-Priv -> Domain Admins' -Detail "Failed to add to Domain Admins: $_" -Success $false
            }

            # ---------------------------------------------------------------
            # Step 4: Create the user d.nguyen
            # ---------------------------------------------------------------
            Write-VulnStatus -Message "Creating user d.nguyen (Customer Support Rep)" -Type 'Info'

            $pwNguyen = Get-VulnPassword -Difficulty $Difficulty -Index 3

            $userNguyen = New-VulnUser `
                -SamAccountName 'd.nguyen' `
                -Name 'Derek Nguyen' `
                -Password $pwNguyen `
                -DomainDN $DomainDN `
                -Description 'Customer Support Representative'

            if ($userNguyen) {
                $createdObjects.Add("CN=Derek Nguyen,$usersOU")

                try {
                    Add-ADGroupMember -Identity 'Support-Team' -Members 'd.nguyen' -ErrorAction Stop
                    Write-VulnResult -Name 'd.nguyen' -Detail "Added to Support-Team (transitive DA via 4 hops)" -Success $true
                }
                catch {
                    Write-VulnResult -Name 'd.nguyen' -Detail "User created but failed to add to Support-Team: $_" -Success $false
                }
            }
            else {
                Write-VulnResult -Name 'd.nguyen' -Detail "Failed to create user" -Success $false
            }

            # ---------------------------------------------------------------
            # Step 5 (Hard only): Create decoy groups
            # ---------------------------------------------------------------
            if ($Difficulty -eq 'Hard') {
                Write-VulnStatus -Message "Creating decoy groups to obscure attack path" -Type 'Info'

                foreach ($decoy in $decoyGroups) {
                    $dGroup = New-VulnGroup `
                        -Name $decoy.Name `
                        -DomainDN $DomainDN `
                        -Description $decoy.Description

                    if ($dGroup) {
                        $createdObjects.Add("CN=$($decoy.Name),$groupsOU")

                        # Add decoy nesting to make analysis harder
                        try {
                            Add-ADGroupMember -Identity $decoy.Name -Members 'd.nguyen' -ErrorAction Stop
                            Write-VulnResult -Name $decoy.Name -Detail "Decoy group created and d.nguyen added (leads nowhere)" -Success $true
                        }
                        catch {
                            Write-VulnResult -Name $decoy.Name -Detail "Decoy group created but membership failed: $_" -Success $false
                        }
                    }
                    else {
                        Write-VulnResult -Name $decoy.Name -Detail "Failed to create decoy group" -Success $false
                    }
                }

                # Cross-link decoys to increase noise
                try {
                    Add-ADGroupMember -Identity 'Network-Monitoring' -Members 'Shadow-Ops' -ErrorAction Stop
                    Write-VulnResult -Name 'Shadow-Ops -> Network-Monitoring' -Detail "Decoy nesting (dead end)" -Success $true -IsLast
                }
                catch {
                    Write-VulnResult -Name 'Shadow-Ops -> Network-Monitoring' -Detail "Decoy nesting failed: $_" -Success $false -IsLast
                }
            }
            else {
                Write-VulnResult -Name 'Deployment' -Detail "Group Nesting scenario complete" -Success $true -IsLast
            }
        }
        catch {
            Write-VulnStatus -Message "Critical error during Group Nesting deployment: $_" -Type 'Error'
            throw
        }
    }

    end {
        # --- Build ASCII attack path ---
        $asciiPath = @(
            '  d.nguyen',
            '    |',
            '    v',
            '  [Support-Team]',
            '    |  (member of)',
            '    v',
            '  [IT-Operations]',
            '    |  (member of)',
            '    v',
            '  [Infrastructure-Admins]',
            '    |  (member of)',
            '    v',
            '  [Server-Operators-Priv]',
            '    |  (member of)',
            '    v',
            '  *** Domain Admins ***'
        ) -join "`n"

        if ($Difficulty -eq 'Hard') {
            $asciiPath += "`n`n  Decoy paths (dead ends):"
            $asciiPath += "`n  d.nguyen -> [Shadow-Ops] -> [Network-Monitoring] -> (nowhere)"
        }

        $result = @{
            Scenario       = 'Group Nesting Privilege Escalation'
            Description    = @(
                'Nested group chain grants Domain Admins through transitive membership.',
                'd.nguyen is a member of Support-Team, which nests 4 levels deep to Domain Admins.',
                'Chain: Support-Team -> IT-Operations -> Infrastructure-Admins -> Server-Operators-Priv -> Domain Admins',
                'This represents a real-world scenario where group nesting obscures effective permissions.'
            ) -join "`n"
            CreatedObjects = $createdObjects.ToArray()
            AttackCommands = @(
                '# --- BloodHound: Visualize group nesting paths ---',
                '# Import SharpHound data and query: "Shortest Paths to Domain Admins"',
                '# Or use Cypher: MATCH p=shortestPath((u:User {name:"D.NGUYEN@' + $Domain.ToUpper() + '"})-[*1..]->(g:Group {name:"DOMAIN ADMINS@' + $Domain.ToUpper() + '"})) RETURN p',
                '',
                '# --- PowerView: Recursive group membership ---',
                "Get-DomainGroup -MemberIdentity 'd.nguyen' -Recurse",
                "Get-DomainGroupMember -Identity 'Domain Admins' -Recurse | Select-Object MemberName,MemberObjectClass",
                '',
                '# --- AD Module: Recursive group enumeration ---',
                "Get-ADGroupMember -Identity 'Domain Admins' -Recursive | Select-Object name,SamAccountName",
                "Get-ADPrincipalGroupMembership -Identity 'd.nguyen' | Select-Object name",
                '',
                '# --- Manual chain verification ---',
                "Get-ADGroupMember -Identity 'Support-Team'",
                "Get-ADGroupMember -Identity 'IT-Operations'",
                "Get-ADGroupMember -Identity 'Infrastructure-Admins'",
                "Get-ADGroupMember -Identity 'Server-Operators-Priv'"
            )
            AttackPath     = $asciiPath
            MitreID        = 'T1078.002'
            Difficulty     = $Difficulty
        }

        Write-VulnStatus -Message "Group Nesting scenario deployed successfully" -Type 'Success'
        return $result
    }
}

function Remove-GroupNesting {
    <#
    .SYNOPSIS
        Removes all objects created by the Group Nesting scenario.

    .PARAMETER DomainDN
        The distinguished name of the domain.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$DomainDN
    )

    begin {
        Write-VulnStatus -Message "Removing Group Nesting scenario objects" -Type 'Info'
        $groupsToRemove = @('Support-Team', 'IT-Operations', 'Infrastructure-Admins', 'Server-Operators-Priv', 'Shadow-Ops', 'Network-Monitoring')
    }

    process {
        # --- Remove Server-Operators-Priv from Domain Admins first ---
        try {
            Remove-ADGroupMember -Identity 'Domain Admins' -Members 'Server-Operators-Priv' -Confirm:$false -ErrorAction Stop
            Write-VulnResult -Name 'Domain Admins membership' -Detail "Server-Operators-Priv removed from Domain Admins" -Success $true
        }
        catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
            Write-VulnResult -Name 'Domain Admins membership' -Detail "Server-Operators-Priv not found in Domain Admins" -Success $true
        }
        catch {
            Write-VulnResult -Name 'Domain Admins membership' -Detail "Failed to remove from Domain Admins: $_" -Success $false
        }

        # --- Remove user ---
        try {
            Remove-ADUser -Identity 'd.nguyen' -Confirm:$false -ErrorAction Stop
            Write-VulnResult -Name 'd.nguyen' -Detail "User removed successfully" -Success $true
        }
        catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
            Write-VulnResult -Name 'd.nguyen' -Detail "User not found (already removed)" -Success $true
        }
        catch {
            Write-VulnResult -Name 'd.nguyen' -Detail "Failed to remove user: $_" -Success $false
        }

        # --- Remove groups (reverse order to avoid dependency issues) ---
        foreach ($groupName in $groupsToRemove) {
            try {
                Remove-ADGroup -Identity $groupName -Confirm:$false -ErrorAction Stop
                Write-VulnResult -Name $groupName -Detail "Group removed successfully" -Success $true -IsLast:($groupName -eq $groupsToRemove[-1])
            }
            catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
                Write-VulnResult -Name $groupName -Detail "Group not found (already removed or not created)" -Success $true -IsLast:($groupName -eq $groupsToRemove[-1])
            }
            catch {
                Write-VulnResult -Name $groupName -Detail "Failed to remove group: $_" -Success $false -IsLast:($groupName -eq $groupsToRemove[-1])
            }
        }
    }

    end {
        Write-VulnStatus -Message "Group Nesting cleanup complete" -Type 'Success'
    }
}

function Test-GroupNesting {
    <#
    .SYNOPSIS
        Validates that Group Nesting scenario objects exist and chain is intact.

    .PARAMETER DomainDN
        The distinguished name of the domain.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$DomainDN
    )

    begin {
        Write-VulnStatus -Message "Testing Group Nesting scenario" -Type 'Info'
        $allPassed = $true
    }

    process {
        # --- Test user exists ---
        try {
            $user = Get-ADUser -Identity 'd.nguyen' -ErrorAction Stop
            Write-VulnResult -Name 'd.nguyen' -Detail "User exists" -Success $true
        }
        catch {
            Write-VulnResult -Name 'd.nguyen' -Detail "User not found: $_" -Success $false
            $allPassed = $false
        }

        # --- Test group chain existence ---
        $expectedGroups = @('Support-Team', 'IT-Operations', 'Infrastructure-Admins', 'Server-Operators-Priv')
        foreach ($groupName in $expectedGroups) {
            try {
                $grp = Get-ADGroup -Identity $groupName -ErrorAction Stop
                Write-VulnResult -Name $groupName -Detail "Group exists" -Success $true
            }
            catch {
                Write-VulnResult -Name $groupName -Detail "Group not found: $_" -Success $false
                $allPassed = $false
            }
        }

        # --- Test transitive DA membership ---
        try {
            $daMembers = Get-ADGroupMember -Identity 'Domain Admins' -Recursive -ErrorAction Stop |
                Select-Object -ExpandProperty SamAccountName

            if ($daMembers -contains 'd.nguyen') {
                Write-VulnResult -Name 'Transitive DA' -Detail "d.nguyen is a recursive member of Domain Admins" -Success $true -IsLast
            }
            else {
                Write-VulnResult -Name 'Transitive DA' -Detail "d.nguyen is NOT a recursive member of Domain Admins" -Success $false -IsLast
                $allPassed = $false
            }
        }
        catch {
            Write-VulnResult -Name 'Transitive DA' -Detail "Failed to check DA membership: $_" -Success $false -IsLast
            $allPassed = $false
        }
    }

    end {
        if ($allPassed) {
            Write-VulnStatus -Message "All Group Nesting tests passed" -Type 'Success'
        }
        else {
            Write-VulnStatus -Message "Some Group Nesting tests failed" -Type 'Warning'
        }
        return $allPassed
    }
}

