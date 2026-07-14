#Requires -Modules ActiveDirectory

<#
.SYNOPSIS
    Deploys, removes, and tests LAPS misconfiguration scenarios for VulnAD.

.DESCRIPTION
    This module simulates overly permissive Local Administrator Password Solution
    (LAPS) configurations where low-privileged groups can read the ms-Mcs-AdmPwd
    attribute on computer objects, exposing local administrator passwords.

    MITRE ATT&CK: T1552.006 - Unsecured Credentials: Group Policy Preferences

.NOTES
    Module:     VulnAD
    Component:  LAPS Misconfiguration
    Author:     VulnAD Project
#>

function Deploy-LAPS {
    <#
    .SYNOPSIS
        Deploys LAPS misconfiguration scenarios.
    .DESCRIPTION
        Creates a helpdesk group with read access to the ms-Mcs-AdmPwd property
        on the Workstations OU, allowing any member to retrieve local admin passwords.
    .PARAMETER Difficulty
        Scenario difficulty: Easy, Medium, or Hard.
    .PARAMETER DomainDN
        The distinguished name of the domain (e.g., DC=contoso,DC=com).
    .PARAMETER Domain
        The FQDN of the domain (e.g., contoso.com).
    .EXAMPLE
        Deploy-LAPS -Difficulty Easy -DomainDN 'DC=lab,DC=local' -Domain 'lab.local'
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
        $scenarioName = 'LAPS Misconfiguration'
        Write-VulnStatus -Message "Deploying $scenarioName scenario ($Difficulty)..." -Type Info
        $createdObjects = [System.Collections.Generic.List[string]]::new()

        # GUID for the ms-Mcs-AdmPwd attribute
        $lapsPropertyGuid = [System.Guid]'18e47bca-fd13-11d2-b9bf-00c04fc2dc04'
    }

    process {
        try {
            # ---------------------------------------------------------------
            # 1. Create Group
            # ---------------------------------------------------------------
            $group = New-VulnGroup -Name 'Helpdesk-L1' `
                                   -DomainDN $DomainDN `
                                   -Description 'Level 1 Helpdesk Support Team'
            $createdObjects.Add("CN=Helpdesk-L1,OU=Groups,OU=ADMonolith,$DomainDN")

            Write-VulnResult -Name 'Helpdesk-L1' -Detail 'Group created' -Success $true

            # ---------------------------------------------------------------
            # 2. Create User and add to group
            # ---------------------------------------------------------------
            $pw1 = Get-VulnPassword -Difficulty $Difficulty -Index 0

            $user = New-VulnUser -SamAccountName 'h.murphy' `
                                 -Name 'Hannah Murphy' `
                                 -Password $pw1 `
                                 -DomainDN $DomainDN `
                                 -Description 'Helpdesk Analyst'
            $createdObjects.Add("CN=Hannah Murphy,OU=Users,OU=ADMonolith,$DomainDN")

            Add-ADGroupMember -Identity 'Helpdesk-L1' -Members 'h.murphy' -ErrorAction Stop
            Write-VulnResult -Name 'h.murphy' -Detail 'Helpdesk Analyst added to Helpdesk-L1' -Success $true

            # ---------------------------------------------------------------
            # 3. Ensure Workstations OU exists
            # ---------------------------------------------------------------
            $workstationsOU = "OU=Workstations,OU=ADMonolith,$DomainDN"
            try {
                Get-ADOrganizationalUnit -Identity $workstationsOU -ErrorAction Stop | Out-Null
            }
            catch {
                New-ADOrganizationalUnit -Name 'Workstations' `
                                        -Path "OU=ADMonolith,$DomainDN" `
                                        -ProtectedFromAccidentalDeletion $false `
                                        -ErrorAction Stop
                $createdObjects.Add($workstationsOU)
            }

            # ---------------------------------------------------------------
            # 4. Create computer object
            # ---------------------------------------------------------------
            try {
                New-ADComputer -Name 'VULN-WS01' `
                               -SamAccountName 'VULN-WS01$' `
                               -Path $workstationsOU `
                               -Enabled $true `
                               -Description 'VulnAD LAPS target workstation' `
                               -ErrorAction Stop
                $createdObjects.Add("CN=VULN-WS01,$workstationsOU")
                Write-VulnResult -Name 'VULN-WS01' -Detail 'Computer object created in Workstations OU' -Success $true
            }
            catch [Microsoft.ActiveDirectory.Management.ADIdentityAlreadyExistsException] {
                Write-VulnStatus -Message 'VULN-WS01 already exists, skipping creation.' -Type Warning
                Write-VulnResult -Name 'VULN-WS01' -Detail 'Computer already exists' -Success $true
            }

            # ---------------------------------------------------------------
            # 5. Grant Helpdesk-L1 read/write on ms-Mcs-AdmPwd on the OU
            # ---------------------------------------------------------------
            try {
                $groupSID = (Get-ADGroup -Identity 'Helpdesk-L1' -ErrorAction Stop).SID
                $identity = [System.Security.Principal.SecurityIdentifier]$groupSID

                $ouPath = "AD:\$workstationsOU"
                $acl = Get-Acl -Path $ouPath -ErrorAction Stop

                # ReadProperty ACE for ms-Mcs-AdmPwd
                $readAce = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                    $identity,
                    [System.DirectoryServices.ActiveDirectoryRights]::ReadProperty,
                    [System.Security.AccessControl.AccessControlType]::Allow,
                    $lapsPropertyGuid,
                    [System.DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents,
                    [System.Guid]'bf967a86-0de6-11d0-a285-00aa003049e2'  # Computer class GUID
                )
                $acl.AddAccessRule($readAce)

                # WriteProperty ACE for ms-Mcs-AdmPwd
                $writeAce = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                    $identity,
                    [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty,
                    [System.Security.AccessControl.AccessControlType]::Allow,
                    $lapsPropertyGuid,
                    [System.DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents,
                    [System.Guid]'bf967a86-0de6-11d0-a285-00aa003049e2'
                )
                $acl.AddAccessRule($writeAce)

                Set-Acl -Path $ouPath -AclObject $acl -ErrorAction Stop

                Write-VulnResult -Name 'LAPS ACL' `
                                 -Detail 'Helpdesk-L1 granted ReadProperty+WriteProperty on ms-Mcs-AdmPwd (Workstations OU)' `
                                 -Success $true
            }
            catch {
                Write-VulnStatus -Message "Failed to set LAPS ACL: $_" -Type Error
                Write-VulnResult -Name 'LAPS ACL' -Detail "ACL configuration failed: $($_.Exception.Message)" -Success $false

                # Gracefully handle LAPS not installed
                if ($_.Exception.Message -match 'ms-Mcs-AdmPwd|LAPS|attribute') {
                    Write-VulnStatus -Message 'LAPS schema extensions may not be installed. The ACL was set but the attribute may not exist on computer objects.' -Type Warning
                }
            }

            Write-VulnResult -Name $scenarioName -Detail 'Deployment complete' -Success $true -IsLast

            # ---------------------------------------------------------------
            # 6. Build result object
            # ---------------------------------------------------------------
            $result = @{
                Scenario       = $scenarioName
                Description    = @(
                    'The Helpdesk-L1 group has been granted ReadProperty and WriteProperty access to the ms-Mcs-AdmPwd'
                    'attribute on all computer objects in OU=Workstations,OU=ADMonolith. Any member of this group, including'
                    "h.murphy (Hannah Murphy), can read local administrator passwords managed by LAPS."
                ) -join ' '
                CreatedObjects = $createdObjects.ToArray()
                AttackCommands = @(
                    "# Native LAPS cmdlet — Read LAPS password"
                    "Get-AdmPwdPassword -ComputerName 'VULN-WS01' | Select-Object ComputerName, Password, ExpirationTimestamp"
                    ""
                    "# LAPSToolkit — Enumerate LAPS delegated groups"
                    "Find-LAPSDelegatedGroups"
                    "Find-AdmPwdExtendedRights"
                    "Get-LAPSComputers"
                    ""
                    "# CrackMapExec — Dump LAPS passwords"
                    "crackmapexec ldap $Domain -u 'h.murphy' -p '$pw1' --laps"
                    ""
                    "# PowerView — Read ms-Mcs-AdmPwd directly"
                    "Get-DomainComputer -SearchBase '$workstationsOU' -Properties 'ms-Mcs-AdmPwd', 'ms-Mcs-AdmPwdExpirationTime' | Where-Object { `$_.'ms-Mcs-AdmPwd' -ne `$null }"
                )
                AttackPath     = @(
                    '1. Enumerate groups with read access to ms-Mcs-AdmPwd via LAPSToolkit or BloodHound.'
                    '2. Compromise a member of Helpdesk-L1 (e.g., h.murphy).'
                    '3. Query LAPS passwords for workstations in the Workstations OU.'
                    '4. Use the retrieved local admin password to authenticate to the target workstation.'
                    '5. Pivot laterally or escalate privileges from the workstation.'
                )
                MitreID        = 'T1552.006'
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

function Remove-LAPS {
    <#
    .SYNOPSIS
        Removes all objects created by Deploy-LAPS.
    .PARAMETER DomainDN
        The distinguished name of the domain.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$DomainDN
    )

    Write-VulnStatus -Message 'Removing LAPS Misconfiguration scenario...' -Type Info

    # Remove user
    try {
        Remove-ADUser -Identity 'h.murphy' -Confirm:$false -ErrorAction Stop
        Write-VulnResult -Name 'h.murphy' -Detail 'User removed' -Success $true
    }
    catch {
        Write-VulnResult -Name 'h.murphy' -Detail "Removal failed: $_" -Success $false
    }

    # Remove computer
    try {
        Remove-ADComputer -Identity 'VULN-WS01' -Confirm:$false -ErrorAction Stop
        Write-VulnResult -Name 'VULN-WS01' -Detail 'Computer removed' -Success $true
    }
    catch {
        Write-VulnResult -Name 'VULN-WS01' -Detail "Removal failed: $_" -Success $false
    }

    # Remove group
    try {
        Remove-ADGroup -Identity 'Helpdesk-L1' -Confirm:$false -ErrorAction Stop
        Write-VulnResult -Name 'Helpdesk-L1' -Detail 'Group removed' -Success $true
    }
    catch {
        Write-VulnResult -Name 'Helpdesk-L1' -Detail "Removal failed: $_" -Success $false
    }

    # Remove LAPS ACLs from the Workstations OU
    $workstationsOU = "OU=Workstations,OU=ADMonolith,$DomainDN"
    try {
        $lapsPropertyGuid = [System.Guid]'18e47bca-fd13-11d2-b9bf-00c04fc2dc04'
        $ouPath = "AD:\$workstationsOU"
        $acl = Get-Acl -Path $ouPath -ErrorAction Stop

        $rulesToRemove = $acl.Access | Where-Object {
            $_.ObjectType -eq $lapsPropertyGuid -and
            $_.IdentityReference -match 'Helpdesk-L1'
        }

        foreach ($rule in $rulesToRemove) {
            $acl.RemoveAccessRule($rule) | Out-Null
        }

        Set-Acl -Path $ouPath -AclObject $acl -ErrorAction Stop
        Write-VulnResult -Name 'LAPS ACL' -Detail 'Permissions removed from Workstations OU' -Success $true
    }
    catch {
        Write-VulnResult -Name 'LAPS ACL' -Detail "ACL cleanup failed: $_" -Success $false
    }

    Write-VulnResult -Name 'LAPS Misconfiguration' -Detail 'Cleanup complete' -Success $true -IsLast
}

function Test-LAPS {
    <#
    .SYNOPSIS
        Validates that the LAPS misconfiguration scenario is correctly deployed.
    .PARAMETER DomainDN
        The distinguished name of the domain.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$DomainDN
    )

    $results = @{}

    # Check user
    try {
        Get-ADUser -Identity 'h.murphy' -ErrorAction Stop | Out-Null
        $results['h.murphy'] = $true
    }
    catch {
        $results['h.murphy'] = $false
    }

    # Check group
    try {
        Get-ADGroup -Identity 'Helpdesk-L1' -ErrorAction Stop | Out-Null
        $results['Helpdesk-L1'] = $true
    }
    catch {
        $results['Helpdesk-L1'] = $false
    }

    # Check group membership
    try {
        $members = Get-ADGroupMember -Identity 'Helpdesk-L1' -ErrorAction Stop
        $results['h.murphy in Helpdesk-L1'] = ($members.SamAccountName -contains 'h.murphy')
    }
    catch {
        $results['h.murphy in Helpdesk-L1'] = $false
    }

    # Check computer
    try {
        Get-ADComputer -Identity 'VULN-WS01' -ErrorAction Stop | Out-Null
        $results['VULN-WS01'] = $true
    }
    catch {
        $results['VULN-WS01'] = $false
    }

    # Check LAPS ACL on Workstations OU
    $workstationsOU = "OU=Workstations,OU=ADMonolith,$DomainDN"
    try {
        $lapsPropertyGuid = [System.Guid]'18e47bca-fd13-11d2-b9bf-00c04fc2dc04'
        $acl = Get-Acl -Path "AD:\$workstationsOU" -ErrorAction Stop
        $lapsAces = $acl.Access | Where-Object {
            $_.ObjectType -eq $lapsPropertyGuid -and
            $_.IdentityReference -match 'Helpdesk-L1'
        }
        $results['LAPS ACL'] = ($null -ne $lapsAces -and $lapsAces.Count -ge 1)
    }
    catch {
        $results['LAPS ACL'] = $false
    }

    $allPassed = $results.Values -notcontains $false

    foreach ($key in $results.Keys) {
        $isLast = ($key -eq ($results.Keys | Select-Object -Last 1))
        Write-VulnResult -Name $key -Detail $(if ($results[$key]) { 'Validated' } else { 'Failed' }) `
                         -Success $results[$key] -IsLast:$isLast
    }

    return $allPassed
}

Export-ModuleMember -Function Deploy-LAPS, Remove-LAPS, Test-LAPS

