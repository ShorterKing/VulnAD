#Requires -Modules ActiveDirectory

<#
.SYNOPSIS
    Deploys password exposure and credential discovery scenarios in Active Directory.

.DESCRIPTION
    Creates users whose passwords are stored in cleartext within insecure AD attributes
    such as Description, extensionAttribute1, and info fields. This simulates a common
    real-world misconfiguration where administrators embed credentials in user object
    properties that are readable by authenticated users.

    MITRE ATT&CK: T1552.001 - Unsecured Credentials: Credentials In Files

.PARAMETER Difficulty
    Scenario difficulty level. Determines password complexity and obfuscation.
    Valid values: Easy, Medium, Hard.

.PARAMETER DomainDN
    The distinguished name of the domain (e.g., DC=contoso,DC=com).

.PARAMETER Domain
    The NetBIOS or FQDN of the domain (e.g., contoso.com).

.EXAMPLE
    Deploy-PasswordExposure -Difficulty Easy -DomainDN 'DC=contoso,DC=com' -Domain 'contoso.com'

.EXAMPLE
    Remove-PasswordExposure -DomainDN 'DC=contoso,DC=com'

.EXAMPLE
    Test-PasswordExposure -DomainDN 'DC=contoso,DC=com'

.NOTES
    Module: VulnAD - Password Exposure Scenarios
    Author: VulnAD Project
    Requires: ActiveDirectory module, VulnAD-Core.ps1 helpers
#>

function Deploy-PasswordExposure {
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
        Write-VulnStatus -Message "Deploying Password Exposure scenario [$Difficulty]" -Type 'Info'

        $usersOU   = "OU=Users,OU=ADMonolith,$DomainDN"
        $createdObjects = [System.Collections.Generic.List[string]]::new()

        # --- Difficulty-tiered password and attribute content ---
        switch ($Difficulty) {
            'Easy' {
                $pwJohnson  = Get-VulnPassword -Difficulty $Difficulty -Index 0
                $pwRoberts  = Get-VulnPassword -Difficulty $Difficulty -Index 1
                $pwSantos   = Get-VulnPassword -Difficulty $Difficulty -Index 2

                $descJohnson = "Temp account password: $pwJohnson - please change"
                $extRoberts  = "Initial password set to $pwRoberts by IT support"
                $infoSantos  = "VPN access granted, credentials: $pwSantos"
            }
            'Medium' {
                $pwJohnson  = Get-VulnPassword -Difficulty $Difficulty -Index 0
                $pwRoberts  = Get-VulnPassword -Difficulty $Difficulty -Index 1
                $pwSantos   = Get-VulnPassword -Difficulty $Difficulty -Index 2

                $descJohnson = "Account reset 2025-01, temp cred: $pwJohnson"
                $extRoberts  = "Initial password set to $pwRoberts by IT support"
                $infoSantos  = "VPN access granted, credentials: $pwSantos"
            }
            'Hard' {
                $pwJohnson  = Get-VulnPassword -Difficulty $Difficulty -Index 0
                $pwRoberts  = Get-VulnPassword -Difficulty $Difficulty -Index 1
                $pwSantos   = Get-VulnPassword -Difficulty $Difficulty -Index 2

                $descJohnson = "Onboarding batch Jan-2025, ref: $pwJohnson - ticket INC0042"
                $extRoberts  = "Initial password set to $pwRoberts by IT support"
                $infoSantos  = "VPN access granted, credentials: $pwSantos"
            }
        }
    }

    process {
        try {
            # ---------------------------------------------------------------
            # User 1: m.johnson — Password exposed in Description field
            # ---------------------------------------------------------------
            Write-VulnStatus -Message "Creating user m.johnson (Finance Analyst) — password in Description" -Type 'Info'

            $userJohnson = New-VulnUser `
                -SamAccountName 'm.johnson' `
                -Name 'Mark Johnson' `
                -Password $pwJohnson `
                -DomainDN $DomainDN `
                -Description $descJohnson

            if ($userJohnson) {
                $createdObjects.Add("CN=Mark Johnson,$usersOU")
                Write-VulnResult -Name 'm.johnson' -Detail "Password stored in Description field" -Success $true
            }
            else {
                Write-VulnResult -Name 'm.johnson' -Detail "Failed to create user" -Success $false
            }

            # ---------------------------------------------------------------
            # User 2: c.roberts — Password exposed in extensionAttribute1
            # ---------------------------------------------------------------
            Write-VulnStatus -Message "Creating user c.roberts (Legal Assistant) — password in extensionAttribute1" -Type 'Info'

            $userRoberts = New-VulnUser `
                -SamAccountName 'c.roberts' `
                -Name 'Claire Roberts' `
                -Password $pwRoberts `
                -DomainDN $DomainDN `
                -Description 'Legal Department - Assistant'

            if ($userRoberts) {
                $createdObjects.Add("CN=Claire Roberts,$usersOU")

                try {
                    Set-ADUser -Identity 'c.roberts' -Replace @{
                        extensionAttribute1 = $extRoberts
                    }
                    Write-VulnResult -Name 'c.roberts' -Detail "Password stored in extensionAttribute1" -Success $true
                }
                catch {
                    Write-VulnResult -Name 'c.roberts' -Detail "User created but failed to set extensionAttribute1: $_" -Success $false
                }
            }
            else {
                Write-VulnResult -Name 'c.roberts' -Detail "Failed to create user" -Success $false
            }

            # ---------------------------------------------------------------
            # User 3: g.santos — Password exposed in info attribute
            # ---------------------------------------------------------------
            Write-VulnStatus -Message "Creating user g.santos (Vendor Contractor) — password in info attribute" -Type 'Info'

            $userSantos = New-VulnUser `
                -SamAccountName 'g.santos' `
                -Name 'Gabriel Santos' `
                -Password $pwSantos `
                -DomainDN $DomainDN `
                -Description 'External Vendor - Contractor Account'

            if ($userSantos) {
                $createdObjects.Add("CN=Gabriel Santos,$usersOU")

                try {
                    Set-ADUser -Identity 'g.santos' -Replace @{
                        info = $infoSantos
                    }
                    Write-VulnResult -Name 'g.santos' -Detail "Password stored in info (Notes) attribute" -Success $true -IsLast
                }
                catch {
                    Write-VulnResult -Name 'g.santos' -Detail "User created but failed to set info attribute: $_" -Success $false -IsLast
                }
            }
            else {
                Write-VulnResult -Name 'g.santos' -Detail "Failed to create user" -Success $false -IsLast
            }
        }
        catch {
            Write-VulnStatus -Message "Critical error during Password Exposure deployment: $_" -Type 'Error'
            throw
        }
    }

    end {
        # --- Build standardized result hashtable ---
        $result = @{
            Scenario       = 'Password Exposure'
            Description    = @(
                'Passwords stored in cleartext within insecure AD user attributes.',
                'm.johnson: password embedded in the Description field.',
                'c.roberts: password stored in extensionAttribute1.',
                'g.santos: password stored in the info (Notes) attribute.',
                'Any authenticated user can query these attributes via LDAP.'
            ) -join "`n"
            CreatedObjects = $createdObjects.ToArray()
            AttackCommands = @(
                '# --- PowerView: Enumerate user descriptions ---',
                "Get-DomainUser -Properties samaccountname,description,info,extensionAttribute1 | Where-Object { `$_.description -or `$_.info -or `$_.extensionAttribute1 }",
                '',
                '# --- ldapsearch (Linux): Query description and info fields ---',
                "ldapsearch -x -H ldap://$Domain -D 'DOMAIN\user' -w 'password' -b '$DomainDN' '(objectClass=user)' description info extensionAttribute1",
                '',
                '# --- CrackMapExec: Enumerate descriptions ---',
                "crackmapexec ldap $Domain -u user -p password -M enum_desc",
                '',
                '# --- AD Explorer: Browse user attributes interactively ---',
                '# Launch ADExplorer.exe, connect to DC, browse user objects',
                '# Inspect Description, Notes (info), and extensionAttribute1 fields',
                '',
                '# --- PowerShell AD Module: Direct query ---',
                "Get-ADUser -Filter * -SearchBase '$usersOU' -Properties description,info,extensionAttribute1 | Select-Object SamAccountName,description,info,extensionAttribute1"
            )
            AttackPath     = @(
                'Authenticated User',
                '  |-- LDAP query user attributes (description, info, extensionAttribute1)',
                '  |-- Extract cleartext passwords from attribute values',
                '  |-- Authenticate as compromised user',
                '  |-- Lateral movement / privilege escalation'
            ) -join "`n"
            MitreID        = 'T1552.001'
            Difficulty     = $Difficulty
        }

        Write-VulnStatus -Message "Password Exposure scenario deployed successfully" -Type 'Success'
        return $result
    }
}

function Remove-PasswordExposure {
    <#
    .SYNOPSIS
        Removes all objects created by the Password Exposure scenario.

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
        Write-VulnStatus -Message "Removing Password Exposure scenario objects" -Type 'Info'
        $usersOU = "OU=Users,OU=ADMonolith,$DomainDN"
        $usersToRemove = @('m.johnson', 'c.roberts', 'g.santos')
    }

    process {
        foreach ($sam in $usersToRemove) {
            try {
                $adUser = Get-ADUser -Identity $sam -ErrorAction Stop
                Remove-ADUser -Identity $sam -Confirm:$false -ErrorAction Stop
                Write-VulnResult -Name $sam -Detail "User removed successfully" -Success $true -IsLast:($sam -eq $usersToRemove[-1])
            }
            catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
                Write-VulnResult -Name $sam -Detail "User not found (already removed)" -Success $true -IsLast:($sam -eq $usersToRemove[-1])
            }
            catch {
                Write-VulnResult -Name $sam -Detail "Failed to remove user: $_" -Success $false -IsLast:($sam -eq $usersToRemove[-1])
            }
        }
    }

    end {
        Write-VulnStatus -Message "Password Exposure cleanup complete" -Type 'Success'
    }
}

function Test-PasswordExposure {
    <#
    .SYNOPSIS
        Validates that Password Exposure scenario objects exist and are correctly configured.

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
        Write-VulnStatus -Message "Testing Password Exposure scenario" -Type 'Info'
        $allPassed = $true
    }

    process {
        # --- Test m.johnson: Description field contains password ---
        try {
            $mj = Get-ADUser -Identity 'm.johnson' -Properties description -ErrorAction Stop
            if ($mj.description -match 'password|cred|ref:') {
                Write-VulnResult -Name 'm.johnson' -Detail "Description contains credential data" -Success $true
            }
            else {
                Write-VulnResult -Name 'm.johnson' -Detail "Description does NOT contain expected credential data" -Success $false
                $allPassed = $false
            }
        }
        catch {
            Write-VulnResult -Name 'm.johnson' -Detail "User not found: $_" -Success $false
            $allPassed = $false
        }

        # --- Test c.roberts: extensionAttribute1 contains password ---
        try {
            $cr = Get-ADUser -Identity 'c.roberts' -Properties extensionAttribute1 -ErrorAction Stop
            if ($cr.extensionAttribute1 -match 'password') {
                Write-VulnResult -Name 'c.roberts' -Detail "extensionAttribute1 contains credential data" -Success $true
            }
            else {
                Write-VulnResult -Name 'c.roberts' -Detail "extensionAttribute1 does NOT contain expected credential data" -Success $false
                $allPassed = $false
            }
        }
        catch {
            Write-VulnResult -Name 'c.roberts' -Detail "User not found: $_" -Success $false
            $allPassed = $false
        }

        # --- Test g.santos: info attribute contains password ---
        try {
            $gs = Get-ADUser -Identity 'g.santos' -Properties info -ErrorAction Stop
            if ($gs.info -match 'credentials') {
                Write-VulnResult -Name 'g.santos' -Detail "info attribute contains credential data" -Success $true -IsLast
            }
            else {
                Write-VulnResult -Name 'g.santos' -Detail "info attribute does NOT contain expected credential data" -Success $false -IsLast
                $allPassed = $false
            }
        }
        catch {
            Write-VulnResult -Name 'g.santos' -Detail "User not found: $_" -Success $false -IsLast
            $allPassed = $false
        }
    }

    end {
        if ($allPassed) {
            Write-VulnStatus -Message "All Password Exposure tests passed" -Type 'Success'
        }
        else {
            Write-VulnStatus -Message "Some Password Exposure tests failed" -Type 'Warning'
        }
        return $allPassed
    }
}

