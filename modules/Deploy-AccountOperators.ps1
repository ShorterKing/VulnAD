#Requires -Modules ActiveDirectory
<#
.SYNOPSIS
    Deploys Account Operators abuse scenario.
.DESCRIPTION
    Creates a user in Account Operators group to manage non-protected users and groups.
#>

function Deploy-AccountOperators {
    [CmdletBinding()]
    param(
        [string]$Difficulty = 'Medium',
        [string]$DomainDN,
        [string]$Domain
    )

    Write-VulnStatus -Message "Deploying Account Operators Scenario..." -Type Info

    $password = Get-VulnPassword -Difficulty $Difficulty -Index 14
    $user = New-VulnUser -SamAccountName 'r.silva' -Name 'Ricardo Silva' -Password $password -DomainDN $DomainDN -Description 'HR Systems Coordinator'

    try {
        Add-ADGroupMember -Identity 'Account Operators' -Members 'r.silva' -ErrorAction Stop
        Write-VulnStatus -Message "Added r.silva to Account Operators group." -Type Success
    } catch {
        Write-VulnStatus -Message "Failed to add r.silva to Account Operators: $_" -Type Warning
    }

    # Target non-protected account
    $targetPw = Get-VulnPassword -Difficulty $Difficulty -Index 15
    $targetUser = New-VulnUser -SamAccountName 'svc_tier1admin' -Name 'Tier1 Admin Service' -Password $targetPw -DomainDN $DomainDN -Description 'Tier 1 Admin Account'

    Write-VulnResult -Name 'Account Operators Setup' -Detail 'r.silva (Account Operators), target: svc_tier1admin' -Success $true -IsLast

    return @{
        Scenario       = 'AccountOperators'
        Description    = 'User in Account Operators group with rights to reset non-protected user passwords'
        CreatedObjects = @('r.silva', 'svc_tier1admin')
        AttackCommands = @(
            'Set-ADAccountPassword -Identity svc_tier1admin',
            'net user svc_tier1admin NewPassword! /domain'
        )
        AttackPath     = 'r.silva (Account Operators) -> Reset Password of svc_tier1admin -> Escalation'
        MitreID        = 'T1098.001'
        Difficulty     = $Difficulty
    }
}

function Remove-AccountOperators {
    [CmdletBinding()]
    param([string]$DomainDN)

    try {
        Remove-ADGroupMember -Identity 'Account Operators' -Members 'r.silva' -Confirm:$false -ErrorAction SilentlyContinue
        Remove-ADUser -Identity 'r.silva' -Confirm:$false -ErrorAction SilentlyContinue
        Remove-ADUser -Identity 'svc_tier1admin' -Confirm:$false -ErrorAction SilentlyContinue
        Write-VulnStatus -Message "Removed Account Operators scenario objects." -Type Success
    } catch {
        Write-VulnStatus -Message "Cleanup error: $_" -Type Warning
    }
}

function Test-AccountOperators {
    [CmdletBinding()]
    param([string]$DomainDN)

    $u = Get-ADUser -Filter "samAccountName -eq 'r.silva'" -ErrorAction SilentlyContinue
    if ($u) {
        $groups = Get-ADPrincipalGroupMembership -Identity 'r.silva' | Select-Object -ExpandProperty Name
        return ('Account Operators' -in $groups)
    }
    return $false
}
