#Requires -Modules ActiveDirectory
<#
.SYNOPSIS
    Deploys Print Operators SeLoadDriverPrivilege scenario.
.DESCRIPTION
    Creates a user in Print Operators group with rights to load kernel drivers (SeLoadDriverPrivilege).
#>

function Deploy-PrintOperators {
    [CmdletBinding()]
    param(
        [string]$Difficulty = 'Medium',
        [string]$DomainDN,
        [string]$Domain
    )

    Write-VulnStatus -Message "Deploying Print Operators Scenario..." -Type Info

    $password = Get-VulnPassword -Difficulty $Difficulty -Index 0
    $user = New-VulnUser -SamAccountName 'm.oconnor' -Name 'Michael OConnor' -Password $password -DomainDN $DomainDN -Description 'Print Services Administrator'

    try {
        Add-ADGroupMember -Identity 'Print Operators' -Members 'm.oconnor' -ErrorAction Stop
        Write-VulnStatus -Message "Added m.oconnor to Print Operators group." -Type Success
    } catch {
        Write-VulnStatus -Message "Failed to add m.oconnor to Print Operators: $_" -Type Warning
    }

    Write-VulnResult -Name 'Print Operators User' -Detail 'm.oconnor added to Print Operators' -Success $true -IsLast

    return @{
        Scenario       = 'PrintOperators'
        Description    = 'User in Print Operators group possessing SeLoadDriverPrivilege'
        CreatedObjects = @('m.oconnor')
        AttackCommands = @(
            'EoPLoadDriver.exe (Load vulnerable kernel driver)',
            'PrintNightmare exploitation framework'
        )
        AttackPath     = 'm.oconnor (Print Operators) -> SeLoadDriverPrivilege -> Kernel Driver Abuse -> SYSTEM'
        MitreID        = 'T1068'
        Difficulty     = $Difficulty
    }
}

function Remove-PrintOperators {
    [CmdletBinding()]
    param([string]$DomainDN)

    try {
        Remove-ADGroupMember -Identity 'Print Operators' -Members 'm.oconnor' -Confirm:$false -ErrorAction SilentlyContinue
        Remove-ADUser -Identity 'm.oconnor' -Confirm:$false -ErrorAction SilentlyContinue
        Write-VulnStatus -Message "Removed Print Operators scenario objects." -Type Success
    } catch {
        Write-VulnStatus -Message "Cleanup error: $_" -Type Warning
    }
}

function Test-PrintOperators {
    [CmdletBinding()]
    param([string]$DomainDN)

    $u = Get-ADUser -Filter "samAccountName -eq 'm.oconnor'" -ErrorAction SilentlyContinue
    if ($u) {
        $groups = Get-ADPrincipalGroupMembership -Identity 'm.oconnor' | Select-Object -ExpandProperty Name
        return ('Print Operators' -in $groups)
    }
    return $false
}
