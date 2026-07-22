#Requires -Modules ActiveDirectory
<#
.SYNOPSIS
    Deploys Pre-Windows 2000 Compatible Access scenario.
.DESCRIPTION
    Configures user in Pre-Windows 2000 Compatible Access group for LDAP enumeration.
#>

function Deploy-PreWin2000 {
    [CmdletBinding()]
    param(
        [string]$Difficulty = 'Medium',
        [string]$DomainDN,
        [string]$Domain
    )

    Write-VulnStatus -Message "Deploying Pre-Windows 2000 Compatible Access Scenario..." -Type Info

    $password = Get-VulnPassword -Difficulty $Difficulty -Index 8
    $user = New-VulnUser -SamAccountName 'y.nomura' -Name 'Yuki Nomura' -Password $password -DomainDN $DomainDN -Description 'Legacy Systems Analyst'

    try {
        Add-ADGroupMember -Identity 'Pre-Windows 2000 Compatible Access' -Members 'y.nomura' -ErrorAction Stop
        Write-VulnStatus -Message "Added y.nomura to Pre-Windows 2000 Compatible Access group." -Type Success
    } catch {
        Write-VulnStatus -Message "Pre-Win2000 group member add: $_" -Type Warning
    }

    Write-VulnResult -Name 'Pre-Win2000 Access' -Detail 'y.nomura added to Pre-Windows 2000 Compatible Access' -Success $true -IsLast

    return @{
        Scenario       = 'PreWin2000'
        Description    = 'Pre-Windows 2000 group grants unauthenticated/anonymous LDAP read access'
        CreatedObjects = @('y.nomura')
        AttackCommands = @(
            'ldapsearch -x -H ldap://<dc_ip> -b "<domain_dn>"',
            'NetExec ldap <dc_ip> -u "" -p "" --users',
            'enum4linux -a <dc_ip>'
        )
        AttackPath     = 'Anonymous LDAP Bind -> Pre-Windows 2000 Access -> Full Domain Object Enumeration'
        MitreID        = 'T1087.002'
        Difficulty     = $Difficulty
    }
}

function Remove-PreWin2000 {
    [CmdletBinding()]
    param([string]$DomainDN)

    try {
        Remove-ADGroupMember -Identity 'Pre-Windows 2000 Compatible Access' -Members 'y.nomura' -Confirm:$false -ErrorAction SilentlyContinue
        Remove-ADUser -Identity 'y.nomura' -Confirm:$false -ErrorAction SilentlyContinue
        Write-VulnStatus -Message "Removed Pre-Windows 2000 scenario objects." -Type Success
    } catch {
        Write-VulnStatus -Message "Cleanup error: $_" -Type Warning
    }
}

function Test-PreWin2000 {
    [CmdletBinding()]
    param([string]$DomainDN)

    $u = Get-ADUser -Filter "samAccountName -eq 'y.nomura'" -ErrorAction SilentlyContinue
    if ($u) {
        $groups = Get-ADPrincipalGroupMembership -Identity 'y.nomura' | Select-Object -ExpandProperty Name
        return ('Pre-Windows 2000 Compatible Access' -in $groups)
    }
    return $false
}
