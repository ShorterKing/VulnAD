#Requires -Modules ActiveDirectory
<#
.SYNOPSIS
    Deploys Machine Account Quota abuse scenario.
.DESCRIPTION
    Ensures ms-DS-MachineAccountQuota is set to 10 and creates a delegated user.
#>

function Deploy-MachineQuota {
    [CmdletBinding()]
    param(
        [string]$Difficulty = 'Medium',
        [string]$DomainDN,
        [string]$Domain
    )

    Write-VulnStatus -Message "Deploying Machine Account Quota Scenario..." -Type Info

    $password = Get-VulnPassword -Difficulty $Difficulty -Index 2
    $user = New-VulnUser -SamAccountName 'n.petrov' -Name 'Nikita Petrov' -Password $password -DomainDN $DomainDN -Description 'Desktop Support Technician'

    # Ensure quota >= 10
    try {
        Set-ADDomain -Identity $Domain -Replace @{'ms-DS-MachineAccountQuota' = 10} -ErrorAction Stop
        Write-VulnStatus -Message "Set ms-DS-MachineAccountQuota to 10." -Type Success
    } catch {
        Write-VulnStatus -Message "MachineAccountQuota check/update: $_" -Type Warning
    }

    Write-VulnResult -Name 'Machine Account Quota' -Detail 'ms-DS-MachineAccountQuota set to 10, user n.petrov' -Success $true -IsLast

    return @{
        Scenario       = 'MachineQuota'
        Description    = 'Authenticated user permitted to join computer accounts to domain (MAQ=10)'
        CreatedObjects = @('n.petrov')
        AttackCommands = @(
            'PowerMad: New-MachineAccount -MachineAccount EVIL01 -Password ...',
            'Impacket addcomputer.py -computer-name EVIL01$ -computer-pass Pass123! domain/n.petrov'
        )
        AttackPath     = 'n.petrov -> Create Computer Account -> RBCD / Relay / SPN Abuse'
        MitreID        = 'T1136.002'
        Difficulty     = $Difficulty
    }
}

function Remove-MachineQuota {
    [CmdletBinding()]
    param([string]$DomainDN)

    try {
        Remove-ADUser -Identity 'n.petrov' -Confirm:$false -ErrorAction SilentlyContinue
        Write-VulnStatus -Message "Removed Machine Account Quota scenario objects." -Type Success
    } catch {
        Write-VulnStatus -Message "Cleanup error: $_" -Type Warning
    }
}

function Test-MachineQuota {
    [CmdletBinding()]
    param([string]$DomainDN)

    $dom = Get-ADDomain -Identity $DomainDN -ErrorAction SilentlyContinue
    if ($dom) {
        return ($dom.'ms-DS-MachineAccountQuota' -gt 0)
    }
    return $false
}
