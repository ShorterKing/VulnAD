#Requires -Modules ActiveDirectory
<#
.SYNOPSIS
    Deploys NTLM Downgrade / Weak Auth scenario.
.DESCRIPTION
    Configures legacy NTLM authentication parameters to demonstrate protocol fallback.
#>

function Deploy-NTLMDowngrade {
    [CmdletBinding()]
    param(
        [string]$Difficulty = 'Medium',
        [string]$DomainDN,
        [string]$Domain
    )

    Write-VulnStatus -Message "Deploying NTLM Downgrade / Weak Auth Scenario..." -Type Info

    $password = Get-VulnPassword -Difficulty $Difficulty -Index 11
    $user = New-VulnUser -SamAccountName 'v.dumont' -Name 'Vincent Dumont' -Password $password -DomainDN $DomainDN -Description 'Security Compliance Auditor'

    try {
        Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'LmCompatibilityLevel' -Value 2 -ErrorAction SilentlyContinue
        Write-VulnStatus -Message "Configured LmCompatibilityLevel to 2 (NTLMv1 fallback permitted)." -Type Success
    } catch {}

    Write-VulnResult -Name 'NTLM Downgrade Setup' -Detail 'v.dumont account created, LmCompatibilityLevel adjusted' -Success $true -IsLast

    return @{
        Scenario       = 'NTLMDowngrade'
        Description    = 'Domain configured to accept legacy NTLMv1 authentication traffic'
        CreatedObjects = @('v.dumont')
        AttackCommands = @(
            'Responder.py -I eth0 (Capture NTLMv1 challenge/response)',
            'ntlmrelayx.py -t ldap://<dc_ip>',
            'crack.sh (NTLMv1 cracking via rainbow tables)'
        )
        AttackPath     = 'Force NTLMv1 Auth -> Capture Hash -> Fast Cracking / Relay'
        MitreID        = 'T1557.001'
        Difficulty     = $Difficulty
    }
}

function Remove-NTLMDowngrade {
    [CmdletBinding()]
    param([string]$DomainDN)

    try {
        Remove-ADUser -Identity 'v.dumont' -Confirm:$false -ErrorAction SilentlyContinue
        Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'LmCompatibilityLevel' -Value 5 -ErrorAction SilentlyContinue
        Write-VulnStatus -Message "Removed NTLM Downgrade scenario objects and restored LmCompatibilityLevel." -Type Success
    } catch {
        Write-VulnStatus -Message "Cleanup error: $_" -Type Warning
    }
}

function Test-NTLMDowngrade {
    [CmdletBinding()]
    param([string]$DomainDN)

    $u = Get-ADUser -Filter "samAccountName -eq 'v.dumont'" -ErrorAction SilentlyContinue
    return ($null -ne $u)
}
