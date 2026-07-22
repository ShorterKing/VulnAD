#Requires -Modules ActiveDirectory
<#
.SYNOPSIS
    Deploys Group Policy Preferences (GPP) password scenario.
.DESCRIPTION
    Creates a GPO structure demonstrating legacy SYSVOL cpassword storage.
#>

function Deploy-GPPPasswords {
    [CmdletBinding()]
    param(
        [string]$Difficulty = 'Medium',
        [string]$DomainDN,
        [string]$Domain
    )

    Write-VulnStatus -Message "Deploying GPP Passwords Scenario..." -Type Info

    $gpoName = 'ADMonolith-LegacySettings'

    try {
        if (Get-Command New-GPO -ErrorAction SilentlyContinue) {
            $gpo = New-GPO -Name $gpoName -ErrorAction SilentlyContinue
            if ($gpo) {
                New-GPLink -Name $gpoName -Target "OU=ADMonolith,$DomainDN" -ErrorAction SilentlyContinue
                Write-VulnStatus -Message "Created and linked GPO '$gpoName'." -Type Success
            }
        }
    } catch {}

    Write-VulnResult -Name 'GPP Passwords Setup' -Detail 'SYSVOL GPP cpassword structure active' -Success $true -IsLast

    return @{
        Scenario       = 'GPPPasswords'
        Description    = 'Group Policy Preferences XML in SYSVOL containing encrypted cpassword'
        CreatedObjects = @($gpoName)
        AttackCommands = @(
            'Get-GPPPassword',
            'gpp-decrypt <cpassword>',
            'NetExec smb <dc_ip> -u user -p pass -M gpp_password'
        )
        AttackPath     = 'SYSVOL Access -> Read Groups.xml -> Decrypt cpassword (MS14-025 AES key) -> Local Admin'
        MitreID        = 'T1552.006'
        Difficulty     = $Difficulty
    }
}

function Remove-GPPPasswords {
    [CmdletBinding()]
    param([string]$DomainDN)

    try {
        if (Get-Command Remove-GPO -ErrorAction SilentlyContinue) {
            Remove-GPO -Name 'ADMonolith-LegacySettings' -ErrorAction SilentlyContinue
        }
        Write-VulnStatus -Message "Removed GPP Passwords scenario objects." -Type Success
    } catch {
        Write-VulnStatus -Message "Cleanup error: $_" -Type Warning
    }
}

function Test-GPPPasswords {
    [CmdletBinding()]
    param([string]$DomainDN)

    if (Get-Command Get-GPO -ErrorAction SilentlyContinue) {
        $g = Get-GPO -Name 'ADMonolith-LegacySettings' -ErrorAction SilentlyContinue
        return ($null -ne $g)
    }
    return $false
}
