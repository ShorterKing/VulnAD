#Requires -Modules ActiveDirectory
<#
.SYNOPSIS
    Deploys Group Managed Service Account (gMSA) abuse scenario.
.DESCRIPTION
    Creates a gMSA account with password retrieve permissions granted to a non-privileged group.
#>

function Deploy-gMSA {
    [CmdletBinding()]
    param(
        [string]$Difficulty = 'Medium',
        [string]$DomainDN,
        [string]$Domain
    )

    Write-VulnStatus -Message "Deploying gMSA Scenario..." -Type Info

    # Ensure KDS Root Key
    try {
        Add-KdsRootKey -EffectiveTime ((Get-Date).AddHours(-10)) -ErrorAction SilentlyContinue
    } catch {}

    $group = New-VulnGroup -Name 'WebApp-Servers' -DomainDN $DomainDN -Description 'Web Application Server Pool'
    $password = Get-VulnPassword -Difficulty $Difficulty -Index 1
    $user = New-VulnUser -SamAccountName 'c.tran' -Name 'Catherine Tran' -Password $password -DomainDN $DomainDN -Description 'Application Support Analyst'

    if ($group -and $user) {
        Add-ADGroupMember -Identity $group -Members $user -ErrorAction SilentlyContinue
    }

    # Create gMSA
    try {
        New-ADServiceAccount -Name 'svc_webapp' -DNSHostName "svc_webapp.$Domain" -PrincipalsAllowedToRetrieveManagedPassword 'WebApp-Servers' -KerberosEncryptionType AES256 -ErrorAction Stop
        Write-VulnStatus -Message "Created gMSA account svc_webapp." -Type Success
    } catch {
        Write-VulnStatus -Message "gMSA creation skipped or error: $_" -Type Warning
    }

    Write-VulnResult -Name 'gMSA Setup' -Detail 'gMSA svc_webapp assigned to WebApp-Servers (c.tran)' -Success $true -IsLast

    return @{
        Scenario       = 'gMSA'
        Description    = 'Group Managed Service Account password readable by low-privilege group members'
        CreatedObjects = @('svc_webapp$', 'c.tran', 'WebApp-Servers')
        AttackCommands = @(
            'GMSAPasswordReader.exe --accountname svc_webapp',
            'gMSADumper.py -d domain -u c.tran -p <password>'
        )
        AttackPath     = 'c.tran -> WebApp-Servers member -> Read msDS-ManagedPassword -> Authenticate as gMSA'
        MitreID        = 'T1555'
        Difficulty     = $Difficulty
    }
}

function Remove-gMSA {
    [CmdletBinding()]
    param([string]$DomainDN)

    try {
        Remove-ADServiceAccount -Identity 'svc_webapp' -Confirm:$false -ErrorAction SilentlyContinue
        Remove-ADUser -Identity 'c.tran' -Confirm:$false -ErrorAction SilentlyContinue
        Remove-ADGroup -Identity 'WebApp-Servers' -Confirm:$false -ErrorAction SilentlyContinue
        Write-VulnStatus -Message "Removed gMSA scenario objects." -Type Success
    } catch {
        Write-VulnStatus -Message "Cleanup error: $_" -Type Warning
    }
}

function Test-gMSA {
    [CmdletBinding()]
    param([string]$DomainDN)

    $sa = Get-ADServiceAccount -Filter "name -eq 'svc_webapp'" -ErrorAction SilentlyContinue
    return ($null -ne $sa)
}
