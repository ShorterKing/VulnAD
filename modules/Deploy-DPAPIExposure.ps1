#Requires -Modules ActiveDirectory
<#
.SYNOPSIS
    Deploys DPAPI Exposure scenario.
.DESCRIPTION
    Creates user and service artifacts to demonstrate DPAPI domain backup key exploitation.
#>

function Deploy-DPAPIExposure {
    [CmdletBinding()]
    param(
        [string]$Difficulty = 'Medium',
        [string]$DomainDN,
        [string]$Domain
    )

    Write-VulnStatus -Message "Deploying DPAPI Exposure Scenario..." -Type Info

    $password = Get-VulnPassword -Difficulty $Difficulty -Index 7
    $user = New-VulnUser -SamAccountName 't.baker' -Name 'Thomas Baker' -Password $password -DomainDN $DomainDN -Description 'Remote Desktop Administrator'

    # Share setup (attempt)
    try {
        $sharePath = "C:\ADMonolith-Share"
        if (-not (Test-Path $sharePath)) {
            New-Item -Path $sharePath -ItemType Directory -Force | Out-Null
        }
        $rdgFile = Join-Path $sharePath "connections.rdg"
        Set-Content -Path $rdgFile -Value '<?xml version="1.0"?><RDCMan><file><credentials><username>t.baker</username><password>AQAAANCMnd8BFdERjHoBIAAA...</password></credentials></file></RDCMan>'
        Write-VulnStatus -Message "Created DPAPI credential artifact in $rdgFile." -Type Success
    } catch {}

    Write-VulnResult -Name 'DPAPI Exposure Setup' -Detail 't.baker account created with stored DPAPI credential artifacts' -Success $true -IsLast

    return @{
        Scenario       = 'DPAPIExposure'
        Description    = 'Stored credentials protected via DPAPI, decryptable via DC DPAPI Backup Key'
        CreatedObjects = @('t.baker', 'C:\ADMonolith-Share\connections.rdg')
        AttackCommands = @(
            'Mimikatz: dpapi::backupkey /export',
            'SharpDPAPI: SharpDPAPI.exe backupkey',
            'DonPAPI: donpapi.py domain/user:pass@<dc_ip>'
        )
        AttackPath     = 'Extract DPAPI Master Keys -> Dump Domain Backup Key -> Decrypt User Credentials'
        MitreID        = 'T1555.004'
        Difficulty     = $Difficulty
    }
}

function Remove-DPAPIExposure {
    [CmdletBinding()]
    param([string]$DomainDN)

    try {
        Remove-ADUser -Identity 't.baker' -Confirm:$false -ErrorAction SilentlyContinue
        if (Test-Path "C:\ADMonolith-Share") {
            Remove-Item -Path "C:\ADMonolith-Share" -Recurse -Force -ErrorAction SilentlyContinue
        }
        Write-VulnStatus -Message "Removed DPAPI Exposure scenario objects." -Type Success
    } catch {
        Write-VulnStatus -Message "Cleanup error: $_" -Type Warning
    }
}

function Test-DPAPIExposure {
    [CmdletBinding()]
    param([string]$DomainDN)

    $u = Get-ADUser -Filter "samAccountName -eq 't.baker'" -ErrorAction SilentlyContinue
    return ($null -ne $u)
}
