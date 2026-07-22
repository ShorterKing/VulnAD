#Requires -Modules ActiveDirectory
<#
.SYNOPSIS
    Deploys Weak Service Permissions scenario.
.DESCRIPTION
    Creates a service with permissive ACLs allowing binary or configuration modification.
#>

function Deploy-ServiceAbuse {
    [CmdletBinding()]
    param(
        [string]$Difficulty = 'Medium',
        [string]$DomainDN,
        [string]$Domain
    )

    Write-VulnStatus -Message "Deploying Weak Service Permissions Scenario..." -Type Info

    $password = Get-VulnPassword -Difficulty $Difficulty -Index 12
    $user = New-VulnUser -SamAccountName 'k.wagner' -Name 'Karl Wagner' -Password $password -DomainDN $DomainDN -Description 'DevOps Engineer'

    $serviceName = 'ADMonolith-Monitor'
    try {
        $folder = "C:\ADMonolith-Svc"
        if (-not (Test-Path $folder)) { New-Item -Path $folder -ItemType Directory -Force | Out-Null }
        $batFile = Join-Path $folder "monitor.bat"
        Set-Content -Path $batFile -Value '@echo off'

        if (-not (Get-Service -Name $serviceName -ErrorAction SilentlyContinue)) {
            New-Service -Name $serviceName -BinaryPathName "cmd.exe /c $batFile" -DisplayName 'AD Monolith Monitoring Service' -StartupType Manual -ErrorAction SilentlyContinue
        }

        # Grant modify permissions on directory
        icacls $folder /grant "$($Domain)\k.wagner:(OI)(CI)M" /Q /C | Out-Null
        Write-VulnStatus -Message "Created service $serviceName with weak folder permissions for k.wagner." -Type Success
    } catch {
        Write-VulnStatus -Message "Service setup: $_" -Type Warning
    }

    Write-VulnResult -Name 'Weak Service Setup' -Detail "Service $serviceName writable by k.wagner" -Success $true -IsLast

    return @{
        Scenario       = 'ServiceAbuse'
        Description    = 'Service running with SYSTEM privileges configured with writable binary path folder'
        CreatedObjects = @('k.wagner', $serviceName)
        AttackCommands = @(
            'Get-ModifiableService (PowerUp)',
            'Invoke-ServiceAbuse -Name ADMonolith-Monitor',
            'sc.exe config ADMonolith-Monitor binpath= "..."'
        )
        AttackPath     = 'k.wagner -> Replace Service Binary -> Restart Service -> Local Administrator / SYSTEM'
        MitreID        = 'T1574.011'
        Difficulty     = $Difficulty
    }
}

function Remove-ServiceAbuse {
    [CmdletBinding()]
    param([string]$DomainDN)

    try {
        Remove-ADUser -Identity 'k.wagner' -Confirm:$false -ErrorAction SilentlyContinue
        $svc = Get-Service -Name 'ADMonolith-Monitor' -ErrorAction SilentlyContinue
        if ($svc) {
            sc.exe delete ADMonolith-Monitor | Out-Null
        }
        if (Test-Path "C:\ADMonolith-Svc") {
            Remove-Item -Path "C:\ADMonolith-Svc" -Recurse -Force -ErrorAction SilentlyContinue
        }
        Write-VulnStatus -Message "Removed Service Abuse scenario objects." -Type Success
    } catch {
        Write-VulnStatus -Message "Cleanup error: $_" -Type Warning
    }
}

function Test-ServiceAbuse {
    [CmdletBinding()]
    param([string]$DomainDN)

    $u = Get-ADUser -Filter "samAccountName -eq 'k.wagner'" -ErrorAction SilentlyContinue
    return ($null -ne $u)
}
