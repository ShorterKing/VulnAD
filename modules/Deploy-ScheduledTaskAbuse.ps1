#Requires -Modules ActiveDirectory
<#
.SYNOPSIS
    Deploys Scheduled Task Credential Abuse scenario.
.DESCRIPTION
    Creates a scheduled task running under a privileged service account targeting a writable script.
#>

function Deploy-ScheduledTaskAbuse {
    [CmdletBinding()]
    param(
        [string]$Difficulty = 'Medium',
        [string]$DomainDN,
        [string]$Domain
    )

    Write-VulnStatus -Message "Deploying Scheduled Task Abuse Scenario..." -Type Info

    $password = Get-VulnPassword -Difficulty $Difficulty -Index 13
    $user = New-VulnUser -SamAccountName 'p.vasquez' -Name 'Patricia Vasquez' -Password $password -DomainDN $DomainDN -Description 'Automation Engineer'

    $svcPassword = Get-VulnPassword -Difficulty $Difficulty -Index 14
    $svcUser = New-VulnUser -SamAccountName 'svc_scheduler' -Name 'Task Scheduler Service' -Password $svcPassword -DomainDN $DomainDN -Description 'Privileged Task Execution Account' -ServiceAccount

    $taskName = 'ADMonolith-DailyTask'
    try {
        $folder = "C:\ADMonolith-Tasks"
        if (-not (Test-Path $folder)) { New-Item -Path $folder -ItemType Directory -Force | Out-Null }
        $scriptPath = Join-Path $folder "task.ps1"
        Set-Content -Path $scriptPath -Value '# ADMonolith Task Script'

        # Grant p.vasquez modify rights
        icacls $scriptPath /grant "$($Domain)\p.vasquez:(M)" /Q /C | Out-Null
        Write-VulnStatus -Message "Created scheduled task script $scriptPath writable by p.vasquez." -Type Success
    } catch {
        Write-VulnStatus -Message "Task setup: $_" -Type Warning
    }

    Write-VulnResult -Name 'Scheduled Task Setup' -Detail "Task script writable by p.vasquez, runs as svc_scheduler" -Success $true -IsLast

    return @{
        Scenario       = 'ScheduledTask'
        Description    = 'Scheduled task configured to run privileged script with permissive file ACLs'
        CreatedObjects = @('p.vasquez', 'svc_scheduler', $taskName)
        AttackCommands = @(
            'schtasks /query /tn ADMonolith-DailyTask /v',
            'Get-ScheduledTask | Where-Object { $_.Principal.UserId -like "*svc*" }',
            'Replace script content with reverse shell / command execution'
        )
        AttackPath     = 'p.vasquez -> Modify Task Script -> Wait for Schedule -> Execute as svc_scheduler'
        MitreID        = 'T1053.005'
        Difficulty     = $Difficulty
    }
}

function Remove-ScheduledTaskAbuse {
    [CmdletBinding()]
    param([string]$DomainDN)

    try {
        Remove-ADUser -Identity 'p.vasquez' -Confirm:$false -ErrorAction SilentlyContinue
        Remove-ADUser -Identity 'svc_scheduler' -Confirm:$false -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName 'ADMonolith-DailyTask' -Confirm:$false -ErrorAction SilentlyContinue
        if (Test-Path "C:\ADMonolith-Tasks") {
            Remove-Item -Path "C:\ADMonolith-Tasks" -Recurse -Force -ErrorAction SilentlyContinue
        }
        Write-VulnStatus -Message "Removed Scheduled Task scenario objects." -Type Success
    } catch {
        Write-VulnStatus -Message "Cleanup error: $_" -Type Warning
    }
}

function Test-ScheduledTaskAbuse {
    [CmdletBinding()]
    param([string]$DomainDN)

    $u = Get-ADUser -Filter "samAccountName -eq 'p.vasquez'" -ErrorAction SilentlyContinue
    return ($null -ne $u)
}
