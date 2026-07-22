#Requires -Modules ActiveDirectory
<#
.SYNOPSIS
    Deploys Password Spraying scenario.
.DESCRIPTION
    Creates multiple users sharing a predictable password pattern under a relaxed domain policy.
#>

function Deploy-PasswordSpraying {
    [CmdletBinding()]
    param(
        [string]$Difficulty = 'Medium',
        [string]$DomainDN,
        [string]$Domain
    )

    Write-VulnStatus -Message "Deploying Password Spraying Scenario..." -Type Info

    $sharedPassword = Get-VulnPassword -Difficulty $Difficulty -Index 6

    # Weaken policy
    try {
        Set-ADDefaultDomainPasswordPolicy -Identity $Domain -MinPasswordLength 7 -LockoutThreshold 0 -ComplexityEnabled $false -ErrorAction SilentlyContinue
        Write-VulnStatus -Message "Adjusted default domain password policy for spraying demonstration." -Type Success
    } catch {}

    $users = @(
        @{ Sam = 'a.miller'; Name = 'Alice Miller'; Dept = 'Marketing' },
        @{ Sam = 'b.wilson'; Name = 'Brandon Wilson'; Dept = 'Sales' },
        @{ Sam = 'c.taylor'; Name = 'Christine Taylor'; Dept = 'Product' },
        @{ Sam = 'd.moore'; Name = 'Daniel Moore'; Dept = 'Engineering' },
        @{ Sam = 'e.jackson'; Name = 'Elena Jackson'; Dept = 'Analytics' },
        @{ Sam = 'f.white'; Name = 'Frank White'; Dept = 'Management' },
        @{ Sam = 'g.harris'; Name = 'Grace Harris'; Dept = 'Content' },
        @{ Sam = 'h.martin'; Name = 'Henry Martin'; Dept = 'QA' },
        @{ Sam = 'i.garcia'; Name = 'Isabella Garcia'; Dept = 'UX Design' },
        @{ Sam = 'j.clark'; Name = 'Justin Clark'; Dept = 'Docs' }
    )

    $created = @()
    foreach ($u in $users) {
        $nu = New-VulnUser -SamAccountName $u.Sam -Name $u.Name -Password $sharedPassword -DomainDN $DomainDN -Description "$($u.Dept) Account"
        if ($nu) { $created += $u.Sam }
    }

    Write-VulnResult -Name 'Password Spraying Setup' -Detail "Created $($created.Count) accounts sharing common password pattern" -Success $true -IsLast

    return @{
        Scenario       = 'PasswordSpraying'
        Description    = 'Multiple domain users created with identical weak password pattern and no lockout'
        CreatedObjects = $created
        AttackCommands = @(
            'NetExec smb <dc_ip> -u userlist.txt -p <password> --continue-on-success',
            'kerbrute passwordspray -d domain userlist.txt <password>'
        )
        AttackPath     = 'Enumerate Users -> Password Spray Common Password -> Initial Access'
        MitreID        = 'T1110.003'
        Difficulty     = $Difficulty
    }
}

function Remove-PasswordSpraying {
    [CmdletBinding()]
    param([string]$DomainDN)

    $sams = @('a.miller','b.wilson','c.taylor','d.moore','e.jackson','f.white','g.harris','h.martin','i.garcia','j.clark')
    foreach ($s in $sams) {
        Remove-ADUser -Identity $s -Confirm:$false -ErrorAction SilentlyContinue
    }
    Write-VulnStatus -Message "Removed Password Spraying scenario objects." -Type Success
}

function Test-PasswordSpraying {
    [CmdletBinding()]
    param([string]$DomainDN)

    $u = Get-ADUser -Filter "samAccountName -eq 'a.miller'" -ErrorAction SilentlyContinue
    return ($null -ne $u)
}
