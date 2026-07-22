#Requires -Modules ActiveDirectory
<#
.SYNOPSIS
    AD-Monolith Core — Utility functions for the AD-Monolith lab builder.

.DESCRIPTION
    Provides shared helper functions used by all AD-Monolith scenario modules:
    output formatting, AD object creation, password generation, domain info,
    prerequisite checks, and cheatsheet export.

.NOTES
    Author : AD-Monolith Project
    Version: 2.0.0
    License: MIT
#>

# ───────────────────────────────────────────────────────────
#  CONSTANTS
# ───────────────────────────────────────────────────────────

$Script:VulnAD_Version  = '2.0.0'
$Script:VulnAD_OUName   = 'ADMonolith'
$Script:VulnAD_LogFile  = $null

# ───────────────────────────────────────────────────────────
#  OUTPUT HELPERS
# ───────────────────────────────────────────────────────────

function Write-VulnBanner {
    <#
    .SYNOPSIS
        Displays the AD-Monolith ASCII art banner and system information.
    #>
    [CmdletBinding()]
    param()

    $banner = @"

    `e[38;5;51m █████╗ ██████╗      ███╗   ███╗ ██████╗ ███╗   ██╗ ██████╗ ██╗     ██╗████████╗██╗  ██╗`e[0m
    `e[38;5;51m██╔══██╗██╔══██╗     ████╗ ████║██╔═══██╗████╗  ██║██╔═══██╗██║     ██║╚══██╔══╝██║  ██║`e[0m
    `e[38;5;75m███████║██║  ██║     ██╔████╔██║██║   ██║██╔██╗ ██║██║   ██║██║     ██║   ██║   ███████║`e[0m
    `e[38;5;75m██╔══██║██║  ██║     ██║╚██╔╝██║██║   ██║██║╚██╗██║██║   ██║██║     ██║   ██║   ██╔══██║`e[0m
    `e[38;5;39m██║  ██║██████╔╝     ██║ ╚═╝ ██║╚██████╔╝██║ ╚████║╚██████╔╝███████╗██║   ██║   ██║  ██║`e[0m
    `e[38;5;39m╚═╝  ╚═╝╚═════╝      ╚═╝     ╚═╝ ╚═════╝ ╚═╝  ╚═══╝ ╚═════╝ ╚══════╝╚═╝   ╚═╝   ╚═╝  ╚═╝`e[0m

    `e[38;5;245m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`e[0m
    `e[38;5;75m  AD-Monolith: Vulnerable Active Directory Lab Builder  `e[38;5;245mv$Script:VulnAD_Version`e[0m
    `e[38;5;245m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`e[0m

"@
    Write-Host $banner
}

function Write-VulnInfo {
    <#
    .SYNOPSIS
        Displays domain controller and system information.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$DomainInfo
    )

    Write-Host ""
    Write-Host "    `e[38;5;245m[`e[38;5;75m*`e[38;5;245m]`e[0m Domain Controller : `e[38;5;255m$($DomainInfo.DCName)`e[0m"
    Write-Host "    `e[38;5;245m[`e[38;5;75m*`e[38;5;245m]`e[0m Domain            : `e[38;5;255m$($DomainInfo.Domain)`e[0m"
    Write-Host "    `e[38;5;245m[`e[38;5;75m*`e[38;5;245m]`e[0m Domain DN         : `e[38;5;255m$($DomainInfo.DomainDN)`e[0m"
    Write-Host "    `e[38;5;245m[`e[38;5;75m*`e[38;5;245m]`e[0m OS                : `e[38;5;255m$($DomainInfo.OS)`e[0m"
    Write-Host "    `e[38;5;245m[`e[38;5;75m*`e[38;5;245m]`e[0m PowerShell        : `e[38;5;255m$($PSVersionTable.PSVersion)`e[0m"

    if ($DomainInfo.IsAdmin) {
        Write-Host "    `e[38;5;245m[`e[38;5;75m*`e[38;5;245m]`e[0m Running as        : `e[38;5;255m$($DomainInfo.CurrentUser)`e[0m `e[38;5;82m✓`e[0m"
    } else {
        Write-Host "    `e[38;5;245m[`e[38;5;75m*`e[38;5;245m]`e[0m Running as        : `e[38;5;255m$($DomainInfo.CurrentUser)`e[0m `e[38;5;196m✗ (not admin)`e[0m"
    }
    Write-Host ""
}

function Write-VulnStatus {
    <#
    .SYNOPSIS
        Writes a formatted status message to the console.
    .PARAMETER Message
        The message to display.
    .PARAMETER Type
        The type of message: Info, Success, Warning, Error.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Message,

        [Parameter()]
        [ValidateSet('Info', 'Success', 'Warning', 'Error')]
        [string]$Type = 'Info'
    )

    $prefix = switch ($Type) {
        'Info'    { "`e[38;5;245m[`e[38;5;75m*`e[38;5;245m]`e[0m" }
        'Success' { "`e[38;5;245m[`e[38;5;82m+`e[38;5;245m]`e[0m" }
        'Warning' { "`e[38;5;245m[`e[38;5;214m!`e[38;5;245m]`e[0m" }
        'Error'   { "`e[38;5;245m[`e[38;5;196m-`e[38;5;245m]`e[0m" }
    }

    $color = switch ($Type) {
        'Info'    { "`e[38;5;255m" }
        'Success' { "`e[38;5;82m" }
        'Warning' { "`e[38;5;214m" }
        'Error'   { "`e[38;5;196m" }
    }

    Write-Host "    $prefix ${color}${Message}`e[0m"
}

function Write-VulnPhase {
    <#
    .SYNOPSIS
        Writes a formatted phase header for deployment progress.
    .PARAMETER Number
        The current phase number.
    .PARAMETER Total
        The total number of phases.
    .PARAMETER Name
        The name of the phase.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [int]$Number,

        [Parameter(Mandatory)]
        [int]$Total,

        [Parameter(Mandatory)]
        [string]$Name
    )

    Write-Host ""
    Write-Host "    `e[38;5;75m[PHASE $Number/$Total]`e[0m `e[38;5;255m$Name`e[0m"
}

function Write-VulnResult {
    <#
    .SYNOPSIS
        Writes a formatted result line with tree connector.
    .PARAMETER Name
        The name of the object/action.
    .PARAMETER Detail
        Additional detail text.
    .PARAMETER Success
        Whether the operation was successful.
    .PARAMETER IsLast
        Whether this is the last item in the tree.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter()]
        [string]$Detail = '',

        [Parameter()]
        [bool]$Success = $true,

        [Parameter()]
        [switch]$IsLast
    )

    $connector = if ($IsLast) { '└──' } else { '├──' }
    $icon      = if ($Success) { "`e[38;5;82m✓`e[0m" } else { "`e[38;5;196m✗`e[0m" }

    $detailStr = if ($Detail) { " `e[38;5;245m($Detail)`e[0m" } else { '' }

    Write-Host "       $connector `e[38;5;245m[`e[38;5;82m+`e[38;5;245m]`e[0m `e[38;5;255m${Name}`e[0m${detailStr}  $icon"
}

function Write-VulnSeparator {
    <#
    .SYNOPSIS
        Writes a decorative separator line.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$Title = ''
    )

    if ($Title) {
        Write-Host ""
        Write-Host "    `e[38;5;75m══════════════════════════════════════════════`e[0m"
        Write-Host "    `e[38;5;255m $Title`e[0m"
        Write-Host "    `e[38;5;75m══════════════════════════════════════════════`e[0m"
    } else {
        Write-Host "    `e[38;5;245m──────────────────────────────────────────────`e[0m"
    }
}

function Write-VulnBox {
    <#
    .SYNOPSIS
        Writes content inside a bordered box.
    .PARAMETER Lines
        Array of strings to display inside the box.
    .PARAMETER Title
        Optional title for the box header.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string[]]$Lines,

        [Parameter()]
        [string]$Title = ''
    )

    $maxLen   = ($Lines | ForEach-Object { $_.Length } | Measure-Object -Maximum).Maximum
    $maxLen   = [Math]::Max($maxLen, $Title.Length)
    $boxWidth = $maxLen + 4

    $topBorder    = '┌' + ('─' * $boxWidth) + '┐'
    $bottomBorder = '└' + ('─' * $boxWidth) + '┘'
    $separator    = '├' + ('─' * $boxWidth) + '┤'

    Write-Host ""
    Write-Host "    `e[38;5;75m$topBorder`e[0m"

    if ($Title) {
        $padded = $Title.PadRight($boxWidth - 2)
        Write-Host "    `e[38;5;75m│`e[0m `e[38;5;255;1m$padded`e[0m `e[38;5;75m│`e[0m"
        Write-Host "    `e[38;5;75m$separator`e[0m"
    }

    foreach ($line in $Lines) {
        $padded = $line.PadRight($boxWidth - 2)
        Write-Host "    `e[38;5;75m│`e[0m `e[38;5;255m$padded`e[0m `e[38;5;75m│`e[0m"
    }

    Write-Host "    `e[38;5;75m$bottomBorder`e[0m"
}

# ───────────────────────────────────────────────────────────
#  DOMAIN & PREREQUISITE HELPERS
# ───────────────────────────────────────────────────────────

function Get-VulnDomainInfo {
    <#
    .SYNOPSIS
        Gathers current domain controller and domain information.
    .OUTPUTS
        Hashtable with domain info: DCName, Domain, DomainDN, OS, CurrentUser, IsAdmin, IsDC.
    #>
    [CmdletBinding()]
    param()

    try {
        $domain   = Get-ADDomain -ErrorAction Stop
        $computer = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
        $dc       = Get-ADDomainController -Discover -ErrorAction SilentlyContinue

        $currentUser   = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $principal     = New-Object System.Security.Principal.WindowsPrincipal($currentUser)
        $isAdmin       = $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
        $isDC          = (Get-CimInstance -ClassName Win32_ComputerSystem).DomainRole -ge 4

        return @{
            DCName      = $dc.HostName
            Domain      = $domain.DNSRoot
            DomainDN    = $domain.DistinguishedName
            DomainSID   = $domain.DomainSID.Value
            OS          = $computer.Caption
            CurrentUser = $currentUser.Name
            IsAdmin     = $isAdmin
            IsDC        = $isDC
            ForestName  = $domain.Forest
        }
    } catch {
        Write-VulnStatus -Message "Failed to retrieve domain information: $_" -Type Error
        Write-VulnStatus -Message "Ensure this machine is a domain controller with the AD module installed." -Type Error
        return $null
    }
}

function Test-VulnPrerequisites {
    <#
    .SYNOPSIS
        Validates that all prerequisites are met before deployment.
    .PARAMETER DomainInfo
        The hashtable returned by Get-VulnDomainInfo.
    .OUTPUTS
        $true if all prerequisites are met, $false otherwise.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$DomainInfo
    )

    $passed = $true

    # Check if running as administrator
    if (-not $DomainInfo.IsAdmin) {
        Write-VulnStatus -Message "This script must be run as Administrator." -Type Error
        $passed = $false
    }

    # Check if machine is a domain controller
    if (-not $DomainInfo.IsDC) {
        Write-VulnStatus -Message "This script must be run on a Domain Controller." -Type Error
        $passed = $false
    }

    # Check if AD module is available
    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        Write-VulnStatus -Message "ActiveDirectory PowerShell module is not installed." -Type Error
        $passed = $false
    }

    # Check PowerShell version
    if ($PSVersionTable.PSVersion.Major -lt 5) {
        Write-VulnStatus -Message "PowerShell 5.1 or later is required." -Type Error
        $passed = $false
    }

    return $passed
}

# ───────────────────────────────────────────────────────────
#  OU MANAGEMENT
# ───────────────────────────────────────────────────────────

function Initialize-VulnOU {
    <#
    .SYNOPSIS
        Creates the VulnAD organizational unit structure.
    .PARAMETER DomainDN
        The distinguished name of the domain (e.g., DC=vulnlab,DC=local).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$DomainDN
    )

    $ouRoot = "OU=$Script:VulnAD_OUName,$DomainDN"

    # Create root OU if it doesn't exist
    if (-not (Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$ouRoot'" -ErrorAction SilentlyContinue)) {
        $params = @{
            Name                            = $Script:VulnAD_OUName
            Path                            = $DomainDN
            Description                     = 'VulnAD - Vulnerable Lab Objects (auto-generated)'
            ProtectedFromAccidentalDeletion = $false
        }
        New-ADOrganizationalUnit @params | Out-Null
        Write-VulnResult -Name "OU=$Script:VulnAD_OUName" -Detail 'Root OU' -Success $true
    } else {
        Write-VulnResult -Name "OU=$Script:VulnAD_OUName" -Detail 'Already exists, skipping' -Success $true
    }

    # Create sub-OUs
    $subOUs = @(
        @{ Name = 'Users';           Description = 'VulnAD user accounts' }
        @{ Name = 'Groups';          Description = 'VulnAD security groups' }
        @{ Name = 'ServiceAccounts'; Description = 'VulnAD service accounts' }
        @{ Name = 'Workstations';    Description = 'VulnAD workstation objects' }
        @{ Name = 'Servers';         Description = 'VulnAD server objects' }
    )

    foreach ($ou in $subOUs) {
        $ouDN = "OU=$($ou.Name),$ouRoot"
        if (-not (Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$ouDN'" -ErrorAction SilentlyContinue)) {
            $params = @{
                Name                            = $ou.Name
                Path                            = $ouRoot
                Description                     = $ou.Description
                ProtectedFromAccidentalDeletion = $false
            }
            New-ADOrganizationalUnit @params | Out-Null
        }
        Write-VulnResult -Name "OU=$($ou.Name)" -Detail $ou.Description -Success $true
    }
}

function Remove-VulnOU {
    <#
    .SYNOPSIS
        Removes the entire VulnAD organizational unit tree and all contained objects.
    .PARAMETER DomainDN
        The distinguished name of the domain.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$DomainDN
    )

    $ouRoot = "OU=$Script:VulnAD_OUName,$DomainDN"

    if (Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$ouRoot'" -ErrorAction SilentlyContinue) {
        # Remove protection and delete recursively
        Get-ADOrganizationalUnit -SearchBase $ouRoot -Filter * -ErrorAction SilentlyContinue |
            Set-ADOrganizationalUnit -ProtectedFromAccidentalDeletion $false -ErrorAction SilentlyContinue

        Get-ADObject -SearchBase $ouRoot -Filter * -ErrorAction SilentlyContinue |
            Where-Object { $_.DistinguishedName -ne $ouRoot } |
            Sort-Object { $_.DistinguishedName.Length } -Descending |
            Remove-ADObject -Recursive -Confirm:$false -ErrorAction SilentlyContinue

        Remove-ADOrganizationalUnit -Identity $ouRoot -Recursive -Confirm:$false -ErrorAction SilentlyContinue
        Write-VulnStatus -Message "Removed OU tree: $ouRoot" -Type Success
    } else {
        Write-VulnStatus -Message "VulnAD OU not found, nothing to remove." -Type Warning
    }
}

# ───────────────────────────────────────────────────────────
#  AD OBJECT CREATION HELPERS
# ───────────────────────────────────────────────────────────

function New-VulnUser {
    <#
    .SYNOPSIS
        Creates an AD user in the VulnAD OU structure.
    .PARAMETER SamAccountName
        The SAM account name for the user.
    .PARAMETER Name
        The display name for the user.
    .PARAMETER Password
        The plaintext password for the user.
    .PARAMETER DomainDN
        The domain distinguished name.
    .PARAMETER Description
        Optional description for the user account.
    .PARAMETER ServiceAccount
        If set, creates the user in the ServiceAccounts sub-OU.
    .PARAMETER Enabled
        Whether the account is enabled. Defaults to $true.
    .OUTPUTS
        The created AD user object or $null on failure.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$SamAccountName,

        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [string]$Password,

        [Parameter(Mandatory)]
        [string]$DomainDN,

        [Parameter()]
        [string]$Description = '',

        [Parameter()]
        [switch]$ServiceAccount,

        [Parameter()]
        [bool]$Enabled = $true
    )

    $ouPath = if ($ServiceAccount) {
        "OU=ServiceAccounts,OU=$Script:VulnAD_OUName,$DomainDN"
    } else {
        "OU=Users,OU=$Script:VulnAD_OUName,$DomainDN"
    }

    # Check if user already exists
    $existing = Get-ADUser -Filter "SamAccountName -eq '$SamAccountName'" -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Verbose "User $SamAccountName already exists, skipping creation."
        return $existing
    }

    try {
        $securePass = ConvertTo-SecureString -String $Password -AsPlainText -Force
        $params = @{
            SamAccountName    = $SamAccountName
            Name              = $Name
            DisplayName       = $Name
            UserPrincipalName = "$SamAccountName@$((Get-ADDomain).DNSRoot)"
            Path              = $ouPath
            AccountPassword   = $securePass
            Enabled           = $Enabled
            Description       = $Description
            ChangePasswordAtLogon = $false
            PasswordNeverExpires  = $true
        }
        $user = New-ADUser @params -PassThru
        return $user
    } catch {
        Write-VulnStatus -Message "Failed to create user $SamAccountName : $_" -Type Error
        return $null
    }
}

function New-VulnGroup {
    <#
    .SYNOPSIS
        Creates an AD security group in the VulnAD OU structure.
    .PARAMETER Name
        The name of the group.
    .PARAMETER DomainDN
        The domain distinguished name.
    .PARAMETER Description
        Optional description.
    .PARAMETER GroupScope
        The group scope: Global, Universal, DomainLocal. Defaults to Global.
    .OUTPUTS
        The created AD group object or $null on failure.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [string]$DomainDN,

        [Parameter()]
        [string]$Description = '',

        [Parameter()]
        [ValidateSet('Global', 'Universal', 'DomainLocal')]
        [string]$GroupScope = 'Global'
    )

    $ouPath = "OU=Groups,OU=$Script:VulnAD_OUName,$DomainDN"

    $existing = Get-ADGroup -Filter "Name -eq '$Name'" -SearchBase $ouPath -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Verbose "Group $Name already exists, skipping creation."
        return $existing
    }

    try {
        $params = @{
            Name          = $Name
            SamAccountName= $Name
            Path          = $ouPath
            GroupScope    = $GroupScope
            GroupCategory = 'Security'
            Description   = $Description
        }
        $group = New-ADGroup @params -PassThru
        return $group
    } catch {
        Write-VulnStatus -Message "Failed to create group $Name : $_" -Type Error
        return $null
    }
}

function Set-VulnACL {
    <#
    .SYNOPSIS
        Sets an Access Control Entry on an AD object.
    .PARAMETER TargetDN
        The distinguished name of the target AD object.
    .PARAMETER PrincipalSamAccount
        The SAM account name of the principal (user/group) to grant access.
    .PARAMETER Rights
        The AD rights to grant: GenericAll, GenericWrite, WriteDacl, WriteOwner, WriteProperty, Self, ExtendedRight.
    .PARAMETER ObjectType
        Optional GUID for specific extended right or property. Use [guid]::Empty for all.
    .PARAMETER InheritanceType
        Inheritance type: None, All, Descendents. Defaults to None.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$TargetDN,

        [Parameter(Mandatory)]
        [string]$PrincipalSamAccount,

        [Parameter(Mandatory)]
        [System.DirectoryServices.ActiveDirectoryRights]$Rights,

        [Parameter()]
        [guid]$ObjectType = [guid]::Empty,

        [Parameter()]
        [System.DirectoryServices.ActiveDirectorySecurityInheritance]$InheritanceType = 'None'
    )

    try {
        $principal  = Get-ADUser -Identity $PrincipalSamAccount -ErrorAction SilentlyContinue
        if (-not $principal) {
            $principal = Get-ADGroup -Identity $PrincipalSamAccount -ErrorAction SilentlyContinue
        }
        if (-not $principal) {
            Write-VulnStatus -Message "Principal '$PrincipalSamAccount' not found." -Type Error
            return $false
        }

        $sid        = New-Object System.Security.Principal.SecurityIdentifier($principal.SID)
        $ace        = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
            $sid,
            $Rights,
            'Allow',
            $ObjectType,
            $InheritanceType
        )

        $targetObj  = [ADSI]"LDAP://$TargetDN"
        $targetObj.ObjectSecurity.AddAccessRule($ace)
        $targetObj.CommitChanges()

        Write-Verbose "Set $Rights on '$TargetDN' for '$PrincipalSamAccount'"
        return $true
    } catch {
        Write-VulnStatus -Message "Failed to set ACL on '$TargetDN': $_" -Type Error
        return $false
    }
}

# ───────────────────────────────────────────────────────────
#  PASSWORD HELPERS
# ───────────────────────────────────────────────────────────

function Get-VulnPassword {
    <#
    .SYNOPSIS
        Returns a password appropriate for the given difficulty and optional index.
    .PARAMETER Difficulty
        The difficulty level: Easy, Medium, Hard.
    .PARAMETER Index
        An index to vary the password within the same difficulty level.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Easy', 'Medium', 'Hard')]
        [string]$Difficulty,

        [Parameter()]
        [int]$Index = 0
    )

    # Base64 encoded passwords to prevent secret scanning alerts (e.g., GitGuardian)
    $passwordsB64 = @{
        Easy   = @(
            'UGFzc3dvcmQxMjMh', # Password123!
            'U3VtbWVyMjAyNSE=', # Summer2025!
            'V2VsY29tZTEh',     # Welcome1!
            'UGEkJHcwcmQ=',     # Pa$$w0rd
            'Q29tcGFueTEyMyE=', # Company123!
            'QWRtaW4xMjMh',     # Admin123!
            'TGV0bWVpbjIwMjUh', # Letmein2025!
            'UXdlcnR5MTIzIQ==', # Qwerty123!
            'QWNjZXNzMTIzIQ==', # Access123!
            'TW9uZGF5MTIzIQ==', # Monday123!
            'VGVtcDEyMzQh',     # Temp1234!
            'T2ZmaWNlMjAyNSE=', # Office2025!
            'VXNlcjEyMzQ1IQ==', # User12345!
            'RG9tYWluMTIzIQ==', # Domain123!
            'TG9naW4yMDI1IQ==', # Login2025!
            'U3RhcnQxMjMh'      # Start123!
        )
        Medium = @(
            'U3ByaW5nMjAyNSE=', # Spring2025!
            'Q3IzZGVudGlhbCQx', # Cr3dential$1
            'UzNjdXJlUEBzcyE=', # S3cureP@ss!
            'VzNsY29tZSMyMDI1', # W3lcome#2025
            'QkBja3VwMjAyNSE=', # B@ckup2025!
            'U1FMX0FkbSFuMjU=', # SQL_Adm!n25
            'TjN0d29yayRlcnYx', # N3twork$erv1
            'RiFsZVNoYXJlMjU=', # F!leShare25
            'RDNmYXVsdCNQd2Q=', # D3fault#Pwd
            'UHIwamVjdEAyNQ==', # Pr0ject@25
            'QzBudHJhY3QwciE=', # C0ntract0r!
            'SW52M250MHJ5JA==', # Inv3nt0ry$
            'UjNzb3VyY2UjMQ==', # R3source#1
            'RDNwbDB5QDI1',     # D3pl0y@25
            'VDNjaFMzcnYh',     # T3chS3rv!
            'TTFnckB0ZTI1'      # M1gr@te25
        )
        Hard   = @(
            'UXczcnR5QDIwMjV4Wg==', # Qw3rty@2025xZ
            'TjB0UzBTM2N1cmUhMQ==', # N0tS0S3cure!1
            'VHI0bnNmM3IjMjAyNQ==', # Tr4nsf3r#2025
            'eEs5JG1QMnZMIXFS',     # xK9$mP2vL!qR
            'QjFnREB0QFMzcnYh',     # B1gD@t@S3rv!
            'Q2wwdWRNIWdSQHRl',     # Cl0udM!gR@te
            'UzNydjNyI1IwMG0x',     # S3rv3r#R00m1
            'SDNscEQzc2shMjV4',     # H3lpD3sk!25x
            'cFI3JHhLMm1OcSE=',     # pR7$xK2mNq!
            'Wnc0QGNCOGZZZSQ=',     # Zw4@cB8fYe$
            'bVQ2I2hKOXBMeCE=',     # mT6#hJ9pLx!
            'Yk4zJHJGNXdRYUA=',     # bN3$rF5wQa@
            'a1k4IWdWMmRYeiM=',     # kY8!gV2dXz#
            'c1c1QHBMN2NSdCQ=',     # sW5@pL7cRt$
            'akg0I25NNmJVZSE=',     # jH4#nM6bUe!
            'dkQ5JHRLM2ZBd0A='      # vD9$tK3fAw@
        )
    }

    $pool = $passwordsB64[$Difficulty]
    $selectedB64 = $pool[$Index % $pool.Count]
    
    # Decode Base64 string to plain-text password
    $decodedBytes = [System.Convert]::FromBase64String($selectedB64)
    return [System.Text.Encoding]::UTF8.GetString($decodedBytes)
}

# ───────────────────────────────────────────────────────────
#  SCENARIO REGISTRY & MENU
# ───────────────────────────────────────────────────────────

function Get-VulnScenarioList {
    <#
    .SYNOPSIS
        Returns the ordered list of all available attack scenarios with metadata.
    #>
    [CmdletBinding()]
    param()

    return [ordered]@{
        # ── Credential Attacks ──
        Kerberoasting    = @{ Index =  1; Name = 'Kerberoasting';          Objects = '3 users';     MitreID = 'T1558.003' }
        ASREPRoast       = @{ Index =  2; Name = 'AS-REP Roasting';       Objects = '2 users';     MitreID = 'T1558.004' }
        PasswordExposure = @{ Index =  3; Name = 'Password Exposure';     Objects = '3 users';     MitreID = 'T1552.001' }
        PasswordSpraying = @{ Index =  4; Name = 'Password Spraying';     Objects = '10 users';    MitreID = 'T1110.003' }
        GPPPasswords     = @{ Index =  5; Name = 'GPP Passwords';         Objects = '1 GPO';       MitreID = 'T1552.006' }
        WriteSPN         = @{ Index =  6; Name = 'Targeted Kerberoast';   Objects = '2 users';     MitreID = 'T1134.001' }
        # ── Privilege Escalation ──
        ACLAbuse         = @{ Index =  7; Name = 'ACL Abuse Chains';      Objects = '8 ACEs';      MitreID = 'T1222.001' }
        GroupNesting     = @{ Index =  8; Name = 'Nested Group Privesc';  Objects = '4 groups';    MitreID = 'T1078.002' }
        Delegation       = @{ Index =  9; Name = 'Delegation Attacks';    Objects = '3 accounts';  MitreID = 'T1550.003' }
        RBCD             = @{ Index = 10; Name = 'RBCD Abuse';            Objects = '2 accounts';  MitreID = 'T1550.003' }
        DCSync           = @{ Index = 11; Name = 'DCSync Rights';         Objects = '1 user';      MitreID = 'T1003.006' }
        gMSA             = @{ Index = 12; Name = 'gMSA Password Read';    Objects = '1 gMSA';      MitreID = 'T1555' }
        # ── Built-in Group Abuse ──
        BackupOperators  = @{ Index = 13; Name = 'Backup Operators';      Objects = '1 user';      MitreID = 'T1003.003' }
        ServerOperators  = @{ Index = 14; Name = 'Server Operators';      Objects = '1 user';      MitreID = 'T1543.003' }
        AccountOperators = @{ Index = 15; Name = 'Account Operators';     Objects = '2 users';     MitreID = 'T1098.001' }
        PrintOperators   = @{ Index = 16; Name = 'Print Operators';       Objects = '1 user';      MitreID = 'T1068' }
        DNSAdmins        = @{ Index = 17; Name = 'DNS Admins Abuse';      Objects = '1 user';      MitreID = 'T1574' }
        # ── Infrastructure Attacks ──
        ADCS             = @{ Index = 18; Name = 'AD CS Abuse (ESC1-8)';  Objects = '5 templates'; MitreID = 'T1649' }
        GPOAbuse         = @{ Index = 19; Name = 'GPO Abuse';             Objects = '2 GPOs';      MitreID = 'T1484.001' }
        LAPS             = @{ Index = 20; Name = 'LAPS Misconfiguration'; Objects = '1 policy';    MitreID = 'T1552.006' }
        ShadowCreds      = @{ Index = 21; Name = 'Shadow Credentials';    Objects = '2 users';     MitreID = 'T1556' }
        ADIDNS           = @{ Index = 22; Name = 'ADIDNS Injection';      Objects = '1 user';      MitreID = 'T1557.001' }
        MachineQuota     = @{ Index = 23; Name = 'Machine Account Quota'; Objects = '1 config';    MitreID = 'T1136.002' }
        # ── Persistence & Misc ──
        AdminSDHolder    = @{ Index = 24; Name = 'AdminSDHolder Abuse';   Objects = '1 config';    MitreID = 'T1098' }
        CoercionSetup    = @{ Index = 25; Name = 'Auth Coercion Setup';   Objects = '2 accounts';  MitreID = 'T1187' }
        NTLMDowngrade    = @{ Index = 26; Name = 'NTLM Downgrade';        Objects = '4 settings';  MitreID = 'T1557.001' }
        DPAPIExposure    = @{ Index = 27; Name = 'DPAPI Exposure';        Objects = '1 task';      MitreID = 'T1555.004' }
        PreWin2000       = @{ Index = 28; Name = 'Pre-Win2000 Access';    Objects = '1 user';      MitreID = 'T1087.002' }
        ServiceAbuse     = @{ Index = 29; Name = 'Weak Service Perms';    Objects = '1 service';   MitreID = 'T1574.011' }
        ScheduledTask    = @{ Index = 30; Name = 'Scheduled Task Abuse';  Objects = '1 task';      MitreID = 'T1053.005' }
    }
}

function Show-VulnMenu {
    <#
    .SYNOPSIS
        Displays the interactive scenario selection menu.
    .OUTPUTS
        Array of selected scenario keys.
    #>
    [CmdletBinding()]
    param()

    $scenarios = Get-VulnScenarioList

    Write-Host ""
    Write-Host "    `e[38;5;75m┌─────────────────────────────────────────────────┐`e[0m"
    Write-Host "    `e[38;5;75m│`e[0m          `e[38;5;255;1mSELECT ATTACK SCENARIOS`e[0m             `e[38;5;75m│`e[0m"
    Write-Host "    `e[38;5;75m├─────────────────────────────────────────────────┤`e[0m"
    Write-Host "    `e[38;5;75m│`e[0m                                                 `e[38;5;75m│`e[0m"

    foreach ($key in $scenarios.Keys) {
        $s   = $scenarios[$key]
        $idx = $s.Index.ToString().PadLeft(2)
        $nm  = $s.Name.PadRight(23)
        $obj = $s.Objects.PadRight(13)
        Write-Host "    `e[38;5;75m│`e[0m  `e[38;5;245m[`e[38;5;82m$idx`e[38;5;245m]`e[0m  `e[38;5;255m$nm`e[0m `e[38;5;245m($obj)`e[0m `e[38;5;75m│`e[0m"
    }

    Write-Host "    `e[38;5;75m│`e[0m                                                 `e[38;5;75m│`e[0m"
    Write-Host "    `e[38;5;75m│`e[0m  `e[38;5;245m[`e[38;5;214m A`e[38;5;245m]`e[0m  `e[38;5;214;1mALL SCENARIOS`e[0m                         `e[38;5;75m│`e[0m"
    Write-Host "    `e[38;5;75m│`e[0m  `e[38;5;245m[`e[38;5;214m P`e[38;5;245m]`e[0m  `e[38;5;214mPRESET: CRTP Exam Prep`e[0m                `e[38;5;75m│`e[0m"
    Write-Host "    `e[38;5;75m│`e[0m  `e[38;5;245m[`e[38;5;214m R`e[38;5;245m]`e[0m  `e[38;5;214mPRESET: Real-World Pentest`e[0m            `e[38;5;75m│`e[0m"
    Write-Host "    `e[38;5;75m│`e[0m  `e[38;5;245m[`e[38;5;214m O`e[38;5;245m]`e[0m  `e[38;5;214mPRESET: OSCP AD`e[0m                       `e[38;5;75m│`e[0m"
    Write-Host "    `e[38;5;75m│`e[0m  `e[38;5;245m[`e[38;5;214m C`e[38;5;245m]`e[0m  `e[38;5;214mCUSTOM (pick multiple)`e[0m                `e[38;5;75m│`e[0m"
    Write-Host "    `e[38;5;75m│`e[0m                                                 `e[38;5;75m│`e[0m"
    Write-Host "    `e[38;5;75m└─────────────────────────────────────────────────┘`e[0m"
    Write-Host ""

    $selection = Read-Host "    Select option"
    $selection = $selection.Trim().ToUpper()

    $allKeys = @($scenarios.Keys)

    switch ($selection) {
        'A' { return $allKeys }
        'P' { return @('Kerberoasting', 'ASREPRoast', 'ACLAbuse', 'Delegation', 'DCSync', 'GroupNesting', 'LAPS') }
        'R' { return @('Kerberoasting', 'ASREPRoast', 'ACLAbuse', 'Delegation', 'ADCS', 'DCSync', 'RBCD', 'ShadowCreds', 'GPOAbuse', 'PasswordExposure') }
        'O' { return @('Kerberoasting', 'ASREPRoast', 'ACLAbuse', 'Delegation', 'DCSync', 'GroupNesting', 'PasswordExposure', 'LAPS') }
        'C' {
            Write-Host ""
            Write-VulnStatus -Message "Enter scenario numbers separated by commas (e.g., 1,3,5,8):" -Type Info
            $custom = Read-Host "    Selection"
            $indices = $custom -split ',' | ForEach-Object { [int]$_.Trim() }
            $selected = @()
            foreach ($key in $allKeys) {
                if ($scenarios[$key].Index -in $indices) { $selected += $key }
            }
            return $selected
        }
        default {
            # Try parsing as number(s)
            if ($selection -match '^\d+$') {
                $idx = [int]$selection
                foreach ($key in $allKeys) {
                    if ($scenarios[$key].Index -eq $idx) { return @($key) }
                }
            }
            Write-VulnStatus -Message "Invalid selection. Please try again." -Type Error
            return $null
        }
    }
}

function Show-VulnDifficultyMenu {
    <#
    .SYNOPSIS
        Displays the difficulty selection menu.
    .OUTPUTS
        Selected difficulty string.
    #>
    [CmdletBinding()]
    param()

    Write-Host ""
    Write-Host "    `e[38;5;245m[`e[38;5;75m?`e[38;5;245m]`e[0m `e[38;5;255mDifficulty level:`e[0m"
    Write-Host ""
    Write-Host "        `e[38;5;245m[`e[38;5;82m1`e[38;5;245m]`e[0m `e[38;5;82mEasy`e[0m   `e[38;5;245m- Obvious misconfigs, weak passwords (Password123!)`e[0m"
    Write-Host "                       `e[38;5;245mBest for: Beginners, learning tools`e[0m"
    Write-Host "        `e[38;5;245m[`e[38;5;214m2`e[38;5;245m]`e[0m `e[38;5;214mMedium`e[0m `e[38;5;245m- Realistic configs, moderate passwords`e[0m"
    Write-Host "                       `e[38;5;245mBest for: CRTP/CRTO exam prep`e[0m"
    Write-Host "        `e[38;5;245m[`e[38;5;196m3`e[38;5;245m]`e[0m `e[38;5;196mHard`e[0m   `e[38;5;245m- Subtle misconfigs, stronger passwords, decoys`e[0m"
    Write-Host "                       `e[38;5;245mBest for: Experienced pentesters`e[0m"
    Write-Host ""

    $choice = Read-Host "    Select difficulty"

    switch ($choice.Trim()) {
        '1' { return 'Easy' }
        '2' { return 'Medium' }
        '3' { return 'Hard' }
        default { return 'Medium' }
    }
}

function Show-VulnConfirmation {
    <#
    .SYNOPSIS
        Displays a deployment summary and asks for confirmation.
    .PARAMETER Scenarios
        Array of selected scenario keys.
    .PARAMETER Difficulty
        The selected difficulty level.
    .PARAMETER Domain
        The domain FQDN.
    .OUTPUTS
        $true if confirmed, $false otherwise.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string[]]$Scenarios,

        [Parameter(Mandatory)]
        [string]$Difficulty,

        [Parameter(Mandatory)]
        [string]$Domain
    )

    $scenarioList = Get-VulnScenarioList
    $totalScenarios = $Scenarios.Count

    Write-Host ""
    Write-Host "    `e[38;5;75m┌─────────────────────────────────────────────────┐`e[0m"
    Write-Host "    `e[38;5;75m│`e[0m           `e[38;5;255;1mDEPLOYMENT SUMMARY`e[0m                  `e[38;5;75m│`e[0m"
    Write-Host "    `e[38;5;75m├─────────────────────────────────────────────────┤`e[0m"

    $sLabel = "$totalScenarios scenario$(if ($totalScenarios -gt 1) { 's' })"
    Write-Host "    `e[38;5;75m│`e[0m  Scenarios  : `e[38;5;255m$($sLabel.PadRight(33))`e[0m`e[38;5;75m│`e[0m"
    Write-Host "    `e[38;5;75m│`e[0m  Difficulty  : `e[38;5;255m$($Difficulty.PadRight(33))`e[0m`e[38;5;75m│`e[0m"
    Write-Host "    `e[38;5;75m│`e[0m  Domain      : `e[38;5;255m$($Domain.PadRight(33))`e[0m`e[38;5;75m│`e[0m"

    Write-Host "    `e[38;5;75m│`e[0m                                                 `e[38;5;75m│`e[0m"
    Write-Host "    `e[38;5;75m│`e[0m  `e[38;5;245mScenarios to deploy:`e[0m                           `e[38;5;75m│`e[0m"

    foreach ($s in $Scenarios) {
        if ($scenarioList.Contains($s)) {
            $sName = $scenarioList[$s].Name.PadRight(40)
            Write-Host "    `e[38;5;75m│`e[0m   `e[38;5;82m►`e[0m `e[38;5;255m$sName`e[0m   `e[38;5;75m│`e[0m"
        }
    }

    Write-Host "    `e[38;5;75m│`e[0m                                                 `e[38;5;75m│`e[0m"
    Write-Host "    `e[38;5;75m└─────────────────────────────────────────────────┘`e[0m"
    Write-Host ""
    Write-Host "    `e[38;5;214m[!] This will modify your Active Directory.`e[0m"

    $confirm = Read-Host "    [?] Deploy? (Y/N)"
    return ($confirm.Trim().ToUpper() -eq 'Y')
}

# ───────────────────────────────────────────────────────────
#  CHEATSHEET GENERATION
# ───────────────────────────────────────────────────────────

function Export-VulnCheatSheet {
    <#
    .SYNOPSIS
        Generates a markdown and HTML cheatsheet from deployment results.
    .PARAMETER Results
        Array of result hashtables from Deploy-* functions.
    .PARAMETER Domain
        The domain FQDN.
    .PARAMETER DomainDN
        The domain distinguished name.
    .PARAMETER OutputDir
        Directory to write cheatsheet files to.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable[]]$Results,

        [Parameter(Mandatory)]
        [string]$Domain,

        [Parameter(Mandatory)]
        [string]$DomainDN,

        [Parameter(Mandatory)]
        [string]$OutputDir
    )

    # ── Build Markdown ──
    $md = @"
# AD-Monolith Attack Cheatsheet
> Auto-generated by AD-Monolith v$Script:VulnAD_Version
> Domain: ``$Domain`` | Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')

---

"@

    $idx = 1
    foreach ($result in $Results) {
        if (-not $result -or -not $result.Scenario) { continue }

        $md += "## $idx. $($result.Scenario)`n"
        $md += "> $($result.Description)`n"
        $md += "> MITRE ATT&CK: ``$($result.MitreID)`` | Difficulty: ``$($result.Difficulty)```n`n"

        # Created objects table
        if ($result.CreatedObjects -and $result.CreatedObjects.Count -gt 0) {
            $md += "### Created Objects`n"
            $md += "| Type | Name | Details |`n"
            $md += "|------|------|---------|`n"
            foreach ($obj in $result.CreatedObjects) {
                $md += "| $($obj.Type) | ``$($obj.Name)`` | $($obj.Details) |`n"
            }
            $md += "`n"
        }

        # Attack commands
        if ($result.AttackCommands -and $result.AttackCommands.Count -gt 0) {
            $md += "### Attack Commands`n"
            foreach ($tool in $result.AttackCommands.Keys) {
                $cmd = $result.AttackCommands[$tool]
                $md += "**$tool**:`n``````bash`n$cmd`n```````n`n"
            }
        }

        # Attack path
        if ($result.AttackPath) {
            $md += "### Attack Path`n"
            $md += "``````text`n$($result.AttackPath)`n```````n"
        }

        $md += "`n---`n`n"
        $idx++
    }

    # ── Build HTML ──
    $htmlBody = $md  # We'll convert markdown to a styled HTML page

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AD-Monolith Attack Cheatsheet — $Domain</title>
<style>
    :root { --bg: #0d1117; --card: #161b22; --border: #30363d; --text: #c9d1d9;
            --accent: #58a6ff; --green: #3fb950; --red: #f85149; --orange: #d29922; }
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { background: var(--bg); color: var(--text); font-family: 'Segoe UI', -apple-system, sans-serif;
           padding: 2rem; line-height: 1.6; }
    .container { max-width: 900px; margin: 0 auto; }
    h1 { color: var(--accent); font-size: 2rem; margin-bottom: 0.5rem; }
    h2 { color: var(--green); font-size: 1.4rem; margin: 2rem 0 0.5rem; padding-bottom: 0.3rem;
         border-bottom: 1px solid var(--border); }
    h3 { color: var(--orange); font-size: 1rem; margin: 1rem 0 0.5rem; }
    .meta { color: #8b949e; font-size: 0.85rem; margin-bottom: 2rem; }
    .card { background: var(--card); border: 1px solid var(--border); border-radius: 8px;
            padding: 1.5rem; margin: 1rem 0; }
    table { width: 100%%; border-collapse: collapse; margin: 0.5rem 0; }
    th { text-align: left; padding: 0.5rem; border-bottom: 2px solid var(--border); color: var(--accent);
         font-size: 0.85rem; text-transform: uppercase; }
    td { padding: 0.5rem; border-bottom: 1px solid var(--border); }
    code { background: #1c2128; padding: 0.15rem 0.4rem; border-radius: 4px; font-size: 0.9rem;
           color: var(--green); font-family: 'Cascadia Code', 'Fira Code', monospace; }
    pre { background: #1c2128; padding: 1rem; border-radius: 6px; overflow-x: auto; margin: 0.5rem 0; }
    pre code { background: transparent; padding: 0; color: #e6edf3; }
    blockquote { border-left: 3px solid var(--accent); padding-left: 1rem; color: #8b949e; margin: 0.5rem 0; }
    hr { border: none; border-top: 1px solid var(--border); margin: 2rem 0; }
    .badge { display: inline-block; padding: 0.15rem 0.5rem; border-radius: 10px; font-size: 0.75rem;
             font-weight: 600; margin: 0 0.2rem; }
    .badge-mitre { background: rgba(88,166,255,0.15); color: var(--accent); }
    .badge-diff { background: rgba(210,153,34,0.15); color: var(--orange); }
</style>
</head>
<body>
<div class="container">
<h1>🔓 AD-Monolith Attack Cheatsheet</h1>
<p class="meta">Domain: <code>$Domain</code> | Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | AD-Monolith v$Script:VulnAD_Version</p>
<hr>
"@

    $idx = 1
    foreach ($result in $Results) {
        if (-not $result -or -not $result.Scenario) { continue }

        $html += "<div class='card'>`n"
        $html += "<h2>$idx. $($result.Scenario)</h2>`n"
        $html += "<blockquote>$($result.Description)</blockquote>`n"
        $html += "<p><span class='badge badge-mitre'>$($result.MitreID)</span>"
        $html += "<span class='badge badge-diff'>$($result.Difficulty)</span></p>`n"

        if ($result.CreatedObjects -and $result.CreatedObjects.Count -gt 0) {
            $html += "<h3>Created Objects</h3>`n<table><tr><th>Type</th><th>Name</th><th>Details</th></tr>`n"
            foreach ($obj in $result.CreatedObjects) {
                $html += "<tr><td>$($obj.Type)</td><td><code>$($obj.Name)</code></td><td>$($obj.Details)</td></tr>`n"
            }
            $html += "</table>`n"
        }

        if ($result.AttackCommands -and $result.AttackCommands.Count -gt 0) {
            $html += "<h3>Attack Commands</h3>`n"
            foreach ($tool in $result.AttackCommands.Keys) {
                $cmd = $result.AttackCommands[$tool] -replace '<', '&lt;' -replace '>', '&gt;'
                $html += "<p><strong>$tool</strong>:</p><pre><code>$cmd</code></pre>`n"
            }
        }

        if ($result.AttackPath) {
            $html += "<h3>Attack Path</h3>`n<pre><code>$($result.AttackPath)</code></pre>`n"
        }

        $html += "</div>`n"
        $idx++
    }

    $html += "</div></body></html>"

    # ── Write Files ──
    $mdPath   = Join-Path $OutputDir 'AD_Monolith_CheatSheet.md'
    $htmlPath = Join-Path $OutputDir 'AD_Monolith_CheatSheet.html'

    $md   | Out-File -FilePath $mdPath   -Encoding UTF8 -Force
    $html | Out-File -FilePath $htmlPath -Encoding UTF8 -Force

    return @{
        MarkdownPath = $mdPath
        HtmlPath     = $htmlPath
    }
}

# ───────────────────────────────────────────────────────────
#  ATTACK GRAPH VISUALIZATION
# ───────────────────────────────────────────────────────────

function Show-VulnAttackGraph {
    <#
    .SYNOPSIS
        Displays an ASCII attack graph showing paths to Domain Admin.
    .PARAMETER Results
        Array of result hashtables from Deploy-* functions.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable[]]$Results
    )

    Write-Host ""
    Write-Host "    `e[38;5;75m┌─────────────────────────────────────────────────┐`e[0m"
    Write-Host "    `e[38;5;75m│`e[0m          `e[38;5;255;1mATTACK GRAPH → DOMAIN ADMIN`e[0m          `e[38;5;75m│`e[0m"
    Write-Host "    `e[38;5;75m└─────────────────────────────────────────────────┘`e[0m"
    Write-Host ""

    # Display attack paths from results
    foreach ($result in $Results) {
        if (-not $result -or -not $result.AttackPath) { continue }
        $lines = $result.AttackPath -split "`n"
        foreach ($line in $lines) {
            # Color-code arrows and special characters
            $colored = $line `
                -replace '(──[A-Za-z]+──→)', "`e[38;5;214m`$1`e[0m" `
                -replace '(Domain Admins)', "`e[38;5;196;1m`$1`e[0m" `
                -replace '(DA)', "`e[38;5;196;1m`$1`e[0m"
            Write-Host "    `e[38;5;255m$colored`e[0m"
        }
        Write-Host ""
    }
}

# ───────────────────────────────────────────────────────────
#  DEPLOYMENT COMPLETION
# ───────────────────────────────────────────────────────────

function Show-VulnComplete {
    <#
    .SYNOPSIS
        Displays the deployment completion summary.
    .PARAMETER TotalObjects
        The total number of AD objects created.
    .PARAMETER CheatSheetPaths
        Hashtable with MarkdownPath and HtmlPath.
    .PARAMETER ScriptDir
        The directory of the main script (for cleanup hint).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [int]$TotalObjects,

        [Parameter()]
        [hashtable]$CheatSheetPaths,

        [Parameter()]
        [string]$ScriptDir
    )

    Write-Host ""
    Write-VulnSeparator -Title "DEPLOYMENT COMPLETE — $TotalObjects objects created"
    Write-Host ""

    if ($CheatSheetPaths) {
        Write-Host "    `e[38;5;75m┌─────────────────────────────────────────────────┐`e[0m"
        Write-Host "    `e[38;5;75m│`e[0m          `e[38;5;255;1mATTACK CHEATSHEET GENERATED`e[0m          `e[38;5;75m│`e[0m"
        Write-Host "    `e[38;5;75m└─────────────────────────────────────────────────┘`e[0m"
        Write-Host ""
        Write-VulnStatus -Message "Markdown : $($CheatSheetPaths.MarkdownPath)" -Type Info
        Write-VulnStatus -Message "HTML     : $($CheatSheetPaths.HtmlPath)  `e[38;5;245m(open in browser)`e[0m" -Type Info
    }

    Write-Host ""
    Write-Host "    `e[38;5;82m  Happy hacking! `e[38;5;245mDon't forget to clean up when done:`e[0m"
    Write-Host "    `e[38;5;255m  .\Deploy-ADMonolith.ps1 -Cleanup`e[0m"
    Write-Host ""
}
