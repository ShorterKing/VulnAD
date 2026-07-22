#Requires -RunAsAdministrator
#Requires -Modules ActiveDirectory

<#
.SYNOPSIS
    AD-Monolith — Vulnerable Active Directory Lab Builder

.DESCRIPTION
    Deploys intentionally vulnerable Active Directory configurations on a single
    Domain Controller for penetration testing practice. Supports 30 attack
    scenarios covering credential attacks, privilege escalation, built-in operator
    abuse, infrastructure misconfigurations, and persistence mechanisms.

    All objects are created inside a dedicated "ADMonolith" Organizational Unit
    and can be fully removed with the -Cleanup switch.

.PARAMETER Scenario
    One or more scenario names to deploy. Supports 30 attack scenarios.
    Use 'All' to deploy all 30 scenarios.

.PARAMETER Difficulty
    Difficulty level affecting password complexity and misconfiguration subtlety.
    Easy   — Obvious misconfigs, weak passwords. Best for beginners.
    Medium — Realistic configs, moderate passwords. Best for CRTP/CRTO prep.
    Hard   — Subtle misconfigs, stronger passwords, decoy objects.

.PARAMETER Preset
    Deploy a curated preset of scenarios:
    CRTP      — Scenarios common in CRTP exam prep
    CRTO      — Scenarios common in CRTO exam prep
    OSCP      — AD-focused scenarios for OSCP
    PNPT      — Practical Network Penetration Tester preset
    RealWorld — Full 30-scenario enterprise misconfiguration set

.PARAMETER Force
    Skip confirmation prompts (non-interactive mode).

.PARAMETER Cleanup
    Remove all AD-Monolith objects and restore the domain.

.PARAMETER Validate
    Check if deployed scenarios are correctly configured and exploitable.

.PARAMETER CheatSheetOnly
    Generate the attack cheatsheet without deploying anything.

.PARAMETER NoBanner
    Suppress the ASCII art banner.

.PARAMETER NoCheatSheet
    Skip cheatsheet generation after deployment.

.EXAMPLE
    .\Deploy-ADMonolith.ps1
    Launches interactive mode with scenario selection menu.

.EXAMPLE
    .\Deploy-ADMonolith.ps1 -Scenario All -Difficulty Medium -Force
    Deploys all scenarios at medium difficulty without prompts.

.EXAMPLE
    .\Deploy-ADMonolith.ps1 -Scenario Kerberoasting,ASREPRoast -Difficulty Easy -Force
    Deploys only Kerberoasting and AS-REP Roasting at easy difficulty.

.EXAMPLE
    .\Deploy-ADMonolith.ps1 -Preset CRTP -Force
    Deploys the CRTP exam prep preset.

.EXAMPLE
    .\Deploy-ADMonolith.ps1 -Cleanup
    Removes all AD-Monolith objects from the domain.

.EXAMPLE
    .\Deploy-ADMonolith.ps1 -Validate
    Checks if all deployed scenarios are working correctly.

.NOTES
    Author  : VulnAD Project
    Version : 1.0.0
    License : MIT

    WARNING: This script creates intentionally vulnerable configurations.
             Only run on isolated lab environments. NEVER run in production.

.LINK
    https://github.com/ShorterKing/VulnAD
#>

[CmdletBinding(DefaultParameterSetName = 'Interactive')]
param(
    [Parameter(ParameterSetName = 'Deploy')]
    [ValidateSet(
        'All', 'Kerberoasting', 'ASREPRoast', 'PasswordExposure', 'PasswordSpraying', 'GPPPasswords', 'WriteSPN',
        'ACLAbuse', 'GroupNesting', 'Delegation', 'RBCD', 'DCSync', 'gMSA',
        'BackupOperators', 'ServerOperators', 'AccountOperators', 'PrintOperators', 'DNSAdmins',
        'ADCS', 'GPOAbuse', 'LAPS', 'ShadowCreds', 'ADIDNS', 'MachineQuota',
        'AdminSDHolder', 'CoercionSetup', 'NTLMDowngrade', 'DPAPIExposure', 'PreWin2000', 'ServiceAbuse', 'ScheduledTask'
    )]
    [string[]]$Scenario,

    [Parameter(ParameterSetName = 'Deploy')]
    [Parameter(ParameterSetName = 'Interactive')]
    [Parameter(ParameterSetName = 'Preset')]
    [ValidateSet('Easy', 'Medium', 'Hard')]
    [string]$Difficulty,

    [Parameter(ParameterSetName = 'Preset')]
    [ValidateSet('CRTP', 'CRTO', 'OSCP', 'PNPT', 'RealWorld')]
    [string]$Preset,

    [Parameter(ParameterSetName = 'Deploy')]
    [Parameter(ParameterSetName = 'Preset')]
    [switch]$Force,

    [Parameter(ParameterSetName = 'Cleanup')]
    [switch]$Cleanup,

    [Parameter(ParameterSetName = 'Validate')]
    [switch]$Validate,

    [Parameter(ParameterSetName = 'CheatSheet')]
    [switch]$CheatSheetOnly,

    [Parameter()]
    [switch]$NoBanner,

    [Parameter(ParameterSetName = 'Deploy')]
    [Parameter(ParameterSetName = 'Preset')]
    [switch]$NoCheatSheet
)

# ═══════════════════════════════════════════════════════════
#  INITIALIZATION
# ═══════════════════════════════════════════════════════════

$ErrorActionPreference = 'Stop'
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition

# Dot-source the core module
. (Join-Path $ScriptDir 'modules\ADMonolith-Core.ps1')

# Dot-source all scenario modules
$moduleFiles = Get-ChildItem -Path (Join-Path $ScriptDir 'modules') -Filter 'Deploy-*.ps1' -ErrorAction SilentlyContinue
foreach ($moduleFile in $moduleFiles) {
    . $moduleFile.FullName
    Write-Verbose "Loaded module: $($moduleFile.Name)"
}

# All available scenario keys (order matters for display)
$AllScenarioKeys = @(
    'Kerberoasting', 'ASREPRoast', 'PasswordExposure', 'PasswordSpraying', 'GPPPasswords', 'WriteSPN',
    'ACLAbuse', 'GroupNesting', 'Delegation', 'RBCD', 'DCSync', 'gMSA',
    'BackupOperators', 'ServerOperators', 'AccountOperators', 'PrintOperators', 'DNSAdmins',
    'ADCS', 'GPOAbuse', 'LAPS', 'ShadowCreds', 'ADIDNS', 'MachineQuota',
    'AdminSDHolder', 'CoercionSetup', 'NTLMDowngrade', 'DPAPIExposure', 'PreWin2000', 'ServiceAbuse', 'ScheduledTask'
)

# Preset definitions
$Presets = @{
    CRTP      = @('Kerberoasting', 'ASREPRoast', 'ACLAbuse', 'Delegation', 'DCSync', 'GroupNesting', 'LAPS', 'BackupOperators', 'gMSA', 'PasswordSpraying')
    CRTO      = @('Kerberoasting', 'ASREPRoast', 'ACLAbuse', 'Delegation', 'ADCS', 'DCSync', 'RBCD', 'ShadowCreds', 'GPOAbuse', 'BackupOperators', 'ServerOperators', 'CoercionSetup', 'GPPPasswords', 'MachineQuota')
    OSCP      = @('Kerberoasting', 'ASREPRoast', 'ACLAbuse', 'Delegation', 'DCSync', 'GroupNesting', 'PasswordExposure', 'LAPS', 'PasswordSpraying', 'GPPPasswords', 'MachineQuota')
    PNPT      = @('Kerberoasting', 'ASREPRoast', 'PasswordSpraying', 'GPPPasswords', 'ACLAbuse', 'DCSync', 'MachineQuota', 'RBCD')
    RealWorld = $AllScenarioKeys
}

# Map scenario keys to Deploy/Remove/Test function names
$ScenarioFunctions = @{
    Kerberoasting    = @{ Deploy = 'Deploy-Kerberoasting';    Remove = 'Remove-Kerberoasting';    Test = 'Test-Kerberoasting' }
    ASREPRoast       = @{ Deploy = 'Deploy-ASREPRoast';       Remove = 'Remove-ASREPRoast';       Test = 'Test-ASREPRoast' }
    PasswordExposure = @{ Deploy = 'Deploy-PasswordExposure'; Remove = 'Remove-PasswordExposure'; Test = 'Test-PasswordExposure' }
    PasswordSpraying = @{ Deploy = 'Deploy-PasswordSpraying'; Remove = 'Remove-PasswordSpraying'; Test = 'Test-PasswordSpraying' }
    GPPPasswords     = @{ Deploy = 'Deploy-GPPPasswords';     Remove = 'Remove-GPPPasswords';     Test = 'Test-GPPPasswords' }
    WriteSPN         = @{ Deploy = 'Deploy-WriteSPN';         Remove = 'Remove-WriteSPN';         Test = 'Test-WriteSPN' }
    ACLAbuse         = @{ Deploy = 'Deploy-ACLAbuse';         Remove = 'Remove-ACLAbuse';         Test = 'Test-ACLAbuse' }
    GroupNesting     = @{ Deploy = 'Deploy-GroupNesting';      Remove = 'Remove-GroupNesting';      Test = 'Test-GroupNesting' }
    Delegation       = @{ Deploy = 'Deploy-Delegation';       Remove = 'Remove-Delegation';       Test = 'Test-Delegation' }
    RBCD             = @{ Deploy = 'Deploy-RBCD';             Remove = 'Remove-RBCD';             Test = 'Test-RBCD' }
    DCSync           = @{ Deploy = 'Deploy-DCSync';           Remove = 'Remove-DCSync';           Test = 'Test-DCSync' }
    gMSA             = @{ Deploy = 'Deploy-gMSA';             Remove = 'Remove-gMSA';             Test = 'Test-gMSA' }
    BackupOperators  = @{ Deploy = 'Deploy-BackupOperators';  Remove = 'Remove-BackupOperators';  Test = 'Test-BackupOperators' }
    ServerOperators  = @{ Deploy = 'Deploy-ServerOperators';  Remove = 'Remove-ServerOperators';  Test = 'Test-ServerOperators' }
    AccountOperators = @{ Deploy = 'Deploy-AccountOperators'; Remove = 'Remove-AccountOperators'; Test = 'Test-AccountOperators' }
    PrintOperators   = @{ Deploy = 'Deploy-PrintOperators';   Remove = 'Remove-PrintOperators';   Test = 'Test-PrintOperators' }
    DNSAdmins        = @{ Deploy = 'Deploy-DNSAdmins';        Remove = 'Remove-DNSAdmins';        Test = 'Test-DNSAdmins' }
    ADCS             = @{ Deploy = 'Deploy-ADCS';             Remove = 'Remove-ADCS';             Test = 'Test-ADCS' }
    GPOAbuse         = @{ Deploy = 'Deploy-GPOAbuse';         Remove = 'Remove-GPOAbuse';         Test = 'Test-GPOAbuse' }
    LAPS             = @{ Deploy = 'Deploy-LAPS';             Remove = 'Remove-LAPS';             Test = 'Test-LAPS' }
    ShadowCreds      = @{ Deploy = 'Deploy-ShadowCreds';      Remove = 'Remove-ShadowCreds';      Test = 'Test-ShadowCreds' }
    ADIDNS           = @{ Deploy = 'Deploy-ADIDNS';           Remove = 'Remove-ADIDNS';           Test = 'Test-ADIDNS' }
    MachineQuota     = @{ Deploy = 'Deploy-MachineQuota';     Remove = 'Remove-MachineQuota';     Test = 'Test-MachineQuota' }
    AdminSDHolder    = @{ Deploy = 'Deploy-AdminSDHolder';    Remove = 'Remove-AdminSDHolder';    Test = 'Test-AdminSDHolder' }
    CoercionSetup    = @{ Deploy = 'Deploy-CoercionSetup';    Remove = 'Remove-CoercionSetup';    Test = 'Test-CoercionSetup' }
    NTLMDowngrade    = @{ Deploy = 'Deploy-NTLMDowngrade';    Remove = 'Remove-NTLMDowngrade';    Test = 'Test-NTLMDowngrade' }
    DPAPIExposure    = @{ Deploy = 'Deploy-DPAPIExposure';    Remove = 'Remove-DPAPIExposure';    Test = 'Test-DPAPIExposure' }
    PreWin2000       = @{ Deploy = 'Deploy-PreWin2000';       Remove = 'Remove-PreWin2000';       Test = 'Test-PreWin2000' }
    ServiceAbuse     = @{ Deploy = 'Deploy-ServiceAbuse';     Remove = 'Remove-ServiceAbuse';     Test = 'Test-ServiceAbuse' }
    ScheduledTask    = @{ Deploy = 'Deploy-ScheduledTaskAbuse'; Remove = 'Remove-ScheduledTaskAbuse'; Test = 'Test-ScheduledTaskAbuse' }
}

# ═══════════════════════════════════════════════════════════
#  DISPLAY BANNER
# ═══════════════════════════════════════════════════════════

if (-not $NoBanner) {
    Write-VulnBanner
}

# ═══════════════════════════════════════════════════════════
#  GATHER DOMAIN INFO & CHECK PREREQUISITES
# ═══════════════════════════════════════════════════════════

$domainInfo = Get-VulnDomainInfo
if (-not $domainInfo) {
    Write-VulnStatus -Message "Cannot continue without domain information. Exiting." -Type Error
    exit 1
}

Write-VulnInfo -DomainInfo $domainInfo

if (-not (Test-VulnPrerequisites -DomainInfo $domainInfo)) {
    Write-VulnStatus -Message "Prerequisites not met. Exiting." -Type Error
    exit 1
}

$DomainDN = $domainInfo.DomainDN
$Domain   = $domainInfo.Domain

# ═══════════════════════════════════════════════════════════
#  MODE: CLEANUP
# ═══════════════════════════════════════════════════════════

if ($Cleanup) {
    Write-VulnSeparator -Title 'CLEANUP MODE'
    Write-Host ""
    Write-VulnStatus -Message "This will remove ALL VulnAD objects from the domain." -Type Warning

    if (-not $Force) {
        $confirm = Read-Host "    [?] Continue? (Y/N)"
        if ($confirm.Trim().ToUpper() -ne 'Y') {
            Write-VulnStatus -Message "Cleanup cancelled." -Type Info
            exit 0
        }
    }

    Write-Host ""
    Write-VulnPhase -Number 1 -Total 2 -Name 'Running scenario cleanup functions'

    foreach ($key in $AllScenarioKeys) {
        $removeFn = $ScenarioFunctions[$key].Remove
        if (Get-Command -Name $removeFn -ErrorAction SilentlyContinue) {
            try {
                & $removeFn -DomainDN $DomainDN
                Write-VulnResult -Name $key -Detail 'cleaned up' -Success $true
            } catch {
                Write-VulnResult -Name $key -Detail "cleanup error: $_" -Success $false
            }
        }
    }

    Write-VulnPhase -Number 2 -Total 2 -Name 'Removing VulnAD OU structure'
    Remove-VulnOU -DomainDN $DomainDN

    Write-Host ""
    Write-VulnSeparator -Title 'CLEANUP COMPLETE'
    Write-Host ""
    exit 0
}

# ═══════════════════════════════════════════════════════════
#  MODE: VALIDATE
# ═══════════════════════════════════════════════════════════

if ($Validate) {
    Write-VulnSeparator -Title 'VALIDATION MODE'
    Write-Host ""
    Write-VulnStatus -Message "Validating deployed attack scenarios..." -Type Info
    Write-Host ""

    $passCount = 0
    $failCount = 0
    $totalCount = 0

    foreach ($key in $AllScenarioKeys) {
        $testFn = $ScenarioFunctions[$key].Test
        if (Get-Command -Name $testFn -ErrorAction SilentlyContinue) {
            try {
                $result = & $testFn -DomainDN $DomainDN -Domain $Domain
                $totalCount++

                $statusIcon = if ($result.Passed) {
                    $passCount++
                    "`e[38;5;82m✓`e[0m"
                } else {
                    $failCount++
                    "`e[38;5;196m✗`e[0m"
                }

                $label  = if ($result.Passed) { 'PASS' } else { 'FAIL' }
                $color  = if ($result.Passed) { '82' } else { '196' }
                $padded = $result.Scenario.PadRight(18)

                Write-Host "    [$statusIcon] `e[38;5;255m$padded`e[0m `e[38;5;245m— $($result.Message)`e[0m  `e[38;5;${color}m$label`e[0m"

                if (-not $result.Passed -and $result.Fix) {
                    Write-Host "        `e[38;5;245m└── Fix: $($result.Fix)`e[0m"
                }
            } catch {
                $failCount++
                $totalCount++
                $padded = $key.PadRight(18)
                Write-Host "    [`e[38;5;196m✗`e[0m] `e[38;5;255m$padded`e[0m `e[38;5;245m— Error: $_`e[0m  `e[38;5;196mFAIL`e[0m"
            }
        }
    }

    Write-Host ""
    $resultMsg = if ($failCount -eq 0) {
        "All $passCount/$totalCount scenarios validated successfully!"
    } else {
        "$passCount/$totalCount scenarios validated ($failCount need$(if ($failCount -gt 1){''}else{'s'}) manual fix)"
    }
    Write-VulnStatus -Message $resultMsg -Type $(if ($failCount -eq 0) { 'Success' } else { 'Warning' })
    Write-Host ""
    exit 0
}

# ═══════════════════════════════════════════════════════════
#  MODE: CHEATSHEET ONLY
# ═══════════════════════════════════════════════════════════

if ($CheatSheetOnly) {
    Write-VulnSeparator -Title 'CHEATSHEET GENERATION'
    Write-Host ""
    Write-VulnStatus -Message "Scanning deployed scenarios and generating cheatsheet..." -Type Info

    # Gather results by running Test functions to see what's deployed
    $deployedResults = @()
    foreach ($key in $AllScenarioKeys) {
        $testFn = $ScenarioFunctions[$key].Test
        if (Get-Command -Name $testFn -ErrorAction SilentlyContinue) {
            try {
                $testResult = & $testFn -DomainDN $DomainDN -Domain $Domain
                if ($testResult.Passed) {
                    # Re-run deploy in report-only mode by calling the function
                    # For now, create a stub result
                    $deployedResults += @{
                        Scenario       = $key
                        Description    = "Deployed $key scenario"
                        CreatedObjects = @()
                        AttackCommands = [ordered]@{}
                        AttackPath     = ''
                        MitreID        = (Get-VulnScenarioList)[$key].MitreID
                        Difficulty     = 'Unknown'
                    }
                }
            } catch { }
        }
    }

    if ($deployedResults.Count -eq 0) {
        Write-VulnStatus -Message "No deployed scenarios found. Deploy first, then generate cheatsheet." -Type Warning
        exit 0
    }

    $cheatPaths = Export-VulnCheatSheet -Results $deployedResults -Domain $Domain -DomainDN $DomainDN -OutputDir $ScriptDir
    Write-VulnStatus -Message "Markdown : $($cheatPaths.MarkdownPath)" -Type Success
    Write-VulnStatus -Message "HTML     : $($cheatPaths.HtmlPath)" -Type Success
    Write-Host ""
    exit 0
}

# ═══════════════════════════════════════════════════════════
#  MODE: DEPLOY (Interactive or Parameterized)
# ═══════════════════════════════════════════════════════════

# ── Determine which scenarios to deploy ──

$selectedScenarios = @()

if ($Preset) {
    # Preset mode
    $selectedScenarios = $Presets[$Preset]
    Write-VulnStatus -Message "Using preset: $Preset ($($selectedScenarios.Count) scenarios)" -Type Info
} elseif ($Scenario) {
    # Explicit scenario mode
    if ('All' -in $Scenario) {
        $selectedScenarios = $AllScenarioKeys
    } else {
        $selectedScenarios = $Scenario
    }
} else {
    # Interactive mode — show menu
    $selectedScenarios = Show-VulnMenu
    if (-not $selectedScenarios) {
        Write-VulnStatus -Message "No scenarios selected. Exiting." -Type Warning
        exit 0
    }
}

# ── Determine difficulty ──

if (-not $Difficulty) {
    if ($Force) {
        $Difficulty = 'Medium'
    } else {
        $Difficulty = Show-VulnDifficultyMenu
    }
}

# ── Confirm deployment ──

if (-not $Force) {
    $confirmed = Show-VulnConfirmation -Scenarios $selectedScenarios -Difficulty $Difficulty -Domain $Domain
    if (-not $confirmed) {
        Write-VulnStatus -Message "Deployment cancelled." -Type Info
        exit 0
    }
}

# ═══════════════════════════════════════════════════════════
#  EXECUTE DEPLOYMENT
# ═══════════════════════════════════════════════════════════

Write-VulnSeparator -Title 'DEPLOYING VULNERABLE LAB'

$totalPhases   = $selectedScenarios.Count + 1  # +1 for OU setup
$currentPhase  = 1
$allResults    = @()
$totalObjects  = 0

# ── Phase 1: Create OU structure ──

Write-VulnPhase -Number $currentPhase -Total $totalPhases -Name 'Creating Organizational Units'
Initialize-VulnOU -DomainDN $DomainDN
$currentPhase++

# ── Deploy each scenario ──

foreach ($scenarioKey in $selectedScenarios) {
    $scenarioInfo = (Get-VulnScenarioList)[$scenarioKey]
    $deployFn     = $ScenarioFunctions[$scenarioKey].Deploy

    Write-VulnPhase -Number $currentPhase -Total $totalPhases -Name $scenarioInfo.Name

    if (-not (Get-Command -Name $deployFn -ErrorAction SilentlyContinue)) {
        Write-VulnStatus -Message "Module for '$scenarioKey' not found. Skipping." -Type Warning
        $currentPhase++
        continue
    }

    try {
        $result = & $deployFn -Difficulty $Difficulty -DomainDN $DomainDN -Domain $Domain

        if ($result) {
            $allResults += $result
            if ($result.CreatedObjects) {
                $totalObjects += $result.CreatedObjects.Count
            }
        }
    } catch {
        Write-VulnStatus -Message "Error deploying ${scenarioKey}: $_" -Type Error
        Write-VulnResult -Name $scenarioKey -Detail "deployment failed: $_" -Success $false -IsLast
    }

    $currentPhase++
}

# ═══════════════════════════════════════════════════════════
#  POST-DEPLOYMENT
# ═══════════════════════════════════════════════════════════

# ── Generate cheatsheet ──

$cheatPaths = $null
if (-not $NoCheatSheet -and $allResults.Count -gt 0) {
    try {
        $cheatPaths = Export-VulnCheatSheet -Results $allResults -Domain $Domain -DomainDN $DomainDN -OutputDir $ScriptDir
    } catch {
        Write-VulnStatus -Message "Failed to generate cheatsheet: $_" -Type Warning
    }
}

# ── Show attack graph ──

if ($allResults.Count -gt 0) {
    Show-VulnAttackGraph -Results $allResults
}

# ── Show completion summary ──

Show-VulnComplete -TotalObjects $totalObjects -CheatSheetPaths $cheatPaths -ScriptDir $ScriptDir
