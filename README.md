<p align="center">
  <img src="assets/banner.png" alt="AD-Monolith Banner" width="800">
</p>

<h1 align="center">AD-Monolith</h1>

<p align="center">
  <strong>🔓 Vulnerable Active Directory Lab Builder — One DC. One Script. Full Attack Surface.</strong>
</p>

<p align="center">
  <a href="#-quick-start"><img src="https://img.shields.io/badge/Quick_Start-▶-82e05e?style=for-the-badge" alt="Quick Start"></a>
  <a href="#-scenarios"><img src="https://img.shields.io/badge/Scenarios-14-ff6b6b?style=for-the-badge" alt="14 Scenarios"></a>
  <a href="#-exam-presets"><img src="https://img.shields.io/badge/Presets-CRTP_|_CRTO_|_OSCP-58a6ff?style=for-the-badge" alt="Exam Presets"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-d29922?style=for-the-badge" alt="MIT License"></a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/PowerShell-5.1+-5391FE?style=flat-square&logo=powershell" alt="PowerShell 5.1+">
  <img src="https://img.shields.io/badge/Windows_Server-2016_|_2019_|_2022-0078D4?style=flat-square&logo=windows" alt="Windows Server">
</p>

---

**AD-Monolith** transforms a single Windows Server Domain Controller into a fully vulnerable Active Directory lab — no multi-VM headaches, no Vagrant, no Ansible, no Terraform. Just run one PowerShell script and start hacking.

```powershell
# That's it. Seriously.
.\Deploy-ADMonolith.ps1 -Scenario All -Difficulty Medium -Force
```

<br>

## 🤔 Why AD-Monolith?

| | **AD-Monolith** | GOAD | DetectionLab | PurpleCloud |
|---|---|---|---|---|
| **VMs Required** | **1** | 5+ | 4+ | Azure VMs |
| **RAM Needed** | **4 GB** | 24+ GB | 16+ GB | Cloud $$ |
| **Setup Time** | **< 2 min** | 1-2 hours | 1+ hour | 30+ min |
| **Dependencies** | **None** | Vagrant, Ansible | Packer, Terraform | Terraform, Azure |
| **Exam Presets** | **CRTP, CRTO, OSCP** | ✗ | ✗ | ✗ |
| **Attack Cheatsheet** | **Auto-generated** | ✗ | ✗ | ✗ |
| **Difficulty Levels** | **Easy/Medium/Hard** | Fixed | Fixed | Fixed |
| **One-Command Cleanup** | **✓** | Manual | Manual | terraform destroy |

<br>

## ⚡ Quick Start

### Prerequisites

- Windows Server 2016/2019/2022 VM (promoted to Domain Controller)
- PowerShell 5.1+ (pre-installed on Windows Server)
- Active Directory PowerShell module (installed with AD DS role)
- Run as **Domain Administrator**

### Installation

```powershell
# Clone the repository
git clone https://github.com/ShorterKing/AD-Monolith.git
cd AD-Monolith

# Deploy everything (interactive mode)
.\Deploy-ADMonolith.ps1

# Or deploy everything non-interactively
.\Deploy-ADMonolith.ps1 -Scenario All -Difficulty Medium -Force

# When you're done — clean slate
.\Deploy-ADMonolith.ps1 -Cleanup
```

### First-Time Setup (if you don't have a DC yet)

```powershell
# 1. Install AD DS role
Install-WindowsFeature AD-Domain-Services -IncludeManagementTools

# 2. Promote to Domain Controller
Install-ADDSForest -DomainName "vulnlab.local" -InstallDns -Force

# 3. After reboot, deploy AD-Monolith
.\Deploy-ADMonolith.ps1 -Scenario All -Difficulty Medium -Force
```

<br>

## 🎯 Scenarios

AD-Monolith deploys **14 attack scenarios** covering the most critical Active Directory attack techniques:

### Credential Attacks
| # | Scenario | Description | MITRE |
|---|----------|-------------|-------|
| 1 | **Kerberoasting** | Service accounts with SPNs and crackable passwords | [T1558.003](https://attack.mitre.org/techniques/T1558/003/) |
| 2 | **AS-REP Roasting** | Users with Kerberos pre-authentication disabled | [T1558.004](https://attack.mitre.org/techniques/T1558/004/) |
| 11 | **Password Exposure** | Credentials stored in AD description/attribute fields | [T1552.001](https://attack.mitre.org/techniques/T1552/001/) |

### Privilege Escalation
| # | Scenario | Description | MITRE |
|---|----------|-------------|-------|
| 3 | **ACL Abuse Chains** | Misconfigured ACLs creating privilege escalation paths | [T1222.001](https://attack.mitre.org/techniques/T1222/001/) |
| 12 | **Nested Group Privesc** | Group nesting chains leading to Domain Admins | [T1078.002](https://attack.mitre.org/techniques/T1078/002/) |
| 14 | **DNS Admins Abuse** | DNS Admins group membership for DLL injection | [T1574](https://attack.mitre.org/techniques/T1574/) |

### Delegation Attacks
| # | Scenario | Description | MITRE |
|---|----------|-------------|-------|
| 4 | **Delegation Attacks** | Unconstrained, constrained, and protocol transition delegation | [T1550.003](https://attack.mitre.org/techniques/T1550/003/) |
| 10 | **RBCD Abuse** | Resource-Based Constrained Delegation misconfiguration | [T1550.003](https://attack.mitre.org/techniques/T1550/003/) |

### Certificate & Credential Abuse
| # | Scenario | Description | MITRE |
|---|----------|-------------|-------|
| 5 | **AD CS Abuse (ESC1-8)** | Vulnerable certificate templates and CA misconfigurations | [T1649](https://attack.mitre.org/techniques/T1649/) |
| 9 | **Shadow Credentials** | Writable msDS-KeyCredentialLink for certificate-based auth | [T1556](https://attack.mitre.org/techniques/T1556/) |

### Domain Dominance
| # | Scenario | Description | MITRE |
|---|----------|-------------|-------|
| 6 | **GPO Abuse** | Writable Group Policy Objects for code execution | [T1484.001](https://attack.mitre.org/techniques/T1484/001/) |
| 7 | **LAPS Misconfiguration** | Local admin password readable by unauthorized groups | [T1552.006](https://attack.mitre.org/techniques/T1552/006/) |
| 8 | **DCSync Rights** | User with directory replication rights for hash extraction | [T1003.006](https://attack.mitre.org/techniques/T1003/006/) |
| 13 | **AdminSDHolder Abuse** | Persistent ACL propagation to all protected groups | [T1098](https://attack.mitre.org/techniques/T1098/) |

<br>

## 📋 Exam Presets

Don't know which scenarios to pick? Use a preset tailored for your certification:

```powershell
# Certified Red Team Professional
.\Deploy-ADMonolith.ps1 -Preset CRTP -Difficulty Medium -Force

# Certified Red Team Operator
.\Deploy-ADMonolith.ps1 -Preset CRTO -Difficulty Medium -Force

# OSCP Active Directory
.\Deploy-ADMonolith.ps1 -Preset OSCP -Difficulty Easy -Force

# Real-World Enterprise (hardest)
.\Deploy-ADMonolith.ps1 -Preset RealWorld -Difficulty Hard -Force
```

| Preset | Scenarios | Best For |
|--------|-----------|----------|
| **CRTP** | Kerberoasting, AS-REP, ACL Abuse, Delegation, DCSync, Group Nesting, LAPS | Pentester Academy CRTP |
| **CRTO** | All CRTP + AD CS, RBCD, Shadow Creds, GPO Abuse | Zero-Point Security CRTO |
| **OSCP** | Core AD attacks + Password Exposure | OffSec OSCP AD module |
| **RealWorld** | 10 scenarios simulating enterprise misconfigs | Experienced pentesters |

<br>

## 🎮 Usage

### Interactive Mode (Recommended for First-Timers)

```powershell
.\Deploy-ADMonolith.ps1
```

Launches an interactive menu where you can:
1. Select individual scenarios or presets
2. Choose a difficulty level
3. Review a deployment summary before confirming

### CLI Mode (Scripted / Automated)

```powershell
# Deploy specific scenarios
.\Deploy-ADMonolith.ps1 -Scenario Kerberoasting,ACLAbuse,DCSync -Difficulty Hard -Force

# Deploy all scenarios
.\Deploy-ADMonolith.ps1 -Scenario All -Difficulty Medium -Force
```

### Validate Deployment

```powershell
.\Deploy-ADMonolith.ps1 -Validate
```

```
[✓] Kerberoasting    — Found 3 Kerberoastable SPNs           PASS
[✓] AS-REP Roast     — Found 2 accounts, preauth disabled    PASS
[✓] ACL Chain        — Path to DA confirmed (3 hops)          PASS
[✗] AD CS ESC1       — CA not installed on this DC            FAIL
    └── Fix: Install ADCS role, then rerun Deploy-ADCS
[✓] DCSync           — Replication rights confirmed            PASS

Result: 13/14 scenarios validated (1 needs manual fix)
```

### Cleanup

```powershell
# Remove everything AD-Monolith created
.\Deploy-ADMonolith.ps1 -Cleanup

# Skip confirmation
.\Deploy-ADMonolith.ps1 -Cleanup -Force
```

<br>

## 📊 Difficulty Levels

| Level | Passwords | Misconfigurations | Extras |
|-------|-----------|-------------------|--------|
| **Easy** | Very common (e.g., Password123...) | Obvious, direct paths to DA | Clean environment |
| **Medium** | Moderate (e.g., Spring2025...) | Realistic corporate misconfigs | Standard noise |
| **Hard** | Complex (e.g., Qw3rty...) | Subtle, multi-step required | Decoy objects, rabbit holes |

<br>

## 📁 Project Structure

```
AD-Monolith/
├── Deploy-ADMonolith.ps1              # Main entry point
├── modules/
│   ├── ADMonolith-Core.ps1            # Core utilities & helpers
│   ├── Deploy-Kerberoasting.ps1   # Kerberoasting scenario
│   ├── Deploy-ASREPRoast.ps1      # AS-REP Roasting scenario
│   ├── Deploy-ACLAbuse.ps1        # ACL abuse chains
│   ├── Deploy-Delegation.ps1      # Delegation attacks
│   ├── Deploy-ADCS.ps1            # AD Certificate Services abuse
│   ├── Deploy-GPOAbuse.ps1        # GPO abuse
│   ├── Deploy-LAPS.ps1            # LAPS misconfiguration
│   ├── Deploy-DCSync.ps1          # DCSync rights
│   ├── Deploy-ShadowCreds.ps1     # Shadow Credentials
│   ├── Deploy-RBCD.ps1            # Resource-Based Constrained Delegation
│   ├── Deploy-PasswordExposure.ps1# Password exposure
│   ├── Deploy-GroupNesting.ps1    # Nested group privilege escalation
│   ├── Deploy-AdminSDHolder.ps1   # AdminSDHolder persistence
│   └── Deploy-DNSAdmins.ps1       # DNS Admins abuse
├── presets/
│   ├── CRTP.json                  # CRTP exam preset
│   ├── CRTO.json                  # CRTO exam preset
│   ├── OSCP-AD.json               # OSCP AD preset
│   └── RealWorld.json             # Real-world enterprise preset
├── assets/                        # Images for README
├── LICENSE                        # MIT License
└── README.md                      # You are here
```

<br>

## 🔒 Auto-Generated Attack Cheatsheet

After deployment, AD-Monolith automatically generates a **complete attack cheatsheet** with:

- ✅ Exact commands for each attack (Impacket, Rubeus, Certipy, PowerView, etc.)
- ✅ Created usernames, passwords, and SPNs
- ✅ Step-by-step attack paths to Domain Admin
- ✅ MITRE ATT&CK mapping for every technique
- ✅ Beautiful HTML version you can open in your browser

```
📄 AD_Monolith_CheatSheet.md    ← Markdown for your notes
🌐 AD_Monolith_CheatSheet.html  ← Open in browser for a styled view
```

<br>

## 🛡️ Security Notice

> **⚠️ WARNING: This tool creates intentionally vulnerable Active Directory configurations.**

- **ONLY** run in isolated lab environments
- **NEVER** run on production domain controllers
- **ALWAYS** clean up with `.\Deploy-ADMonolith.ps1 -Cleanup` when done
- This tool is intended for **authorized security testing and education only**

<br>

## 🤝 Contributing

Contributions are welcome! Here's how you can help:

1. **New Scenarios** — Add new attack technique modules
2. **Bug Fixes** — Find and fix issues
3. **Difficulty Tuning** — Help calibrate difficulty levels
4. **Documentation** — Improve the cheatsheet and docs

```bash
# Fork the repo, create a branch, make changes, submit a PR
git checkout -b feature/new-scenario
```

### Adding a New Scenario

1. Create `modules/Deploy-YourScenario.ps1` following the existing module pattern
2. Implement `Deploy-`, `Remove-`, and `Test-` functions
3. Add the scenario to `Get-VulnScenarioList` in `ADMonolith-Core.ps1`
4. Add the scenario key to `$AllScenarioKeys` and `$ScenarioFunctions` in `Deploy-ADMonolith.ps1`
5. Submit a PR!

<br>

## 📜 License

This project is licensed under the [MIT License](LICENSE).

<br>

## 🙏 Acknowledgements

Built with inspiration from these amazing projects:

- [GOAD](https://github.com/Orange-Cyberdefense/GOAD) — Game of Active Directory
- [BadBlood](https://github.com/davidprowe/BadBlood) — AD filling tool
- [ADModule](https://github.com/samratashok/ADModule) — AD PowerShell module
- [Vulnerable-AD](https://github.com/safebuffer/vulnerable-AD) — Create vulnerable AD environment

And the incredible work of the offensive security community:
[BloodHound](https://github.com/BloodHoundAD/BloodHound) •
[Impacket](https://github.com/fortra/impacket) •
[Rubeus](https://github.com/GhostPack/Rubeus) •
[Certipy](https://github.com/ly4k/Certipy) •
[PowerView](https://github.com/PowerShellMafia/PowerSploit)

---

<p align="center">
  <strong>⭐ If AD-Monolith saved you from setting up 5 VMs, consider starring this repo!</strong>
</p>

<p align="center">
  <a href="https://github.com/ShorterKing/AD-Monolith/issues">Report Bug</a> •
  <a href="https://github.com/ShorterKing/AD-Monolith/issues">Request Feature</a>
</p>

