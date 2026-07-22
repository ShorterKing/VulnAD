<p align="center">
  <img src="assets/banner.png" alt="AD-Monolith Banner" width="800">
</p>

<h1 align="center">AD-Monolith</h1>

<p align="center">
  <strong>🔓 Vulnerable Active Directory Lab Builder — One DC. One Script. Full Attack Surface.</strong>
</p>

<p align="center">
  <a href="#-quick-start"><img src="https://img.shields.io/badge/Quick_Start-▶-82e05e?style=for-the-badge" alt="Quick Start"></a>
  <a href="#-scenarios"><img src="https://img.shields.io/badge/Scenarios-30-ff6b6b?style=for-the-badge" alt="30 Scenarios"></a>
  <a href="#-exam-presets"><img src="https://img.shields.io/badge/Presets-CRTP_|_CRTO_|_OSCP_|_PNPT-58a6ff?style=for-the-badge" alt="Exam Presets"></a>
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

| | **AD-Monolith** | GOAD | BadBlood | DetectionLab | PurpleCloud |
|---|---|---|---|---|---|
| **VMs Required** | **1** | 5+ | 1 | 4+ | Azure VMs |
| **RAM Needed** | **4 GB** | 24+ GB | 4 GB | 16+ GB | Cloud $$ |
| **Setup Time** | **< 2 min** | 1-2 hours | 15 min | 1+ hour | 30+ min |
| **Dependencies** | **None** | Vagrant, Ansible | None | Packer, Terraform | Terraform, Azure |
| **Scenarios Deployed** | **30** | 15 | Random data | Logging focus | Cloud focus |
| **Exam Presets** | **CRTP, CRTO, OSCP, PNPT** | ✗ | ✗ | ✗ | ✗ |
| **Attack Cheatsheet** | **Auto-generated** | ✗ | ✗ | ✗ | ✗ |
| **Difficulty Levels** | **Easy/Medium/Hard** | Fixed | Fixed | Fixed | Fixed |
| **One-Command Cleanup** | **✓** | Manual | Manual | Manual | terraform destroy |

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

AD-Monolith deploys **30 attack scenarios** covering the full Active Directory attack surface:

### 🔑 Credential & Password Attacks
| # | Scenario | Description | MITRE |
|---|----------|-------------|-------|
| 1 | **Kerberoasting** | Service accounts with SPNs and crackable passwords | [T1558.003](https://attack.mitre.org/techniques/T1558/003/) |
| 2 | **AS-REP Roasting** | Users with Kerberos pre-authentication disabled | [T1558.004](https://attack.mitre.org/techniques/T1558/004/) |
| 3 | **Password Exposure** | Credentials stored in AD description/attribute fields | [T1552.001](https://attack.mitre.org/techniques/T1552/001/) |
| 4 | **Password Spraying** | Weak policy + identical shared password pattern across accounts | [T1110.003](https://attack.mitre.org/techniques/T1110/003/) |
| 5 | **GPP Passwords** | SYSVOL Group Policy Preferences XML containing cpassword | [T1552.006](https://attack.mitre.org/techniques/T1552/006/) |
| 6 | **Targeted Kerberoast** | WriteSPN permission over target accounts to enable Kerberoasting | [T1134.001](https://attack.mitre.org/techniques/T1134/001/) |

### 📈 Privilege Escalation
| # | Scenario | Description | MITRE |
|---|----------|-------------|-------|
| 7 | **ACL Abuse Chains** | Misconfigured ACLs creating multi-hop privilege escalation paths | [T1222.001](https://attack.mitre.org/techniques/T1222/001/) |
| 8 | **Nested Group Privesc** | Deep group nesting chains leading to Domain Admins | [T1078.002](https://attack.mitre.org/techniques/T1078/002/) |
| 9 | **Delegation Attacks** | Unconstrained, constrained, and protocol transition delegation | [T1550.003](https://attack.mitre.org/techniques/T1550/003/) |
| 10 | **RBCD Abuse** | Resource-Based Constrained Delegation misconfiguration | [T1550.003](https://attack.mitre.org/techniques/T1550/003/) |
| 11 | **DCSync Rights** | User with directory replication rights for hash extraction | [T1003.006](https://attack.mitre.org/techniques/T1003/006/) |
| 12 | **gMSA Password Read** | Group Managed Service Account password readable by low-priv users | [T1555](https://attack.mitre.org/techniques/T1555/) |

### 🛡️ Built-in Privileged Groups Abuse
| # | Scenario | Description | MITRE |
|---|----------|-------------|-------|
| 13 | **Backup Operators** | Group membership granting NTDS.dit / SYSTEM hive extraction | [T1003.003](https://attack.mitre.org/techniques/T1003/003/) |
| 14 | **Server Operators** | Group membership allowing DC service modification | [T1543.003](https://attack.mitre.org/techniques/T1543/003/) |
| 15 | **Account Operators** | Group membership permitting password resets on non-protected accounts | [T1098.001](https://attack.mitre.org/techniques/T1098/001/) |
| 16 | **Print Operators** | Group membership providing SeLoadDriverPrivilege for kernel exploit | [T1068](https://attack.mitre.org/techniques/T1068/) |
| 17 | **DNS Admins Abuse** | Group membership allowing DNS service plugin DLL injection | [T1574](https://attack.mitre.org/techniques/T1574/) |

### 🏗️ Infrastructure & Certificate Misconfigurations
| # | Scenario | Description | MITRE |
|---|----------|-------------|-------|
| 18 | **AD CS Abuse (ESC1-8)** | Vulnerable certificate templates and CA misconfigurations | [T1649](https://attack.mitre.org/techniques/T1649/) |
| 19 | **GPO Abuse** | Writable Group Policy Objects for code execution | [T1484.001](https://attack.mitre.org/techniques/T1484/001/) |
| 20 | **LAPS Misconfiguration** | Local admin password readable by unauthorized groups | [T1552.006](https://attack.mitre.org/techniques/T1552/006/) |
| 21 | **Shadow Credentials** | Writable msDS-KeyCredentialLink for certificate-based auth | [T1556](https://attack.mitre.org/techniques/T1556/) |
| 22 | **ADIDNS Injection** | Writable Active Directory Integrated DNS zone for record injection | [T1557.001](https://attack.mitre.org/techniques/T1557/001/) |
| 23 | **Machine Account Quota** | ms-DS-MachineAccountQuota set allowing computer account creation | [T1136.002](https://attack.mitre.org/techniques/T1136/002/) |

### 🔄 Persistence & Protocol Abuse
| # | Scenario | Description | MITRE |
|---|----------|-------------|-------|
| 24 | **AdminSDHolder Abuse** | Persistent ACL propagation to all protected groups | [T1098](https://attack.mitre.org/techniques/T1098/) |
| 25 | **Auth Coercion Setup** | Active Print Spooler / RPC services for PetitPotam / PrinterBug | [T1187](https://attack.mitre.org/techniques/T1187/) |
| 26 | **NTLM Downgrade** | LmCompatibilityLevel configured allowing NTLMv1 fallback | [T1557.001](https://attack.mitre.org/techniques/T1557/001/) |
| 27 | **DPAPI Exposure** | Stored DPAPI secrets decryptable via DC DPAPI Backup Key | [T1555.004](https://attack.mitre.org/techniques/T1555/004/) |
| 28 | **Pre-Win2000 Access** | Pre-Windows 2000 Compatible Access group enabling anonymous LDAP | [T1087.002](https://attack.mitre.org/techniques/T1087/002/) |
| 29 | **Weak Service Perms** | Service running as SYSTEM with writable binary/folder ACLs | [T1574.011](https://attack.mitre.org/techniques/T1574/011/) |
| 30 | **Scheduled Task Abuse** | Scheduled task running privileged script with permissive file ACLs | [T1053.005](https://attack.mitre.org/techniques/T1053/005/) |

<br>

## 📋 Exam Presets

Tailored preset configurations matching major pentesting certification exams:

```powershell
# Certified Red Team Professional (CRTP)
.\Deploy-ADMonolith.ps1 -Preset CRTP -Difficulty Medium -Force

# Certified Red Team Operator (CRTO)
.\Deploy-ADMonolith.ps1 -Preset CRTO -Difficulty Medium -Force

# OSCP Active Directory
.\Deploy-ADMonolith.ps1 -Preset OSCP -Difficulty Easy -Force

# Practical Network Penetration Tester (PNPT)
.\Deploy-ADMonolith.ps1 -Preset PNPT -Difficulty Easy -Force

# Real-World Enterprise (All 30 Scenarios)
.\Deploy-ADMonolith.ps1 -Preset RealWorld -Difficulty Hard -Force
```

| Preset | Scenarios Deployed | Target Certification |
|--------|--------------------|----------------------|
| **CRTP** | Kerberoasting, AS-REP, ACL Abuse, Delegation, DCSync, Group Nesting, LAPS, Backup Operators, gMSA, Password Spraying | Pentester Academy CRTP |
| **CRTO** | Kerberoasting, AS-REP, ACL Abuse, Delegation, ADCS, DCSync, RBCD, Shadow Creds, GPO Abuse, Backup/Server Operators, Coercion, GPP Passwords, MAQ | Zero-Point Security CRTO |
| **OSCP** | Kerberoasting, AS-REP, ACL Abuse, Delegation, DCSync, Group Nesting, Password Exposure, LAPS, Password Spraying, GPP Passwords, MAQ | OffSec OSCP |
| **PNPT** | Kerberoasting, AS-REP, Password Spraying, GPP Passwords, ACL Abuse, DCSync, MAQ, RBCD | TCM Security PNPT |
| **RealWorld** | All 30 Scenarios | Full Penetration Testing / Red Team Range |

<br>

## 🎛️ Difficulty Levels

| Level | Passwords | Misconfiguration Subtlety | Environment Complexity |
|-------|-----------|---------------------------|------------------------|
| **Easy** | Common passwords (e.g., `Password123!`) | Direct, clear attack paths | Clean environment |
| **Medium** | Moderate complexity (e.g., `Spring2025!`) | Realistic enterprise misconfigurations | Standard noise |
| **Hard** | Complex passwords (e.g., `Qw3rty@2025xZ`) | Multi-hop chains, decoy objects | Complex enterprise noise |

<br>

## 📄 Auto-Generated Cheatsheet

Every deployment automatically generates an interactive HTML and Markdown cheatsheet saved to your project folder containing:
- Exact account usernames and passwords
- Custom attack commands tailored to your domain name and IP
- ASCII visual attack path flowcharts
- MITRE ATT&CK mappings

<br>

## 📁 Project Structure

```
AD-Monolith/
├── Deploy-ADMonolith.ps1          # Main orchestrator script
├── README.md                      # Documentation
├── LICENSE                        # MIT License
├── assets/
│   └── banner.png                 # Header banner image
├── modules/                       # 30 Attack scenario modules
│   ├── ADMonolith-Core.ps1        # Shared helper library & scenario registry
│   ├── Deploy-Kerberoasting.ps1
│   ├── Deploy-ASREPRoast.ps1
│   ├── Deploy-PasswordExposure.ps1
│   ├── Deploy-PasswordSpraying.ps1
│   ├── Deploy-GPPPasswords.ps1
│   ├── Deploy-WriteSPN.ps1
│   ├── Deploy-ACLAbuse.ps1
│   ├── Deploy-GroupNesting.ps1
│   ├── Deploy-Delegation.ps1
│   ├── Deploy-RBCD.ps1
│   ├── Deploy-DCSync.ps1
│   ├── Deploy-gMSA.ps1
│   ├── Deploy-BackupOperators.ps1
│   ├── Deploy-ServerOperators.ps1
│   ├── Deploy-AccountOperators.ps1
│   ├── Deploy-PrintOperators.ps1
│   ├── Deploy-DNSAdmins.ps1
│   ├── Deploy-ADCS.ps1
│   ├── Deploy-GPOAbuse.ps1
│   ├── Deploy-LAPS.ps1
│   ├── Deploy-ShadowCreds.ps1
│   ├── Deploy-ADIDNS.ps1
│   ├── Deploy-MachineQuota.ps1
│   ├── Deploy-AdminSDHolder.ps1
│   ├── Deploy-CoercionSetup.ps1
│   ├── Deploy-NTLMDowngrade.ps1
│   ├── Deploy-DPAPIExposure.ps1
│   ├── Deploy-PreWin2000.ps1
│   ├── Deploy-ServiceAbuse.ps1
│   └── Deploy-ScheduledTaskAbuse.ps1
└── presets/                       # Pre-configured exam presets
    ├── CRTP.json
    ├── CRTO.json
    ├── OSCP.json
    ├── PNPT.json
    └── RealWorld.json
```

<br>

## ⚖️ License & Disclaimer

Distributed under the **MIT License**.

> **WARNING:** This tool is designed strictly for educational purposes, authorized security testing, and cyber range development. Never deploy on production networks without explicit written authorization.
