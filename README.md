# ACEHound

### Active Directory ACL Analysis & Security Assessment Tool

<img width="1029" height="434" alt="Screenshot 2026-09-03 154130" src="https://github.com/user-attachments/assets/1335ce17-4788-4f4a-9c52-d7d89d0594d2" />


**ACEHound** is a C#-based **Active Directory security assessment tool for penetration testers, red teamers, and security researchers**. It enumerates and analyzes Active Directory ACLs, identifies potentially dangerous permissions, resolves SIDs, maps inbound and outbound relationships, and provides security-relevant abuse guidance.

ACEHound is designed to help penetration testers quickly understand **who has control over what Active Directory objects** and identify potentially exploitable permission relationships during an authorized assessment.

> **Built for authorized penetration testing, red-team operations, Active Directory security assessments, labs, CTFs, and security research.**

---
## 📥 Download

### Windows

Download the latest compiled `ACEHound.exe` from the [Releases](https://github.com/yamish67/ACEHound/releases) page. and run:

```powershell
ACEHound.exe --help
```

### Linux

Clone the repository:

```bash
git clone https://github.com/yamish67/ACEHound.git
cd ACEHound
```

Or download the repository as a ZIP from GitHub.

Run the Windows binary with Wine:

```bash
wine ACEHound.exe --help
```

> Linux requires Wine to run the Windows binary.



## 🎯 Designed for Penetration Testers

ACEHound focuses on one of the most important areas of Active Directory security: **ACL-based privilege relationships**.

During an assessment, it can help answer questions such as:

* Who has `GenericAll` over this object?
* Which principals can modify this user or group?
* Who has dangerous permissions over privileged objects?
* What inbound permissions exist on a target?
* What outbound permissions does a principal have?
* Which SIDs correspond to actual users or groups?
* Which ACLs may represent privilege-escalation opportunities?
* What security impact does a particular ACE have?
* What tools or attack techniques are commonly associated with the permission?

Example:

```text
[LOW-PRIVILEGED USER]
        |
        | GenericAll
        v
[PRIVILEGED AD OBJECT]
```

ACEHound makes these relationships easier for a penetration tester to identify and investigate.

---

## 🔴 Penetration Testing Features

### Active Directory Reconnaissance

* Domain discovery
* RootDSE enumeration
* Base DN discovery
* User enumeration
* Group enumeration
* Computer enumeration
* Group membership enumeration

### ACL Enumeration & Analysis

* Security descriptor enumeration
* ACE parsing
* Active Directory permission analysis
* Interesting ACL detection
* Dangerous permission identification
* SID resolution
* Principal resolution

### Attack-Path & Relationship Analysis

* Inbound ACL relationships
* Outbound ACL relationships
* Principal → Object relationships
* Object → Principal relationships
* ACL relationship graph
* Security-relevant relationship identification

### Security-Relevant Permissions

ACEHound can identify permissions commonly investigated during Active Directory penetration tests, including:

```text
GenericAll
GenericWrite
WriteDacl
WriteOwner
WriteProperty
WriteMembers
AddMember
ForceChangePassword
AllExtendedRights
WriteAllowedToAct
RBCD-related permissions
GMSA-related permissions
```

The exact security impact depends on the target object, principal, inheritance, and surrounding AD configuration.

---

## 🚀 Usage

ACEHound is a command-line Active Directory ACL analysis tool.

### Basic Usage

```powershell
ACEHound <command> [argument]
```

### Available Commands

| Command                   | Description                                                                                                   |
| ------------------------- | ------------------------------------------------------------------------------------------------------------- |
| `--help`                  | Display ACEHound usage information, available commands, and examples.                                         |
| `--version`               | Display the current ACEHound version and author information.                                                  |
| `interesting`             | Identify security-relevant and potentially dangerous Active Directory ACL permissions.                        |
| `user <username>`         | Analyze ACL relationships for a specific user, including inbound and outbound permissions and SID resolution. |
| `permission <permission>` | Search for principals that have a specific Active Directory permission.                                       |

### Command Examples

#### `--help`

Displays available commands and usage information.

```powershell
ACEHound --help
```

---

#### `--version`

Displays the current ACEHound version.

```powershell
ACEHound --version
```

---

#### `interesting`

Searches Active Directory ACLs for security-relevant permissions that may warrant further investigation during a penetration test.

```powershell
ACEHound interesting
```

---

#### `user <username>`

Analyzes ACL relationships associated with a specific Active Directory user.

The command can display:

* Inbound permissions
* Outbound permissions
* SID-to-account resolution
* Security-relevant ACL relationships
* Permission relationships involving the selected user

Example:

```powershell
ACEHound user administrator
```

---

#### `permission <permission>`

Searches Active Directory for a specific permission and shows the principals associated with that permission.

Example:

```powershell
ACEHound permission GenericAll
```

Other supported examples:

```powershell
ACEHound permission GenericWrite
ACEHound permission ForceChangePassword
ACEHound permission AddMember
ACEHound permission ReadGMSAPassword
```

This allows a tester to quickly answer questions such as:

```text
Who has GenericAll?
Who has GenericWrite?
Who can ForceChangePassword?
Who has AddMember?
Who can ReadGMSAPassword?
```

### Example Workflow

A basic ACEHound assessment workflow can be:

```powershell
ACEHound --help
ACEHound --version
ACEHound interesting
ACEHound permission GenericAll
ACEHound permission GenericWrite
ACEHound user administrator
```

This workflow starts with tool discovery, identifies interesting ACLs, searches for specific permissions, and then investigates relationships associated with a particular user.




## 🧭 Pentesting Workflow

ACEHound can be used as part of an Active Directory assessment workflow:

```text
        AD Environment
              │
              ▼
       Domain Discovery
              │
              ▼
      Object Enumeration
              │
              ▼
       ACL Enumeration
              │
              ▼
          ACE Parsing
              │
              ▼
      Permission Analysis
              │
              ▼
    Interesting ACL Detection
              │
              ▼
       SID Resolution
              │
              ▼
     Relationship Mapping
              │
              ▼
      Attack-Path Analysis
              │
              ▼
       Manual Validation
```

ACEHound is intended to help the tester **identify and understand potential attack paths**, while exploitation and validation can be performed separately using appropriate authorized testing tools.

---

## 🧰 Security Tooling Ecosystem

ACEHound is intended to complement established Active Directory penetration-testing tools rather than replace them.

It can be used alongside tools such as:

* **BloodHound** — attack-path and relationship analysis
* **PowerView** — Active Directory reconnaissance
* **Rubeus** — Kerberos security testing
* **Certipy** — AD CS security assessment
* **Impacket** — Windows/Active Directory network protocols
* **CrackMapExec / NetExec** — network and domain assessment
* **Mimikatz** — Windows credential-security testing

ACEHound's focus is specifically **ACL and ACE analysis**, helping testers investigate permission relationships that may otherwise be difficult to interpret manually.

---

## 🧪 Example

```text
==========================================
          INBOUND PERMISSIONS
==========================================

[01] NT AUTHORITY\Authenticated Users
      |
      | GenericAll
      v
      CN=Administrator,CN=Users,DC=DRY,DC=MARTINI,DC=BARS

[+] Inbound relationships: 23


==========================================
          OUTBOUND PERMISSIONS
==========================================

[+] Outbound relationships: 0


==========================================
          ACL RELATIONSHIP GRAPH
==========================================

[NT AUTHORITY\Authenticated Users]
        |
        | GenericAll
        v
[CN=Administrator,CN=Users,DC=DRY,DC=MARTINI,DC=BARS]
```

This allows a penetration tester to quickly recognize potentially significant ACL relationships and investigate them further.

---

## 📸 Screenshots

Screenshots showcasing ACEHound's core functionality and Active Directory security-analysis capabilities.

### 🖥️ Main Interface

ACEHound's main console interface and available commands.

<img width="1029" height="434" alt="Screenshot 2026-09-03 154130" src="https://github.com/user-attachments/assets/782744a5-4ac0-4bba-80b3-a4366bb39116" />

<img width="1115" height="588" alt="Screenshot 2026-09-03 151901" src="https://github.com/user-attachments/assets/455143a6-dd9e-4822-b663-0d4f978caeb5" />


---

### 🏷️ Version Command

Displays the current ACEHound version and tool information.

<img width="651" height="112" alt="Screenshot 2026-09-03 154207" src="https://github.com/user-attachments/assets/b54b57e0-f0e5-42b3-be2f-3821a4e4e28e" />


---
### 👤 User Command

User enumeration and user-specific ACL relationship analysis, including inbound and outbound permissions.

<img width="1024" height="392" alt="Screenshot 2026-09-03 161952" src="https://github.com/user-attachments/assets/67c26962-663f-4dfc-bf5c-8bb820f4eac6" />


---

### 🔎 Interesting ACLs

Identification of security-relevant and potentially dangerous Active Directory permissions.

<img width="1024" height="646" alt="Screenshot 2026-09-03 162032" src="https://github.com/user-attachments/assets/5c4ab230-0aef-453f-ae2e-abd29eedcb53" />


---

### 🔗 ACL Relationships & Graph

Console-based visualization of principal-to-object ACL relationships and permission paths.

<img width="1023" height="713" alt="Screenshot 2026-09-03 162336" src="https://github.com/user-attachments/assets/a9778ba4-ffaf-42cf-9cd4-ecb7c9ba11c8" />


---

### 💥 Abuse Guidance

Security-relevant guidance explaining the potential impact of identified permissions and commonly associated assessment techniques.

<img width="1024" height="458" alt="Screenshot 2026-09-03 162356" src="https://github.com/user-attachments/assets/01491504-4d40-4071-8c10-41d86d06866f" />


---

### 🔐 Permission Command

Search and identify specific Active Directory permissions and the principals associated with them.

<img width="1022" height="499" alt="Screenshot 2026-09-03 162232" src="https://github.com/user-attachments/assets/72eb84ba-f99a-46f3-bb74-4d70cadcaeb9" />



## 🛡️ Authorized Use

ACEHound is a **security assessment and research tool**.

Use it only against:

* Active Directory environments you own
* Authorized penetration-testing engagements
* Red-team engagements with explicit authorization
* CTFs
* Training labs
* Research environments

Do not use ACEHound to access, modify, or compromise systems without authorization.

---

## 👨‍💻 Author

**Yamish Marshall**

[LinkedIn](https://www.linkedin.com/in/yamish-marshall-b8b931304/)

---

**ACEHound — Hunt the ACE. Map the relationship. Find the path.**

