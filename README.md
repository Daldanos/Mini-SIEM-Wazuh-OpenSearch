# Project Overview & Architecture

## 1.1 Project Identity
* **Project Name:** Mini-SIEM (Wazuh + OpenSearch)
* **Subtitle:** Automated Defense for Legacy Infrastructure (Zero-Trust Lab)
* **Version:** MVP v1.0
* **Methodology:** Continuous Implementation
* **Lead Role:** DevOps

## 1.2 Executive Summary
This project implements a comprehensive **Local Mini-SIEM** solution designed to monitor, detect, and actively defend a mixed-OS environment.

Using **Wazuh 4.14.1** as the core engine, the project demonstrates a **"Zero-Trust"** defense strategy applied to legacy infrastructure. The primary achievement is the protection of a **Windows 7 Ultimate SP1** endpoint—a system often considered defenseless against modern threats—by leveraging **Sysmon** telemetry and a custom **Global Isolation Response (GIR)** mechanism.

Unlike standard deployments, this lab integrates a custom Reverse Proxy (**Nginx**) for secure access, real-time alerting via **Discord**, and threat intelligence via **VirusTotal**.

## 1.3 Business Case & Scenario
**The Context:** A simulated Industrial/OT environment relies on critical control software that is strictly compatible with **Windows 7**. These systems cannot be patched or upgraded to Windows 11 due to legacy software dependencies, making them high-value targets for lateral movement and ransomware.

**The Solution:** Since the OS kernel cannot be hardened via modern patches, security is enforced at the network and behavior layer.
* **Telemetry:** Sysmon is deployed to capture granular execution logs that Windows Event Viewer misses.
* **Response:** A "Panic Button" script (GIR) is implemented. Upon detecting an identity-based attack (Brute Force), the SIEM triggers a firewall lockdown that isolates the machine from the network instantly, preventing lateral spread.

## 1.4 Technical Architecture

### Hardware Infrastructure (Host)
The lab runs on high-performance hardware to ensure low latency for log indexing (OpenSearch).
* **CPU:** Intel Core i7 (12th Gen).
* **RAM:** 16GB DDR4.
* **Storage:** NVMe SSD (Critical for Elastic/OpenSearch I/O performance).

### Virtualization Stack
* **Hypervisor:** Oracle VirtualBox **7.1.6**.
* **Guest Additions:** Installed on all nodes for time synchronization and performance.
* **Network:** Host-Only Network (`192.168.56.0/24`) to simulate an air-gapped environment.

### Node Specifications

| Node | Role | OS | IP Address | Resources | Storage Config |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **SIEM Server** | Manager, Indexer, Dashboard | Debian 12 (Bookworm) | `192.168.56.10` | 4 vCPU, 8GB RAM | 120GB NVMe (Dynamic)<br>*Custom partitioning for `/var`* |
| **Legacy Agent** | Vulnerable Endpoint | Windows 7 Ultimate SP1 | `192.168.56.101` (DHCP) | 1 vCPU, 1GB RAM | 60GB Dynamic |
| **Attacker** | Threat Actor / Auditor | Host / Kali Linux | `192.168.56.1` | Native | N/A |

## 1.5 Software Stack & Integrations

### Core Components
1.  **Wazuh Manager (v4.14.1):** The central brain for log analysis and correlation.
2.  **OpenSearch (v7.10.2):** The indexing and storage backend.
3.  **Wazuh Agent:** Endpoint security module.
4.  **Sysmon:** Advanced background monitoring for process creation and network connections.

### External Integrations
* **Nginx Reverse Proxy:** Configured to serve the dashboard securely via a custom local domain:
    * URL: `https://siem.proteus.local/`
* **VirusTotal API:** Automated scanning of file hashes (FIM) to detect malware.
* **Discord Webhooks:** Real-time critical alerts delivered to a mobile-accessible channel.
* **Nmap:** Used for auditing port visibility before and after "Lockdown" events.

## 1.6 Key Innovations

### 🛡️ GIR (Global Isolation Response)
A custom script developed specifically for this lab to overcome Windows 7 logging limitations (missing Source IP in logs).
* **Function:** It does not block a specific IP; it isolates the *entire* machine.
* **Capability:** The script includes commented logic to block specific high-risk ports (SMB/445, RDP/3389) or enforce a "Total Blackout" (Block All).

### 🌍 Log Injection for GeoIP
To validate the **Geo-IP Enrichment** module within a private Host-Only network, we implemented a Log Injection strategy.
* **Technique:** Using `logger` on the Debian server to inject simulated SSH failure logs containing public IPs from China, Russia, and Brazil.
* **Result:** Validated the Threat Hunting map visualization without exposing the lab to the public internet.

## 1.7 Network Topology

```plaintext
[ INTERNET ] <---(API)---> [ VirusTotal ]
      ^
      | (Updates/Enrichment)
      v
[ HOST MACHINE (i7/NVMe) ]
      |
      +--- [ Nginx Proxy ] <---> [https://siem.proteus.local](https://siem.proteus.local)
      |
      +--- [ VirtualBox Host-Only Switch: 192.168.56.x ]
               |
               +--- [ Debian 12 SIEM Manager ]
               |       (IP: .10)
               |       (Ingests Logs, Triggers Active Response)
               |
               +--- [ Windows 7 Agent ]
                       (IP: .101)
                       (Runs Sysmon + GIR Script)
```

# Infrastructure Deployment

## 2.1 Server Provisioning (Debian 12)
The SIEM core runs on **Debian 12 (Bookworm)**, selected for its stability and lower resource footprint compared to Ubuntu.

### Partitioning Strategy
During installation, a **custom partitioning scheme** was implemented. Separating `/var` is a critical SIEM best practice to ensure that log flooding (which fills `/var`) does not consume root storage (`/`) and crash the operating system.

* **`/` (Root):** 30GB (System Binaries)
* **`/var`:** 80GB (Log Storage, Wazuh Indices, Docker containers)
* **`swap`:** 4GB

### Network Configuration
A Static IP assignment was configured manually via `/etc/network/interfaces` to ensure the Manager remains accessible at a fixed address within the Host-Only network.

```bash
# File: /etc/network/interfaces
auto enp0s8
iface enp0s8 inet static
    address 192.168.56.10
    netmask 255.255.255.0
```

### System Hardening & Prerequisites
Before installing the SIEM stack, the server was prepared with essential dependencies and time synchronization (Montevideo/Uruguay timezone) to ensure accurate log correlation.

```bash
# 1. Update System
apt-get update && apt-get upgrade -y

# 2. Install Dependencies & Guest Additions
apt-get install curl gnupg apt-transport-https build-essential module-assistant -y

# 3. Set Timezone (Critical for Logs)
timedatectl set-timezone America/Montevideo

# 4. Firewall Rules (UFW)
# Allowed ports: SSH (22), Dashboard (443), Agent Connection (1514), Registration (1515).
ufw allow 22/tcp
ufw allow 443/tcp
ufw allow 1514/tcp
ufw allow 1515/tcp
ufw enable
```

## 2.2 Wazuh Installation (All-in-One)
We utilized the **Wazuh Installation Assistant** for a monolithic deployment. This script handles the installation of the Wazuh Indexer, Server, and Dashboard automatically.

* **Version:** 4.14.1
* **Method:** Scripted (`wazuh-install.sh`)

```bash
curl -sO [https://packages.wazuh.com/4.14/wazuh-install.sh](https://packages.wazuh.com/4.14/wazuh-install.sh) && sudo bash ./wazuh-install.sh -a
```

*Outcome:* The installation completed without errors. Credentials were generated and stored in `wazuh-install-files.tar`.

## 2.3 Secure Access & Reverse Proxy (Nginx)
To simulate a production environment and access the dashboard via a friendly FQDN (`https://siem.proteus.local`) instead of an IP address, **Nginx** was configured as a reverse proxy on the Manager.

### Host Machine Configuration
The `hosts` file on the physical Windows 11 machine was modified to resolve the local domain:
`C:\Windows\System32\drivers\etc\hosts`:
```text
192.168.56.10  siem.proteus.local
```

### Nginx Configuration Block
Nginx listens on port 443 and forwards traffic to the Wazuh Dashboard (localhost:5601), handling SSL termination using self-signed certificates.

```nginx
server {
    listen 443 ssl;
    server_name siem.proteus.local;
    
    ssl_certificate /etc/nginx/cert.pem;
    ssl_certificate_key /etc/nginx/key.pem;

    location / {
        proxy_pass [https://127.0.0.1:5601](https://127.0.0.1:5601);
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```

## 2.4 Endpoint Preparation (Windows 7)
The legacy endpoint required specific tooling to provide telemetry equivalent to modern systems.

### Sysmon Implementation
Since standard Windows Event Logs are insufficient for advanced threat hunting (lacking detailed process hierarchy), **Sysmon (System Monitor)** was installed using the industry-standard **SwiftOnSecurity** configuration.

1.  **Download:** Sysmon v14.
2.  **Config:** `sysmonconfig-export.xml` (SwiftOnSecurity profile).
3.  **Installation Command (CMD as Admin):**

```cmd
sysmon64.exe -accepteula -i sysmonconfig-export.xml
```

This configuration enables the detection of:
* Process Creations (Event ID 1)
* Network Connections (Event ID 3)
* File Creation Stream Hash (Event ID 15)

### Network Profile Fix (Legacy Issue)
A known issue in virtualized Windows 7 environments is the "Unidentified Network" defaulting to a **Public** profile, which blocks WinRM, ICMP, and remote management.
* **Fix:** `secpol.msc` > Network List Manager Policies > Unidentified Networks > Set location type to **Private**. *


# The Legacy Agent & Active Response Engineering

## 3.1 Windows 7 Agent Deployment
Deploying modern security agents on legacy operating systems presents compatibility challenges. We utilized the **Wazuh Agent v4.14.1 (MSI)**, which still supports Windows 7 SP1.

### Installation Process
Unlike the Linux agents deployed via CLI, the Windows agent was installed using the **Graphical User Interface (GUI)** to ensure correct registration with the Manager.

1.  **Installer:** `wazuh-agent-4.14.1-1.msi`
2.  **Manager IP:** `192.168.56.10`
3.  **Key Generation:** The agent automatically negotiated a registration key via port 1515.

Once installed, the agent service (`WazuhSvc`) was verified running with:
```powershell
Get-Service WazuhSvc
```

## 3.2 Detection Logic (Ruleset)
Standard detection rules often focus on single events. To detect a coordinated Brute Force attack, we implemented a stateful correlation rule that aggregates multiple failures over time.

### Rule 100001: RDP Brute Force Aggregation
* **Trigger:** 5 failed login attempts (Event ID 4625) within 60 seconds.
* **Level:** 10 (High Severity).
* **Location:** `/var/ossec/etc/rules/local_rules.xml`

```xml
<group name="windows, rdp_defense,">
  <rule id="100001" level="10" frequency="5" timeframe="60">
    <if_sid>60122</if_sid> <field name="win.system.eventID">^4625$</field>
    <description>Wazuh Lab: RDP Brute Force Attack Detected (5 attempts)</description>
    <mitre>
      <id>T1110</id>
    </mitre>
  </rule>
</group>
```

## 3.3 Active Response Engineering (The GIR Script)
To neutralize threats on legacy systems where logs often lack the attacker's Source IP, we developed a **Global Isolation Response (GIR)** mechanism.

### The "Stateless" Challenge
Standard Wazuh responses (like `firewall-drop`) require an `<expect>srcip</expect>` tag. Since Windows 7 Security Event 4625 often logs the source as `-` (null), standard responses fail.

### The Solution: Blind Lockdown
We modified the Manager configuration to execute a script **without expecting arguments**, triggering purely on the Alert ID.

**Manager Configuration (`ossec.conf`):**
*(Note: The `<expect>` tag is intentionally omitted)*

```xml
<command>
  <name>win_generic_lockdown</name>
  <executable>lockdown.bat</executable>
  <timeout_allowed>no</timeout_allowed>
</command>

<active-response>
  <command>win_generic_lockdown</command>
  <location>local</location>
  <rules_id>100001</rules_id>
</active-response>
```

**The Script (`lockdown.bat`):**
Located at: `C:\Program Files (x86)\ossec-agent\active-response\bin\`

```batch
@echo off
:: Wazuh Active Response Script - GIR Protocol (Global Isolation Response)
:: Designed for Windows 7 / Legacy Systems

:: OPTION A: BLOCK CRITICAL PORTS (Default)
:: ---------------------------------------------------------
:: Block RDP (Remote Desktop)
netsh advfirewall firewall add rule name="WAZUH_PANIC_RDP" dir=in action=block protocol=TCP localport=3389

:: Block SMB (Lateral Movement / Ransomware)
netsh advfirewall firewall add rule name="WAZUH_PANIC_SMB" dir=in action=block protocol=TCP localport=445

:: Block RPC (Remote Procedure Call)
netsh advfirewall firewall add rule name="WAZUH_PANIC_RPC" dir=in action=block protocol=TCP localport=135

:: Block ICMP (Disables "Ping" for visual confirmation of isolation)
netsh advfirewall firewall add rule name="WAZUH_PANIC_ICMP" dir=in action=block protocol=ICMPV4


:: OPTION B: TOTAL NETWORK BLACKOUT (Commented by default)
:: ---------------------------------------------------------
:: To isolate the machine COMPLETELY from any inbound traffic, 
:: uncomment the following line:
:: netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound
