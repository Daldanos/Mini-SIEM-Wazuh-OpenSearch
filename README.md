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
