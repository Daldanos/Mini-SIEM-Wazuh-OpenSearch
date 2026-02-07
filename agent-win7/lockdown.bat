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
