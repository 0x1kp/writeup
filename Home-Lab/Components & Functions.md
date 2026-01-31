# 1. Hardware Foundation

You already own the main components. Let’s explain each:

### Mini PCs (Beelink SER8 and Beelink EQR5)

- **What they are:** Small form-factor desktop computers. Inside, they’re just like laptops — CPU, RAM, SSD — but they don’t come with a screen.
- **Why they matter:** They’ll be your **servers**, the machines that run _virtual machines (VMs)_.
- **Role in lab:**
    - SER8 = main “hypervisor host” (where most virtual machines live).
    - EQR5 = backup, storage, and extra workloads.

### Lenovo V15 Laptop (dual boot Kali/Ubuntu)

- **What it is:** Your attacker workstation.
- **Why it matters:** You’ll use this machine to simulate “hackers” attacking your lab.

### MacBook Pro

- **What it is:** Your personal laptop, macOS.
- **Why it matters:** Useful for management, mobile testing (iOS), and remote access into your lab.

### TP-Link 8-Port Gigabit Smart Switch (TL-SG108E)

- **What it is:** A device that connects computers with cables (Ethernet). “Smart” means it can do VLANs (we’ll explain later).
- **Why it matters:** It separates your network traffic into “virtual lanes” (e.g., safe traffic vs. hacker traffic vs. malware traffic).

### TP-Link Omada Access Point (EAP245)

- **What it is:** A Wi-Fi access point. Lets laptops/phones connect to your lab wirelessly.
- **Why it matters:** You’ll create multiple Wi-Fi networks (mapped to VLANs), e.g., a “Red Team” Wi-Fi, a “Malware Lab” Wi-Fi, and a “Safe Corporate Wi-Fi.”

---

# 2. Networking Concepts

This is where most beginners trip up, so let’s go slow.

### IP Address

- Like a “house number” for a computer.
- Example: `192.168.10.5` = one machine in your lab.

### Subnet

- A “neighborhood” of IPs.
- Example: `192.168.10.0/24` means “all the house numbers from .1 to .254.”

### VLAN (Virtual Local Area Network)

- Imagine painting lanes on a single road. Cars can only drive in their lane, even though they share the same asphalt.
- VLANs let you run multiple separate networks on one physical cable.
- Why you care: Your switch + pfSense firewall can put “dangerous” traffic (malware, red team) into separate lanes from your “safe” traffic (Windows domain, SIEM logs).

### Firewall

- Like a bouncer at a club. Decides which traffic can go in/out of a network.
- You’ll use **pfSense** (firewall software) to control what each VLAN is allowed to do.

### DHCP (Dynamic Host Configuration Protocol)

- The “address-giver.”
- Without DHCP, you’d manually type in an IP for every device. DHCP auto-assigns them.

### [[92-Library/00-Foundations/Networking/Networking Protocols/DNS|DNS]] (Domain Name System)

- The “phonebook” of the internet. Translates `google.com` → `142.250.72.14`.
- You’ll use **Unbound** (a DNS server) inside pfSense to simulate this role.

---

# 3. Virtualization

### Hypervisor

- Software that lets you run many VMs on one physical machine.
- **Proxmox VE** is your hypervisor. Runs on bare metal (directly on the Beelink SER8).

### Virtual Machine (VM)

- A “computer inside a computer.” Gets virtual CPUs, RAM, and disks.
- Example: You create a Windows Server VM that thinks it’s running on its own PC, but really it’s inside Proxmox.

### Container

- Lightweight alternative to VMs. Instead of a whole “fake computer,” it just isolates apps.
- Example: A container running a web app vulnerable to hacking.
- You’ll use **Docker** or **k3s (lightweight Kubernetes)** for this later.

---

# 4. Core Software Pieces

Here’s where acronyms pile up. Let’s break them down:

### pfSense (Firewall + Router)

- A VM you’ll install inside Proxmox.
- It will:
    - Connect VLANs (virtual lanes) together.
    - Block/allow traffic with firewall rules.
    - Run DHCP (assign IPs) and DNS (resolve names).

### AD DS (Active Directory Domain Services)

- Microsoft’s enterprise identity system.
- Controls logins, groups, permissions.
- You’ll install it on a Windows Server VM.

### AD CS (Active Directory Certificate Services)

- PKI (Public Key Infrastructure). Issues digital certificates.
- Certificates prove identity (e.g., “this website is legit”).

### SIEM (Security Information and Event Management)

- Collects logs from everywhere → central place.
- Lets you search “show me all failed logins at 3AM.”
- Example: **Wazuh** (open source SIEM + EDR).

### EDR (Endpoint Detection & Response)

- Like antivirus on steroids. Watches processes, logs, memory. Detects attackers living off the land.
- Example: **Velociraptor** or Wazuh agents on endpoints.

### IDS/IPS (Intrusion Detection/Prevention System)

- IDS = Watches traffic, alerts on attacks.
- IPS = Can block bad traffic.
- Example: **Suricata** (free IDS/IPS).

### NSM (Network Security Monitoring)

- Tools like **Zeek** that log everything on the network ([[HTTP]] requests, DNS queries, SSL certificates).

### SOAR (Security Orchestration, Automation, Response)

- Automates tasks like “if malware hash seen → auto-check VirusTotal.”
- Example: **Shuffle**.

### MISP (Malware Information Sharing Platform)

- CTI (Cyber Threat Intelligence) tool. Share IOCs (Indicators of Compromise).

### TheHive + Cortex

- Case management + automated enrichment. SOC analysts use it.

---

# 5. Specialized Labs

### Malware Lab (Air-Gapped)

- VLAN with **no internet access**.
- You run malware inside VMs (Windows FLARE VM, Linux REMnux).
- Fake internet provided by **INetSim** (responds like “real” servers, but safe).

### AD Attack Lab

- You misconfigure Active Directory (weak Kerberos tickets, unconstrained delegation).
- Use attack tools (BloodHound, Mimikatz, Rubeus) from Kali to compromise accounts.
- Then detect those attacks with Sysmon logs + SIEM.

### Cloud Environments

- AWS, Azure, GCP.
- Build small “hub + spoke” networks with vulnerable VMs.
- Connect back to pfSense via VPN.
- Log all cloud activity back to SIEM.

---

# 6. Management & Continuity

### Guacamole

- Web app that lets you RDP/SSH/VNC into any VM in your lab through just your browser.
- Why: No need to install a ton of clients on each laptop.

### Proxmox Backup Server

- Runs on your second Beelink.
- Takes snapshots of VMs (like “save states”) so you can roll back after an exercise.

### IaC (Infrastructure as Code)

- Scripts that auto-build your lab instead of clicking around.
- **Terraform** = makes VMs/networks in Proxmox + Cloud.
- **Ansible** = configures them (installs agents, sets firewall rules).
- **Packer** = builds golden VM templates (pre-installed Windows/Linux).

---

# 7. Step-by-Step Build Order

1. **Install Proxmox VE** on SER8 → this becomes your virtualization platform.
2. **Create pfSense VM** → make VLAN subnets, DHCP, DNS.
3. **Connect switch** (SG108E) to Proxmox → set VLAN tagging.
4. **Set up Wi-Fi VLANs** on Omada AP → Corp, Red Team, Malware, Guest.
5. **Deploy Windows Server VM** → make it AD DC + PKI.
6. **Deploy Windows Client VM** → join it to AD.
7. **Deploy SIEM (Wazuh)** → point logs from Windows + pfSense + Suricata.
8. **Add IDS/IPS (Suricata)** → mirror traffic from switch.
9. **Add EDR (Velociraptor)** → install agents on endpoints.
10. **Build malware lab VLAN** → add REMnux + FLARE.
11. **Add offensive Kali VM** → attack AD.
12. **Deploy SOAR stack (TheHive + Cortex + Shuffle + MISP)**.
13. **Expand to cloud** → AWS/GCP/Azure minimal VPCs → connect via VPN → send logs home.
14. **Automate with IaC** → Packer, Terraform, Ansible.