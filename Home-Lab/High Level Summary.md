 ## 1. Hardware Foundation

### Mini PCs (Beelink SER8 and EQR5)

- **Definition:** Compact computers with desktop-grade processors, memory, and storage.
    
- **Role:** They will act as servers running **Proxmox VE**, your hypervisor (the software that creates and manages virtual machines).
    
- **Specs:**
    
    - SER8 (Ryzen 7, 32 GB RAM, 1 TB NVMe): Primary hypervisor host.
        
    - EQR5 (Ryzen 5, 8 GB RAM, 500 GB SSD): Backup server + Proxmox Backup Server (PBS).
        
- **Integration:** These two devices form your **compute + storage backbone**. SER8 runs the workloads; EQR5 ensures you have backups and extra capacity.
    

### Lenovo V15 Laptop (Dual Boot Kali/Ubuntu)

- **Definition:** Regular laptop that can boot into two operating systems: **Kali Linux** (offensive security tools) and **Ubuntu** (general Linux work).
    
- **Role:** Your dedicated **attacker workstation** — simulates hackers.
    
- **Integration:** Connects to your Red Team VLAN for attacks.
    

### MacBook Pro (2017)

- **Role:** Your management/admin laptop. Also used for **mobile security testing** (iOS apps, Xcode simulator).
    
- **Integration:** Connects via Guacamole or VPN to manage VMs.
    

### TP-Link 8-Port Smart Switch (TL-SG108E)

- **Definition:** A network switch with VLAN support.
    
- **Analogy:** Like a road intersection with painted lanes (VLANs).
    
- **Integration:** Ensures Red Team traffic, malware traffic, and corporate traffic stay separate.
    

### TP-Link Omada Access Point (EAP245)

- **Definition:** Wi-Fi access point.
    
- **Role:** Broadcasts multiple SSIDs (Wi-Fi networks) each mapped to a VLAN.
    
- **Integration:** Lets you connect wireless devices to the correct VLANs.
    

---

## 2. Networking Concepts (Deep Explanation)

### IP Address

- Unique identifier (like a house number).
    
- Format: IPv4 (e.g., `192.168.10.5`).
    
- In the lab, each VLAN has its own subnet.
    

### Subnet

- A grouping of IPs (like a neighborhood).
    
- Example: `192.168.10.0/24` = 254 usable IPs (`.1`–`.254`).
    

### VLAN (Virtual LAN)

- Logical segmentation of networks.
    
- **Why critical:** You don’t want malware or red team traffic mixing with production-like traffic.
    
- VLANs in lab: Management (10), Servers (20), Clients (30), Red Team (40), Malware (80).
    

### Firewall

- Controls traffic between VLANs.
    
- In lab: **pfSense** VM acts as your firewall and router.
    
- Example: Red Team VLAN cannot talk to Clients VLAN unless you explicitly allow.
    

### DHCP

- Auto-assigns IP addresses to devices.
    
- In lab: pfSense assigns IPs per VLAN.
    

### DNS

- Translates names (e.g., `lab.local`) into IPs.
    
- In lab: DC1 provides DNS for `lab.local`; pfSense forwards external lookups.
    

---

## 3. Virtualization

### Hypervisor (Proxmox VE)

- The software layer that creates VMs.
    
- **Bare-metal hypervisor:** Runs directly on hardware, not inside another OS.
    
- Why: Maximizes performance and isolation.
    

### VM (Virtual Machine)

- A simulated computer. Each VM gets CPU cores, RAM, disk space, and network interfaces.
    
- Example: Windows Server DC1 running inside Proxmox.
    

### Container

- Lightweight isolation for apps (not full OS).
    
- Example: Run OWASP Juice Shop in a Docker container.
    
- Managed by **k3s (lightweight Kubernetes)** in lab.
    

---

## 4. Core Software

### pfSense

- FreeBSD-based firewall/router software.
    
- Functions: DHCP, DNS, firewall rules, VPNs.
    
- Critical role: Controls VLAN communication and lab internet access.
    

### Active Directory (AD DS)

- Microsoft’s enterprise identity service.
    
- Manages logins, groups, permissions.
    
- In lab: You’ll use `lab.local` domain.
    

### AD CS (Certificates)

- Provides certificates for TLS/SSL and Kerberos smartcard auth.
    
- Important for simulating PKI-based attacks (ADCS abuses).
    

### SIEM (Wazuh)

- Collects and correlates logs from endpoints, servers, firewalls.
    
- Provides a SOC analyst’s “single pane of glass.”
    

### EDR (Velociraptor, Wazuh Agent)

- Endpoint monitoring for suspicious activity.
    
- Detects things like Mimikatz running or malicious processes.
    

### IDS/IPS (Suricata)

- Watches raw network packets.
    
- Can alert (IDS) or block (IPS).
    

### NSM (Zeek)

- Provides rich context on network activity (e.g., full DNS logs).
    

### SOAR (Shuffle, TheHive, Cortex)

- Automates incident workflows.
    
- Example: Wazuh alert triggers → case in TheHive → hash enriched in Cortex → IP auto-blocked in pfSense.
    

### MISP

- Threat intelligence sharing platform.
    
- Stores malware hashes, domains, IPs.
    

---

## 5. Specialized Labs

### Malware Lab

- VLAN 80 = **isolated network** with no internet access.
    
- Runs: REMnux (Linux for malware analysis), FLARE VM (Windows reverse engineering), INetSim (fake internet).
    

### AD Attack Lab

- Your domain + clients with intentional misconfigs.
    
- Red team can run BloodHound, Mimikatz, Rubeus, etc.
    
- Blue team detects via Sysmon + SIEM.
    

### Cloud Labs

- AWS, Azure, GCP mini environments.
    
- Connected via VPN (WireGuard/IPsec).
    
- Simulate real hybrid enterprise.
    

---

## 6. Management & Continuity

### Guacamole

- Web-based RDP/SSH/VNC gateway.
    
- Access all lab machines from a browser.
    

### Proxmox Backup Server

- Handles snapshots and backups of VMs.
    
- Ensures safe rollback after attacks.
    

### Infrastructure as Code (IaC)

- Packer = build golden VM templates.
    
- Terraform = define networks + VMs in code.
    
- Ansible = configure services automatically.


---

# Ultimate Cybersecurity Home Lab Guide — Zero-Assumption Deep Dive + Full 5-Phase Build (Click/Command Level)

---

## Table of Contents

- [Part A — Zero-Assumption Fundamentals](#part-a--zero-assumption-fundamentals)
    
    - [A1. Hardware](#a1-hardware)
        
    - [A2. Core Networking (OSI, IP, VLANs, NAT, DHCP, DNS)](#a2-core-networking-osi-ip-vlans-nat-dhcp-dns)
        
    - [A3. Virtualization (Proxmox, VMs, Containers, Images)](#a3-virtualization-proxmox-vms-containers-images)
        
    - [A4. Identity & Windows Concepts](#a4-identity--windows-concepts)
        
    - [A5. Security Telemetry (SIEM, EDR, IDS/IPS, NSM, SOAR, CTI)](#a5-security-telemetry-siem-edr-idsips-nsm-soar-cti)
        
    - [A6. Cloud & Hybrid Basics](#a6-cloud--hybrid-basics)
        
- [Part B — Network Topology & IP Plan](#part-b--network-topology--ip-plan)
    
- [Part C — Full Build Phases (1–5)](#part-c--full-build-phases-15)
    
    - [Phase 1 — Base Foundation](#phase-1--base-foundation)
        
    - [Phase 2 — Core Infrastructure](#phase-2--core-infrastructure)
        
    - [Phase 3 — Cloud + Offensive](#phase-3--cloud--offensive)
        
    - [Phase 4 — DevSecOps + Containers + SOAR + Malware](#phase-4--devsecops--containers--soar--malware)
        
    - [Phase 5 — Advanced Scenarios + IaC](#phase-5--advanced-scenarios--iac)
        
- [Part D — Runbooks (Step-by-Step Exercises)](#part-d--runbooks-step-by-step-exercises)
    
- [Part E — Ops: Backups, Snapshots, Profiles, Cost, Safety](#part-e--ops-backups-snapshots-profiles-cost-safety)
    
- [Part F — Appendix: Commands, Configs, and Sanity Checks](#part-f--appendix-commands-configs-and-sanity-checks)
    

---

# Part A — Zero-Assumption Fundamentals

## A1. Hardware

**Mini PCs (Beelink SER8, EQR5)**

- _CPU_ = Central Processing Unit (brains). More cores → more simultaneous VMs.
    
- _RAM_ = Memory. If you run out, everything thrashes. Upgrade SER8 to **64 GB** and 2 TB NVMe ASAP.
    
- _SSD/NVMe_ = Storage. NVMe > SATA. Keep **separate disk** (or PBS host) for backups.
    
- **Roles:** SER8 = hypervisor (runs VMs). EQR5 = Proxmox Backup Server (PBS) + utility services.
    

**Switch (TL-SG108E)**

- L2 device. Understands MAC addresses. Supports **VLANs** and **Port Mirroring** (SPAN). Not a full L3 switch—routing happens on pfSense.
    

**Access Point (EAP245)**

- Wi-Fi radios. Multiple SSIDs each mapped to a VLAN ID → devices join the right subnet wirelessly.
    

**Laptops**

- Lenovo (Kali/Ubuntu) = attacker kit. MacBook = management and iOS work. Treat them as **clients** living on specific VLANs or VPN.
    

---

## A2. Core Networking (OSI, IP, VLANs, NAT, DHCP, DNS)

**OSI layers (quickly):** 1-Physical (cables), 2-Data Link (Ethernet/VLANs), 3-Network (IP), 4-Transport (TCP/UDP), 7-Application (HTTP/DNS/etc.). Most lab pain is L2/L3 misconfig.

**IP addressing:**

- Private ranges: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16.
    
- CIDR `/24` = 256 addresses (254 usable). Gateways are typically `.1`.
    

**VLANs:**

- Tag frames with a **VLAN ID** (802.1Q). **Trunk** port = carries many VLANs (tagged). **Access** port = one VLAN (untagged).
    
- Your Proxmox NIC → **Trunk** to the switch. pfSense has **sub-interfaces** per VLAN.
    

**Routing & NAT:**

- pfSense = L3 router between VLANs and out to WAN.
    
- NAT (Network Address Translation) hides many internal IPs behind your single public IP.
    

**DHCP & DNS:**

- DHCP leases IPs. DNS resolves names. pfSense **Unbound** can do both; AD DC will serve **authoritative** DNS for `lab.local` domain.
    

**Port mirroring (SPAN):**

- Switch copies traffic from trunk → sensor port for Suricata/Zeek. It’s best-effort, not guaranteed at high throughput (it’s a small switch).
    

---

## A3. Virtualization (Proxmox, VMs, Containers, Images)

**Hypervisor (Proxmox VE):**

- Bare-metal Debian-based hypervisor. Manages **VMs** and **LXC containers**.
    
- **vmbr0** = Linux bridge acting like a virtual switch. Make it **VLAN-aware**.
    

**VMs vs Containers:**

- VMs = full OS isolation, heavier, safest for malware.
    
- Containers = process-level isolation; fast & light; great for apps and infra services.
    

**Images & Templates:**

- **ISO** installs raw OS → then you Sysprep (Windows) or cloud-init (Linux) → convert to **template** → clone quickly.
    

---

## A4. Identity & Windows Concepts

**Active Directory (AD DS):**

- _Domain_ (e.g., `lab.local`) = security boundary. _Domain Controller (DC)_ = the server that authenticates users, applies policies.
    
- _GPO (Group Policy Object)_ = config pushed to machines/users. You’ll use it for logging, agent rollout, and misconfigs (on purpose).
    

**PKI (AD CS):**

- CA issues certificates → TLS, code-signing, smartcard logon. Misconfigs lead to __ADCS ESC-_ abuses_* (attacker gold).
    

**Windows Logging (must-have):**

- **Sysmon** (detailed process/file/network telemetry).
    
- **Windows Event Forwarding (WEF)** or direct agent → SIEM.
    

---

## A5. Security Telemetry (SIEM, EDR, IDS/IPS, NSM, SOAR, CTI)

- **SIEM (Wazuh)**: centralize and correlate events. Write rules/dashboards.
    
- **EDR (Velociraptor/Wazuh Agent)**: deep endpoint visibility & live response.
    
- **IDS/IPS (Suricata)**: signature-based traffic alerts; can output EVE JSON.
    
- **NSM (Zeek)**: protocol metadata (DNS, HTTP, TLS). Great for hunting.
    
- **SOAR (TheHive+Cortex+Shuffle)**: cases, enrichment (VirusTotal), and automated actions (block IP in pfSense).
    
- **CTI (MISP)**: store/share IOCs; feed detections.
    

---

## A6. Cloud & Hybrid Basics

- **AWS/GCP/Azure** each have VPC/VNet (private networks), subnets (AZ-scoped), SG/NSG (firewall), IAM (identity/permissions).
    
- **Connectivity**: Site-to-site **IPsec** (needs public IP) or **WireGuard** overlay (works through NAT).
    
- **Telemetry**: CloudTrail/Activity Logs/Audit Logs + VPC/NSG Flow Logs → ship to SIEM.
    

---

# Part B — Network Topology & IP Plan

                         `┌──────────────── Internet ────────────────┐                          │                                          │                          │          (Optional) Cloud VPCs           │                          │     AWS   Azure   GCP (VPN/WireGuard)    │                          └───────────────┬──────────────────────────┘                                          │                                  (WAN) pfSense VM                                          │ trunk (802.1Q)                                      Proxmox vmbr0                                          │                               TL-SG108E Smart Switch  (SPAN → Sensor)                       ┌──────────────┬───────────────┬───────────────┐                  VLAN 10         VLAN 20          VLAN 30         VLAN 40                  MGMT            SERVERS          CLIENTS          RED                  192.168.10.0/24 192.168.20.0/24  192.168.30.0/24  192.168.40.0/24                       └─ AP SSIDs map to VLANs (Corp, Red, Malware, Guest)                  VLAN 60 = NSM Sensor, VLAN 80 = Malware (no WAN), VLAN 90 = Guest`

**Gateways (.1):** pfSense sub-interfaces per VLAN, e.g., 192.168.20.1 for SERVERS.  
**DHCP:** per VLAN, controlled in pfSense.  
**DNS:** `lab.local` queries → DC1; everything else → pfSense → upstream.

---

# Part C — Full Build Phases (1–5)

## Phase 1 — Base Foundation

### 1. Proxmox Install (SER8)

1. Download Proxmox VE ISO; write to USB (Rufus on Windows, `dd` on Linux).
    
2. BIOS: enable virtualization (SVM/VT-x), set USB boot.
    
3. Installer choices:
    
    - Filesystem: **ext4** (ZFS is great, but eats RAM; PBS handles backups).
        
    - Hostname: `pve.lab.local`
        
    - IP (temp for now): `192.168.10.2/24`, GW `192.168.10.1`
        
4. First login: `https://192.168.10.2:8006` → add **No-subscription** repo, update:
    
    `sed -i 's/enterprise/no-subscription/g' /etc/apt/sources.list.d/pve-enterprise.list || true echo "deb http://download.proxmox.com/debian/pve bookworm pve-no-subscription" > /etc/apt/sources.list.d/pve-no-subscription.list apt update && apt -y full-upgrade && reboot`
    

### 2. Proxmox Networking

- **Goal:** one VLAN-aware bridge `vmbr0` bound to physical NIC.
    

1. GUI → _Datacenter > Node > System > Network_.
    
2. Create **Linux Bridge** `vmbr0`:
    
    - Bridge ports: your NIC (e.g., `enp3s0`)
        
    - Check **VLAN Aware**.
        
3. Apply & reboot if prompted.
    

### 3. pfSense VM (firewall/router)

1. Upload pfSense ISO to `local:iso`.
    
2. Create VM:
    
    - 2 vCPU, 4 GB RAM, 20 GB disk.
        
    - NIC: `vmbr0`, **tag VLAN 10** (MGMT) initially.
        
3. Install pfSense (accept defaults).
    
4. Inside pfSense console, set LAN IP: `192.168.10.1/24`.
    
5. Web UI: `http://192.168.10.1` → run setup wizard (set DNS to public resolver or your ISP).
    

### 4. VLANs in pfSense

- **Interfaces → Assignments → VLANs → Add:**
    
    - VLAN10 (MGMT), VLAN20 (SERVERS), VLAN30 (CLIENTS), VLAN40 (RED), VLAN60 (NSM), VLAN80 (MALWARE), VLAN90 (GUEST).
        
- **Interfaces → Assign → add OPTs** for each VLAN, enable with static IPs:
    
    - `VLAN20 on vtnet0` → 192.168.20.1/24
        
    - `VLAN30` → 192.168.30.1/24, etc.
        
- **Services → DHCP Server**: enable per VLAN with ranges:
    
    - VLAN20: 192.168.20.100–200
        
    - VLAN30: 192.168.30.100–200, etc.
        
- **Services → DNS Resolver (Unbound):**
    
    - Enable.
        
    - Add **Domain Override**: `lab.local` → `192.168.20.10` (DC1 you’ll build later).
        

### 5. Switch (TL-SG108E) configuration

- Connect Proxmox uplink to **Port 1**.
    
- **VLAN → 802.1Q VLAN → Add IDs** 10/20/30/40/60/80/90.
    
- **Port Config:**
    
    - Port 1 (to Proxmox): **Tagged** for all VLANs (TRUNK).
        
    - Port 2 (to AP): **Tagged** for all VLANs you want over Wi-Fi.
        
    - Any Access ports for wired clients: **Untagged** in the chosen VLAN.
        
- **Port Mirroring:** Mirror **Port 1** (source) → **Port 8** (destination) for sensor.
    

### 6. Access Point (EAP245)

- Controller or web UI:
    
    - SSID `Corp-Lab` → VLAN 30
        
    - SSID `RedTeam` → VLAN 40
        
    - SSID `Malware` → VLAN 80 (will have **no WAN** in pfSense rules)
        
    - SSID `Guest` → VLAN 90 (internet only)
        

**Sanity checks:**

- Plug a laptop into an Access port for VLAN30 → it should get 192.168.30.x.
    
- From VLAN30, you can reach `http://192.168.10.1` (pfSense) but cannot reach VLAN40/80 unless allowed.
    

---

## Phase 2 — Core Infrastructure

### 1. Windows Server 2022 (DC1)

1. Create VM: 2 vCPU, 4–8 GB RAM, 60 GB disk, NIC VLAN **20**.
    
2. Inside Windows:
    
    - Set hostname `DC1`.
        
    - Static IP `192.168.20.10/24`, GW `192.168.20.1`, DNS **self** `192.168.20.10`.
        
3. Add AD DS role:
    
    `Install-WindowsFeature AD-Domain-Services -IncludeManagementTools Install-ADDSForest -DomainName "lab.local" -DomainNetbiosName "LAB" -InstallDns`
    
    - Reboot. This installs DNS; it becomes authoritative for `lab.local`.
        

### 2. DNS integration with pfSense

- pfSense → **DNS Resolver → Domain Overrides**:
    
    - `lab.local` → `192.168.20.10` (DC1).
        
- On DC1 DNS Manager:
    
    - Forwarders: add pfSense `192.168.10.1` or public DNS.
        
- Test on any client:
    
    - `nslookup dc1.lab.local 192.168.20.10` → returns 192.168.20.10.
        

### 3. AD CS (Certificate Services)

- On DC1:
    
    `Install-WindowsFeature ADCS-Cert-Authority -IncludeManagementTools Install-AdcsCertificationAuthority -CAType EnterpriseRootCA -CACommonName "LAB-RootCA"`
    
- (Optional lab misconfigs for ADCS ESC1/ESC8 later.)
    

### 4. Windows Client (Win11-Client1)

1. VM: 2 vCPU, 4 GB RAM, 40 GB, NIC VLAN **30**.
    
2. Set DNS to `192.168.20.10`.
    
3. Join domain:
    
    - System → About → Rename this PC (advanced) → **Change** → Domain `lab.local`.
        
4. After reboot, login with `LAB\Administrator`.
    
5. Create a normal user `LAB\student`, add test OU structure and GPOs later.
    

### 5. Logging on Windows (Sysmon + WEF optional)

- Download Sysmon + config (e.g., SwiftOnSecurity):
    
    `.\sysmon64.exe -accepteula -i sysmonconfig-export.xml`
    
- Confirm Event Viewer → Applications and Services Logs → Microsoft → Sysmon → Operational.
    

### 6. Wazuh SIEM (Ubuntu 22.04)

1. VM: 4 vCPU, 8 GB RAM, 100 GB, VLAN **20** (IP e.g., 192.168.20.50).
    
2. Install:
    
    `curl -sO https://packages.wazuh.com/4.8/wazuh-install.sh sudo bash wazuh-install.sh -a`
    
3. Access: `https://192.168.20.50:5601` (create admin user on first run).
    
4. Add Windows agent:
    
    - Download agent MSI from Wazuh UI.
        
    - Set manager IP `192.168.20.50` during install.
        
    - Wazuh UI → **Agents** → confirm registration.
        
5. Enable Windows module + Sysmon decoders in `ossec.conf` (many enabled by default in recent builds).
    

### 7. IDS/NSM Sensor (Ubuntu)

1. VM `Sensor`: 4 vCPU, 6 GB RAM, 50 GB.
    
    - NIC1 (mgmt): VLAN **20** (192.168.20.60).
        
    - NIC2 (monitor): connect to **vmbr0**, **no VLAN tag**, no IP (promiscuous). In Proxmox, set bridge port to promisc mode.
        
2. Install Suricata + Zeek:
    
    `apt update apt -y install suricata zeek filebeat`
    
3. Suricata `/etc/suricata/suricata.yaml` key edits:
    
    - `af-packet:` → set `interface: <monitor-nic>` (e.g., `ens19`).
        
    - `vars: address-groups: HOME_NET: "[192.168.0.0/16]"`
        
    - Enable `eve-log` (JSON) outputs (alerts, dns, http).
        
    
    `systemctl enable --now suricata tail -f /var/log/suricata/eve.json`
    
4. Zeek:
    
    `echo "@load policy/protocols/conn" >> /opt/zeek/share/zeek/site/local.zeek zeekctl deploy tail -f /opt/zeek/logs/current/*.log`
    
5. Ship logs to Wazuh (via Filebeat or Wazuh module). Example Filebeat minimal:
    
    `apt -y install filebeat # point to Wazuh/Elastic; example: sed -i 's/hosts: \[.*/hosts: \["192.168.20.50:9200"\]/' /etc/filebeat/filebeat.yml systemctl enable --now filebeat`
    

### 8. Initial Firewall Policies (pfSense)

- **Default stance**: inter-VLAN **deny** except what you explicitly allow.
    
- Rules examples:
    
    - VLAN30 (Clients) → DNS to `192.168.20.10`, HTTP/HTTPS to internet.
        
    - VLAN40 (Red) → ONLY to allowed targets (e.g., DC1) during exercises.
        
    - VLAN80 (Malware) → **NO WAN**, only intra-VLAN and INetSim.
        

---

## Phase 3 — Cloud + Offensive

### A. Connectivity — WireGuard (easier at home)

**pfSense:**

1. Install WireGuard package.
    
2. **VPN → WireGuard → Add Tunnel**: generate keys.
    
    - Address: `10.200.0.1/24`
        
3. **Add Peer** for AWS node:
    
    - Public key: _from AWS VM_
        
    - Endpoint: `aws_public_ip:51820`
        
    - Allowed IPs: `10.200.0.2/32, 10.100.0.0/16` (AWS VPC range)
        

**AWS VM (Ubuntu in public subnet):**

`apt update && apt -y install wireguard wg genkey | tee /etc/wireguard/privatekey | wg pubkey > /etc/wireguard/publickey cat >/etc/wireguard/wg0.conf <<'EOF' [Interface] Address = 10.200.0.2/24 PrivateKey = <AWS_PRIVATE_KEY> ListenPort = 51820  [Peer] PublicKey = <PFSENSE_PUBLIC_KEY> Endpoint = <your_home_ip_or_ddns>:51820 AllowedIPs = 192.168.0.0/16, 10.200.0.0/24 PersistentKeepalive = 25 EOF systemctl enable --now wg-quick@wg0`

- Add VPC routes to send `192.168.0.0/16` via the AWS VM.
    

_(Repeat with Azure/GCP.)_

### B. Minimal Cloud Networks (Terraform sketch – AWS)

`resource "aws_vpc" "lab" { cidr_block = "10.100.0.0/16" } resource "aws_subnet" "public_a"  { vpc_id = aws_vpc.lab.id cidr_block = "10.100.1.0/24" map_public_ip_on_launch = true } resource "aws_subnet" "private_a" { vpc_id = aws_vpc.lab.id cidr_block = "10.100.2.0/24" } # Security groups, IGW, NATGW as needed...`

- Create a bastion in public subnet, workloads in private subnets.
    

### C. Cloud Logging to SIEM

- **AWS**: Enable CloudTrail (all regions), VPC Flow Logs to S3/Kinesis. Use lightweight ingestor (e.g., Logstash/Filebeat lambda) → Wazuh.
    
- **Azure**: Diagnostic settings → send to Event Hub/Log Analytics; forwarder → Wazuh.
    
- **GCP**: Log sinks to Pub/Sub; puller to Wazuh.
    

### D. Offensive Platform

**Kali VM (VLAN 40):**

`apt update && apt -y full-upgrade apt -y install bloodhound neo4j`

- BloodHound ingestor (SharpHound) run from domain context; or `bloodhound-python` from Linux.
    

**C2 (Sliver):**

`curl https://sliver.sh/install | sudo bash sliver-server # In sliver: generate beacon generate --os windows --arch amd64 --http`

**AD Recon & Attacks:**

- SharpHound to collect AD graph → import into BloodHound.
    
- Kerberoast (Rubeus), AS-REP roast, Unconstrained Delegation, DCSync.
    

**Detections in Wazuh:**

- Windows Events 4768/4769 anomalies, Sysmon process chains, Suricata Kerberos signatures.
    

---

## Phase 4 — DevSecOps + Containers + SOAR + Malware

### A. Git + CI

**Gitea (Docker Compose example):**

`version: "3" services:   gitea:     image: gitea/gitea:1.22     ports: ["3000:3000","222:22"]     volumes:       - ./gitea:/data     environment:       - USER_UID=1000       - USER_GID=1000     restart: unless-stopped`

- Create repos: `vuln-web`, `iac-lab`.
    
- CI: Use Drone CI or GitHub Actions runner; runners execute SAST/DAST/SCA.
    

### B. k3s (single node)

`curl -sfL https://get.k3s.io | sh - kubectl get nodes kubectl create deployment juice --image=bkimminich/juice-shop kubectl expose deployment juice --type=NodePort --port=3000 kubectl get svc`

### C. Container Security

**Trivy (image scan):**

`apt -y install trivy trivy image bkimminich/juice-shop`

**Falco (runtime):**

`helm repo add falcosecurity https://falcosecurity.github.io/charts helm install falco falcosecurity/falco`

- Ship Falco alerts via **falcosidekick** to Wazuh HTTP input or to TheHive.
    

### D. CI Security (example pipeline snippet)

`pipeline:   sast:     image: returntocorp/semgrep     commands: ["semgrep --config=p/ci ."]   sca:     image: anchore/grype     commands: ["grype . --fail-on=medium"]   dast:     image: owasp/zap2docker-stable     commands: ["zap-baseline.py -t http://juice.lab.local -r zap.html"]`

### E. SOAR Stack

- **TheHive + Cortex + MISP** via Docker (compose templates available).
    
- **Shuffle**: build flow → trigger (Wazuh alert webhook) → actions:
    
    - Lookup IoC in MISP/VT
        
    - Add pfSense firewall rule via API
        
    - Notify Slack/Email
        

**pfSense API (package: pfSense-api):** create alias or block rule → apply changes.

### F. Malware Range (VLAN 80)

- **pfSense rules:** block WAN for VLAN 80 (no default allow).
    
- **INetSim (fake internet):**
    

`apt -y install inetsim systemctl enable --now inetsim`

- **REMnux** toolset: strings, peframe, YARA, Volatility (for memory if you snapshot Windows).
    
- **FLARE VM**: install package from FireEye repo; includes IDA Free, x64dbg, PEStudio, etc.
    
- Workflow: snapshot → execute sample → capture Procmon/network → revert → extract IOCs → push to **MISP**.
    

---

## Phase 5 — Advanced Scenarios + IaC

### A. Scenario Chains

1. **AD Kerberoast → Detect → Respond**
    
    - Attack: Rubeus → dump service tickets.
        
    - Detect: spike in 4769; Sysmon 1 (process creation) with Rubeus; Suricata Kerberos anomalies.
        
    - Respond: Shuffle → create TheHive case → Cortex VT lookup → pfSense auto-block attacker IP.
        
2. **Cloud → On-Prem Pivot**
    
    - Misconfigured S3 with keys → attacker uses AWS CLI → spins bastion → WireGuard to lab → lateral movement.
        
    - Detect: CloudTrail unusual API calls; new VPN peer; Zeek catches odd DNS from new host.
        
3. **Container Escape**
    
    - Juice Shop RCE → mount `/var/run/docker.sock` → schedule privileged pod.
        
    - Detect: Falco rules (`Write below /etc`, `Contact K8s API from container`).
        

### B. DFIR with Velociraptor + Volatility

- **Server install** (Ubuntu VM), deploy agents to Windows endpoints.
    
- **Hunts:**
    
    - Collect `Security.evtx`, `Sysmon.evtx`, browser history, prefetch.
        
- Memory dump → `volatility3 -f mem.raw windows.pslist` etc.
    
- Build timeline: Zeek + Sysmon + Windows Events.
    

### C. Infrastructure as Code

**Packer (Proxmox) HCL example:**

`source "proxmox-iso" "ubuntu" {   proxmox_url = "https://192.168.10.2:8006/api2/json"   username    = "root@pam"   password    = var.pm_password   node        = "pve"   iso_storage = "local"   iso_file    = "local:iso/ubuntu-22.04.iso"   ssh_username= "packer"   ssh_password= var.ssh_password   cores       = 2   memory      = 4096   disk_size   = "40G"   cloud_init  = true } build { sources = ["source.proxmox-iso.ubuntu"] }`

**Terraform (Proxmox provider) — clone from template:**

`provider "proxmox" {   pm_api_url  = "https://192.168.10.2:8006/api2/json"   pm_user     = "root@pam"   pm_password = var.pm_password }  resource "proxmox_vm_qemu" "win11" {   name        = "Win11-Client2"   target_node = "pve"   clone       = "win11-template"   cores       = 2   memory      = 4096   network {     bridge = "vmbr0"     tag    = 30   } }`

**Ansible (Windows agent deploy):**

`- hosts: windows_clients   gather_facts: no   tasks:     - name: Install Wazuh agent       win_package:         path: https://packages.wazuh.com/4.x/windows/wazuh-agent.msi         arguments: /q ADDRESS=192.168.20.50`

### D. Rebuild Profiles

- **Profiles** = which VMs are powered during a session (Blue, Red, Cloud, Malware). Use Proxmox tags and Ansible to **power on/off sets** quickly.
    

---

# Part D — Runbooks (Step-by-Step Exercises)

## RB-1: Kerberoasting

1. Pre-req: Domain user with no special rights, SPN-bearing service account exists.
    
2. Attack (Kali w/ `impacket` or Windows with `Rubeus`):
    
    `impacket-GetUserSPNs LAB/student:'Passw0rd!' -dc-ip 192.168.20.10 -request # or on Windows: Rubeus kerberoast /nowrap`
    
3. Crack ticket offline with `hashcat` (mode 13100 for Kerberos 5 TGS-Rep etype 23).
    
4. Detection (Wazuh searches):
    
    - Windows Event `4769` volume anomaly.
        
    - Sysmon event 1: suspicious process invoking Rubeus/Impacket.
        
    - Correlate source host (VLAN 40?) and time window.
        
5. Response:
    
    - Shuffle → TheHive case.
        
    - Cortex → VT hash checks of tools (optional).
        
    - pfSense API → block offender IP or quarantine VLAN.
        

## RB-2: ADCS ESC1

1. Misconfigure web enrollment template: Enroll with client auth, supply SubjectAltName.
    
2. Attack:
    
    - Request cert for `Administrator` UPN via ESC1.
        
    - Use cert for **PKINIT** to obtain TGT → become domain admin.
        
3. Detection:
    
    - AD CS logs unusual template usage.
        
    - KDC events for smartcard/PKINIT issuance anomalous to user.
        
4. Response:
    
    - Revoke template, audit CA permissions, rotate creds.
        

## RB-3: Cloud Key Abuse

1. Plant fake AWS key in public S3.
    
2. Attacker uses key:
    
    `AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... aws ec2 describe-instances`
    
3. Detection: CloudTrail `List*`/`Describe*` from odd ASN/location; create-instance events.
    
4. Response: Disable key, SCP to restrict, rotate secrets, alert.
    

## RB-4: Container Escape

1. Get pod shell in Juice Shop.
    
2. Mount Docker socket:
    
    `docker -H unix:///var/run/docker.sock run -v /:/host -it alpine chroot /host /bin/sh`
    
3. Detection: Falco rules (`Write below /root`, `Contact K8s API from container`).
    
4. Response: Kill pod, rotate node credentials, enforce PSP/OPA (Gatekeeper), NetworkPolicy deny-all by default.
    

## RB-5: Ransomware DFIR

1. Execute sample in VLAN 80 (snapshot first).
    
2. Collect:
    
    - Velociraptor triage: Event Logs, Prefetch, Shimcache.
        
    - Memory dump → Volatility process tree, injected threads.
        
    - Zeek/Suricata: C2 domains, TLS certs.
        
3. Build a timeline, push IOCs to MISP, write detections in Wazuh.
    

---

# Part E — Ops: Backups, Snapshots, Profiles, Cost, Safety

- **PBS (on EQR5):** nightly VM backups; keep 7 daily / 4 weekly / 6 monthly.
    
- **Snapshots:** before every exercise; mark “protected” golden images.
    
- **Profiles:** don’t run everything at once on 32 GB; upgrade to 64 GB RAM.
    
- **Cloud cost:** budgets + alerts; TTL tags + nightly terraform destroy for attack sandboxes.
    
- **Safety:** Malware VLAN has **no WAN**. Don’t bridge red/malware Wi-Fi into home LAN. Legal: only attack what you own.
    

---

# Part F — Appendix: Commands, Configs, and Sanity Checks

## pfSense Basic Allow/Deny Examples

- Block VLAN80 → WAN: **Firewall > Rules > VLAN80**: add “Block any to any” above default.
    
- Allow VLAN30 → DNS to DC1:
    
    - Rule: VLAN30 net → 192.168.20.10 TCP/UDP 53 (pass).
        
- Allow management to everywhere (careful): VLAN10 → any (pass).
    

## Quick Health Checks

- `ping 192.168.10.1` (pfSense) from each VLAN.
    
- `nslookup dc1.lab.local 192.168.20.10` from client VLAN.
    
- Suricata `eve.json` non-empty while browsing from client VLAN.
    
- Wazuh shows **agent connected** for Win11 client.
    
- BloodHound graph renders users/computers—if empty, you didn’t ingest.
    

## Troubleshooting Heuristics

- VLAN issues? 99% it’s **wrong tag/untag** on switch or Proxmox NIC.
    
- No DHCP? Ensure you enabled DHCP **on that VLAN interface** in pfSense.
    
- Can’t resolve `lab.local`? Domain override in pfSense must point to DC1.