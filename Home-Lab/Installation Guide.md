# Phase 1: The Base Foundation (Networking + Hypervisor)

This phase sets the “ground” your entire lab stands on. Without it, nothing else will work.

---

## Step 1: Install Proxmox VE on Beelink SER8

**Concept:** Proxmox VE is your **hypervisor** (software that runs VMs). It will replace Windows on the SER8.

**Instructions:**

1. Download **Proxmox VE ISO**:  
    👉 https://www.proxmox.com/en/downloads
    
2. Burn ISO to USB (use **Rufus** on Windows or `dd` on Linux).
    
3. Plug USB into Beelink SER8, boot, and install.
    
    - During install:
        
        - Choose disk: your 1 TB NVMe.
            
        - File system: **ext4** (ZFS is nice but eats RAM; ext4 is safer for small labs).
            
        - Hostname: `ser8.lab.local`
            
        - IP: `192.168.10.2` (this will be in your Management VLAN later).
            
4. After install, access Proxmox UI from another device:  
    👉 `https://192.168.10.2:8006`
    

**Expected result:** You can log in to the Proxmox web interface.

---

## Step 2: Configure Network VLANs in Proxmox

**Concept:** VLANs = separate “lanes” of traffic. You’ll make a single **trunk** cable from Proxmox → Switch → pfSense.

**Instructions:**

1. In Proxmox, go to **Datacenter → Node → System → Network**.
    
2. Create a Linux Bridge called `vmbr0`.
    
    - This is the “virtual switch” that VMs connect to.
        
    - Attach it to your physical NIC (probably `enp3s0` on the SER8).
        
3. Do **not** give VMs IPs here yet. Just create the bridge.
    

**Expected result:** `vmbr0` exists and can be used by VMs.

---

## Step 3: Set Up pfSense VM

**Concept:** pfSense = your **firewall + router** inside Proxmox. It gives IPs, enforces VLAN separation, and routes traffic.

**Instructions:**

1. Download pfSense ISO:  
    👉 https://www.pfsense.org/download/
    
2. In Proxmox, create new VM:
    
    - CPU: 2 cores
        
    - RAM: 4 GB
        
    - Disk: 20 GB
        
    - Network Device: connect to `vmbr0`, set VLAN tag = **10** (management network).
        
3. Install pfSense inside VM (follow defaults).
    
4. After install, access pfSense WebUI at:  
    👉 `http://192.168.10.1` (default gateway).
    

**Expected result:** pfSense is running and you can reach its web interface.

---

## Step 4: Define VLANs in pfSense

**Concept:** VLANs allow you to split networks. Example: one for “safe corporate clients,” one for “attackers.”

**Instructions:**

1. In pfSense, go to **Interfaces → Assignments → VLANs**.
    
2. Create VLANs on your NIC:
    
    - VLAN 10 = Management (192.168.10.0/24)
        
    - VLAN 20 = Servers (192.168.20.0/24)
        
    - VLAN 30 = Clients (192.168.30.0/24)
        
    - VLAN 40 = Red Team (192.168.40.0/24)
        
    - VLAN 80 = Malware Lab (192.168.80.0/24)
        
3. Go to **Services → DHCP Server**, enable DHCP for each VLAN. Example:
    
    - VLAN 20 range: 192.168.20.100–192.168.20.200
        

**Expected result:** pfSense now gives out IPs depending on which VLAN a VM connects to.

---

## Step 5: Configure Switch (TL-SG108E)

**Concept:** Your switch needs to know which ports are trunks (carry all VLANs) vs. access (belong to one VLAN).

**Instructions:**

1. Log into switch (find IP from your router).
    
2. Set **Port 1** (to Proxmox) = Trunk (all VLANs).
    
3. Set **Port 2** (to pfSense WAN) = Access VLAN 10.
    
4. Set **Port 3** (to Omada AP) = Trunk (so Wi-Fi can map SSIDs → VLANs).
    
5. Leave other ports as needed (e.g., your laptop can plug into VLAN 30).
    

**Expected result:** VLAN traffic now flows through the switch correctly.

---

## Step 6: Configure Access Point (Omada EAP245)

**Concept:** Each Wi-Fi SSID is mapped to a VLAN. Example:

- `Corp-Lab` → VLAN 30
    
- `RedTeam` → VLAN 40
    
- `Malware` → VLAN 80
    

**Instructions:**

1. Log into Omada web UI.
    
2. Create SSID “Corp-Lab” → VLAN 30.
    
3. Create SSID “RedTeam” → VLAN 40.
    
4. Create SSID “Malware” → VLAN 80 (disable WAN access later).
    
5. Optional: Hidden SSID “Mgmt” → VLAN 10 (only your admin devices).
    

**Expected result:** When you join Wi-Fi, you land in the right VLAN subnet.

---

# ✅ Phase 1 Outcome

At this point you have:

- Proxmox hypervisor installed.
    
- pfSense running as a VM, giving out IPs and separating VLANs.
    
- Switch carrying VLANs properly.
    
- Wi-Fi mapping to VLANs.
    

Basically: **your virtual enterprise network skeleton is alive**.

----

# Phase 2: Core Infrastructure

---

## Step 1: Deploy Active Directory Domain Controller (Windows Server)

**Concept:**

- **Active Directory (AD DS)** = Microsoft’s system for managing users, groups, and computers in enterprises.
    
- **Domain Controller (DC)** = the server that runs AD.
    
- You’ll use this to simulate corporate environments where attackers target AD.
    

**Instructions:**

1. In Proxmox → **Create VM**:
    
    - Name: `DC1`
        
    - OS: Windows Server 2022 ISO (download eval from Microsoft)
        
    - CPU: 2 vCPUs
        
    - RAM: 4 GB
        
    - Disk: 60 GB
        
    - Network: `vmbr0` → VLAN tag **20** (servers VLAN).
        
2. Install Windows Server (choose “Desktop Experience” for GUI).
    
3. After install, log in and set:
    
    - Hostname: `DC1.lab.local`
        
    - Static IP: `192.168.20.10`
        
    - DNS: point to itself (`192.168.20.10`).
        
4. Open **Server Manager → Add Roles and Features → Active Directory Domain Services (AD DS)**.
    
5. After install, promote the server to a **Domain Controller**:
    
    - Create new forest: `lab.local`.
        
    - DSRM password = keep safe.
        

**Expected result:** `DC1.lab.local` is now your first domain controller.

---

## Step 2: Add DNS + DHCP to Domain Controller

**Concept:**

- **DNS (Domain Name System)** lets your clients resolve names like `dc1.lab.local`.
    
- **DHCP** (Dynamic Host Config Protocol) can also be run by AD DCs to give clients IPs — but in your setup pfSense is already doing DHCP.
    
- So here: DC will do DNS, pfSense will forward queries to DC for your `lab.local` zone.
    

**Instructions:**

1. On DC1, open **DNS Manager**.
    
    - Ensure the zone `lab.local` exists.
        
    - Add forwarders to `192.168.10.1` (pfSense) for external queries.
        
2. On pfSense:
    
    - Go to **Services → DNS Resolver**.
        
    - Add domain override: `lab.local → 192.168.20.10`.
        

**Expected result:** Any VM that asks “where is dc1.lab.local?” will be answered correctly.

---

## Step 3: Add Certificate Authority (AD CS)

**Concept:**

- **PKI (Public Key Infrastructure)** issues certificates (like HTTPS).
    
- AD CS lets you test cert-based auth, TLS inspection, and ADCS attacks (ESC1, ESC8, etc.).
    

**Instructions:**

1. On DC1, open **Server Manager → Add Roles → Active Directory Certificate Services (AD CS)**.
    
2. Choose:
    
    - Certification Authority.
        
    - Enterprise CA.
        
    - Root CA.
        
    - Create new private key.
        
3. Finish wizard.
    

**Expected result:** You now have a CA (`lab-DC1-CA`) that can issue certificates to users/machines.

---

## Step 4: Deploy Windows Client

**Concept:**

- You need a “victim workstation” to join the domain. This will let you test logins, GPOs, and attacks.
    

**Instructions:**

1. In Proxmox → Create VM:
    
    - Name: `Win11-Client1`.
        
    - OS: Windows 11 ISO (eval from Microsoft).
        
    - CPU: 2 vCPUs
        
    - RAM: 4 GB
        
    - Disk: 40 GB
        
    - Network: `vmbr0`, VLAN tag **30** (clients VLAN).
        
2. Install Windows 11.
    
3. Log in as local admin → open **System Properties → Domain** → join `lab.local`.
    
    - Use `Administrator` + password from DC1.
        
4. Reboot. Log in with domain account (`lab\administrator`).
    

**Expected result:** `Win11-Client1` is now a member of `lab.local` domain.

---

## Step 5: Deploy SIEM (Wazuh)

**Concept:**

- **SIEM (Security Information & Event Management)** collects logs from everywhere → central view.
    
- **Wazuh** is open source, combining SIEM + EDR.
    

**Instructions:**

1. In Proxmox → Create VM:
    
    - Name: `Wazuh-Server`.
        
    - OS: Ubuntu 22.04 LTS ISO.
        
    - CPU: 4 vCPUs
        
    - RAM: 8 GB
        
    - Disk: 100 GB
        
    - VLAN tag **20** (servers).
        
2. Install Ubuntu.
    
3. Install Wazuh using official script:
    
    `curl -sO https://packages.wazuh.com/4.8/wazuh-install.sh bash wazuh-install.sh -a`
    
4. Access web UI:  
    👉 `https://192.168.20.50:5601` (default admin:admin).
    

**Expected result:** Wazuh dashboard is running.

---

## Step 6: Deploy Endpoint Agent (Wazuh Agent + Sysmon)

**Concept:**

- **Agent** = little program on each endpoint that sends logs to SIEM.
    
- **Sysmon** = Microsoft tool that logs detailed system events (process starts, registry changes, etc.).
    

**Instructions (on Win11 client):**

1. Download Wazuh agent:  
    👉 `https://packages.wazuh.com/4.x/windows/wazuh-agent.msi`
    
2. Install with server IP = `192.168.20.50`.
    
3. Start Wazuh service.
    
4. Download Sysmon:  
    👉 https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
    
5. Install with SwiftOnSecurity config (popular baseline):
    
    `sysmon.exe -accepteula -i sysmonconfig-export.xml`
    
6. Confirm logs flow into Wazuh.
    

**Expected result:** When you open apps on the client, you see events appear in Wazuh.

---

## Step 7: Deploy IDS/IPS (Suricata + Zeek)

**Concept:**

- **IDS (Intrusion Detection System)** looks at network traffic for attack patterns.
    
- **IPS (Prevention)** can block them.
    
- You’ll mirror traffic from your switch to a VM running Suricata/Zeek.
    

**Instructions:**

1. In TL-SG108E switch:
    
    - Set **Port 1** (Proxmox trunk) as “monitored.”
        
    - Set **Port 8** (sensor VM NIC) as “mirror.”
        
    - This makes a copy of all traffic go to sensor VM.
        
2. In Proxmox → Create VM:
    
    - Name: `IDS-Sensor`.
        
    - OS: Ubuntu 22.04.
        
    - CPU: 4 vCPUs
        
    - RAM: 6 GB
        
    - Disk: 50 GB
        
    - NIC 1: connect to `vmbr0`, no IP (mirror interface).
        
    - NIC 2: management, VLAN tag 20.
        
3. Install Suricata:
    
    `sudo apt update && sudo apt install -y suricata sudo nano /etc/suricata/suricata.yaml`
    
    - Set interface = mirrored NIC (`ens19`).
        
    - Enable EVE JSON output.
        
4. Install Zeek:
    
    `sudo apt install -y zeek`
    
    - Run on mirrored NIC.
        
5. Send logs to Wazuh/Elastic: configure Filebeat/Logstash forwarder.
    

**Expected result:** Wazuh now receives **network alerts** (from Suricata) and **metadata logs** (from Zeek).


---

# Phase 3: Cloud + Offensive Security

---

## Step 1: Connect pfSense to the Cloud

**Concept:**

- Enterprises don’t live only on-prem anymore — they extend into **cloud providers** (AWS, Azure, GCP).
    
- To simulate this, you’ll connect your lab’s pfSense firewall to cloud networks.
    
- Two main ways:
    
    1. **IPsec VPN** (real enterprise style, but requires public IP).
        
    2. **Overlay VPN (WireGuard/Tailscale)** if you’re behind home NAT.
        

**Instructions (WireGuard approach — easiest at home):**

1. In pfSense → install WireGuard package.
    
2. Generate keypair.
    
3. On AWS EC2 instance (small Ubuntu VM in new VPC):
    
    - Install WireGuard:
        
        `sudo apt update && sudo apt install -y wireguard wg genkey | tee privatekey | wg pubkey > publickey`
        
    - Configure `/etc/wireguard/wg0.conf` with pfSense peer info.
        
4. Bring tunnel up:
    
    `sudo wg-quick up wg0`
    
5. Repeat for Azure VM and GCP VM.
    

**Expected result:** pfSense can route into AWS/Azure/GCP private subnets.

---

## Step 2: Build Minimal Cloud Networks

**Concept:**

- Each cloud will have its own “hub-and-spoke” design.
    
- Hub = shared services (logging, bastion).
    
- Spokes = “Prod,” “Dev,” “Attack-Cloud.”
    

**Instructions (AWS example):**

1. In AWS console → VPC → Create new VPC: `lab-hub`.
    
    - CIDR: `10.100.0.0/16`.
        
2. Add subnets:
    
    - Public (10.100.1.0/24) → Bastion host.
        
    - Private (10.100.2.0/24) → Workloads.
        
3. Create Security Groups:
    
    - Bastion SG: allow SSH only from pfSense WAN IP.
        
    - Workload SG: allow only from Bastion + pfSense tunnel.
        
4. Launch EC2 instance:
    
    - Ubuntu `t2.micro` in private subnet.
        
    - Tag as “Workload-1.”
        

**Repeat similar in Azure and GCP.**

**Expected result:** You have reachable cloud VMs inside isolated subnets.

---

## Step 3: Enable Cloud Logging

**Concept:**

- You need to simulate cloud security monitoring (SIEM integration).
    
- Each provider has native logging:
    
    - AWS = CloudTrail, VPC Flow Logs.
        
    - Azure = Activity Logs, NSG Flow Logs.
        
    - GCP = Audit Logs, VPC Flow Logs.
        

**Instructions (AWS example):**

1. Enable CloudTrail (all regions).
    
2. Send logs to S3 bucket.
    
3. Deploy CloudWatch Agent on EC2.
    
4. Configure Filebeat on pfSense or Wazuh → pull logs from S3/CloudWatch → send to Wazuh server.
    

**Expected result:** Wazuh SIEM now receives AWS logs alongside your on-prem logs.

---

## Step 4: Deploy Attack Workstation (Kali)

**Concept:**

- **Kali Linux** = attacker’s Swiss army knife. Preloaded with tools for recon, exploitation, AD attacks.
    
- You’ll place this in your **Red Team VLAN (40)**.
    

**Instructions:**

1. In Proxmox → Create VM:
    
    - Name: `Kali-RedTeam`.
        
    - OS: Kali ISO.
        
    - CPU: 2 vCPUs, RAM: 4 GB, Disk: 50 GB.
        
    - Network: VLAN tag **40**.
        
2. Install Kali.
    
3. Update + upgrade:
    
    `sudo apt update && sudo apt full-upgrade -y`
    
4. Install BloodHound + Neo4j (for AD attack graphs).
    
    `sudo apt install bloodhound neo4j -y`
    

**Expected result:** You have a hacker box ready inside VLAN 40.

---

## Step 5: Deploy C2 (Command & Control)

**Concept:**

- C2 frameworks simulate attacker persistence.
    
- Examples: **Sliver, Covenant, Mythic.**
    
- They generate “beacons” that connect from victims back to the C2 server.
    

**Instructions (Sliver example):**

1. On Kali:
    
    `curl https://sliver.sh/install | sudo bash sliver-server`
    
2. Generate implant:
    
    `generate --os windows --arch amd64 --format exe --http`
    
3. Drop on Win11 client, execute.
    

**Expected result:** Kali has a C2 session from your Win11 client.

---

## Step 6: Offensive AD Attacks

**Concept:**

- AD has many weaknesses. Classic red-team training.
    
- Tools: **Rubeus, Mimikatz, CrackMapExec, SharpHound.**
    

**Instructions:**

1. From Kali, run BloodHound/SharpHound against AD:
    
    `bloodhound-python -u lab\student -p Passw0rd! -ip 192.168.20.10`
    
2. Import results into BloodHound GUI.
    
3. Identify Kerberoast or DCSync paths.
    

**Expected result:** You can map AD attack paths visually.

---

## Step 7: Detection in Wazuh

**Concept:**

- Your SOC side should now _see_ these attacks.
    
- Sysmon → Wazuh detects unusual LSASS access, Kerberoast attempts, failed logins.
    
- Suricata → Wazuh sees abnormal Kerberos traffic.
    
- Cloud logs → SIEM shows suspicious IAM use (if you attack cloud).
    

**Instructions:**

1. In Wazuh → go to **Security Events**.
    
2. Search:
    
    - `event_id:4625` → failed logins.
        
    - `event_id:4769` → Kerberos ticket requests.
        
    - Suricata → search `ET ATTACK Kerberos TGT Request`.
        
3. Write detection rules → trigger alerts in SIEM.
    

**Expected result:** You simulate real attacks and **see detections** firing in Wazuh.


---

# Phase 4: DevSecOps + Containers + SOAR + Malware Range

---

## Step 1: Set Up a Git/CI Environment

**Concept:**

- Real orgs build apps via pipelines (code → build → test → deploy).
    
- You’ll simulate this with **Gitea** (lightweight GitHub alternative) or **GitLab CE** if you want heavier.
    
- CI/CD pipelines let you integrate **SAST, DAST, dependency scanning** (security automation).
    

**Instructions (Gitea + Runner):**

1. In Proxmox → Create VM:
    
    - Name: `Gitea-Server`.
        
    - OS: Ubuntu 22.04.
        
    - CPU: 2 vCPUs, RAM: 4 GB, Disk: 50 GB, VLAN tag 20.
        
2. Install Gitea:
    
    `sudo apt update && sudo apt install -y git docker docker-compose mkdir -p /srv/gitea && cd /srv/gitea wget https://dl.gitea.io/gitea/1.21/gitea-1.21-linux-amd64 chmod +x gitea-1.21-linux-amd64 ./gitea-1.21-linux-amd64 web`
    
3. Access UI → `http://192.168.20.60:3000` → create admin account.
    
4. Install CI runner (Drone CI or GitHub Actions runner).
    

**Expected result:** You can push code repos, trigger builds, and run pipeline jobs.

---

## Step 2: Deploy a k3s Cluster (Lightweight Kubernetes)

**Concept:**

- **Kubernetes (k8s)** orchestrates containers across nodes.
    
- Enterprises use it heavily — lots of real-world exploits focus here.
    
- **k3s** = lightweight k8s, perfect for your lab.
    

**Instructions (single node):**

1. In Proxmox → Create VM:
    
    - Name: `k3s-node1`.
        
    - OS: Ubuntu 22.04.
        
    - CPU: 4 vCPUs, RAM: 6 GB, Disk: 60 GB.
        
    - VLAN tag 20.
        
2. Install k3s:
    
    `curl -sfL https://get.k3s.io | sh - sudo kubectl get nodes`
    
3. Deploy test app:
    
    `kubectl create deployment juice --image=bkimminich/juice-shop kubectl expose deployment juice --type=NodePort --port=3000`
    

**Expected result:** You have a vulnerable web app (`Juice Shop`) running on Kubernetes.

---

## Step 3: Add Container Security Tools

**Concept:**

- Containers need runtime + image scanning.
    
- You’ll simulate:
    
    - **Trivy** (image vulnerability scanner).
        
    - **Falco** (runtime detection).
        
    - **Cilium** (eBPF-powered network policy).
        

**Instructions:**

1. Install Trivy on k3s node:
    
    `sudo apt install -y trivy trivy image bkimminich/juice-shop`
    
    → See CVEs in vulnerable image.
    
2. Install Falco (runtime detection):
    
    `helm repo add falcosecurity https://falcosecurity.github.io/charts helm install falco falcosecurity/falco`
    
    → Logs events like “exec into container.”
    
3. Optional: Install Cilium for advanced network visibility.
    

**Expected result:** k3s cluster now produces **security alerts** on container activity.

---

## Step 4: Integrate Security Scans into CI/CD

**Concept:**

- Every time code is pushed → pipeline runs:
    
    - **SAST** (static code scan with Semgrep).
        
    - **SCA** (dependency scan with Grype/Trivy).
        
    - **DAST** (ZAP scan of running app).
        

**Instructions (example Drone CI pipeline):**

`pipeline:   sast:     image: returntocorp/semgrep     commands:       - semgrep --config=p/ci .   sca:     image: anchore/grype     commands:       - grype . --fail-on medium   dast:     image: owasp/zap2docker-stable     commands:       - zap-baseline.py -t http://juice.lab.local`

**Expected result:** Your pipeline **fails builds if security scans find issues.**

---

## Step 5: Deploy SOAR Stack (TheHive + Cortex + Shuffle + MISP)

**Concept:**

- **SOAR (Security Orchestration, Automation, Response)** automates incident response.
    
- **TheHive** = case management.
    
- **Cortex** = enrich IOCs (hash lookups, VirusTotal).
    
- **MISP** = threat intel feeds.
    
- **Shuffle** = glue that automates actions.
    

**Instructions (Docker compose on Ubuntu VM):**

1. Create VM: `SOAR-Server` (4 vCPUs, 8 GB RAM, VLAN 20).
    
2. Install Docker + Docker Compose.
    
3. Use TheHive Project’s docker-compose:
    
    `git clone https://github.com/TheHive-Project/Docker-Templates cd Docker-Templates/thehive docker-compose up -d`
    
4. Access UI:
    
    - TheHive: `http://192.168.20.70:9000`
        
    - Cortex: `http://192.168.20.70:9001`
        
    - MISP: `http://192.168.20.70:9002`
        
5. Deploy Shuffle in container:  
    👉 [https://github.com/Shuffle/Shuffle](https://github.com/Shuffle/Shuffle)
    

**Expected result:** You have a full **SOC automation stack** running.

---

## Step 6: Connect SOAR to SIEM + EDR

**Concept:**

- Incidents flow like this:
    
    1. Wazuh detects suspicious event.
        
    2. Alert sent to TheHive as a case.
        
    3. Cortex runs analyzers (hash → VirusTotal, domain → WHOIS).
        
    4. Shuffle can auto-block in pfSense or cloud SG.
        

**Instructions:**

1. In Wazuh, enable webhook connector → forward alerts to TheHive.
    
2. In TheHive, create rule: “If hash → send to Cortex.”
    
3. In Cortex, add analyzers (VirusTotal, AbuseIPDB).
    
4. In Shuffle, build playbook:
    
    - Trigger: Wazuh alert.
        
    - Action: block IP in pfSense via API.
        

**Expected result:** Your SOC can **auto-enrich and respond** to incidents.

---

## Step 7: Malware Detonation Range

**Concept:**

- You need a safe, isolated network where you can run malware.
    
- Components:
    
    - **REMnux** (Linux for malware analysis).
        
    - **FLARE VM** (Windows with reversing tools).
        
    - **INetSim** (fake internet responses).
        

**Instructions:**

1. In Proxmox → Create VLAN 80 VMs:
    
    - `REMnux` (Ubuntu-based).
        
    - `FLARE-VM` (Windows 10).
        
    - `INetSim` (Debian with `inetsim`).
        
2. On pfSense:
    
    - Block **all outbound WAN** for VLAN 80.
        
    - Allow VLAN 80 → VLAN 80 (internal only).
        
3. Snapshot FLARE VM → run malware samples.
    
4. Capture with Wireshark/Procmon → export IOCs to MISP.
    

**Expected result:** You can run malware safely, analyze behavior, and feed results into your SOC stack.

---

# Phase 5: Advanced Exercises + Automation

---

## Step 1: Design End-to-End Attack → Detect → Respond Exercises

**Concept:**

- Enterprises don’t just see “one event” — attacks are **multi-step kill chains**.
    
- You’ll simulate full scenarios: attacker → exploit → persistence → detection → SOAR response.
    

**Example Exercise (AD attack → SOAR auto-block):**

1. **Red team:** From Kali, use Rubeus to Kerberoast a service account.
    
    `Rubeus kerberoast /user:svc_sql /nowrap`
    
2. **Blue team (SIEM):** Sysmon logs event `4769` (Kerberos TGS request).
    
    - Wazuh rule detects abnormal spike in Kerberos tickets.
        
3. **SOAR (TheHive):** Case created: “Possible Kerberoasting.”
    
4. **Cortex:** Hash submitted to VirusTotal → flagged as malicious.
    
5. **Shuffle:** Playbook auto-blocks attacker IP in pfSense (via API).
    

**Expected result:** Attack is visible in SIEM, enriched in TheHive, and automatically contained by SOAR.

---

## Step 2: Cloud → On-Prem Pivot Scenario

**Concept:**

- Real-world breaches often start in cloud (misconfig) → pivot into internal network.
    
- You’ll simulate a stolen AWS key → attacker pivot via VPN into on-prem.
    

**Instructions:**

1. On AWS, intentionally misconfigure an S3 bucket with public write.
    
2. Place a fake AWS key file inside (`credentials`).
    
3. From Kali:
    
    `aws configure --profile stolen aws s3 ls --profile stolen`
    
4. Use stolen creds to spin up an EC2 in private subnet.
    
5. From EC2 → pivot back to pfSense via WireGuard tunnel.
    

**Expected result:** You simulate an attacker moving from cloud → lab network. Wazuh should see unusual AWS API calls + new WireGuard session.

---

## Step 3: Container Exploitation Exercise

**Concept:**

- Containers + k8s are high-value targets.
    
- You’ll attack a vulnerable app (Juice Shop) in k3s → escape container → persist in cluster.
    

**Instructions:**

1. From Kali, scan exposed NodePort of Juice Shop.
    
2. Exploit vulnerable API → get shell in container.
    
3. From inside container, mount host filesystem (`/var/run/docker.sock`) to escalate.
    
4. Deploy backdoor pod into k3s.
    

**Detection:**

- Falco alerts: `exec in container`, `write to docker socket`.
    
- Wazuh ingests Falco alerts → case in TheHive.
    

**Expected result:** You simulate a container escape → Falco detects → SOC investigates.

---

## Step 4: Malware Analysis Workflow

**Concept:**

- SOC must handle suspicious binaries.
    
- You’ll take a sample → detonate in malware VLAN → extract IOCs → push to MISP.
    

**Instructions:**

1. Place sample on FLARE VM.
    
2. Run Procmon, capture processes/registry changes.
    
3. Run Wireshark on REMnux, capture traffic (C2 IP, domain).
    
4. Use strings/PEStudio/IDA to extract persistence mechanisms.
    
5. Export:
    
    - File hash (SHA256).
        
    - Domain contacted.
        
    - Registry key modified.
        
6. Push to MISP → propagate into Wazuh rules.
    

**Expected result:** Your SOC can identify malware, share IOCs, and detect if it spreads.

---

## Step 5: Digital Forensics Incident Response (DFIR) Scenario

**Concept:**

- After breach → collect memory/disk → analyze.
    
- You’ll use Velociraptor for endpoint triage.
    

**Instructions:**

1. On Win11 client, simulate ransomware (e.g., run WannaCry sample in safe VLAN).
    
2. From Velociraptor server:
    
    `hunt create --artifact Windows.EventLogs.Security hunt create --artifact Windows.System.Detection.Prefetch`
    
3. Collect memory dump → analyze with Volatility:
    
    `volatility -f dump.mem --profile=Win10x64 pslist`
    
4. Correlate timeline with Wazuh + Zeek.
    

**Expected result:** You can do full DFIR: detect → isolate → analyze → recover.

---

## Step 6: IaC Automation (Terraform, Ansible, Packer)

**Concept:**

- Manually building is good for learning. But in real life, infra is defined in code → reproducible, version-controlled.
    
- You’ll use:
    
    - **Packer**: build golden VM images (with Sysmon, Wazuh agent preinstalled).
        
    - **Terraform**: provision Proxmox VMs + cloud infra.
        
    - **Ansible**: configure apps (Wazuh, Zeek, AD, etc.).
        

**Instructions:**

**Packer template (Ubuntu VM for Proxmox):**

`{   "builders": [{     "type": "proxmox",     "proxmox_url": "https://192.168.10.2:8006/api2/json",     "username": "root@pam",     "password": "yourpassword",     "node": "pve",     "storage": "local-lvm",     "vm_id": 9000,     "iso": "local:iso/ubuntu-22.04.iso",     "cores": 2,     "memory": 4096,     "disk_size": 40   }] }`

**Terraform (Proxmox VM):**

`provider "proxmox" {   pm_api_url = "https://192.168.10.2:8006/api2/json"   pm_user    = "root@pam"   pm_password= "yourpassword" }  resource "proxmox_vm_qemu" "win11_client" {   name   = "Win11-Client2"   target_node = "pve"   clone  = "win11-template"   cores  = 2   memory = 4096   network {     bridge = "vmbr0"     tag    = 30   } }`

**Ansible playbook (install Wazuh agent):**

`- hosts: windows_clients   tasks:     - name: Install Wazuh agent       win_package:         path: https://packages.wazuh.com/4.x/windows/wazuh-agent.msi         product_id: '{GUID}'         arguments: /q ADDRESS=192.168.20.50`

**Expected result:** You can rebuild **the whole lab from scratch in hours** with scripts, instead of days clicking through UIs.

---

# ✅ Phase 5 Outcome

At this point, you can:

- Run **multi-step attack simulations** (AD, cloud, container, malware).
    
- Detect them with SIEM/IDS/EDR.
    
- Automate response with SOAR (block IPs, enrich IOCs).
    
- Perform **malware analysis + DFIR**.
    
- Use IaC (Terraform, Ansible, Packer) to tear down and rebuild environments at will.
    

You now have what most professionals never get at home: a **self-contained cyber range** that covers:

- Blue Team (SOC, SIEM, EDR, SOAR, DFIR).
    
- Red Team (AD, C2, exploits, cloud pivots, k8s).
    
- DevSecOps (pipelines, scanning, runtime alerts).
    
- Malware Analysis (safe detonation).
    
- Cloud Security (AWS/Azure/GCP).
    

You’ve essentially built a **mini Fortune 500 security lab** at home.