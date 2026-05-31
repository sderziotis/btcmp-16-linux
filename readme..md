# BTCMP-16 — DF-4.2 Disk Image Acquisition (Linux)

| Field | Value |
|---|---|
| Learning Node Title | Disk Image Acquisition - Linux - Lab |
| Learning Node Code | DF-4.2 |
| Type | Cyber Range (CR) |
| Difficulty | Easy |
| Duration | 25 minutes |
| MITRE ATT&CK | T1005 – Data from Local System |

---


## Roles

- Defender / Blue Team Member
- Forensic Analyst

---

## Topology

### Network Layout

| Name | CIDR | Notes |
|---|---|---|
| network-2 (LAN) | 192.168.0.0/24 | Accessible by user |
| network-1 (WAN) | 10.10.10.0/24 | Management |

### Virtual Machines

#### uavm — Analyst Workstation

| Field | Value |
|---|---|
| OS | Xubuntu Noble (x86_64) |
| IP | 192.168.0.10 |
| Flavor | c2_r4_d40 |
| Username | user |
| Password | Password123 |
| Visible | Yes |
| Tools | dc3dd, Docker, Jupyter Notebook (port 8888), ViperMonkey |

#### targetvm — Evidence Target

| Field | Value |
|---|---|
| OS | Ubuntu Noble (x86_64) |
| IP | 192.168.0.20 |
| Flavor | standard.small |
| Username | user |
| Password | btcmp16@admin |
| Visible | No (hidden) |
| Volumes | vda — OS disk (8GB), vdb — evidence disk (2GB) |
| Evidence Disk | `/dev/vdb` (static, read-only, pre-built image) |
| Tools | dc3dd, netcat-openbsd, openssh-server |

> **Note:** `targetvm` is hidden from the trainee in the KYPO portal. The trainee must connect to it via SSH from `uavm` over the LAN.

### Router

| Field | Value |
|---|---|
| IP | 192.168.0.1 |
| Network | network-2 |

---


### Evidence Disk

The evidence disk `/dev/vdb` on `targetvm` is:
- **Static** — content is fixed and never changes between deployments
- **Read-only** — mounted with `ro` flag, the OS cannot write to it
- **Pre-built** — written from a known binary image (`target_disk.img`) during provisioning
- **Consistent** — the SHA256 hash of the acquired image is always the same across all trainee attempts

---


### Provisioning Details

**uavm** pre-installed tools:
- `dc3dd` — forensic imaging
- `netcat-openbsd` — network streaming
- `docker`, `docker-compose` — container runtime
- Jupyter Notebook — running via Docker on port `8888` (token: `forensics`)
- `ViperMonkey` — macro analysis tool

**targetvm** pre-installed tools:
- `dc3dd` — disk streaming
- `netcat-openbsd` — listener on port `9999`
- `openssh-server` — persistent SSH service (password auth enabled)

### Evidence Disk Provisioning

The evidence disk is provisioned by the Ansible playbook as follows:
1. `target_disk.img` is downloaded from GitHub releases
2. Written byte-for-byte to `/dev/vdb` using `dd`
3. Mounted read-only at `/mnt/target_disc` using the label `target disc`

---

## Files Reference

| File | Location | Description |
|---|---|---|
| Evidence image | `/home/user/case-001/evidence.img` | Acquired disk image on uavm |
| Acquisition log | `/home/user/case-001/acquisition.log` | dc3dd log with SHA256 hash |
| Evidence disk | `/dev/vdb` on targetvm | Static read-only source disk |
| Mount point | `/mnt/target_disc` on targetvm | Read-only mount of evidence disk |
