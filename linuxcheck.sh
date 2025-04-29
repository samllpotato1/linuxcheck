#!/bin/bash
# Comprehensive Linux security audit script.
# This script performs multiple checks for system integrity and security issues,
# outputs detailed logs with timestamps, and can optionally upload results remotely.

# Configuration: remote server details for log upload (via scp or curl)
REMOTE_USER="user"
REMOTE_HOST="host"
REMOTE_PATH="/path/"

# Directory and log file
LOGDIR="/tmp"
TIMESTAMP=$(date +'%Y%m%d_%H%M%S')
LOGFILE="$LOGDIR/security_audit_$TIMESTAMP.log"
mkdir -p "$LOGDIR"
echo "[INFO] Starting security audit at $(date '+%Y-%m-%d %H:%M:%S')" > "$LOGFILE"

# Logging function
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOGFILE"
}

# 1. Check common binaries for tampering (Debian/Ubuntu: debsums; RHEL/CentOS: rpm -Va) :contentReference[oaicite:0]{index=0}&#8203;:contentReference[oaicite:1]{index=1}
log "=== Checking common binaries for tampering ==="
if [ -f /etc/debian_version ]; then
    if command -v debsums >/dev/null 2>&1; then
        log "Running debsums on installed packages..."
        # List only files that changed or are missing
        debsums -ca 2>&1 | while read -r line; do
            log "[!] DEBSUMS: $line"
        done
    else
        log "debsums not installed; consider installing debsums for MD5 checks."
        # Alternative: use dpkg verify
        if command -v dpkg >/dev/null 2>&1; then
            log "Running dpkg --verify for package integrity..."
            dpkg -V 2>&1 | awk '/^\S+\s+.*\s+.*[\.\S]*5/ {print "[!] DPkg verify:", $0}' | while read -r line; do
                log "$line"
            done
        else
            log "dpkg not available."
        fi
    fi
elif [ -f /etc/redhat-release ]; then
    if command -v rpm >/dev/null 2>&1; then
        log "Running rpm -Va to verify all installed packages..."
        # Filter for changed checksum (M)
        rpm -Va 2>/dev/null | awk '/^[SM5]/ && (/\\/bin\\// || /\\/usr\\/bin\\//) {print "[!] RPM verify:", $0}' | while read -r line; do
            log "$line"
        done
    else
        log "rpm command not found."
    fi
else
    log "Unknown OS or package manager; skipping binary integrity checks."
fi

# 2. Check environment variables for LD_PRELOAD and /etc/ld.so.preload (potential library injection) :contentReference[oaicite:2]{index=2}
log "=== Checking for LD_PRELOAD injections ==="
if [ -f /etc/ld.so.preload ]; then
    log "[!] /etc/ld.so.preload exists; contents:"
    sed 's/^/[Preload] /' /etc/ld.so.preload | while read -r line; do log "$line"; done
else
    log "/etc/ld.so.preload not found."
fi
if [[ -n "$LD_PRELOAD" ]]; then
    log "[!] LD_PRELOAD is set: $LD_PRELOAD"
else
    log "LD_PRELOAD not set in current environment."
fi
if [[ -n "$LD_LIBRARY_PATH" ]]; then
    log "[!] LD_LIBRARY_PATH is set: $LD_LIBRARY_PATH"
fi
# Also check for any exported LD_PRELOAD in /etc/profile or /etc/environment
grep -R "LD_PRELOAD" /etc/profile /etc/environment /etc/bash.bashrc /etc/profile.d 2>/dev/null | while read -r line; do
    log "[!] Found LD_PRELOAD in config: $line"
done

# 3. Detect hidden processes and suspicious kernel modules :contentReference[oaicite:3]{index=3}
log "=== Detecting hidden processes ==="
# Compare /proc PIDs with `ps` output
proc_pids=$(ls /proc | grep -E '^[0-9]+' | sort -n)
ps_pids=$(ps -e -o pid= | sort -n)
# PIDs in /proc not in ps
for pid in $proc_pids; do
    if ! grep -q "^$pid$" <<< "$ps_pids"; then
        log "[!] PID $pid found in /proc but not listed by ps"
    fi
done
# PIDs in ps not in /proc
for pid in $ps_pids; do
    if ! grep -q "^$pid$" <<< "$proc_pids"; then
        log "[!] PID $pid listed by ps but no /proc entry"
    fi
done

log "Checking for PIDs listening on ports but not in process list..."
if command -v netstat >/dev/null 2>&1; then
    netstat -tulnp 2>/dev/null | awk '/LISTEN/ {split($7,a,"/"); pid=a[1]; if(pid!="" && pid != "0") print pid}' | sort -u | while read -r pid; do
        if ! ps -p "$pid" > /dev/null 2>&1; then
            log "[!] Listening PID $pid in netstat but not found in ps"
        fi
    done
elif command -v ss >/dev/null 2>&1; then
    ss -tunlp 2>/dev/null | grep -E 'LISTEN' | awk -F "pid=" '{print $2}' | cut -d, -f1 | sort -u | while read -r pid; do
        if ! ps -p "$pid" > /dev/null 2>&1; then
            log "[!] Listening PID $pid in ss but not found in ps"
        fi
    done
fi

log "=== Checking loaded kernel modules (lsmod) ==="
if command -v lsmod >/dev/null 2>&1; then
    lsmod | awk 'NR>1 {print $1}' | while read -r mod; do
        log "Module: $mod"
    done
else
    log "lsmod not available."
fi
log "Checking module info for suspicious modules..."
if command -v modinfo >/dev/null 2>&1; then
    for mod in $(lsmod | awk 'NR>1 {print $1}'); do
        mod_path=$(modinfo -n "$mod" 2>/dev/null)
        if [ -z "$mod_path" ]; then
            log "[!] No modinfo for $mod (possible built-in or hidden module)"
        elif [[ "$mod_path" != /lib/modules/$(uname -r)* ]]; then
            log "[!] Module $mod loaded from unexpected path: $mod_path"
        fi
    done
fi
log "Review last dmesg lines for suspicious messages..."
dmesg | tail -n 20 | while read -r line; do log "dmesg: $line"; done

# 4. Open ports and external IP GeoIP lookup :contentReference[oaicite:4]{index=4}
log "=== Checking open ports and external connections ==="
if command -v ss >/dev/null 2>&1; then
    ss -tunlp 2>/dev/null | tee -a "$LOGFILE"
elif command -v netstat >/dev/null 2>&1; then
    netstat -tunlp 2>/dev/null | tee -a "$LOGFILE"
fi

log "Checking external connections and GeoIP information..."
# List established connections (IPv4) excluding common private addresses
connections=$(ss -tn state established 2>/dev/null | awk 'NR>1 {split($5,a,":"); ip=a[1]; print ip}' | grep -E -v '^(127\\.|10\\.|192\\.168\\.|172\\.(1[6-9]|2[0-9]|3[0-1])\\.|169\\.254\\.)' | sort -u)
if [ -z "$connections" ]; then
    log "No external connections detected."
else
    for ip in $connections; do
        if command -v curl >/dev/null 2>&1; then
            country=$(curl -s ipinfo.io/$ip/country)
            city=$(curl -s ipinfo.io/$ip/city)
            log "External IP: $ip, Location: ${city:-Unknown}, ${country:-Unknown}"
        else
            log "curl not found: cannot lookup IP $ip location"
        fi
    done
fi

# 5. Run chkrootkit and rkhunter for rootkit scanning :contentReference[oaicite:5]{index=5}
log "=== Running chkrootkit scan ==="
if command -v chkrootkit >/dev/null 2>&1; then
    chkrootkit -q 2>&1 | tee -a "$LOGFILE"
    if grep -q "INFECTED" "$LOGFILE"; then
        log "[!] chkrootkit reports potential infections"
    fi
else
    log "chkrootkit not installed; skipping."
fi

log "=== Running rkhunter scan ==="
if command -v rkhunter >/dev/null 2>&1; then
    rkhunter --check --sk --nocolors 2>&1 | tee -a "$LOGFILE"
    if grep -q "Warning:" "$LOGFILE"; then
        log "[!] rkhunter reports warnings"
    fi
else
    log "rkhunter not installed; skipping."
fi

# 6. Analyze SSH login attempts from logs (/var/log/auth.log or /var/log/secure) :contentReference[oaicite:6]{index=6}&#8203;:contentReference[oaicite:7]{index=7}
log "=== Analyzing SSH login logs ==="
if [ -f /var/log/auth.log ]; then
    sshlog="/var/log/auth.log"
elif [ -f /var/log/secure ]; then
    sshlog="/var/log/secure"
else
    sshlog=""
    log "SSH log file not found (no /var/log/auth.log or /var/log/secure)."
fi
if [ -n "$sshlog" ]; then
    log "Parsing SSH authentication log: $sshlog"
    log "Failed SSH login attempts by IP:"
    grep "Failed password" "$sshlog" | grep -oE '([0-9]{1,3}\\.){3}[0-9]{1,3}' | sort | uniq -c | sort -nr | while read -r count ip; do
        log "  $ip ($count attempts)"
    done
    log "Invalid user login attempts by IP:"
    grep "Invalid user" "$sshlog" | grep -oE '([0-9]{1,3}\\.){3}[0-9]{1,3}' | sort | uniq -c | sort -nr | while read -r count ip; do
        log "  $ip ($count attempts)"
    done
    log "Successful SSH logins by IP:"
    grep "Accepted password" "$sshlog" | grep -oE '([0-9]{1,3}\\.){3}[0-9]{1,3}' | sort | uniq -c | sort -nr | while read -r count ip; do
        log "  $ip ($count logins)"
    done
fi

# 7. Package logs and upload if configured
log "=== Packaging logs for upload ==="
archive_name="security_audit_${TIMESTAMP}.tar.gz"
tar czf "$LOGDIR/$archive_name" -C "$LOGDIR" "$(basename "$LOGFILE")" 2>/dev/null
if [ -n "$REMOTE_HOST" ] && [ "$REMOTE_HOST" != "host" ]; then
    if command -v scp >/dev/null 2>&1; then
        log "Uploading log archive to $REMOTE_USER@$REMOTE_HOST:$REMOTE_PATH"
        scp "$LOGDIR/$archive_name" "$REMOTE_USER@$REMOTE_HOST:$REMOTE_PATH"
        if [ $? -eq 0 ]; then
            log "Logs uploaded successfully."
        else
            log "[!] Failed to upload logs."
        fi
    else
        log "scp not available; skipping upload."
    fi
elif [ -n "$REMOTE_HOST" ] && [ "$REMOTE_HOST" != "host" ]; then
    log "[!] Remote upload details not configured; set REMOTE_HOST."
else
    log "Remote upload disabled or not configured."
fi

log "Security audit completed."
