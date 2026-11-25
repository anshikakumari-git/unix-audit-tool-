#!/bin/bash

LOG_FILE="/var/log/auth.log"
OUTPUT_FILE="log_results.txt"

> "$OUTPUT_FILE"

echo "================================"
echo "   AUTHENTICATION LOG ANALYZER"
echo "================================"

if [ ! -f "$LOG_FILE" ]; then
    echo "Authentication log not found."
    exit 1
fi

echo "Analyzing authentication logs..."

grep -i "Failed password" "$LOG_FILE" |
awk '{for(i=1;i<=NF;i++) if($i=="from") print $(i+1)}' |
sort | uniq -c |
while read count ip
do
    if [ "$count" -ge 5 ]; then
        echo "REPEATED_FAILED_IP|Repeated failed login attempts|IP $ip had $count failed attempts|Investigate the IP" >> "$OUTPUT_FILE"
    fi
done

grep -i "Failed password" "$LOG_FILE" |
awk '{for(i=1;i<=NF;i++) if($i=="for") print $(i+1)}' |
sort | uniq -c |
while read count username
do
    if [ "$count" -ge 5 ]; then
        echo "REPEATED_FAILED_USER|Repeated failed login attempts for user|User $username had $count failed attempts|Review the account" >> "$OUTPUT_FILE"
    fi
done

sudo_failures=$(grep -i "sudo" "$LOG_FILE" | grep -iE "authentication failure|auth could not identify password" | wc -l)

if [ "$sudo_failures" -gt 0 ]; then
    echo "SUDO_FAILURES|Sudo authentication failures|Found $sudo_failures failures|Review sudo access" >> "$OUTPUT_FILE"
fi

successful_logins=$(grep -c "session opened for user" "$LOG_FILE")

echo "SUCCESSFUL_SESSIONS|Successful login sessions|Found $successful_logins session openings|Review login activity" >> "$OUTPUT_FILE"

echo "Analysis completed."
echo "Results saved in $OUTPUT_FILE"
echo "Total successful sessions: $successful_logins"

# 1. Detect repeated failed login attempts from the same IP
grep -i "Failed password" "$LOG_FILE" |
awk '{for(i=1;i<=NF;i++) if($i=="from") print $(i+1)}' |
sort | uniq -c |
while read count ip
do
    if [ "$count" -ge 5 ]; then
        echo "REPEATED_FAILED_IP|Repeated failed login attempts|IP $ip had $count failed attempts|Investigate the IP and review access controls" >> "$OUTPUT_FILE"
    fi
done

# 2. Detect repeated failed login attempts for the same username
grep -i "Failed password" "$LOG_FILE" |
awk '{for(i=1;i<=NF;i++) if($i=="for") print $(i+1)}' |
sort | uniq -c |
while read count username
do
    if [ "$count" -ge 5 ]; then
        echo "REPEATED_FAILED_USER|Repeated failed login attempts for user|User $username had $count failed attempts|Review the account and check for suspicious activity" >> "$OUTPUT_FILE"
    fi
done

# 3. Detect sudo authentication failures
sudo_failures=$(grep -i "authentication failure" "$LOG_FILE" | grep -i "sudo" | wc -l)

if [ "$sudo_failures" -gt 0 ]; then
    echo "SUDO_FAILURES|Sudo authentication failures|Found $sudo_failures sudo authentication failures|Review sudo access and authentication records" >> "$OUTPUT_FILE"
fi

echo "Analysis completed."
echo "Results saved in $OUTPUT_FILE"
