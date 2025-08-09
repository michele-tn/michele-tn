#!/bin/bash
#
# DNS Speed Test (ASCII-safe, colonne allineate, fix seconda tabella)
#

DNS_SERVERS=(
"1.1.1.1|Cloudflare"
"8.8.8.8|Google"
"8.8.4.4|Google-Backup"
"9.9.9.9|Quad9"
"208.67.222.222|OpenDNS"
"208.67.220.220|OpenDNS-Backup"
"94.140.14.14|AdGuard"
"94.140.15.15|AdGuard-Backup"
"76.76.2.0|ControlD"
"76.76.10.0|ControlD-Backup"
)

DOMAIN="${1:-example.com}"
TMPFILE=$(mktemp)
trap 'rm -f "$TMPFILE"' EXIT

strlen() { printf "%s" "$1" | wc -c; }

name_w=4
ip_w=2
time_w=4

for e in "${DNS_SERVERS[@]}"; do
    IP="${e%%|*}"
    NAME="${e#*|}"

    DIG_OUT=$(dig @"$IP" "$DOMAIN" +time=2 +tries=1 +stats 2>/dev/null)
    TIME_NUM=$(printf "%s" "$DIG_OUT" | awk -F': ' '/Query time/ {print $2; exit}' | awk '{print $1}')

    if [ -n "$TIME_NUM" ]; then
        SORT_KEY="$TIME_NUM"
        TIME_LABEL="${TIME_NUM}ms"
    else
        SORT_KEY=9999
        TIME_LABEL="NO RESP"
    fi

    [ "$(strlen "$NAME")" -gt "$name_w" ] && name_w=$(strlen "$NAME")
    [ "$(strlen "$IP")" -gt "$ip_w" ] && ip_w=$(strlen "$IP")
    [ "$(strlen "$TIME_LABEL")" -gt "$time_w" ] && time_w=$(strlen "$TIME_LABEL")

    printf "%s|%s|%s|%s\n" "$SORT_KEY" "$NAME" "$IP" "$TIME_LABEL" >> "$TMPFILE"
done

border="+-$(printf '%*s' "$name_w" '' | tr ' ' '-')-+-$(printf '%*s' "$ip_w" '' | tr ' ' '-')-+-$(printf '%*s' "$time_w" '' | tr ' ' '-')-+"

# Tabella originale
echo "$border"
printf "| %-*s | %-*s | %-*s |\n" "$name_w" "Name" "$ip_w" "IP" "$time_w" "Time"
echo "$border"
while IFS='|' read -r key name ip time_label; do
    printf "| %-*s | %-*s | %*s |\n" "$name_w" "$name" "$ip_w" "$ip" "$time_w" "$time_label"
done < "$TMPFILE"
echo "$border"

# Tabella ordinata
echo
echo "Sorted (dal piu' veloce al piu' lento):"
echo "$border"
printf "| %-*s | %-*s | %-*s |\n" "$name_w" "Name" "$ip_w" "IP" "$time_w" "Time"
echo "$border"

# Legge il file ordinato
sort -t'|' -k1,1n "$TMPFILE" > "${TMPFILE}.sorted"
while IFS='|' read -r key name ip time_label; do
    printf "| %-*s | %-*s | %*s |\n" "$name_w" "$name" "$ip_w" "$ip" "$time_w" "$time_label"
done < "${TMPFILE}.sorted"

echo "$border"
