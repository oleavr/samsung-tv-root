#!/bin/bash
# TV-side backup sender for the Samsung TV root session.
#
# Streams tar/dd output from the TV back to the host over a bash /dev/tcp
# socket.  Every part is a separate connection, prefixed by a header line
# "PART <name>", so the host can store each part independently and restart
# after a transport failure without redoing the whole backup.
#
# Usage: tv_backup.sh <host-ip> <port>
#
# Notes:
#  * The archive-root session runs in a private mount namespace where
#    /etc/passwd and /usr/share/sdbd/public.pem are replaced by substitutes.
#    The genuine files are read through /proc/1/root (init's namespace).
#  * Per-part SHA-256 is computed on the TV and written to
#    /tmp/tvbackup.parts/<name>.sha256 for later comparison.

HOST="$1"
PORT="$2"
LOG=/tmp/tvbackup.log
PARTS=/tmp/tvbackup.parts

mkdir -p "$PARTS"
exec >>"$LOG" 2>&1

echo "=== tv_backup start $(date '+%F %T') host=$HOST port=$PORT ==="

send() {
    local name="$1"; shift
    if [ -f /tmp/tvbackup.skip ] && grep -qx "$name" /tmp/tvbackup.skip; then
        echo "--- part $name skipped"
        return 0
    fi
    echo "--- part $name begin $(date '+%T')"
    if ! exec 3<>"/dev/tcp/$HOST/$PORT"; then
        echo "--- part $name FAILED: cannot connect to $HOST:$PORT"
        return 1
    fi
    printf 'PART %s\n' "$name" >&3

    local fifo="/tmp/tvbackup.fifo.$$"
    rm -f "$fifo"
    mkfifo "$fifo" || { echo "--- part $name FAILED: mkfifo"; exec 3>&-; return 1; }
    sha256sum <"$fifo" >"$PARTS/$name.sha256" 2>/dev/null &
    local hasher=$!

    # The command's stderr is captured separately so that tar diagnostics do
    # not corrupt the stream on fd 3.
    "$@" 2>"$PARTS/$name.err" | tee "$fifo" >&3
    local status=${PIPESTATUS[0]}

    wait "$hasher" 2>/dev/null
    exec 3>&-
    rm -f "$fifo"
    echo "--- part $name end status=$status $(date '+%T') sha=$(cut -d' ' -f1 "$PARTS/$name.sha256" 2>/dev/null)"
    return $status
}

# Raw eMMC: the complete storage device, every partition, byte for byte.
send emmc-raw dd if=/dev/mmcblk0 bs=4M

# The root filesystem (/), minus virtual mounts, minus the two files the
# archive-root namespace substitutes (captured separately from init's view).
send root-fs tar -C / --ignore-failed-read \
    --exclude=./proc --exclude=./sys --exclude=./dev --exclude=./tmp \
    --exclude=./run --exclude=./opt --exclude=./prd --exclude=./factory_peq \
    --exclude=./mnt --exclude=./etc/passwd \
    --exclude=./usr/share/sdbd/public.pem -cf - .

# /opt: 325 app packages, shared libraries and the owner content area.
send opt-fs tar -C /opt --ignore-failed-read -cf - .

# Smaller read-only and read-write partitions.
send prd-fs tar -C /prd --ignore-failed-read -cf - .
send factory-peq tar -C /factory_peq --ignore-failed-read -cf - .
send systemrw-fs tar -C /mnt/systemrw --ignore-failed-read -cf - .
send drm-fs tar -C /mnt/drm --ignore-failed-read -cf - .

# Genuine copies of the files the root session shadows.
send real-etc tar -C /proc/1/root --ignore-failed-read -cf - \
    etc/passwd etc/shadow etc/secure usr/share/sdbd/public.pem

# Signal completion to the host.
if exec 3<>"/dev/tcp/$HOST/$PORT"; then
    printf 'END\n' >&3
    exec 3>&-
fi
echo "=== tv_backup done $(date '+%F %T') ==="
