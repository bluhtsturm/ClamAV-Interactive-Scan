#!/usr/bin/env bash
#
# antivirus-en.sh — interactive ClamAV scanner with a live progress bar
#
# Scans the running system, an external drive or any directory. Either with
# clamscan (standalone process, loads the signature database itself) or via
# clamd/clamdscan (daemon, much faster, can be parallelised). The progress
# bar is fed live from ClamAV's own output.
#
# License: MIT
#

# No "set -e": clamscan returns exit code 1 on a detection and 2 on errors —
# neither of these is a script failure.
set -uo pipefail

VERSION="1.1.0"

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Size of the chunks used by the parallel clamdscan path (files per chunk).
# Smaller = finer-grained progress and faster stall detection, but more
# process starts. 1000–5000 is a sensible range.
CHUNK_SIZE=2000

# STALL_TIMEOUT is the real safety net: seconds WITHOUT a single new result
# line after which a chunk is considered stuck. What is measured is progress,
# not total runtime — a slow machine (weak CPU, few threads, huge media
# files) may take as long as it likes as long as it keeps moving at all.
# Only genuine standstill is aborted.
STALL_TIMEOUT=900

# Absolute upper bound per chunk as a last resort in case stall detection
# fails. Deliberately very high — it should never trigger in normal use.
BATCH_TIMEOUT=28800

# Extra paths that should always be skipped. Useful for Wine/Proton/Steam
# trees with hundreds of thousands of tiny files, or for network mounts.
# Example:
#   EXCLUDE_PATHS=( /opt/wine-staging "$HOME/.wine" "$HOME/.steam" )
EXCLUDE_PATHS=()

# Pseudo filesystems that must never be scanned.
PSEUDO_PATHS=( /proc /sys /dev /run /snap )

# ---------------------------------------------------------------------------
# Prerequisites
# ---------------------------------------------------------------------------

# Required: associative arrays (4.0), "wait -n" (4.3) and "mapfile -d" (4.4).
if [ -z "${BASH_VERSINFO:-}" ] ||
   [ "${BASH_VERSINFO[0]}" -lt 4 ] ||
   { [ "${BASH_VERSINFO[0]}" -eq 4 ] && [ "${BASH_VERSINFO[1]}" -lt 4 ]; }; then
    echo "This script requires Bash 4.4 or newer." >&2
    exit 1
fi

APP_USER=${SUDO_USER:-${USER:-$(id -un)}}
HOME_DIR=$(getent passwd "$APP_USER" | cut -d: -f6)
[ -n "$HOME_DIR" ] && [ -d "$HOME_DIR" ] || HOME_DIR="/tmp"

# Colours only when stdout really is a terminal.
# $'...' (ANSI-C quoting) puts the actual escape bytes into the variable —
# that way both echo and printf work without -e.
if [ -t 1 ]; then
    GREEN=$'\033[0;32m'; GRAY=$'\033[0;37m'; YELLOW=$'\033[1;33m'
    RED=$'\033[0;31m';   BOLD=$'\033[1m';    RESET=$'\033[0m'
    CLREOL=$'\033[K';    HIDE=$'\033[?25l';  SHOW=$'\033[?25h'
else
    GREEN=""; GRAY=""; YELLOW=""; RED=""; BOLD=""; RESET=""
    CLREOL=""; HIDE=""; SHOW=""
fi

FRESHCLAM_WAS_RUNNING=false
QUARANTINE_DIR=""
RESULTS_FILE=""
FILE_LIST=""
CHUNK_DIR=""
RUN_PID=""
CLEANED=false
CROSS_DEVICE=false
THREADS=1

check_command() { command -v "$1" >/dev/null 2>&1; }

# Runs a command with root privileges — directly if we already are root,
# otherwise through sudo. This keeps the script usable on systems without
# sudo installed.
as_root() {
    if [ "$EUID" -eq 0 ]; then
        "$@"
    elif check_command sudo; then
        sudo "$@"
    else
        echo "${YELLOW}Root privileges required, but sudo is missing:${RESET} $*" >&2
        return 1
    fi
}

# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------

# Terminates the whole worker hierarchy in the right order:
#   1. the dispatcher and its worker subshells, so no further chunk starts,
#   2. the actual scanners (timeout -> script -> clamdscan) via the recorded
#      PID files; without this step the scanner outlives the signal sent to
#      its parent,
#   3. a short grace period so the processes are gone before their working
#      directory is removed.
kill_workers() {
    local pidfile pid i

    if [ -n "$RUN_PID" ] && kill -0 "$RUN_PID" 2>/dev/null; then
        check_command pkill && pkill -TERM -P "$RUN_PID" 2>/dev/null
        kill -TERM "$RUN_PID" 2>/dev/null
    fi

    if [ -n "$CHUNK_DIR" ] && [ -d "$CHUNK_DIR" ]; then
        for pidfile in "$CHUNK_DIR"/part_*.pid; do
            [ -f "$pidfile" ] || continue
            pid=$(cat "$pidfile" 2>/dev/null) || continue
            [ -n "$pid" ] || continue
            check_command pkill && pkill -TERM -P "$pid" 2>/dev/null
            kill -TERM "$pid" 2>/dev/null
        done
    fi

    if [ -n "$RUN_PID" ]; then
        for (( i = 0; i < 20; i++ )); do
            kill -0 "$RUN_PID" 2>/dev/null || break
            sleep 0.1
        done
        kill -KILL "$RUN_PID" 2>/dev/null
    fi
    return 0
}

cleanup() {
    # The EXIT trap also fires after a signal trap — without this guard the
    # cleanup would run twice.
    [ "$CLEANED" = true ] && return 0
    CLEANED=true

    printf '%s' "$SHOW"          # make the cursor visible again
    kill_workers

    # restart the freshclam service if we stopped it
    if [ "$FRESHCLAM_WAS_RUNNING" = true ]; then
        as_root systemctl start clamav-freshclam >/dev/null 2>&1
    fi

    [ -n "$FILE_LIST" ] && rm -f "$FILE_LIST"
    [ -n "$CHUNK_DIR" ] && rm -rf "$CHUNK_DIR"

    # hand the log file over to the real user, not to root
    if [ "$EUID" -eq 0 ] && [ -n "$RESULTS_FILE" ] && [ -f "$RESULTS_FILE" ]; then
        chown "$APP_USER:" "$RESULTS_FILE" 2>/dev/null
    fi
    return 0
}

trap 'cleanup' EXIT
trap 'printf "\n%sAborted by user.%s\n" "$YELLOW" "$RESET"; exit 130' INT
trap 'exit 143' TERM

# ---------------------------------------------------------------------------
# Input helpers (handle EOF properly instead of spinning forever)
# ---------------------------------------------------------------------------

# ask_yes_no "question" [y|n]  -> return code 0 = yes, 1 = no/EOF
ask_yes_no() {
    local prompt=$1 default=${2:-n} reply
    if [ "$default" = "y" ]; then
        printf '%s [Y/n]: ' "$prompt"
    else
        printf '%s [y/N]: ' "$prompt"
    fi
    read -r reply || { echo; return 1; }
    reply=${reply:-$default}
    [[ "$reply" =~ ^([Yy]|[Yy][Ee][Ss])$ ]]
}

# ask_line "question"  -> answer on stdout (empty on EOF)
ask_line() {
    local prompt=$1 reply
    printf '%s' "$prompt" >&2
    read -r reply || reply=""
    printf '%s' "$reply"
}

# seconds -> HH:MM:SS or MM:SS
fmt_duration() {
    local s=$1
    if [ "$s" -ge 3600 ]; then
        printf '%d:%02d:%02d' $(( s / 3600 )) $(( (s % 3600) / 60 )) $(( s % 60 ))
    else
        printf '%02d:%02d' $(( s / 60 )) $(( s % 60 ))
    fi
}

# ---------------------------------------------------------------------------
# Distribution detection (also evaluates ID_LIKE)
# ---------------------------------------------------------------------------

detect_family() {
    local id="" like=""
    if [ -f /etc/os-release ]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        id="${ID:-}"; like="${ID_LIKE:-}"
    fi
    case " $id $like " in
        *" debian "*|*" ubuntu "*)            echo "debian" ;;
        *" fedora "*|*" rhel "*|*" centos "*) echo "fedora" ;;
        *" arch "*)                           echo "arch"   ;;
        *" suse "*|*" opensuse "*)            echo "suse"   ;;
        *)                                    echo "unknown" ;;
    esac
}

install_clamav() {
    case "$(detect_family)" in
        debian) as_root apt update && as_root apt install -y clamav clamav-daemon ;;
        fedora) as_root dnf install -y clamav clamav-update clamd ;;
        arch)   as_root pacman -S --needed --noconfirm clamav ;;
        suse)   as_root zypper install -y clamav ;;
        *)
            echo "Unknown distribution. Please install ClamAV manually."
            exit 1
            ;;
    esac
}

if ! check_command clamscan && ! check_command clamdscan; then
    echo "ClamAV was not found."
    if ask_yes_no "Install it now?" y; then
        install_clamav
    else
        echo "Cannot continue without ClamAV. Aborting."
        exit 1
    fi
fi

# ---------------------------------------------------------------------------
# Update signatures
# ---------------------------------------------------------------------------

update_signatures() {
    echo
    ask_yes_no "Update virus signatures?" y || return 0

    # freshclam cannot run while the service holds a lock on the log file.
    if systemctl is-active --quiet clamav-freshclam 2>/dev/null; then
        echo "Stopping clamav-freshclam for the duration of the update ..."
        as_root systemctl stop clamav-freshclam && FRESHCLAM_WAS_RUNNING=true
    fi

    echo "Updating signatures ..."
    if ! as_root freshclam; then
        echo "${YELLOW}Warning:${RESET} update failed — scanning with the existing signatures."
    fi

    if [ "$FRESHCLAM_WAS_RUNNING" = true ]; then
        as_root systemctl start clamav-freshclam >/dev/null 2>&1
        FRESHCLAM_WAS_RUNNING=false
    fi
}

# ---------------------------------------------------------------------------
# Start clamd on demand
# ---------------------------------------------------------------------------

start_clamd_if_needed() {
    if systemctl is-active --quiet clamav-daemon 2>/dev/null ||
       systemctl is-active --quiet clamd@scan    2>/dev/null ||
       systemctl is-active --quiet clamd         2>/dev/null; then
        return 0
    fi

    echo "Starting clamd ..."
    case "$(detect_family)" in
        debian) as_root systemctl start clamav-daemon ;;
        fedora) as_root systemctl start clamd@scan ;;
        *)      as_root systemctl start clamd ;;
    esac

    # after starting, clamd needs up to ~60 s to load the database
    local i
    for (( i = 0; i < 60; i++ )); do
        clamdscan --ping 1 >/dev/null 2>&1 && return 0
        sleep 1
    done
    echo "${YELLOW}clamd is not responding.${RESET}"
    return 1
}

# ---------------------------------------------------------------------------
# Menus
# ---------------------------------------------------------------------------

show_main_menu() {
    echo
    echo "===================================="
    echo "   ${BOLD}ClamAV — interactive scan${RESET} v$VERSION"
    echo "===================================="
    echo "1) Scan the internal system (/)"
    echo "2) Scan an external drive"
    echo "3) Scan an arbitrary directory"
    echo "4) Quit"
    printf 'Choice: '
}

select_external_drive() {
    local media_path="/media/$APP_USER"
    [ -d "/run/media/$APP_USER" ] && media_path="/run/media/$APP_USER"

    if [ ! -d "$media_path" ]; then
        echo "No mount point found under /media/$APP_USER or /run/media/$APP_USER."
        return 1
    fi

    local drives=()
    # -print0 + mapfile -d '': tolerates spaces and special characters in names
    mapfile -t -d '' drives < <(find "$media_path" -mindepth 1 -maxdepth 1 -type d -print0)

    if [ "${#drives[@]}" -eq 0 ]; then
        echo "No mounted drives found under $media_path."
        return 1
    fi

    echo
    echo "Available drives:"
    local d PS3="Choice: "
    select d in "${drives[@]}" "Cancel"; do
        [ "${d:-}" = "Cancel" ] && return 1
        if [ -n "${d:-}" ]; then SCAN_PATH="$d"; return 0; fi
        echo "Invalid selection."
    done
    # select only ends on EOF
    return 1
}

select_custom_path() {
    local input
    input=$(ask_line "Enter path: ")
    [ -n "$input" ] || return 1

    # Resolve a leading tilde ourselves — read does not expand it.
    # shellcheck disable=SC2088  # the tilde is intentional here: a pattern, not an expansion
    case "$input" in
        "~")   input="$HOME_DIR" ;;
        "~/"*) input="$HOME_DIR/${input#\~/}" ;;
    esac

    if [ ! -e "$input" ]; then
        echo "Path does not exist: $input"
        return 1
    fi
    SCAN_PATH="$input"
    return 0
}

# ---------------------------------------------------------------------------
# Progress bar (no subprocesses, no seq)
# ---------------------------------------------------------------------------

draw_progress_bar() {
    local progress=$1 total=$2 infected=$3
    local bar_length=40 bar pad percent filled elapsed
    elapsed=$(fmt_duration $(( SECONDS - SCAN_START )))

    if [ "$total" -gt 0 ]; then
        percent=$(( progress * 100 / total ))
        [ "$percent" -gt 100 ] && percent=100
        filled=$(( progress * bar_length / total ))
        [ "$filled" -gt "$bar_length" ] && filled=$bar_length
        printf -v bar '%*s' "$filled" ''
        printf -v pad '%*s' "$(( bar_length - filled ))" ''
        printf '\r%s[%s%s%s%s%s] %s%3d%%%s (%d/%d) — %d hit(s) — %s' \
            "$CLREOL" "$GREEN" "${bar// /#}" "$GRAY" "${pad// /-}" "$RESET" \
            "$YELLOW" "$percent" "$RESET" "$progress" "$total" "$infected" "$elapsed"
    else
        printf '\r%s%s%d%s files scanned — %d hit(s) — %s' \
            "$CLREOL" "$YELLOW" "$progress" "$RESET" "$infected" "$elapsed"
    fi
}

# ---------------------------------------------------------------------------
# Build the file list
# ---------------------------------------------------------------------------

# Both scanners get an explicit list instead of the raw path:
#   * clamdscan cannot exclude directories on its own — without a list it
#     walks into /proc/kcore and hangs there.
#   * The list also provides the total count for the percentage display, so
#     no second directory traversal is needed.
build_file_list() {
    local -a find_opts=() prune=()
    local p

    # Without -xdev the scan stays on the filesystem holding SCAN_PATH.
    [ "$CROSS_DEVICE" = false ] && find_opts+=( -xdev )

    for p in "${PSEUDO_PATHS[@]}" "${EXCLUDE_PATHS[@]}" "$QUARANTINE_DIR" "$FILE_LIST"; do
        [ -n "$p" ] || continue
        prune+=( -path "$p" -o )
    done
    # drop the trailing "-o" again
    [ "${#prune[@]}" -gt 0 ] && unset 'prune[${#prune[@]}-1]'

    if [ "${#prune[@]}" -gt 0 ]; then
        find "$SCAN_PATH" "${find_opts[@]}" \
             \( "${prune[@]}" \) -prune \
             -o -type f -readable -print 2>/dev/null > "$FILE_LIST"
    else
        find "$SCAN_PATH" "${find_opts[@]}" \
             -type f -readable -print 2>/dev/null > "$FILE_LIST"
    fi
}

# ---------------------------------------------------------------------------
# The actual scan
# ---------------------------------------------------------------------------

run_scan() {
    local flags=() use_clamdscan=false total=0 ans action confirm

    update_signatures

    # --- What to do with detections -----------------------------------------
    echo
    echo "What should happen to infected files?"
    echo "  1) Report only (recommended)"
    echo "  2) Move to quarantine"
    echo "  3) Delete (${RED}irreversible${RESET})"
    action=$(ask_line "Choice [1]: ")
    case "${action:-1}" in
        2)
            QUARANTINE_DIR="$HOME_DIR/clamav_quarantine"
            mkdir -p "$QUARANTINE_DIR" 2>/dev/null || as_root mkdir -p "$QUARANTINE_DIR"
            chmod 700 "$QUARANTINE_DIR" 2>/dev/null || as_root chmod 700 "$QUARANTINE_DIR"
            [ "$EUID" -eq 0 ] && chown "$APP_USER:" "$QUARANTINE_DIR" 2>/dev/null
            flags+=( "--move=$QUARANTINE_DIR" )
            echo "Detections will be moved to $QUARANTINE_DIR."
            ;;
        3)
            echo
            echo "${RED}${BOLD}Warning:${RESET} ClamAV produces false positives on a regular basis."
            echo "Deleting during a system scan can destroy perfectly good system files."
            confirm=$(ask_line "Type DELETE to confirm: ")
            if [ "$confirm" = "DELETE" ]; then
                flags+=( --remove )
                echo "Detections will be deleted."
            else
                echo "Not confirmed — reporting only."
            fi
            ;;
        *)
            echo "Detections will only be logged."
            ;;
    esac

    # --- Daemon or standalone process ---------------------------------------
    if check_command clamdscan; then
        echo
        if ask_yes_no "Use clamdscan (daemon, considerably faster)?" y; then
            if start_clamd_if_needed; then
                use_clamdscan=true
            else
                echo "Falling back to clamscan."
            fi
        fi
    fi
    if [ "$use_clamdscan" = false ] && ! check_command clamscan; then
        echo "${RED}Neither a reachable clamd nor clamscan is available. Aborting.${RESET}"
        return 1
    fi

    # --- Scanner-specific options -------------------------------------------
    if [ "$use_clamdscan" = false ]; then
        echo
        ask_yes_no "Skip archives (faster, but incomplete)?" n &&
            flags+=( --scan-archive=no )

        # The default is 100 MB — larger files would be skipped silently
        flags+=( --max-filesize=1000M --max-scansize=1000M )
        flags+=( --stdout )
    else
        # clamdscan knows neither --exclude-dir nor --max-filesize; those
        # limits live in /etc/clamav/clamd.conf. Exclusions are handled by the
        # file list. No -m: multiscan opens a very large number of file
        # descriptors within a SINGLE connection and is the most likely cause
        # of hangs. Parallelism comes from several independent clamdscan
        # processes instead (see THREADS below) — each holding only one
        # descriptor at a time, which is exactly the model clamd's MaxThreads
        # is designed for.
        flags+=( --fdpass --stdout )

        # --- Parallelism: detect thread count automatically -------------------
        local detected
        detected=$(nproc 2>/dev/null || echo 1)
        echo
        ans=$(ask_line "Parallel clamdscan connections [detected: $detected]: ")
        if [[ "$ans" =~ ^[0-9]+$ ]] && [ "$ans" -ge 1 ]; then
            THREADS="$ans"
        else
            THREADS="$detected"
        fi
        echo "Using $THREADS parallel connections."

        # Best-effort hint in case clamd itself allows fewer concurrent
        # connections (MaxThreads in clamd.conf). That file is usually
        # readable by root only — if access fails, the hint is simply skipped.
        local conf maxthreads
        for conf in /etc/clamav/clamd.conf /etc/clamd.d/scan.conf; do
            [ -r "$conf" ] || continue
            maxthreads=$(awk '/^[[:space:]]*MaxThreads/{print $2; exit}' "$conf")
            if [[ "${maxthreads:-}" =~ ^[0-9]+$ ]] && [ "$THREADS" -gt "$maxthreads" ]; then
                echo "${YELLOW}Note:${RESET} according to $conf clamd allows only $maxthreads concurrent"
                echo "connections (MaxThreads). Excess requests are queued, not rejected — so this"
                echo "works, but it will not actually use all $THREADS connections at once."
            fi
            break
        done
    fi

    # --- Scope ---------------------------------------------------------------
    echo
    if ask_yes_no "Also scan mounted filesystems (e.g. a separate /home, USB)?" n; then
        CROSS_DEVICE=true
    else
        CROSS_DEVICE=false
    fi

    # --- File list -----------------------------------------------------------
    FILE_LIST=$(mktemp)
    echo
    echo "Collecting files (may take a while on large volumes) ..."
    build_file_list

    total=$(wc -l < "$FILE_LIST")
    echo "To be scanned: $total files"
    if [ "$total" -eq 0 ]; then
        echo "Nothing to scan."
        return 0
    fi

    # --- Log file ------------------------------------------------------------
    RESULTS_FILE="$HOME_DIR/clamav_scan_$(date +%Y%m%d_%H%M%S).log"
    {
        echo "ClamAV scan started: $(date)"
        echo "Script version: $VERSION"
        echo "Path:     $SCAN_PATH"
        echo "Scope:    $([ "$CROSS_DEVICE" = true ] && echo "including mounted filesystems" || echo "own filesystem only (-xdev)")"
        echo "Scanner:  $([ "$use_clamdscan" = true ] && echo clamdscan || echo clamscan)"
        echo "Flags:    ${flags[*]}"
        [ "$use_clamdscan" = true ] && echo "Threads:  $THREADS"
        echo "Files:    $total"
        echo "-------------------------------------------"
    } > "$RESULTS_FILE"

    local scanned=0 infected=0 errors=0 last_file="" scanner
    scanner=clamscan
    [ "$use_clamdscan" = true ] && scanner=clamdscan

    echo
    [ "$use_clamdscan" = false ] && echo "Loading signature database (takes 20–40 seconds) ..."
    echo "Scan running — press Ctrl+C to abort."
    printf '%s' "$HIDE"

    local rc=0 f v
    SCAN_START=$SECONDS

    if [ "$use_clamdscan" = true ]; then
        # --- Parallel clamdscan path ------------------------------------------
        CHUNK_DIR=$(mktemp -d)
        # -a 4: suffix length 4 instead of 2 — otherwise split gives up after
        # 676 chunks (roughly 1.35 million files).
        split -a 4 -l "$CHUNK_SIZE" "$FILE_LIST" "$CHUNK_DIR/part_"

        # Each worker scans exactly one chunk over its own connection and
        # writes to its own output file rather than to a shared stdout —
        # otherwise lines from several concurrently writing processes could
        # interleave mid-line. "wait -n" keeps at most $THREADS workers alive
        # at a time without requiring GNU parallel or xargs -P.
        run_scanner_parallel() {
            local chunk c active=0
            for chunk in "$CHUNK_DIR"/part_*; do
                (
                    local wrc tpid done_n=0 total_n suspect saved ln reason
                    printf -v c '%q ' "$scanner" "${flags[@]}" "--file-list=$chunk"

                    # Start in the background and record the PID so the monitor
                    # can terminate this specific chunk if it stalls.
                    if check_command script; then
                        timeout -k 30 "$BATCH_TIMEOUT" script -qfec "$c" /dev/null \
                            < /dev/null > "$chunk.out" 2>&1 &
                    else
                        timeout -k 30 "$BATCH_TIMEOUT" stdbuf -oL "$scanner" \
                            "${flags[@]}" "--file-list=$chunk" < /dev/null > "$chunk.out" 2>&1 &
                    fi
                    tpid=$!
                    echo "$tpid" > "$chunk.pid"
                    wait "$tpid"
                    wrc=$?
                    rm -f "$chunk.pid"

                    # 124 = absolute upper bound, 137/143 = terminated by the
                    # monitor because of a stall. Anything else is a normal end.
                    case "$wrc" in
                        124|137|143)
                            if [ -f "$chunk.stalled" ]; then
                                reason="no progress for ${STALL_TIMEOUT}s"
                            else
                                reason="absolute time limit reached"
                            fi
                            # The number of result lines already written equals
                            # the number of files that finished. The next line
                            # of the chunk list is where it got stuck.
                            while IFS= read -r ln; do
                                ln=${ln%$'\r'}
                                case "$ln" in
                                    LibClamAV*|WARNING*|Loading*|"Session terminated"*|"") : ;;
                                    *) done_n=$(( done_n + 1 )) ;;
                                esac
                            done < "$chunk.out"
                            total_n=$(wc -l < "$chunk")
                            suspect=$(sed -n "$((done_n + 1))p" "$chunk")
                            saved="$HOME_DIR/clamav_aborted_$(basename "$chunk")_$(date +%H%M%S).list"
                            if cp "$chunk" "$saved" 2>/dev/null; then
                                [ "$EUID" -eq 0 ] && chown "$APP_USER:" "$saved" 2>/dev/null
                            fi
                            {
                                printf '\nCHUNK ABORTED (%s): %d/%d files done\n' \
                                    "$reason" "$done_n" "$total_n"
                                printf 'Stopped at: %s\n' "${suspect:-unknown}"
                                printf 'Full chunk list saved to: %s\n' "$saved"
                            } >> "$chunk.out"
                            wrc=2
                            ;;
                    esac
                    echo "$wrc" > "$chunk.rc"
                # All worker payload goes to $chunk.out/.rc/.pid. Whatever else
                # ends up on stdout/stderr is just the shell's own abort
                # messages — those would write right into the progress bar.
                ) >/dev/null 2>&1 &
                active=$(( active + 1 ))
                if [ "$active" -ge "$THREADS" ]; then
                    wait -n
                    active=$(( active - 1 ))
                fi
            done
            wait
        }

        # Evaluates a single new line from a chunk output file. Uses
        # scanned/infected/errors/last_file/RESULTS_FILE from run_scan and
        # IN_SUMMARY from monitor_parallel (bash scoping: a call sees the
        # "local" variables of every function it was called from).
        categorize_line() {
            local line=$1 chunk=$2
            case "$line" in
                *"SCAN SUMMARY"*) IN_SUMMARY[$chunk]=true;  return ;;
                "Time:"*)         IN_SUMMARY[$chunk]=false; return ;;
                /*:\ *)           IN_SUMMARY[$chunk]=false ;;
            esac
            [ "${IN_SUMMARY[$chunk]:-false}" = true ] && return

            case "$line" in
                *"CHUNK ABORTED ("*|"Stopped at:"*|"Full chunk list"*)
                    printf '\r%s%s%s%s\n' "$CLREOL" "$YELLOW" "$line" "$RESET"
                    printf '%s\n' "$line" >> "$RESULTS_FILE"
                    ;;
                *" FOUND")
                    scanned=$(( scanned + 1 )); infected=$(( infected + 1 ))
                    printf '\r%s%s%s%s\n' "$CLREOL" "$RED" "$line" "$RESET"
                    printf '%s\n' "$line" >> "$RESULTS_FILE"
                    ;;
                *ERROR*|*"Access denied"*|*"Can't open"*|*"Can't access"*)
                    # Unreadable files are processed too — otherwise the bar
                    # would never reach 100%.
                    scanned=$(( scanned + 1 )); errors=$(( errors + 1 ))
                    printf '%s\n' "$line" >> "$RESULTS_FILE"
                    ;;
                LibClamAV*|WARNING*|Loading*|"Session terminated"*|"")
                    : # ignore start-up and status messages
                    ;;
                /*:\ *)
                    last_file=${line%%:*}
                    scanned=$(( scanned + 1 ))
                    ;;
            esac
        }

        # On each call, reads only the COMPLETE lines that a file has gained
        # since last time. "wc -l" counts newline-terminated lines only — a
        # line that has just been started without its \n is therefore not
        # counted and is automatically deferred to the next round. That
        # removes any need to manage partial line remainders by hand.
        poll_chunk_outputs() {
            local chunk out_file new_total prev line
            # "! -name '*.*'": matches only the chunks produced by split
            # (part_aaaa ...), not their own .out/.rc files — otherwise the
            # match list would grow needlessly on every poll.
            while IFS= read -r -d '' chunk; do
                out_file="$chunk.out"
                [ -f "$out_file" ] || continue
                new_total=$(wc -l < "$out_file" 2>/dev/null) || new_total=0
                prev=${SEEN_LINES[$chunk]:-0}
                [ "$new_total" -le "$prev" ] && continue
                while IFS= read -r line; do
                    # 'script' yields CRLF — without stripping it here a
                    # pattern such as '*" FOUND"' no longer matches, because
                    # the line then ends in "FOUND\r" instead of "FOUND".
                    line=${line%$'\r'}
                    categorize_line "$line" "$chunk"
                done < <(sed -n "$((prev + 1)),${new_total}p" "$out_file")
                SEEN_LINES[$chunk]=$new_total
                LAST_GROWTH[$chunk]=$SECONDS   # timestamp of the last progress
            done < <(find "$CHUNK_DIR" -maxdepth 1 -type f -name 'part_*' ! -name '*.*' -print0)
        }

        # Terminates chunks that have not written a single new result line for
        # STALL_TIMEOUT seconds. A chunk that moves forward slowly but steadily
        # is therefore never aborted, no matter how long it takes overall.
        check_stalled_chunks() {
            local chunk pid age
            while IFS= read -r -d '' chunk; do
                [ -f "$chunk.pid" ] || continue       # not running (any more)
                [ -f "$chunk.rc"  ] && continue       # already finished
                [ -f "$chunk.stalled" ] && continue   # already aborted
                # Start the clock on first sight, so a chunk that produces no
                # output at all right from the start is detected as well.
                : "${LAST_GROWTH[$chunk]:=$SECONDS}"
                age=$(( SECONDS - LAST_GROWTH[$chunk] ))
                [ "$age" -lt "$STALL_TIMEOUT" ] && continue

                pid=$(cat "$chunk.pid" 2>/dev/null) || continue
                [ -n "$pid" ] || continue
                : > "$chunk.stalled"
                # First the children of 'timeout' (i.e. script/clamdscan),
                # then 'timeout' itself — otherwise the actual scanner
                # survives.
                check_command pkill && pkill -TERM -P "$pid" 2>/dev/null
                kill -TERM "$pid" 2>/dev/null
            done < <(find "$CHUNK_DIR" -maxdepth 1 -type f -name 'part_*' ! -name '*.*' -print0)
        }

        monitor_parallel() {
            local run_pid=$1
            declare -A SEEN_LINES IN_SUMMARY LAST_GROWTH
            while :; do
                poll_chunk_outputs
                check_stalled_chunks
                draw_progress_bar "$scanned" "$total" "$infected"
                kill -0 "$run_pid" 2>/dev/null || break
                sleep 1
            done
            poll_chunk_outputs   # final remainder after the process ended
        }

        run_scanner_parallel &
        RUN_PID=$!
        monitor_parallel "$RUN_PID"
        wait "$RUN_PID" 2>/dev/null
        RUN_PID=""

        for f in "$CHUNK_DIR"/part_*.rc; do
            [ -f "$f" ] || continue
            v=$(cat "$f" 2>/dev/null)
            [[ "$v" =~ ^[0-9]+$ ]] || continue
            [ "$v" -gt "$rc" ] && rc=$v
        done
    else
        # --- Serial clamscan path ---------------------------------------------
        # clamscan reloads the signature database on every start, so a single
        # call with the complete list is the right thing here; unlike with
        # clamdscan there is nothing to parallelise without paying for RAM and
        # load time several times over.
        run_scanner() {
            local c wrc
            printf -v c '%q ' "$scanner" "${flags[@]}" "--file-list=$FILE_LIST"
            if check_command script; then
                script -qfec "$c" /dev/null < /dev/null
            else
                stdbuf -oL "$scanner" "${flags[@]}" "--file-list=$FILE_LIST" < /dev/null
            fi
            wrc=$?
            return "$wrc"
        }

        local rc_file line started=false rc_read stalls=0
        rc_file=$(mktemp)
        local in_summary=false

        # read -t 120: returns an exit code > 128 on timeout and 1 on EOF.
        # That way it becomes visible when clamscan gets stuck on a file,
        # instead of the bar simply freezing without comment.
        while :; do
            IFS= read -r -t 120 line; rc_read=$?
            if [ "$rc_read" -gt 128 ]; then
                stalls=$(( stalls + 1 ))
                printf '\r%s%sNo output for 2 minutes (#%d) — last file: %s%s\n' \
                    "$CLREOL" "$YELLOW" "$stalls" "${last_file:-?}" "$RESET"
                continue
            fi
            [ "$rc_read" -ne 0 ] && break

            line=${line%$'\r'}

            case "$line" in
                *"SCAN SUMMARY"*) in_summary=true;  continue ;;
                "Time:"*)         in_summary=false; continue ;;
                /*:\ *)           in_summary=false ;;
            esac
            [ "$in_summary" = true ] && continue

            case "$line" in
                *" FOUND")
                    scanned=$(( scanned + 1 )); infected=$(( infected + 1 ))
                    printf '\r%s%s%s%s\n' "$CLREOL" "$RED" "$line" "$RESET"
                    printf '%s\n' "$line" >> "$RESULTS_FILE"
                    ;;
                *ERROR*|*"Access denied"*|*"Can't open"*|*"Can't access"*)
                    scanned=$(( scanned + 1 )); errors=$(( errors + 1 ))
                    printf '%s\n' "$line" >> "$RESULTS_FILE"
                    ;;
                LibClamAV*|WARNING*|Loading*|"Session terminated"*|"")
                    :
                    ;;
                /*:\ *)
                    last_file=${line%%:*}
                    scanned=$(( scanned + 1 ))
                    ;;
            esac

            if [ "$started" = false ] && [ "$scanned" -gt 0 ]; then
                started=true
                draw_progress_bar "$scanned" "$total" "$infected"
            elif (( scanned > 0 && scanned % 20 == 0 )); then
                draw_progress_bar "$scanned" "$total" "$infected"
            fi
        done < <( { run_scanner; echo $? > "$rc_file"; } 2>&1 )

        rc=$(cat "$rc_file" 2>/dev/null); rm -f "$rc_file"
        [[ "$rc" =~ ^[0-9]+$ ]] || rc=2
    fi

    draw_progress_bar "$scanned" "$total" "$infected"
    printf '%s' "$SHOW"
    echo; echo

    # --- Summary -------------------------------------------------------------
    echo "-------------------------------------------"
    echo "Files scanned: $scanned of $total"
    echo "Detections:    $infected"
    echo "Read errors:   $errors"
    echo "Duration:      $(fmt_duration $(( SECONDS - SCAN_START )))"
    case "$rc" in
        0) echo "Result: ${GREEN}clean${RESET}" ;;
        1) echo "Result: ${RED}malware found${RESET}" ;;
        *) echo "Result: ${YELLOW}finished with errors (exit code $rc)${RESET}" ;;
    esac
    echo "Log: $RESULTS_FILE"
    [ -n "$QUARANTINE_DIR" ] && echo "Quarantine: $QUARANTINE_DIR"

    {
        echo "-------------------------------------------"
        echo "Scanned:   $scanned of $total"
        echo "Detections: $infected"
        echo "Errors:    $errors"
        echo "Duration:  $(fmt_duration $(( SECONDS - SCAN_START )))"
        echo "Exit code: $rc"
        echo "Finished: $(date)"
    } >> "$RESULTS_FILE"

    if [ "$errors" -gt 0 ] && [ "$EUID" -ne 0 ]; then
        echo
        echo "${YELLOW}Note:${RESET} $errors files could not be read."
        echo "Run the script with sudo for a complete system scan."
    fi
    return 0
}

# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

SCAN_PATH=""
SCAN_START=$SECONDS

while true; do
    show_main_menu
    if ! read -r choice; then
        echo; echo "Bye."
        exit 0
    fi
    case "$choice" in
        1)
            if [ "$EUID" -ne 0 ]; then
                echo "${YELLOW}A system scan without root cannot read most files.${RESET}"
                ask_yes_no "Continue anyway?" n || continue
            fi
            SCAN_PATH="/"
            run_scan
            ;;
        2) select_external_drive && run_scan ;;
        3) select_custom_path   && run_scan ;;
        4) echo "Bye."; exit 0 ;;
        *) echo "Invalid input. Please choose 1–4." ;;
    esac
done
