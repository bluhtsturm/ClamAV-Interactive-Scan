#!/usr/bin/env bash
#
# antivirus_de.sh — interaktiver ClamAV-Scanner mit Fortschrittsanzeige
#
# Scannt das laufende System, ein externes Laufwerk oder ein beliebiges
# Verzeichnis. Wahlweise mit clamscan (eigener Prozess, lädt die Signatur-
# datenbank selbst) oder über clamd/clamdscan (Daemon, deutlich schneller,
# parallelisierbar). Der Fortschrittsbalken wird live aus der Ausgabe von
# ClamAV gespeist.
#
# Lizenz: MIT
#

# Kein "set -e": clamscan liefert Exit-Code 1 bei Fund und 2 bei Fehlern —
# beides sind keine Skriptfehler.
set -uo pipefail

VERSION="1.2.0"

# ---------------------------------------------------------------------------
# Konfiguration
# ---------------------------------------------------------------------------

# Größe der Teilpakete für den parallelen clamdscan-Pfad (Dateien pro Paket).
# Kleiner = feinkörniger Fortschritt und schnellere Erkennung von Hängern,
# aber mehr Prozessstarts. 1000–5000 ist ein sinnvoller Bereich.
CHUNK_SIZE=2000

# STALL_TIMEOUT ist das eigentliche Sicherheitsnetz: Sekunden OHNE eine
# einzige neue Ergebniszeile, nach denen ein Paket als hängend gilt.
# Gemessen wird Fortschritt, nicht Gesamtdauer — ein langsamer Rechner
# (schwache CPU, wenige Threads, große Mediendateien) darf beliebig lange
# brauchen, solange er überhaupt vorankommt. Nur echter Stillstand wird
# abgebrochen.
STALL_TIMEOUT=900

# Absolute Obergrenze pro Paket als letzter Notnagel, falls die
# Stillstandserkennung versagt. Bewusst sehr hoch — sie soll im
# Normalbetrieb nie greifen.
BATCH_TIMEOUT=28800

# Zusätzliche Pfade, die grundsätzlich übersprungen werden sollen.
# Nützlich z.B. für Wine-/Proton-/Steam-Bäume mit hunderttausenden
# winzigen Dateien oder für Netzlaufwerke. Beispiel:
#   EXCLUDE_PATHS=( /opt/wine-staging "$HOME/.wine" "$HOME/.steam" )
EXCLUDE_PATHS=()

# Pseudo-Dateisysteme, die nie gescannt werden dürfen.
PSEUDO_PATHS=( /proc /sys /dev /run /snap )

# Die Dienstnamen unterscheiden sich je nach Distribution:
#   clamav-daemon / clamav-freshclam   Debian, Ubuntu, Arch (Upstream-Namen)
#   clamd@scan    / clamav-freshclam   Fedora, RHEL
#   clamd         / freshclam          openSUSE
CLAMD_UNITS=( clamav-daemon clamd@scan clamd )
FRESHCLAM_UNITS=( clamav-freshclam freshclam )

# ---------------------------------------------------------------------------
# Vorbedingungen
# ---------------------------------------------------------------------------

# Benötigt werden: assoziative Arrays (4.0), "wait -n" (4.3) und
# "mapfile -d" (4.4).
if [ -z "${BASH_VERSINFO:-}" ] ||
   [ "${BASH_VERSINFO[0]}" -lt 4 ] ||
   { [ "${BASH_VERSINFO[0]}" -eq 4 ] && [ "${BASH_VERSINFO[1]}" -lt 4 ]; }; then
    echo "Dieses Skript benötigt Bash 4.4 oder neuer." >&2
    exit 1
fi

APP_USER=${SUDO_USER:-${USER:-$(id -un)}}
HOME_DIR=$(getent passwd "$APP_USER" | cut -d: -f6)
[ -n "$HOME_DIR" ] && [ -d "$HOME_DIR" ] || HOME_DIR="/tmp"
QUARANTINE_PATH="$HOME_DIR/clamav_quarantine"

# Farben nur, wenn stdout wirklich ein Terminal ist.
# $'...' (ANSI-C-Quoting) legt die echten Escape-Bytes in die Variable —
# damit funktionieren sowohl echo als auch printf ohne -e.
if [ -t 1 ]; then
    GREEN=$'\033[0;32m'; GRAY=$'\033[0;37m'; YELLOW=$'\033[1;33m'
    RED=$'\033[0;31m';   BOLD=$'\033[1m';    RESET=$'\033[0m'
    CLREOL=$'\033[K';    HIDE=$'\033[?25l';  SHOW=$'\033[?25h'
else
    GREEN=""; GRAY=""; YELLOW=""; RED=""; BOLD=""; RESET=""
    CLREOL=""; HIDE=""; SHOW=""
fi

FRESHCLAM_UNIT=""        # der von uns gestoppte freshclam-Dienst (zum Neustart)
QUARANTINE_DIR=""        # nur gesetzt, solange der aktuelle Scan die Quarantäne nutzt
RESULTS_FILE=""
FILE_LIST=""
CHUNK_DIR=""
RC_FILE=""
RUN_PID=""
CLEANED=false
CROSS_DEVICE=false
THREADS=1
SKIPPED_FILES=0          # nicht lesbar, daher nicht in der Dateiliste
SKIPPED_DIRS=0
TERM_COLS=80
COLS_CHECKED=-1
LAST_DRAW=-1

check_command() { command -v "$1" >/dev/null 2>&1; }

# Führt einen Befehl mit root-Rechten aus — direkt, wenn wir schon root sind,
# sonst über sudo. So läuft das Skript auch in Umgebungen ohne sudo.
as_root() {
    if [ "$EUID" -eq 0 ]; then
        "$@"
    elif check_command sudo; then
        sudo "$@"
    else
        echo "${YELLOW}Benötigt root-Rechte, aber sudo fehlt:${RESET} $*" >&2
        return 1
    fi
}

# ---------------------------------------------------------------------------
# Aufräumen
# ---------------------------------------------------------------------------

# Beendet die komplette Worker-Hierarchie in der richtigen Reihenfolge:
#   1. den Verteiler und seine Worker-Subshells, damit kein weiteres Paket
#      nachrückt,
#   2. die eigentlichen Scanner (timeout -> script -> clamdscan) über die
#      hinterlegten PID-Dateien; ohne diesen Schritt überlebt der Scanner
#      das Signal an seinen Elternprozess,
#   3. eine kurze Gnadenfrist, damit die Prozesse enden, bevor ihr
#      Arbeitsverzeichnis gelöscht wird.
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

# Entfernt die Temporärdateien eines Scans und übergibt dessen Protokoll
# dem echten Benutzer. Läuft nach JEDEM Scan, nicht erst beim Beenden —
# sonst sammeln sich bei mehreren Scans pro Sitzung Temporärdateien an und
# ältere Protokolle bleiben root-eigen liegen.
finish_scan() {
    [ -n "$FILE_LIST" ] && rm -f "$FILE_LIST"
    [ -n "$CHUNK_DIR" ] && rm -rf "$CHUNK_DIR"
    [ -n "$RC_FILE" ]   && rm -f "$RC_FILE"
    FILE_LIST=""; CHUNK_DIR=""; RC_FILE=""

    # Logdatei dem echten Benutzer übergeben, nicht root
    if [ "$EUID" -eq 0 ] && [ -n "$RESULTS_FILE" ] && [ -f "$RESULTS_FILE" ]; then
        chown "$APP_USER:" "$RESULTS_FILE" 2>/dev/null
    fi
    return 0
}

cleanup() {
    # Der EXIT-Trap feuert auch nach einem Signal-Trap — ohne Wachposten
    # liefe das Aufräumen zweimal.
    [ "$CLEANED" = true ] && return 0
    CLEANED=true

    printf '%s' "$SHOW"          # Cursor wieder sichtbar machen
    kill_workers

    # freshclam-Dienst wieder starten, falls wir ihn gestoppt haben
    if [ -n "$FRESHCLAM_UNIT" ]; then
        as_root systemctl start "$FRESHCLAM_UNIT" >/dev/null 2>&1
    fi

    finish_scan
    return 0
}

trap 'cleanup' EXIT
trap 'printf "\n%sAbbruch durch Benutzer.%s\n" "$YELLOW" "$RESET"; exit 130' INT
trap 'exit 143' TERM

# ---------------------------------------------------------------------------
# Eingabehilfen (behandeln EOF sauber, statt in Endlosschleifen zu laufen)
# ---------------------------------------------------------------------------

# ask_yes_no "Frage" [j|n]  -> Rückgabewert 0 = ja, 1 = nein/EOF
ask_yes_no() {
    local prompt=$1 default=${2:-n} reply
    if [ "$default" = "j" ]; then
        printf '%s [J/n]: ' "$prompt"
    else
        printf '%s [j/N]: ' "$prompt"
    fi
    read -r reply || { echo; return 1; }
    reply=${reply:-$default}
    [[ "$reply" =~ ^([Jj]|[Yy]|[Jj][Aa]|[Yy][Ee][Ss])$ ]]
}

# ask_line "Frage"  -> Antwort auf stdout (leer bei EOF)
ask_line() {
    local prompt=$1 reply
    printf '%s' "$prompt" >&2
    read -r reply || reply=""
    printf '%s' "$reply"
}

# fmt_duration VAR Sekunden  -> VAR = HH:MM:SS bzw. MM:SS
# Schreibt in eine Variable statt nach stdout, damit Aufrufer keine
# $(...)-Subshell brauchen — der Fortschrittsbalken ruft das sekündlich auf.
fmt_duration() {
    local s=$2
    if [ "$s" -ge 3600 ]; then
        printf -v "$1" '%d:%02d:%02d' $(( s / 3600 )) $(( (s % 3600) / 60 )) $(( s % 60 ))
    else
        printf -v "$1" '%02d:%02d' $(( s / 60 )) $(( s % 60 ))
    fi
}

# ---------------------------------------------------------------------------
# Distributionserkennung (wertet auch ID_LIKE aus)
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
            echo "Unbekannte Distribution. Bitte ClamAV manuell installieren."
            exit 1
            ;;
    esac
}

if ! check_command clamscan && ! check_command clamdscan; then
    echo "ClamAV wurde nicht gefunden."
    if ask_yes_no "Jetzt installieren?" j; then
        install_clamav
        if ! check_command clamscan && ! check_command clamdscan; then
            echo "${RED}ClamAV ist weiterhin nicht verfügbar — ist die Installation fehlgeschlagen?${RESET}"
            exit 1
        fi
    else
        echo "Ohne ClamAV kann nicht fortgefahren werden. Abbruch."
        exit 1
    fi
fi

# ---------------------------------------------------------------------------
# Signaturen aktualisieren
# ---------------------------------------------------------------------------

update_signatures() {
    local unit
    echo
    ask_yes_no "Virensignaturen aktualisieren?" j || return 0

    # freshclam kann nicht laufen, solange der Dienst die Logdatei sperrt.
    for unit in "${FRESHCLAM_UNITS[@]}"; do
        systemctl is-active --quiet "$unit" 2>/dev/null || continue
        echo "Stoppe $unit für die Dauer des Updates ..."
        as_root systemctl stop "$unit" && FRESHCLAM_UNIT=$unit
        break
    done

    echo "Aktualisiere Signaturen ..."
    if ! as_root freshclam; then
        echo "${YELLOW}Warnung:${RESET} Update fehlgeschlagen — es wird mit den vorhandenen Signaturen gescannt."
    fi

    if [ -n "$FRESHCLAM_UNIT" ]; then
        as_root systemctl start "$FRESHCLAM_UNIT" >/dev/null 2>&1
        FRESHCLAM_UNIT=""
    fi
}

# ---------------------------------------------------------------------------
# clamd bei Bedarf starten
# ---------------------------------------------------------------------------

start_clamd_if_needed() {
    local unit="" u i

    # Antwortet er schon? Dann ist egal, wie er gestartet wurde
    # (systemd, von Hand, im Container ...).
    clamdscan --ping 1 >/dev/null 2>&1 && return 0

    for u in "${CLAMD_UNITS[@]}"; do
        if systemctl is-active --quiet "$u" 2>/dev/null; then
            unit=$u
            break
        fi
    done
    if [ -z "$unit" ]; then
        # die erste Unit starten, die es auf diesem System tatsächlich gibt
        for u in "${CLAMD_UNITS[@]}"; do
            systemctl cat "$u" >/dev/null 2>&1 || continue
            echo "Starte clamd ($u) ..."
            as_root systemctl start "$u" && unit=$u
            break
        done
    fi
    if [ -z "$unit" ]; then
        echo "${YELLOW}Kein clamd-Dienst gefunden, oder er ließ sich nicht starten.${RESET}"
        return 1
    fi

    # "active" heißt nicht bereit: Nach einem (Neu-)Start braucht clamd bis
    # zu ~60 s zum Laden der Signaturdatenbank und antwortet erst danach.
    echo "Warte auf clamd (das Laden der Datenbank kann bis zu einer Minute dauern) ..."
    for (( i = 0; i < 60; i++ )); do
        clamdscan --ping 1 >/dev/null 2>&1 && return 0
        sleep 1
    done
    echo "${YELLOW}clamd antwortet nicht.${RESET}"
    return 1
}

# ---------------------------------------------------------------------------
# Menüs
# ---------------------------------------------------------------------------

show_main_menu() {
    echo
    echo "===================================="
    echo "   ${BOLD}ClamAV — interaktiver Scan${RESET} v$VERSION"
    echo "===================================="
    echo "1) Internes System scannen (/)"
    echo "2) Externes Laufwerk scannen"
    echo "3) Beliebiges Verzeichnis scannen"
    echo "4) Beenden"
    printf 'Auswahl: '
}

select_external_drive() {
    local media_path="/media/$APP_USER"
    [ -d "/run/media/$APP_USER" ] && media_path="/run/media/$APP_USER"

    if [ ! -d "$media_path" ]; then
        echo "Kein Einhängepunkt unter /media/$APP_USER oder /run/media/$APP_USER gefunden."
        return 1
    fi

    local drives=()
    # -print0 + mapfile -d '': verträgt Leerzeichen und Sonderzeichen im Namen
    mapfile -t -d '' drives < <(find "$media_path" -mindepth 1 -maxdepth 1 -type d -print0)

    if [ "${#drives[@]}" -eq 0 ]; then
        echo "Keine eingehängten Laufwerke unter $media_path gefunden."
        return 1
    fi

    echo
    echo "Verfügbare Laufwerke:"
    local d PS3="Auswahl: "
    select d in "${drives[@]}" "Abbrechen"; do
        [ "${d:-}" = "Abbrechen" ] && return 1
        if [ -n "${d:-}" ]; then SCAN_PATH="$d"; return 0; fi
        echo "Ungültige Auswahl."
    done
    # select endet nur bei EOF
    return 1
}

select_custom_path() {
    local input
    input=$(ask_line "Pfad eingeben: ")
    [ -n "$input" ] || return 1

    # Drag & Drop aus dem Dateimanager fügt den Pfad in Anführungszeichen
    # ein: '/home/ich/Meine Dateien'
    case "$input" in
        \'*\'|\"*\") input=${input:1:${#input}-2} ;;
    esac

    # Führende Tilde selbst auflösen — read expandiert sie nicht.
    # shellcheck disable=SC2088  # die Tilde ist hier Absicht: Suchmuster, keine Expansion
    case "$input" in
        "~")   input="$HOME_DIR" ;;
        "~/"*) input="$HOME_DIR/${input#\~/}" ;;
    esac

    if [ ! -e "$input" ]; then
        echo "Pfad existiert nicht: $input"
        return 1
    fi

    # Pfad absolut machen: clamscan gibt jeden Pfad genau so aus, wie er in
    # der Dateiliste steht, und die Auswertung erkennt nur Zeilen, die mit
    # "/" beginnen — bei einem relativen Pfad würde nichts gezählt.
    # Symlinks werden bewusst NICHT aufgelöst (-s), damit EXCLUDE_PATHS
    # weiterhin greifen.
    case "$input" in
        /*) ;;
        *)  input="$PWD/$input" ;;
    esac
    SCAN_PATH=$(realpath -s -- "$input" 2>/dev/null) || SCAN_PATH=$input
    return 0
}

# ---------------------------------------------------------------------------
# Fortschrittsbalken
# ---------------------------------------------------------------------------

# Liest die Terminalbreite höchstens einmal pro Sekunde neu ein — das
# Fenster kann während eines langen Scans verändert werden.
refresh_term_cols() {
    local size
    [ "$SECONDS" -eq "$COLS_CHECKED" ] && return 0
    COLS_CHECKED=$SECONDS
    size=$(stty size 2>/dev/null < /dev/tty) || return 0
    size=${size##* }
    if [[ "$size" =~ ^[0-9]+$ ]] && [ "$size" -gt 0 ]; then
        TERM_COLS=$size
    fi
    return 0
}

draw_progress_bar() {
    local progress=$1 total=$2 infected=$3
    local bar_length bar pad percent filled elapsed tail
    LAST_DRAW=$SECONDS
    refresh_term_cols
    fmt_duration elapsed $(( SECONDS - SCAN_START ))

    if [ "$total" -gt 0 ]; then
        percent=$(( progress * 100 / total ))
        [ "$percent" -gt 100 ] && percent=100
        printf -v tail ' (%d/%d) — %d Fund(e) — %s' "$progress" "$total" "$infected" "$elapsed"

        # Die Zeile muss schmaler als das Terminal bleiben: Bricht sie um,
        # springt "\r" nur an den Anfang des umgebrochenen Teils, und jedes
        # Neuzeichnen hinterlässt eine Kopie. Neben dem Balken braucht sie
        # "[", "] ", "100%", den Rest der Zeile und eine Spalte Reserve.
        bar_length=$(( TERM_COLS - ${#tail} - 8 ))
        [ "$bar_length" -gt 40 ] && bar_length=40

        if [ "$bar_length" -ge 10 ]; then
            filled=$(( progress * bar_length / total ))
            [ "$filled" -gt "$bar_length" ] && filled=$bar_length
            printf -v bar '%*s' "$filled" ''
            printf -v pad '%*s' "$(( bar_length - filled ))" ''
            printf '\r%s[%s%s%s%s%s] %s%3d%%%s%s' \
                "$CLREOL" "$GREEN" "${bar// /#}" "$GRAY" "${pad// /-}" "$RESET" \
                "$YELLOW" "$percent" "$RESET" "$tail"
        else
            # zu schmal für einen Balken: nur Zahlen, auf Terminalbreite gekürzt
            printf -v tail '%3d%%%s' "$percent" "$tail"
            printf '\r%s%s' "$CLREOL" "${tail:0:TERM_COLS-1}"
        fi
    else
        printf '\r%s%s%d%s Dateien geprüft — %d Fund(e) — %s' \
            "$CLREOL" "$YELLOW" "$progress" "$RESET" "$infected" "$elapsed"
    fi
}

# ---------------------------------------------------------------------------
# Dateiliste aufbauen
# ---------------------------------------------------------------------------

# Beide Scanner bekommen eine explizite Liste statt des rohen Pfads:
#   * clamdscan kann Verzeichnisse nicht selbst ausschließen — ohne Liste
#     läuft es in /proc/kcore und bleibt dort hängen.
#   * Die Liste liefert zugleich die Gesamtzahl für die Prozentanzeige,
#     ein zweiter Verzeichnisdurchlauf entfällt.
build_file_list() {
    local -a find_opts=() prune=()
    local p counts

    # Mit -xdev bleibt der Scan auf dem Dateisystem von SCAN_PATH.
    [ "$CROSS_DEVICE" = false ] && find_opts+=( -xdev )

    for p in "${PSEUDO_PATHS[@]}" "${EXCLUDE_PATHS[@]}" "$FILE_LIST"; do
        [ -n "$p" ] || continue
        prune+=( -path "$p" -o )
    done
    # Die eigene Quarantäne nie scannen (ihr Inhalt würde sonst bei jedem
    # Scan erneut gemeldet) — außer der Scan beginnt bewusst darin.
    case "$SCAN_PATH/" in
        "$QUARANTINE_PATH"/*) ;;
        *) prune+=( -path "$QUARANTINE_PATH" -o ) ;;
    esac
    # letztes "-o" wieder entfernen
    unset 'prune[${#prune[@]}-1]'

    # Ein Durchlauf, drei Ergebnisse:
    #   * lesbare Dateien                   -> in die Dateiliste (-fprint)
    #   * nicht lesbare Dateien und Ordner  -> je eine "f"/"d"-Zeile auf
    #     stdout, die gezählt wird, damit die Zusammenfassung sagen kann,
    #     wie viel übersprungen wurde
    # -H: Ist SCAN_PATH selbst ein Symlink, wird ihm gefolgt (nur dem Startpunkt).
    counts=$(find -H "$SCAN_PATH" "${find_opts[@]}" \
                  \( "${prune[@]}" \) -prune -o \
                  -type d \( ! -readable -o ! -executable \) -printf 'd\n' -prune -o \
                  -type f \( -readable -fprint "$FILE_LIST" -o -printf 'f\n' \) \
                  2>/dev/null |
             awk '{ n[$0]++ } END { printf "%d %d\n", n["f"], n["d"] }')
    read -r SKIPPED_FILES SKIPPED_DIRS <<< "$counts"
    [[ "$SKIPPED_FILES" =~ ^[0-9]+$ ]] || SKIPPED_FILES=0
    [[ "$SKIPPED_DIRS"  =~ ^[0-9]+$ ]] || SKIPPED_DIRS=0
}

# ---------------------------------------------------------------------------
# Auswertung der Scannerausgabe (gemeinsam für beide Scan-Pfade)
# ---------------------------------------------------------------------------

# Wertet eine Ausgabezeile von clamscan/clamdscan aus.
#   $1 = die Zeile (CR bereits entfernt), $2 = ihre Quelle (Paketdatei oder
#        "serial"), damit der Zusammenfassungsblock je Quelle getrennt
#        verfolgt wird.
# Ändert scanned/infected/errors/last_file/IN_SUMMARY aus perform_scan
# (Bash-Scoping: eine Funktion sieht die "local"-Variablen aller
# Funktionen, aus denen heraus sie aufgerufen wurde).
handle_output_line() {
    local line=$1 src=$2
    case "$line" in
        *"SCAN SUMMARY"*) IN_SUMMARY[$src]=true;  return ;;
        "Time:"*)         IN_SUMMARY[$src]=false; return ;;
        /*:\ *)           IN_SUMMARY[$src]=false ;;
    esac
    [ "${IN_SUMMARY[$src]:-false}" = true ] && return

    case "$line" in
        *"PAKET-ABBRUCH ("*|"Stehengeblieben bei:"*|"Komplette Paketliste"*)
            printf '\r%s%s%s%s\n' "$CLREOL" "$YELLOW" "$line" "$RESET"
            printf '%s\n' "$line" >> "$RESULTS_FILE"
            ;;
        # Reguläre Ergebnisse zuerst: Eine Datei, die "ERROR" oder
        # "Can't open" bloß im NAMEN trägt, darf nicht als Lesefehler zählen.
        /*": OK"|/*": Empty file")
            last_file=${line%: *}
            scanned=$(( scanned + 1 ))
            ;;
        *" FOUND")
            scanned=$(( scanned + 1 )); infected=$(( infected + 1 ))
            printf '\r%s%s%s%s\n' "$CLREOL" "$RED" "$line" "$RESET"
            printf '%s\n' "$line" >> "$RESULTS_FILE"
            ;;
        *ERROR*|*"Access denied"*|*"Can't open"*|*"Can't access"*)
            # Auch nicht lesbare Dateien sind abgearbeitet — sonst erreicht
            # der Balken nie 100 %.
            scanned=$(( scanned + 1 )); errors=$(( errors + 1 ))
            printf '%s\n' "$line" >> "$RESULTS_FILE"
            ;;
        LibClamAV*|WARNING*|Loading*|"Session terminated"*|"")
            : # Vorlauf- und Statusmeldungen ignorieren
            ;;
        /*:\ *)
            last_file=${line%: *}
            scanned=$(( scanned + 1 ))
            ;;
    esac
}

# ---------------------------------------------------------------------------
# Der eigentliche Scan
# ---------------------------------------------------------------------------

perform_scan() {
    local flags=() use_clamdscan=false total=0 ans action confirm

    # Zustand eines vorherigen Scans in dieser Sitzung zurücksetzen
    QUARANTINE_DIR=""; RESULTS_FILE=""; SKIPPED_FILES=0; SKIPPED_DIRS=0

    update_signatures

    # --- Umgang mit Funden ---------------------------------------------------
    echo
    echo "Was soll mit infizierten Dateien geschehen?"
    echo "  1) Nur melden (empfohlen)"
    echo "  2) In Quarantäne verschieben"
    echo "  3) Löschen (${RED}unwiderruflich${RESET})"
    action=$(ask_line "Auswahl [1]: ")
    case "${action:-1}" in
        2)
            QUARANTINE_DIR="$QUARANTINE_PATH"
            mkdir -p "$QUARANTINE_DIR" 2>/dev/null || as_root mkdir -p "$QUARANTINE_DIR"
            chmod 700 "$QUARANTINE_DIR" 2>/dev/null || as_root chmod 700 "$QUARANTINE_DIR"
            [ "$EUID" -eq 0 ] && chown "$APP_USER:" "$QUARANTINE_DIR" 2>/dev/null
            flags+=( "--move=$QUARANTINE_DIR" )
            echo "Funde werden nach $QUARANTINE_DIR verschoben."
            ;;
        3)
            echo
            echo "${RED}${BOLD}Achtung:${RESET} ClamAV produziert regelmäßig Fehlalarme."
            echo "Beim Löschen im Systemscan können funktionierende Systemdateien zerstört werden."
            confirm=$(ask_line "Zum Bestätigen bitte LOESCHEN eingeben: ")
            if [ "$confirm" = "LOESCHEN" ]; then
                flags+=( --remove )
                echo "Funde werden gelöscht."
            else
                echo "Nicht bestätigt — es wird nur gemeldet."
            fi
            ;;
        *)
            echo "Funde werden nur protokolliert."
            ;;
    esac

    # --- Daemon oder Einzelprozess ------------------------------------------
    if check_command clamdscan; then
        echo
        if ask_yes_no "clamdscan verwenden (Daemon, deutlich schneller)?" j; then
            if start_clamd_if_needed; then
                use_clamdscan=true
            else
                echo "Fallback auf clamscan."
            fi
        fi
    fi
    if [ "$use_clamdscan" = false ] && ! check_command clamscan; then
        echo "${RED}Weder ein erreichbarer clamd noch clamscan verfügbar. Abbruch.${RESET}"
        return 1
    fi

    # --- Scannerspezifische Optionen -----------------------------------------
    if [ "$use_clamdscan" = false ]; then
        echo
        ask_yes_no "Archive überspringen (schneller, aber unvollständig)?" n &&
            flags+=( --scan-archive=no )

        # Standard ist 100 MB — größere Dateien würden sonst still übersprungen
        flags+=( --max-filesize=1000M --max-scansize=1000M )
        flags+=( --stdout )
    else
        # clamdscan kennt weder --exclude-dir noch --max-filesize; die Limits
        # stehen in /etc/clamav/clamd.conf. Ausschlüsse macht die Dateiliste.
        # Kein -m: Multiscan öffnet innerhalb EINER Verbindung sehr viele
        # Dateideskriptoren gleichzeitig und ist die wahrscheinlichste Ursache
        # für Hänger. Parallelität kommt stattdessen über mehrere
        # unabhängige clamdscan-Prozesse (siehe THREADS unten) — jeder hält
        # jeweils nur einen Deskriptor offen, genau das Modell, für das clamd
        # mit MaxThreads ausgelegt ist.
        flags+=( --fdpass --stdout )

        # --- Parallelität: Threads automatisch erkennen ----------------------
        local detected
        detected=$(nproc 2>/dev/null || echo 1)
        echo
        ans=$(ask_line "Parallele clamdscan-Verbindungen [erkannt: $detected]: ")
        if [[ "$ans" =~ ^[0-9]+$ ]] && [ "$ans" -ge 1 ]; then
            THREADS="$ans"
        else
            THREADS="$detected"
        fi
        echo "Verwende $THREADS parallele Verbindungen."

        # Bestmöglicher Hinweis, falls clamd selbst weniger gleichzeitige
        # Verbindungen erlaubt (MaxThreads in clamd.conf). Die Datei ist meist
        # nur für root lesbar — schlägt der Zugriff fehl, wird der Hinweis
        # einfach ausgelassen.
        local conf maxthreads
        for conf in /etc/clamav/clamd.conf /etc/clamd.d/scan.conf; do
            [ -r "$conf" ] || continue
            maxthreads=$(awk '/^[[:space:]]*MaxThreads/{print $2; exit}' "$conf")
            if [[ "${maxthreads:-}" =~ ^[0-9]+$ ]] && [ "$THREADS" -gt "$maxthreads" ]; then
                echo "${YELLOW}Hinweis:${RESET} clamd erlaubt laut $conf nur $maxthreads gleichzeitige"
                echo "Verbindungen (MaxThreads). Überzählige Anfragen werden verzögert bearbeitet,"
                echo "nicht abgelehnt — es funktioniert also, nutzt aber nicht alle $THREADS Verbindungen aus."
            fi
            break
        done
    fi

    # --- Umfang --------------------------------------------------------------
    echo
    if ask_yes_no "Auch eingehängte Dateisysteme mitscannen (z.B. separates /home, Btrfs-Subvolumes, USB)?" n; then
        CROSS_DEVICE=true
    else
        CROSS_DEVICE=false
    fi

    # --- Dateiliste ----------------------------------------------------------
    FILE_LIST=$(mktemp)
    echo
    echo "Erfasse Dateien (kann bei großen Volumes dauern) ..."
    build_file_list

    total=$(wc -l < "$FILE_LIST")
    echo "Zu scannen: $total Dateien"
    if [ $(( SKIPPED_FILES + SKIPPED_DIRS )) -gt 0 ]; then
        echo "${YELLOW}Nicht lesbar, übersprungen:${RESET} $SKIPPED_FILES Dateien, $SKIPPED_DIRS Verzeichnisse"
    fi
    if [ "$total" -eq 0 ]; then
        echo "Nichts zu scannen."
        return 0
    fi

    # --- Logdatei ------------------------------------------------------------
    RESULTS_FILE="$HOME_DIR/clamav_scan_$(date +%Y%m%d_%H%M%S).log"
    {
        echo "ClamAV-Scan gestartet: $(date)"
        echo "Skriptversion: $VERSION"
        echo "Pfad:     $SCAN_PATH"
        echo "Umfang:   $([ "$CROSS_DEVICE" = true ] && echo "inkl. eingehängter Dateisysteme" || echo "nur eigenes Dateisystem (-xdev)")"
        echo "Scanner:  $([ "$use_clamdscan" = true ] && echo clamdscan || echo clamscan)"
        echo "Flags:    ${flags[*]}"
        [ "$use_clamdscan" = true ] && echo "Threads:  $THREADS"
        echo "Dateien:  $total"
        echo "Übersprungen: $SKIPPED_FILES Dateien, $SKIPPED_DIRS Verzeichnisse (nicht lesbar)"
        echo "-------------------------------------------"
    } > "$RESULTS_FILE"

    local scanned=0 infected=0 errors=0 last_file="" scanner
    local -A IN_SUMMARY=()
    scanner=clamscan
    [ "$use_clamdscan" = true ] && scanner=clamdscan

    echo
    [ "$use_clamdscan" = false ] && echo "Lade Signaturdatenbank (dauert 20–40 Sekunden) ..."
    echo "Scan läuft — Abbruch mit Strg+C."
    printf '%s' "$HIDE"

    local rc=0 f v
    SCAN_START=$SECONDS

    if [ "$use_clamdscan" = true ]; then
        # --- Paralleler clamdscan-Pfad ----------------------------------------
        CHUNK_DIR=$(mktemp -d)
        # -a 4: Suffixlänge 4 statt 2 — sonst ist bei mehr als 676 Paketen
        # (also ~1,35 Mio. Dateien) Schluss und split bricht ab.
        split -a 4 -l "$CHUNK_SIZE" "$FILE_LIST" "$CHUNK_DIR/part_"
        # Die Menge der Pakete steht ab hier fest. "part_????" trifft nur die
        # Pakete selbst (4-stelliges Suffix), nicht die später angelegten
        # .out/.rc/.pid-Dateien.
        local -a CHUNKS=( "$CHUNK_DIR"/part_???? )

        # Jeder Worker scannt genau ein Paket über eine eigene Verbindung und
        # schreibt in seine eigene Ausgabedatei statt auf ein gemeinsames
        # stdout — sonst könnten sich die Zeilen mehrerer gleichzeitig
        # schreibender Prozesse mitten in der Zeile vermischen. "wait -n"
        # hält höchstens $THREADS Worker gleichzeitig am Laufen, ohne dass
        # dafür GNU parallel oder xargs -P nötig wäre.
        run_scanner_parallel() {
            local chunk c active=0
            for chunk in "${CHUNKS[@]}"; do
                (
                    local wrc tpid done_n=0 total_n suspect saved ln reason=""
                    printf -v c '%q ' "$scanner" "${flags[@]}" "--file-list=$chunk"

                    # Im Hintergrund starten und die PID hinterlegen, damit der
                    # Monitor das Paket bei Stillstand gezielt beenden kann.
                    # SHELL: 'script' führt den Befehl über $SHELL aus, und das
                    # %q-Quoting oben ist Bash-Syntax — mit fish oder einer
                    # anderen Login-Shell könnte es falsch gelesen werden.
                    if check_command script; then
                        SHELL="$BASH" timeout -k 30 "$BATCH_TIMEOUT" script -qfec "$c" /dev/null \
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

                    # Abgebrochen? Die Stillstandsmarke des Monitors ist das
                    # verlässliche Signal — der Exit-Code nach einem Kill hängt
                    # davon ab, wie script und die Shell das Signal melden.
                    # Ohne Marke heißt 124 (bzw. 137, falls timeout SIGKILL
                    # brauchte) absolute Obergrenze. Alles andere ist ein
                    # normales Ende.
                    if [ -f "$chunk.stalled" ]; then
                        reason="kein Fortschritt seit ${STALL_TIMEOUT}s"
                    elif [ "$wrc" -eq 124 ] || [ "$wrc" -eq 137 ]; then
                        reason="absolute Obergrenze erreicht"
                    fi
                    if [ -n "$reason" ]; then
                        # Zahl der bereits geschriebenen Ergebniszeilen =
                        # Dateien, die fertig wurden. Die nächste Zeile der
                        # Paketliste ist die, an der es stehenblieb.
                        while IFS= read -r ln; do
                            ln=${ln%$'\r'}
                            case "$ln" in
                                LibClamAV*|WARNING*|Loading*|"Session terminated"*|"") : ;;
                                *) done_n=$(( done_n + 1 )) ;;
                            esac
                        done < "$chunk.out"
                        total_n=$(wc -l < "$chunk")
                        suspect=$(sed -n "$((done_n + 1))p" "$chunk")
                        saved="$HOME_DIR/clamav_abbruch_$(basename "$chunk")_$(date +%H%M%S).list"
                        if cp "$chunk" "$saved" 2>/dev/null; then
                            [ "$EUID" -eq 0 ] && chown "$APP_USER:" "$saved" 2>/dev/null
                        fi
                        {
                            printf '\nPAKET-ABBRUCH (%s): %d/%d Dateien geschafft\n' \
                                "$reason" "$done_n" "$total_n"
                            printf 'Stehengeblieben bei: %s\n' "${suspect:-unbekannt}"
                            printf 'Komplette Paketliste gesichert unter: %s\n' "$saved"
                        } >> "$chunk.out"
                        wrc=2
                    fi
                    echo "$wrc" > "$chunk.rc"
                # Alle Nutzdaten der Worker landen in $chunk.out/.rc/.pid.
                # Was sonst noch auf stdout/stderr fällt, sind nur
                # Abbruchmeldungen der Shell selbst — die würden mitten in
                # den Fortschrittsbalken schreiben.
                ) >/dev/null 2>&1 &
                active=$(( active + 1 ))
                if [ "$active" -ge "$THREADS" ]; then
                    wait -n
                    active=$(( active - 1 ))
                fi
            done
            wait
        }

        # Liest bei jedem Aufruf nur die seit dem letzten Mal neu
        # hinzugekommenen VOLLSTÄNDIGEN Zeilen einer Datei nach. "wc -l"
        # zählt ausschließlich zeilenendenterminierte Zeilen — eine gerade
        # erst angefangene letzte Zeile ohne \n wird also nicht mitgezählt
        # und automatisch bis zum nächsten Durchlauf zurückgestellt. Damit
        # entfällt jede manuelle Verwaltung unvollständiger Zeilenreste.
        poll_chunk_outputs() {
            local chunk out_file new_total prev line finished
            for chunk in "${CHUNKS[@]}"; do
                # Fertige Pakete werden nie wieder angefasst — sonst kostet
                # jeder Poll ein wc pro Paket, gegen Ende eines großen Scans
                # also Hunderte Prozessstarts pro Sekunde.
                [ -n "${DONE_CHUNKS[$chunk]:-}" ] && continue
                out_file="$chunk.out"
                [ -f "$out_file" ] || continue
                # .rc wird erst nach der letzten Ausgabezeile geschrieben.
                # Existiert sie JETZT, ist das unten Gelesene die komplette
                # Ausgabe.
                finished=false
                [ -f "$chunk.rc" ] && finished=true
                new_total=$(wc -l < "$out_file" 2>/dev/null) || new_total=0
                prev=${SEEN_LINES[$chunk]:-0}
                if [ "$new_total" -gt "$prev" ]; then
                    while IFS= read -r line; do
                        # 'script' liefert CRLF — ohne das Abschneiden hier
                        # matcht z.B. das Muster '*" FOUND"' nicht mehr, weil
                        # die Zeile dann auf "FOUND\r" endet.
                        handle_output_line "${line%$'\r'}" "$chunk"
                    done < <(sed -n "$((prev + 1)),${new_total}p" "$out_file")
                    SEEN_LINES[$chunk]=$new_total
                    LAST_GROWTH[$chunk]=$SECONDS   # Zeitpunkt des letzten Fortschritts
                fi
                [ "$finished" = true ] && DONE_CHUNKS[$chunk]=1
            done
        }

        # Beendet Pakete, die seit STALL_TIMEOUT Sekunden keine einzige neue
        # Ergebniszeile mehr geschrieben haben. Ein Paket, das langsam aber
        # stetig vorankommt, wird dadurch nie abgebrochen — egal wie lange es
        # insgesamt braucht.
        check_stalled_chunks() {
            local chunk pid age
            for chunk in "${CHUNKS[@]}"; do
                [ -n "${DONE_CHUNKS[$chunk]:-}" ] && continue
                [ -f "$chunk.pid" ] || continue       # läuft nicht (mehr)
                [ -f "$chunk.rc"  ] && continue       # schon abgeschlossen
                [ -f "$chunk.stalled" ] && continue   # bereits abgebrochen
                # Beim ersten Sichten die Uhr stellen, damit auch ein Paket
                # erkannt wird, das von Anfang an gar nichts ausgibt.
                : "${LAST_GROWTH[$chunk]:=$SECONDS}"
                age=$(( SECONDS - LAST_GROWTH[$chunk] ))
                [ "$age" -lt "$STALL_TIMEOUT" ] && continue

                pid=$(cat "$chunk.pid" 2>/dev/null) || continue
                [ -n "$pid" ] || continue
                : > "$chunk.stalled"
                # Erst die Kinder von 'timeout' (also script/clamdscan), dann
                # 'timeout' selbst — sonst überlebt der eigentliche Scanner.
                check_command pkill && pkill -TERM -P "$pid" 2>/dev/null
                kill -TERM "$pid" 2>/dev/null
            done
        }

        monitor_parallel() {
            local run_pid=$1
            declare -A SEEN_LINES LAST_GROWTH DONE_CHUNKS
            while :; do
                poll_chunk_outputs
                check_stalled_chunks
                draw_progress_bar "$scanned" "$total" "$infected"
                kill -0 "$run_pid" 2>/dev/null || break
                sleep 1
            done
            poll_chunk_outputs   # letzter Rest nach Prozessende
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
        # --- Serieller clamscan-Pfad ------------------------------------------
        # clamscan lädt die Signaturdatenbank bei jedem Start neu — ein
        # einziger Aufruf mit der kompletten Liste ist hier also richtig;
        # anders als bei clamdscan gibt es nichts zu parallelisieren, ohne
        # dafür mehrfach RAM und Ladezeit zu bezahlen.
        run_scanner() {
            local c wrc
            printf -v c '%q ' "$scanner" "${flags[@]}" "--file-list=$FILE_LIST"
            if check_command script; then
                SHELL="$BASH" script -qfec "$c" /dev/null < /dev/null
            else
                stdbuf -oL "$scanner" "${flags[@]}" "--file-list=$FILE_LIST" < /dev/null
            fi
            wrc=$?
            return "$wrc"
        }

        local line rc_read partial="" quiet_since=$SECONDS stalls=0
        RC_FILE=$(mktemp)

        # read -t 1: liefert Exit-Code > 128 bei Zeitüberschreitung, 1 bei
        # EOF. Der kurze Timeout lässt die Laufzeit weiterzählen, während
        # clamscan seine Datenbank lädt oder an einer großen Datei arbeitet,
        # und nach 2 Minuten ganz ohne Ausgabe fällt auf, dass clamscan sich
        # an einer Datei festbeißt, statt dass der Balken kommentarlos
        # stehenbleibt.
        while :; do
            IFS= read -r -t 1 line; rc_read=$?
            if [ "$rc_read" -gt 128 ]; then
                # Bei Zeitüberschreitung legt read eine halb empfangene Zeile
                # in $line ab — aufheben, bis der Rest kommt.
                partial+=$line
                if (( SECONDS - quiet_since >= 120 )); then
                    quiet_since=$SECONDS
                    stalls=$(( stalls + 1 ))
                    printf '\r%s%sSeit 2 Minuten keine Ausgabe (%d.) — letzte Datei: %s%s\n' \
                        "$CLREOL" "$YELLOW" "$stalls" "${last_file:-?}" "$RESET"
                fi
                draw_progress_bar "$scanned" "$total" "$infected"
                continue
            fi
            [ "$rc_read" -ne 0 ] && break

            line=$partial$line; partial=""
            quiet_since=$SECONDS
            handle_output_line "${line%$'\r'}" serial

            # alle 20 Dateien neu zeichnen, mindestens aber einmal pro Sekunde
            if (( scanned % 20 == 0 || SECONDS != LAST_DRAW )); then
                draw_progress_bar "$scanned" "$total" "$infected"
            fi
        done < <( { run_scanner; echo $? > "$RC_FILE"; } 2>&1 )

        rc=$(cat "$RC_FILE" 2>/dev/null)
        [[ "$rc" =~ ^[0-9]+$ ]] || rc=2
    fi

    draw_progress_bar "$scanned" "$total" "$infected"
    printf '%s' "$SHOW"
    echo; echo

    # --- Zusammenfassung -----------------------------------------------------
    local duration result
    fmt_duration duration $(( SECONDS - SCAN_START ))
    # Funde haben Vorrang vor dem Exit-Code: Eine einzige nicht lesbare Datei
    # in irgendeinem Paket hebt den Gesamt-Exit-Code auf 2 und würde die
    # Funde sonst hinter "mit Fehlern beendet" verstecken.
    if [ "$infected" -gt 0 ] || [ "$rc" -eq 1 ]; then
        result="${RED}Schadsoftware gefunden${RESET}"
        [ "$rc" -ge 2 ] && result+=" ${YELLOW}(zusätzlich Fehler, Exit-Code $rc)${RESET}"
    elif [ "$rc" -eq 0 ]; then
        result="${GREEN}sauber${RESET}"
    else
        result="${YELLOW}mit Fehlern beendet (Exit-Code $rc)${RESET}"
    fi

    echo "-------------------------------------------"
    echo "Geprüfte Dateien: $scanned von $total"
    echo "Funde:             $infected"
    echo "Lesefehler:        $errors"
    echo "Dauer:             $duration"
    echo "Ergebnis: $result"
    echo "Protokoll: $RESULTS_FILE"
    [ -n "$QUARANTINE_DIR" ] && echo "Quarantäne: $QUARANTINE_DIR"

    {
        echo "-------------------------------------------"
        echo "Geprüft: $scanned von $total"
        echo "Funde:    $infected"
        echo "Fehler:   $errors"
        echo "Dauer:    $duration"
        echo "Exit-Code: $rc"
        echo "Beendet: $(date)"
    } >> "$RESULTS_FILE"

    # Ohne root lässt find Nicht-Lesbares schon beim Erfassen weg — die
    # Lesefehler allein würden also untertreiben, wie unvollständig der
    # Scan ist.
    if [ "$EUID" -ne 0 ] && [ $(( errors + SKIPPED_FILES + SKIPPED_DIRS )) -gt 0 ]; then
        echo
        echo "${YELLOW}Hinweis:${RESET} Nicht alles war lesbar ($errors Lesefehler;"
        echo "übersprungen: $SKIPPED_FILES Dateien, $SKIPPED_DIRS Verzeichnisse)."
        echo "Für einen vollständigen Systemscan das Skript mit sudo starten."
    fi
    return 0
}

# Führt einen Scan aus und räumt danach immer auf — egal, auf welchem Weg
# perform_scan zurückkehrt.
run_scan() {
    local rc
    perform_scan
    rc=$?
    finish_scan
    return "$rc"
}

# ---------------------------------------------------------------------------
# Hauptschleife
# ---------------------------------------------------------------------------

SCAN_PATH=""
SCAN_START=$SECONDS

while true; do
    show_main_menu
    if ! read -r choice; then
        echo; echo "Beendet."
        exit 0
    fi
    case "$choice" in
        1)
            if [ "$EUID" -ne 0 ]; then
                echo "${YELLOW}Ein Systemscan ohne root liest die meisten Dateien nicht.${RESET}"
                ask_yes_no "Trotzdem fortfahren?" n || continue
            fi
            SCAN_PATH="/"
            run_scan
            ;;
        2) select_external_drive && run_scan ;;
        3) select_custom_path   && run_scan ;;
        4) echo "Beendet."; exit 0 ;;
        *) echo "Ungültige Eingabe. Bitte 1–4 wählen." ;;
    esac
done
