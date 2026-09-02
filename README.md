# ClamAV Interactive Scan

Ein interaktives Bash-Frontend für ClamAV mit Live-Fortschrittsbalken, parallelem
`clamdscan` und Hänger-Erkennung.
*An interactive Bash front-end for ClamAV with a live progress bar, parallel
`clamdscan` and stall detection.*

🇩🇪 [Deutsche Dokumentation](#deutsch) · 🇬🇧 [English documentation](#english)

| Datei / File      | Sprache / Language          |
| ----------------- | --------------------------- |
| `antivirus.sh`    | Deutsche Oberfläche         |
| `antivirus-en.sh` | English user interface      |

Beide Dateien sind funktional identisch — nur Texte und Kommentare unterscheiden sich.
*Both files are functionally identical — only texts and comments differ.*

---

<a id="deutsch"></a>

## Deutsch

### Warum dieses Skript?

`clamscan` auf ein komplettes System loszulassen ist unangenehm: Es gibt keinen
Fortschritt, keine Zeitschätzung, es läuft in `/proc/kcore` hinein und bleibt bei
einzelnen Dateien gerne minutenlang oder dauerhaft hängen. `clamdscan` ist deutlich
schneller, kann aber weder Verzeichnisse ausschließen noch parallel arbeiten.

Dieses Skript legt eine Bedienoberfläche darüber:

* **Live-Fortschrittsbalken** mit Prozent, Dateizähler, Trefferzahl und Laufzeit —
  gespeist aus der laufenden ClamAV-Ausgabe, ohne zweiten Verzeichnisdurchlauf.
* **Paralleler `clamdscan`-Modus**: Die Dateiliste wird in Pakete zerlegt, die von
  mehreren unabhängigen `clamdscan`-Prozessen gleichzeitig abgearbeitet werden.
* **Hänger-Erkennung**: Ein Paket, das seit `STALL_TIMEOUT` Sekunden keine einzige
  neue Ergebniszeile schreibt, wird gezielt beendet — und das Skript sagt genau,
  **bei welcher Datei** es stehengeblieben ist.
* **Explizite Dateiliste** statt rohem Pfad: Pseudo-Dateisysteme (`/proc`, `/sys`,
  `/dev`, `/run`, `/snap`) und eigene Ausschlüsse werden sicher übersprungen.
* **Automatische Vorbereitung**: Signatur-Update, Start von `clamd`, Erkennung der
  Distribution und optionale Installation von ClamAV.
* **Sauberer Abbruch**: Strg+C beendet die komplette Prozesshierarchie und räumt
  temporäre Dateien auf.

### Beispielausgabe

```
====================================
   ClamAV — interaktiver Scan v1.1.0
====================================
1) Internes System scannen (/)
2) Externes Laufwerk scannen
3) Beliebiges Verzeichnis scannen
4) Beenden
Auswahl: 1

Virensignaturen aktualisieren? [J/n]: j
...
Erfasse Dateien (kann bei großen Volumes dauern) ...
Zu scannen: 612483 Dateien

Scan läuft — Abbruch mit Strg+C.
/home/user/Downloads/test.exe: Win.Test.EICAR_HDB-1 FOUND
[##############################----------]  74% (453901/612483) — 1 Fund(e) — 41:07
```

### Voraussetzungen

| Komponente         | Anmerkung                                                     |
| ------------------ | ------------------------------------------------------------- |
| **Bash ≥ 4.4**     | wegen assoziativer Arrays, `wait -n` und `mapfile -d`          |
| **ClamAV**         | `clamscan` und/oder `clamdscan` (+ `clamav-daemon` empfohlen)  |
| **coreutils**      | `split`, `timeout`, `stdbuf`, `nproc`, `wc`, `sed`             |
| **findutils**      | GNU `find` (`-readable`, `-xdev`, `-print0`)                   |
| **procps**         | `pkill` — ohne das Paket funktioniert der Abbruch weniger sauber |
| **util-linux**     | `script` (optional, erzwingt zeilenweise Ausgabe von ClamAV)   |
| **systemd**        | optional, für Start/Stopp von `clamav-daemon` und `freshclam`  |
| **sudo**           | optional; als root läuft das Skript auch ohne                  |

Getestet unter Debian/Ubuntu; Fedora, Arch und openSUSE werden bei der Installation
und beim Dienststart mit berücksichtigt.

### Installation

```bash
git clone https://github.com/bluhtsturm/clamav-interactive-scan.git
cd clamav-interactive-scan
chmod +x antivirus.sh antivirus-en.sh
```

ClamAV selbst kann das Skript beim ersten Start installieren; manuell etwa so:

```bash
sudo apt install clamav clamav-daemon      # Debian/Ubuntu
sudo dnf install clamav clamav-update clamd # Fedora
sudo pacman -S clamav                       # Arch
sudo zypper install clamav                  # openSUSE
```

Optional systemweit verfügbar machen:

```bash
sudo install -m 755 antivirus.sh /usr/local/bin/antivirus
```

### Benutzung

```bash
./antivirus.sh          # Benutzerkontext: liest nur, was der eigene Account darf
sudo ./antivirus.sh     # empfohlen für den Systemscan (/)
```

Das Skript führt durch folgende Fragen:

1. **Was soll gescannt werden?** System (`/`), externes Laufwerk (aus
   `/media/$USER` bzw. `/run/media/$USER`) oder ein beliebiger Pfad.
2. **Signaturen aktualisieren?** Stoppt bei Bedarf `clamav-freshclam`, ruft
   `freshclam` auf und startet den Dienst danach wieder.
3. **Umgang mit Funden:** nur melden (Standard), in Quarantäne verschieben oder
   löschen. Löschen muss durch Eintippen von `LOESCHEN` (englische Fassung:
   `DELETE`) bestätigt werden.
4. **`clamdscan` verwenden?** Startet `clamd` bei Bedarf und wartet, bis der
   Daemon antwortet. Schlägt das fehl, wird automatisch auf `clamscan`
   zurückgefallen.
5. **Parallele Verbindungen** (nur `clamdscan`): Vorgabe ist `nproc`.
6. **Auch eingehängte Dateisysteme?** Ohne diese Option bleibt der Scan per
   `-xdev` auf dem Dateisystem des Startpfads — ein separat eingehängtes `/home`
   wird dann **nicht** mitgescannt.

Abbruch jederzeit mit **Strg+C**: Worker werden beendet, Temporärdateien gelöscht,
das bisherige Protokoll bleibt erhalten.

### Wie der parallele Scan funktioniert

```
   find -> Dateiliste
              |
        split -l CHUNK_SIZE
              |
   part_aaaa  part_aaab  part_aaac ...      (Pakete)
        |          |          |
   clamdscan  clamdscan  clamdscan          (max. THREADS gleichzeitig)
        |          |          |
   part_*.out  part_*.out  part_*.out       (je eigene Ausgabedatei)
              |
        Monitor-Schleife (1 s Takt)
        - liest neue Zeilen nach
        - zeichnet den Fortschrittsbalken
        - erkennt Pakete ohne Fortschritt
```

Wichtige Entscheidungen dahinter:

* **Kein `clamdscan -m` (Multiscan).** Multiscan öffnet innerhalb *einer*
  Verbindung sehr viele Dateideskriptoren gleichzeitig und ist die
  wahrscheinlichste Ursache für Hänger. Stattdessen laufen mehrere unabhängige
  Prozesse — genau das Modell, für das `clamd` mit `MaxThreads` ausgelegt ist.
* **Jeder Worker schreibt in eine eigene Datei.** Auf gemeinsamem stdout können
  sich Zeilen mehrerer Prozesse mitten in der Zeile vermischen.
* **Fortschritt statt Gesamtdauer als Kriterium.** Ein langsamer Rechner darf
  beliebig lange brauchen, solange überhaupt etwas passiert. Nur echter
  Stillstand wird abgebrochen.
* **Nur vollständige Zeilen werden ausgewertet.** `wc -l` zählt ausschließlich
  zeilenendenterminierte Zeilen; eine gerade erst begonnene Zeile wird
  automatisch bis zum nächsten Durchlauf zurückgestellt.

### Konfiguration

Am Kopf des Skripts:

| Variable          | Standard | Bedeutung                                                          |
| ----------------- | -------- | ------------------------------------------------------------------ |
| `CHUNK_SIZE`      | `2000`   | Dateien pro Paket. Kleiner = feinerer Fortschritt, mehr Prozessstarts |
| `STALL_TIMEOUT`   | `900`    | Sekunden ohne neue Ergebniszeile, ab denen ein Paket als hängend gilt |
| `BATCH_TIMEOUT`   | `28800`  | absolute Obergrenze pro Paket (Notnagel, sollte nie greifen)        |
| `EXCLUDE_PATHS`   | leer     | zusätzliche Pfade, die immer übersprungen werden                    |
| `PSEUDO_PATHS`    | `/proc /sys /dev /run /snap` | Pseudo-Dateisysteme, nie scannen                |

Beispiel für Wine-/Proton-/Steam-Installationen, die aus zehntausenden winzigen
Dateien bestehen und einen Systemscan enorm ausbremsen:

```bash
EXCLUDE_PATHS=(
    /opt/wine-staging
    "$HOME/.wine"
    "$HOME/.steam"
    "$HOME/.local/share/Steam"
)
```

### Ergebnisse

* **Protokoll:** `~/clamav_scan_JJJJMMTT_HHMMSS.log` — Kopfzeilen mit Pfad,
  Scanner, Flags und Dateizahl, danach alle Funde und Lesefehler sowie eine
  Zusammenfassung. Wird nach dem Lauf dem aufrufenden Benutzer übereignet, auch
  wenn das Skript unter `sudo` lief.
* **Quarantäne:** `~/clamav_quarantine`, Rechte `700`.
* **Abgebrochene Pakete:** `~/clamav_abbruch_part_XXXX_HHMMSS.list` — die
  vollständige Dateiliste des Pakets, damit sich der Rest gezielt nachscannen
  lässt:

  ```bash
  clamdscan --fdpass --file-list=~/clamav_abbruch_part_aaad_141233.list
  ```

### Exit-Codes

| Code | Bedeutung                                             |
| ---- | ----------------------------------------------------- |
| `0`  | sauber                                                |
| `1`  | Schadsoftware gefunden                                |
| `2`  | mit Fehlern beendet (u. a. abgebrochene Pakete)       |
| `130`| durch Strg+C abgebrochen                              |

### Fehlerbehebung

**„clamd antwortet nicht.“**
Der Daemon lädt beim Start ~30–60 s die Signaturdatenbank. Prüfen mit
`systemctl status clamav-daemon` und `clamdscan --ping 3`. Bei wenig RAM
(< 1,5 GB frei) startet `clamd` unter Umständen gar nicht.

**Hinweis zu `MaxThreads`**
Erlaubt `clamd` weniger gleichzeitige Verbindungen als angefragt, werden
überzählige Anfragen verzögert bearbeitet, nicht abgelehnt. Für mehr Durchsatz
`MaxThreads` in `/etc/clamav/clamd.conf` erhöhen und den Dienst neu starten.

**Pakete brechen wegen Stillstand ab**
Typisch bei Wine-/Proton-/Steam-Bäumen und sehr großen Archiven. Optionen:
betroffene Pfade in `EXCLUDE_PATHS` aufnehmen, `STALL_TIMEOUT` erhöhen,
`CHUNK_SIZE` verkleinern oder in `clamd.conf` die Limits (`MaxScanSize`,
`MaxFileSize`, `MaxRecursion`, `MaxFiles`) anpassen.

**Viele Lesefehler**
Ohne `sudo` sind die meisten Systemdateien nicht lesbar. Das Skript weist am Ende
darauf hin.

**Der Balken erreicht keine 100 %**
Erwartetes Verhalten, wenn Pakete abgebrochen wurden: deren restliche Dateien
werden nie gezählt. Die Zusammenfassung zeigt „geprüft X von Y“.

**Ein separates `/home` wird nicht gescannt**
`-xdev` ist Standard. Beim Umfang die Frage nach eingehängten Dateisystemen mit
`j` beantworten.

### Sicherheitshinweise

* **ClamAV produziert Fehlalarme.** Der Löschmodus kann funktionierende System-
  dateien zerstören. Im Zweifel „nur melden“ wählen und Funde bei
  [VirusTotal](https://www.virustotal.com/) gegenprüfen.
* Ein Fund heißt nicht automatisch „infiziertes System“ — häufig sind es
  Testdateien, Windows-Malware in Wine-Präfixen oder Beispiele in Mailarchiven.
* Der Quarantäneordner enthält weiterhin die Originaldateien. Er liegt mit
  Rechten `700` im Home-Verzeichnis, ist aber kein sicherer Container.

### Bekannte Grenzen

* Dateinamen mit Zeilenumbruch lassen sich über `--file-list` nicht übergeben
  (Einschränkung von ClamAV, nicht des Skripts).
* Kein Echtzeitschutz — das Skript ist ein On-Demand-Scanner.
* `clamdscan` nutzt die Limits aus `clamd.conf`; die Optionen `--max-filesize`
  und `--max-scansize` gelten nur im `clamscan`-Modus.
* Die Restlaufzeit wird nicht geschätzt, nur die bisherige Laufzeit angezeigt.

### Lizenz

MIT — siehe [LICENSE](LICENSE).

---

<a id="english"></a>

## English

### Why this script?

Turning `clamscan` loose on a whole system is unpleasant: no progress, no time
estimate, it walks into `/proc/kcore` and happily stalls on individual files for
minutes or forever. `clamdscan` is much faster but can neither exclude
directories nor work in parallel.

This script puts a usable front-end on top:

* **Live progress bar** with percentage, file counter, hit count and elapsed
  time — fed from ClamAV's running output, without a second directory traversal.
* **Parallel `clamdscan` mode**: the file list is split into chunks that several
  independent `clamdscan` processes work through at the same time.
* **Stall detection**: a chunk that has not written a single new result line for
  `STALL_TIMEOUT` seconds is terminated on purpose — and the script reports
  **exactly which file** it got stuck on.
* **Explicit file list** instead of a raw path: pseudo filesystems (`/proc`,
  `/sys`, `/dev`, `/run`, `/snap`) and your own exclusions are safely skipped.
* **Automatic preparation**: signature update, starting `clamd`, distribution
  detection and optional ClamAV installation.
* **Clean abort**: Ctrl+C terminates the whole process hierarchy and removes
  temporary files.

### Sample output

```
====================================
   ClamAV — interactive scan v1.1.0
====================================
1) Scan the internal system (/)
2) Scan an external drive
3) Scan an arbitrary directory
4) Quit
Choice: 1

Update virus signatures? [Y/n]: y
...
Collecting files (may take a while on large volumes) ...
To be scanned: 612483 files

Scan running — press Ctrl+C to abort.
/home/user/Downloads/test.exe: Win.Test.EICAR_HDB-1 FOUND
[##############################----------]  74% (453901/612483) — 1 hit(s) — 41:07
```

### Requirements

| Component        | Note                                                          |
| ---------------- | ------------------------------------------------------------- |
| **Bash ≥ 4.4**   | for associative arrays, `wait -n` and `mapfile -d`             |
| **ClamAV**       | `clamscan` and/or `clamdscan` (+ `clamav-daemon` recommended)  |
| **coreutils**    | `split`, `timeout`, `stdbuf`, `nproc`, `wc`, `sed`             |
| **findutils**    | GNU `find` (`-readable`, `-xdev`, `-print0`)                   |
| **procps**       | `pkill` — without it aborting is less clean                    |
| **util-linux**   | `script` (optional, forces line-buffered ClamAV output)        |
| **systemd**      | optional, to start/stop `clamav-daemon` and `freshclam`        |
| **sudo**         | optional; as root the script works without it                  |

Tested on Debian/Ubuntu; Fedora, Arch and openSUSE are handled for installation
and service startup.

### Installation

```bash
git clone https://github.com/bluhtsturm/clamav-interactive-scan.git
cd clamav-interactive-scan
chmod +x antivirus.sh antivirus-en.sh
```

The script can install ClamAV on first start; manually it is:

```bash
sudo apt install clamav clamav-daemon       # Debian/Ubuntu
sudo dnf install clamav clamav-update clamd # Fedora
sudo pacman -S clamav                       # Arch
sudo zypper install clamav                  # openSUSE
```

Optionally make it available system-wide:

```bash
sudo install -m 755 antivirus-en.sh /usr/local/bin/antivirus
```

### Usage

```bash
./antivirus-en.sh        # user context: reads only what your account may read
sudo ./antivirus-en.sh   # recommended for a system scan (/)
```

The script walks you through these questions:

1. **What to scan?** System (`/`), an external drive (from `/media/$USER` or
   `/run/media/$USER`) or an arbitrary path.
2. **Update signatures?** Stops `clamav-freshclam` if needed, runs `freshclam`
   and starts the service again afterwards.
3. **What to do with detections:** report only (default), move to quarantine or
   delete. Deleting must be confirmed by typing `DELETE` (German version:
   `LOESCHEN`).
4. **Use `clamdscan`?** Starts `clamd` if needed and waits until the daemon
   answers. If that fails it falls back to `clamscan` automatically.
5. **Parallel connections** (`clamdscan` only): defaults to `nproc`.
6. **Also scan mounted filesystems?** Without this the scan stays on the
   filesystem of the starting path via `-xdev` — a separately mounted `/home`
   is then **not** included.

Abort any time with **Ctrl+C**: workers are terminated, temporary files removed,
and the log written so far is kept.

### How the parallel scan works

```
   find -> file list
              |
        split -l CHUNK_SIZE
              |
   part_aaaa  part_aaab  part_aaac ...      (chunks)
        |          |          |
   clamdscan  clamdscan  clamdscan          (at most THREADS at a time)
        |          |          |
   part_*.out  part_*.out  part_*.out       (one output file each)
              |
        monitor loop (1 s tick)
        - reads new lines
        - draws the progress bar
        - detects chunks without progress
```

The reasoning behind it:

* **No `clamdscan -m` (multiscan).** Multiscan opens a very large number of file
  descriptors within a *single* connection and is the most likely cause of
  hangs. Several independent processes are used instead — exactly the model
  `clamd`'s `MaxThreads` is designed for.
* **Each worker writes to its own file.** On a shared stdout, lines from several
  processes can interleave mid-line.
* **Progress, not total runtime, is the criterion.** A slow machine may take as
  long as it likes as long as something is happening. Only genuine standstill is
  aborted.
* **Only complete lines are evaluated.** `wc -l` counts newline-terminated lines
  only, so a line that has just been started is automatically deferred to the
  next round.

### Configuration

At the top of the script:

| Variable        | Default  | Meaning                                                        |
| --------------- | -------- | -------------------------------------------------------------- |
| `CHUNK_SIZE`    | `2000`   | files per chunk. Smaller = finer progress, more process starts  |
| `STALL_TIMEOUT` | `900`    | seconds without a new result line before a chunk counts as stuck |
| `BATCH_TIMEOUT` | `28800`  | absolute limit per chunk (last resort, should never trigger)    |
| `EXCLUDE_PATHS` | empty    | additional paths that are always skipped                        |
| `PSEUDO_PATHS`  | `/proc /sys /dev /run /snap` | pseudo filesystems, never scanned           |

Example for Wine/Proton/Steam installations, which consist of tens of thousands
of tiny files and slow a system scan down enormously:

```bash
EXCLUDE_PATHS=(
    /opt/wine-staging
    "$HOME/.wine"
    "$HOME/.steam"
    "$HOME/.local/share/Steam"
)
```

### Results

* **Log:** `~/clamav_scan_YYYYMMDD_HHMMSS.log` — header with path, scanner,
  flags and file count, then every detection and read error plus a summary.
  Ownership is handed to the calling user after the run, even when the script
  ran under `sudo`.
* **Quarantine:** `~/clamav_quarantine`, mode `700`.
* **Aborted chunks:** `~/clamav_aborted_part_XXXX_HHMMSS.list` — the complete
  file list of that chunk, so the remainder can be rescanned deliberately:

  ```bash
  clamdscan --fdpass --file-list=~/clamav_aborted_part_aaad_141233.list
  ```

### Exit codes

| Code  | Meaning                                        |
| ----- | ---------------------------------------------- |
| `0`   | clean                                          |
| `1`   | malware found                                  |
| `2`   | finished with errors (including aborted chunks)|
| `130` | aborted with Ctrl+C                            |

### Troubleshooting

**"clamd is not responding."**
The daemon needs ~30–60 s to load the signature database at startup. Check with
`systemctl status clamav-daemon` and `clamdscan --ping 3`. With little RAM
(< 1.5 GB free) `clamd` may not start at all.

**The `MaxThreads` note**
If `clamd` allows fewer concurrent connections than requested, excess requests
are queued rather than rejected. For more throughput raise `MaxThreads` in
`/etc/clamav/clamd.conf` and restart the service.

**Chunks abort because of a stall**
Typical for Wine/Proton/Steam trees and very large archives. Options: add the
affected paths to `EXCLUDE_PATHS`, raise `STALL_TIMEOUT`, lower `CHUNK_SIZE`, or
adjust the limits in `clamd.conf` (`MaxScanSize`, `MaxFileSize`, `MaxRecursion`,
`MaxFiles`).

**Lots of read errors**
Without `sudo` most system files are unreadable. The script points this out at
the end.

**The bar never reaches 100%**
Expected when chunks were aborted: their remaining files are never counted. The
summary shows "scanned X of Y".

**A separate `/home` is not scanned**
`-xdev` is the default. Answer the scope question about mounted filesystems with
`y`.

### Safety notes

* **ClamAV produces false positives.** Delete mode can destroy perfectly good
  system files. When in doubt choose "report only" and cross-check detections on
  [VirusTotal](https://www.virustotal.com/).
* A detection does not automatically mean an infected system — often it is test
  files, Windows malware inside Wine prefixes, or samples in mail archives.
* The quarantine folder still contains the original files. It sits in your home
  directory with mode `700`, but it is not a secure container.

### Known limitations

* File names containing a newline cannot be passed via `--file-list` (a ClamAV
  limitation, not one of this script).
* No real-time protection — this is an on-demand scanner.
* `clamdscan` uses the limits from `clamd.conf`; the options `--max-filesize`
  and `--max-scansize` only apply in `clamscan` mode.
* No remaining-time estimate, only elapsed time.

### License

MIT — see [LICENSE](LICENSE).
