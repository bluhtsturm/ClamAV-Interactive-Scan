# Changelog

🇩🇪 [Deutsch](#deutsch) · 🇬🇧 [English](#english)

---

<a id="deutsch"></a>

## Deutsch

### 1.3.0

**Neu**

* **Restzeit-Schätzung** im Fortschrittsbalken („41:07, noch ~14:12“), berechnet
  aus dem bisherigen Durchschnittstempo. Sie erscheint nach 10 s mit
  Ergebnissen; die Ladezeit der Signaturdatenbank zählt nicht mit.
* **Btrfs-Subvolumes** desselben Dateisystems (Fedora, openSUSE: `/home`, `/var`,
  `/opt` …) werden ohne Rückfrage mitgescannt und vor dem Scan aufgelistet.
  Verschachtelte Subvolumes und Snapshots bleiben draußen.
* **`SNAPSHOT_PATHS`** (Standard `/.snapshots`): Snapshot-Bäume werden auch beim
  Scan über Dateisystemgrenzen hinweg übersprungen.
* **`doas`** wird als Alternative zu `sudo` unterstützt (inkl. `DOAS_USER` für
  Protokoll und Quarantäne).
* **ShellCheck-CI** (GitHub Actions) bei jedem Push und Pull Request, inklusive
  Prüfung, dass beide Sprachfassungen dieselbe Version tragen.

**Geändert**

* Beginnt ein Scan innerhalb eines ausgeschlossenen Pfads (`EXCLUDE_PATHS`,
  `SNAPSHOT_PATHS`, Quarantäne), wird er trotzdem gescannt — die ausdrückliche
  Wahl hat Vorrang. Pseudo-Dateisysteme bleiben immer ausgeschlossen.

### 1.2.0

**Fehlerbehebungen**

* Fortschrittszeile war 82–87 Zeichen breit und brach in 80-Spalten-Terminals
  um; jedes Neuzeichnen hinterließ eine Kopie. Der Balken passt sich jetzt der
  Terminalbreite an.
* Relativer Scanpfad: `clamscan` gab relative Pfade aus, die nicht gezählt
  wurden („2 von 32 Dateien“). Ein Symlink als Startordner lieferte 0 Dateien.
* Dateien mit „ERROR“ oder „Can't open“ im Namen wurden als Lesefehler gezählt.
* Mehrere Scans pro Sitzung: Temporärdateien blieben liegen, ältere Protokolle
  blieben root-eigen, der Quarantäne-Hinweis wurde in spätere Scans übernommen.
* Serieller `clamscan`-Modus: Anzeige stand bei großen Dateien still; sie wird
  jetzt jede Sekunde aktualisiert.
* „Mit Fehlern beendet“ verdeckte gefundene Schadsoftware — Funde haben jetzt
  Vorrang.
* `clamd`-Start: falscher Dienstname unter Arch, „active“ wurde schon als bereit
  gewertet, `clamd` außerhalb von systemd wurde ignoriert; `freshclam`-Dienst
  unter openSUSE.
* Ohne root wurden nicht lesbare Dateien stillschweigend weggelassen; sie werden
  jetzt gezählt und gemeldet.

**Verbesserungen**

* Hänger-Erkennung über Markierungsdatei statt Exit-Code; `script` läuft immer
  mit Bash; fertige Pakete werden nicht mehr jede Sekunde neu geprüft.
* Quarantäne-Ordner wird immer übersprungen; Pfade per Drag & Drop (in
  Anführungszeichen) werden akzeptiert; Prüfung nach automatischer Installation.

### 1.1.0

Erste veröffentlichte Version.

---

<a id="english"></a>

## English

### 1.3.0

**New**

* **Remaining-time estimate** in the progress bar ("41:07, ~14:12 left"),
  computed from the average speed so far. It appears after 10 s of results; the
  time spent loading the signature database does not count.
* **Btrfs subvolumes** of the same filesystem (Fedora, openSUSE: `/home`, `/var`,
  `/opt` …) are scanned without asking and listed before the scan. Nested
  subvolumes and snapshots stay out.
* **`SNAPSHOT_PATHS`** (default `/.snapshots`): snapshot trees are skipped even
  when scanning across filesystems.
* **`doas`** is supported as an alternative to `sudo` (including `DOAS_USER` for
  log and quarantine).
* **ShellCheck CI** (GitHub Actions) on every push and pull request, including a
  check that both language versions carry the same version number.

**Changed**

* A scan that starts inside an excluded path (`EXCLUDE_PATHS`,
  `SNAPSHOT_PATHS`, quarantine) still scans it — the explicit choice wins.
  Pseudo filesystems always stay excluded.

### 1.2.0

**Bug fixes**

* The progress line was 82–87 columns wide and wrapped in 80-column terminals;
  every redraw left a copy behind. The bar now adapts to the terminal width.
* Relative scan path: `clamscan` printed relative paths that were never counted
  ("2 of 32 files"). A symlink as start directory yielded 0 files.
* Files with "ERROR" or "Can't open" in their name were counted as read errors.
* Several scans per session: temp files piled up, earlier logs stayed owned by
  root, the quarantine note carried over into later scans.
* Serial `clamscan` mode: the display froze on large files; it now updates
  every second.
* "Finished with errors" hid detected malware — detections now take priority.
* `clamd` start: wrong service name on Arch, "active" was taken as ready, a
  `clamd` outside systemd was ignored; `freshclam` service on openSUSE.
* Without root, unreadable files were silently dropped; they are now counted
  and reported.

**Improvements**

* Stall detection via marker file instead of exit code; `script` always runs
  the command with bash; finished chunks are no longer polled every second.
* The quarantine folder is always skipped; drag & drop paths (in quotes) are
  accepted; ClamAV is re-checked after an automatic installation.

### 1.1.0

First published version.
