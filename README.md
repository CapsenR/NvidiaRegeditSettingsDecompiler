# NVIDIA Registry Settings Decompiler

GUI-Werkzeug (Windows, Python + tkinter), das die Registry-Werte aus einem
Process-Monitor-Export (`nvidia.csv`) in den installierten NVIDIA-Treiberdateien
sucht und die Code-Stellen, die sie lesen, mit **Ghidra** (headless) dekompiliert.
Aus dem dekompilierten Code wird eine heuristische Erklärung erzeugt: über welche
Funktion der Wert gelesen wird, mit welchen Konstanten, womit er verglichen oder
maskiert wird und in welche globale Variable er wandert.

## Voraussetzungen

* Windows 10/11 mit installiertem NVIDIA-Treiber
* Python 3.10+ (python.org-Installer, enthält tkinter)
* Ghidra 11.x oder neuer (https://ghidra-sre.org) und ein JDK 21 (z.B. Adoptium)
* Viel RAM/Zeit für `nvlddmkm.sys` (≈100 MB): Import + Autoanalyse dauert je nach
  Rechner 30–120 Minuten und braucht 8–16 GB Heap. Das passiert nur **einmal**;
  danach wird das gespeicherte Ghidra-Projekt wiederverwendet (`-process -noanalysis`).

## Start

```
start.bat
```
oder `python -m nvregdecomp`.

1. **Ghidra-Installation** wählen (Ordner, der `support\analyzeHeadless.bat` enthält) → „Prüfen“.
2. **NVIDIA-Treiberordner**: „Automatisch finden“ liest `UserModeDriverName` aus
   `HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-…}` bzw. sucht
   `C:\Windows\System32\DriverStore\FileRepository\nv*.inf_amd64_*`. Alternativ
   `C:\Windows\System32\drivers` (dann nur `nv*`-Dateien).
3. **Registry-CSV**: die mitgelieferte `nvidia.csv` wird automatisch geladen.
4. **▶ Alles** startet:
   * **Vorscan** (Sekunden): alle `.sys/.dll/.exe` werden nach den Namen als
     ASCII und UTF-16LE durchsucht (Groß-/Kleinschreibung egal), `nvlddmkm.sys`
     zuerst. Mit „Nur erste Datei pro Wert“ wird ein gefundener Wert in weiteren
     Dateien nicht mehr gesucht.
   * **Ghidra-Analyse**: nur Dateien mit Treffern werden importiert. Das Skript
     `ghidra_scripts/RegValueFinder.java` findet die Strings, folgt allen
     Referenzen (inkl. Fallback-Scan nach Zeigern und RIP-relativen `LEA`),
     dekompiliert die Funktionen und gibt JSON zurück. Bei Verweisen aus
     Registry-Tabellen (`{L"Name", Typ, Default, &Variable}`) werden die Bytes
     des Tabelleneintrags und die Funktionen, die die Tabelle verwenden, geliefert.
5. Tabelle anklicken → Tab **Erklärung** (Zusammenfassung) und **Dekompilierter
   Code** (Fundstelle gelb, Name rot markiert).
6. **Export…** als HTML-Bericht, CSV (Excel) oder JSON. Ergebnisse werden
   zusätzlich automatisch in `<Arbeitsordner>\letzte_ergebnisse.json` gesichert.

**Overlay**: „Immer im Vordergrund“, Deckkraft-Regler und „Overlay (kompakt)“
(blendet die Einstellungen aus, kleines Fenster über Spiel/Desktop).

## Grenzen – bitte lesen

* **„Was der Wert macht“ ist eine Heuristik**, keine echte Semantik. Das Tool
  zeigt die Fakten (Lesefunktion, Vergleiche, Bitmasken, Zielvariable); die
  eigentliche Bedeutung muss man oft im Code weiterverfolgen (z.B. wo die globale
  `DAT_…`-Variable später benutzt wird).
* Neuere Treiber speichern viele Registry-Namen in `nvlddmkm.sys` **verschleiert/
  verschlüsselt** oder setzen sie zur Laufzeit zusammen. Solche Werte erscheinen
  als „nicht gefunden“, obwohl der Treiber sie liest.
* Manche Werte werden gar nicht vom NVIDIA-Treiber, sondern von Windows (dxgkrnl,
  DWM) oder anderen Komponenten gelesen.
* `nvlddmkm.sys` hat keine öffentlichen Symbole; Funktionen heißen `FUN_…`.
* Das Tool liest die Treiberdateien nur; es ändert nichts an System oder Registry.

## Tests

```
python -m unittest discover -s tests
```
(Die Tests simulieren Ghidra; das Java-Skript selbst braucht eine echte Ghidra-Installation.)
