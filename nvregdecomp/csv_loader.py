"""Einlesen der Registry-Werte aus einer Process-Monitor-CSV.

Unterstützt wird vor allem der Export von "Tools > Count Occurrences / Registry
Summary" (Spalten: Time, Total, Opens, Closes, Reads, Writes, Other, Path),
aber auch jede andere CSV, bei der eine Spalte einen Registry-Pfad enthält,
sowie einfache Textdateien mit einem Wertnamen pro Zeile.
"""

from __future__ import annotations

import csv
import io
from dataclasses import dataclass, field

REG_PREFIXES = ("HKLM\\", "HKCU\\", "HKCR\\", "HKU\\", "HKCC\\", "HKEY_", "\\REGISTRY\\")


@dataclass
class RegValue:
    name: str                 # Name des Werts, z.B. "AllowMaxPerf"
    key: str = ""             # vollständiger Schlüsselpfad
    total: int = 0            # Anzahl Zugriffe laut ProcMon
    reads: int = 0
    writes: int = 0
    paths: list[str] = field(default_factory=list)

    @property
    def full_path(self) -> str:
        return f"{self.key}\\{self.name}" if self.key else self.name


def _to_int(text: str) -> int:
    try:
        return int(float(text.strip()))
    except (ValueError, AttributeError):
        return 0


def _find_path_column(row: list[str]) -> int:
    for i in range(len(row) - 1, -1, -1):
        cell = row[i].strip()
        if cell.upper().startswith(REG_PREFIXES):
            return i
    return -1


def parse_text(text: str) -> list[RegValue]:
    text = text.lstrip("﻿")
    values: dict[str, RegValue] = {}
    header_map: dict[str, int] = {}

    for row in csv.reader(io.StringIO(text)):
        if not row or all(not c.strip() for c in row):
            continue
        idx = _find_path_column(row)
        if idx < 0:
            # Kopfzeile merken, sonst als "ein Name pro Zeile" behandeln
            lowered = [c.strip().lower() for c in row]
            if "path" in lowered or "pfad" in lowered:
                header_map = {name: i for i, name in enumerate(lowered)}
                continue
            if len(row) == 1 and row[0].strip() and "\\" not in row[0]:
                name = row[0].strip()
                values.setdefault(name.lower(), RegValue(name=name))
            continue

        path = row[idx].strip()
        key, _, name = path.rpartition("\\")
        if not name:
            continue
        # Werte in Unterschlüsseln (z.B. ...\0001\Session\Foo) behalten den
        # Namen "Foo"; der Unterschlüssel steht in key.
        entry = values.get(name.lower())
        if entry is None:
            entry = RegValue(name=name, key=key)
            values[name.lower()] = entry
        entry.paths.append(path)

        if header_map:
            entry.total += _to_int(row[header_map["total"]]) if "total" in header_map else 0
            entry.reads += _to_int(row[header_map["reads"]]) if "reads" in header_map else 0
            entry.writes += _to_int(row[header_map["writes"]]) if "writes" in header_map else 0
        elif idx >= 7:
            # ProcMon Registry Summary ohne Kopfzeile:
            # Time, Total, Opens, Closes, Reads, Writes, Other, Path
            entry.total += _to_int(row[1])
            entry.reads += _to_int(row[4])
            entry.writes += _to_int(row[5])
        else:
            entry.total += 1

    return sorted(values.values(), key=lambda v: v.name.lower())


def load_csv(path: str) -> list[RegValue]:
    with open(path, "rb") as fh:
        raw = fh.read()
    for enc in ("utf-8-sig", "utf-16", "cp1252", "latin-1"):
        try:
            text = raw.decode(enc)
            break
        except UnicodeDecodeError:
            continue
    return parse_text(text)
