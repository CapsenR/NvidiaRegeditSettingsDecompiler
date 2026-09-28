"""Schneller Vorscan: welche Datei enthält welchen Wertnamen als String?

Ghidra auf einer 100-MB-Datei wie nvlddmkm.sys laufen zu lassen dauert lange.
Deshalb wird zuerst in Python nach den Namen gesucht (ASCII und UTF-16LE,
Groß-/Kleinschreibung egal), und Ghidra wird nur für Dateien mit Treffern
gestartet.
"""

from __future__ import annotations

import mmap
import os
import re
from dataclasses import dataclass, field
from typing import Callable, Iterable

MIN_LEN = 3
_ASCII_RE = re.compile(rb"[\x20-\x7e]{%d,}" % MIN_LEN)
_UTF16_RE = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % MIN_LEN)


@dataclass
class Hit:
    file: str
    offset: int          # Dateioffset des Strings
    encoding: str        # "utf16" oder "ascii"
    exact: bool          # ganzer String == Wertname (sonst Teilstring)
    text: str            # gefundener String


@dataclass
class PrescanResult:
    hits: dict[str, list[Hit]] = field(default_factory=dict)   # key = name.lower()
    files_scanned: list[str] = field(default_factory=list)
    files_with_hits: dict[str, set[str]] = field(default_factory=dict)  # file -> names


def _iter_strings(data) -> Iterable[tuple[int, str, str]]:
    for m in _UTF16_RE.finditer(data):
        yield m.start(), "utf16", m.group().decode("utf-16-le")
    for m in _ASCII_RE.finditer(data):
        yield m.start(), "ascii", m.group().decode("ascii")


def scan_file(path: str, names_lower: set[str], max_hits_per_name: int = 20) -> dict[str, list[Hit]]:
    """Sucht alle Namen in einer Datei. Liefert name.lower() -> Treffer."""
    found: dict[str, list[Hit]] = {}
    try:
        size = os.path.getsize(path)
    except OSError:
        return found
    if size == 0:
        return found

    with open(path, "rb") as fh, mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ) as mm:
        partial: list[tuple[int, str, str]] = []
        for off, enc, s in _iter_strings(mm):
            low = s.lower()
            if low in names_lower:
                lst = found.setdefault(low, [])
                if len(lst) < max_hits_per_name:
                    lst.append(Hit(path, off, enc, True, s))
            elif len(s) > MIN_LEN + 2:
                partial.append((off, enc, s))

        # Teilstring-Treffer (z.B. "Name=%d" oder Pfade) nur für Namen, die
        # nicht exakt gefunden wurden. Kurze Namen würden zu viel Rauschen
        # erzeugen, deshalb erst ab 6 Zeichen.
        missing = [n for n in names_lower if n not in found and len(n) >= 6]
        if missing and partial:
            pattern = re.compile(
                r"(?<![a-z0-9_])(" + "|".join(re.escape(n) for n in sorted(missing, key=len, reverse=True)) + r")(?![a-z0-9_])"
            )
            for off, enc, s in partial:
                for m in pattern.finditer(s.lower()):
                    low = m.group(1)
                    lst = found.setdefault(low, [])
                    if len(lst) < max_hits_per_name:
                        step = 2 if enc == "utf16" else 1
                        lst.append(Hit(path, off + m.start() * step, enc, False, s))
    return found


def prescan(
    files: list[str],
    names: list[str],
    stop_at_first_file: bool = True,
    progress: Callable[[int, int, str], None] | None = None,
    should_stop: Callable[[], bool] | None = None,
) -> PrescanResult:
    """Scannt die Dateien der Reihe nach.

    stop_at_first_file=True: sobald ein Name (exakt) in einer Datei gefunden
    wurde, wird er in späteren Dateien nicht mehr gesucht.
    """
    res = PrescanResult()
    remaining = {n.lower() for n in names}
    for i, path in enumerate(files):
        if should_stop and should_stop():
            break
        if progress:
            progress(i, len(files), path)
        if not remaining:
            break
        try:
            hits = scan_file(path, remaining)
        except (OSError, ValueError) as exc:  # gesperrte Datei o.ä.
            if progress:
                progress(i, len(files), f"{path}: {exc}")
            continue
        res.files_scanned.append(path)
        for low, lst in hits.items():
            res.hits.setdefault(low, []).extend(lst)
            res.files_with_hits.setdefault(path, set()).add(low)
            if stop_at_first_file and any(h.exact for h in lst):
                remaining.discard(low)
    if progress:
        progress(len(files), len(files), "fertig")
    return res
