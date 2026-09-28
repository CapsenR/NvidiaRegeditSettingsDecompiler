"""Speichern/Laden und Export der Ergebnisse (JSON, CSV, HTML)."""

from __future__ import annotations

import csv
import html
import json
from dataclasses import asdict, dataclass, field

from .csv_loader import RegValue
from .explain import RefAnalysis
from .prescan import Hit


@dataclass
class Record:
    value: RegValue
    hits: list[Hit] = field(default_factory=list)
    analyses: list[RefAnalysis] = field(default_factory=list)
    status: str = "offen"
    summary: str = ""
    confidence: str = ""
    analyzed_files: list[str] = field(default_factory=list)

    @property
    def files(self) -> list[str]:
        return list(dict.fromkeys(h.file for h in self.hits))


def save_json(path: str, records: list[Record]) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump([asdict(r) for r in records], fh, ensure_ascii=False, indent=1)


def load_json(path: str) -> list[Record]:
    with open(path, encoding="utf-8") as fh:
        raw = json.load(fh)
    out = []
    for r in raw:
        out.append(Record(
            value=RegValue(**r["value"]),
            hits=[Hit(**h) for h in r.get("hits", [])],
            analyses=[RefAnalysis(**a) for a in r.get("analyses", [])],
            status=r.get("status", ""),
            summary=r.get("summary", ""),
            confidence=r.get("confidence", ""),
            analyzed_files=r.get("analyzed_files", []),
        ))
    return out


def export_csv(path: str, records: list[Record]) -> None:
    with open(path, "w", encoding="utf-8-sig", newline="") as fh:
        w = csv.writer(fh, delimiter=";")
        w.writerow(["Wert", "Zugriffe", "Status", "Sicherheit", "Dateien", "Funktionen", "Zusammenfassung"])
        for r in records:
            funcs = sorted({a.function for a in r.analyses if a.function})
            w.writerow([r.value.name, r.value.total, r.status, r.confidence,
                        " | ".join(r.files), " | ".join(funcs), r.summary])


def export_html(path: str, records: list[Record]) -> None:
    e = html.escape
    rows = []
    for r in records:
        details = []
        for a in r.analyses:
            head = f"{e(a.file)} – {e(a.function or 'Datenverweis')} {e(a.entry)} [{e(a.kind)}]"
            details.append(f"<details><summary>{head}</summary><pre>{e(a.snippet)}</pre></details>")
        rows.append(
            f"<tr><td><b>{e(r.value.name)}</b></td><td>{r.value.total}</td><td>{e(r.status)}</td>"
            f"<td>{e(r.confidence)}</td><td>{e(', '.join(r.files))}</td>"
            f"<td><pre class=s>{e(r.summary)}</pre>{''.join(details)}</td></tr>"
        )
    doc = f"""<!doctype html><html lang="de"><head><meta charset="utf-8">
<title>NVIDIA Registry-Werte</title>
<style>
body{{font-family:Segoe UI,sans-serif;margin:16px;background:#fff;color:#111}}
table{{border-collapse:collapse;width:100%}}td,th{{border:1px solid #ccc;padding:4px;vertical-align:top}}
th{{background:#eee;position:sticky;top:0}}pre{{white-space:pre-wrap;font-size:12px;margin:2px 0}}
pre.s{{font-family:inherit;font-size:13px}}input{{padding:4px;width:300px;margin-bottom:8px}}
</style></head><body>
<h1>NVIDIA Registry-Werte – Analyse</h1>
<input id=q placeholder="Filter…" oninput="for(const t of document.querySelectorAll('tbody tr'))t.hidden=!t.textContent.toLowerCase().includes(this.value.toLowerCase())">
<table><thead><tr><th>Wert</th><th>Zugriffe</th><th>Status</th><th>Sicherheit</th><th>Dateien</th><th>Analyse</th></tr></thead>
<tbody>{''.join(rows)}</tbody></table></body></html>"""
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(doc)
