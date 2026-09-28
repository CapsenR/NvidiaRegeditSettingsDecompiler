"""Heuristische Auswertung: was macht ein Registry-Wert?

Automatisch "verstehen" kann das Programm den Code nicht. Es sammelt aber die
Hinweise, die man sonst von Hand im Decompiler suchen würde:

* über welche Funktion der Wert gelesen wird und mit welchen Konstanten
  (Typ, Standardwert, Größe),
* in welcher Variable das Ergebnis landet,
* womit diese Variable danach verglichen / maskiert wird,
* in welche globale Variable (DAT_...) sie geschrieben wird,
* dazu eine Einschätzung anhand der Namensbestandteile.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# ------------------------------------------------------------ Namensanalyse

KEYWORDS: list[tuple[str, str]] = [
    ("disable", "schaltet eine Funktion ab"),
    ("enable", "schaltet eine Funktion ein"),
    ("allow", "erlaubt ein Verhalten"),
    ("force", "erzwingt ein Verhalten (überschreibt Automatik)"),
    ("override", "überschreibt einen automatisch ermittelten Wert"),
    ("support", "meldet/aktiviert Unterstützung eines Features"),
    ("timeout", "Zeitlimit"),
    ("delay", "Verzögerung"),
    ("interval", "Intervall"),
    ("max", "Obergrenze"),
    ("min", "Untergrenze"),
    ("threshold", "Schwellwert"),
    ("mask", "Bitmaske – einzelne Bits haben eigene Bedeutung"),
    ("flags", "Bitfeld – einzelne Bits haben eigene Bedeutung"),
    ("mode", "wählt einen Betriebsmodus"),
    ("level", "Stufe"),
    ("debug", "Debug-/Diagnosefunktion"),
    ("log", "Protokollierung"),
    ("trace", "Tracing/Protokollierung"),
    ("perf", "Performance / P-States"),
    ("pstate", "Performance-States (Taktstufen)"),
    ("clock", "Taktfrequenz"),
    ("clk", "Taktfrequenz"),
    ("power", "Energieverwaltung"),
    ("pwr", "Energieverwaltung"),
    ("gc6", "GC6 – GPU-Tiefschlafzustand"),
    ("gcoff", "GC-Off – GPU komplett abschalten"),
    ("aspm", "PCIe Active State Power Management"),
    ("pcie", "PCI-Express-Link"),
    ("thermal", "Temperatur-/Kühlungssteuerung"),
    ("fan", "Lüftersteuerung"),
    ("volt", "Spannung"),
    ("hdcp", "HDCP-Kopierschutz"),
    ("hdr", "HDR-Ausgabe"),
    ("dsc", "Display Stream Compression"),
    ("edid", "EDID – Monitor-Identifikationsdaten"),
    ("dp", "DisplayPort"),
    ("hdmi", "HDMI"),
    ("vrr", "Variable Refresh Rate"),
    ("gsync", "G-SYNC"),
    ("flip", "Present/Flip (Bildwechsel)"),
    ("vsync", "Vertikale Synchronisation"),
    ("dwm", "Desktop Window Manager"),
    ("mpo", "Multiplane Overlay"),
    ("overlay", "Overlay-Ebenen"),
    ("color", "Farbverarbeitung"),
    ("gamma", "Gamma/Farbkurven"),
    ("dither", "Dithering"),
    ("scaling", "Skalierung"),
    ("display", "Display-Ausgabe"),
    ("disp", "Display-Ausgabe"),
    ("monitor", "Monitor"),
    ("mux", "Display-MUX (Umschaltung iGPU/dGPU)"),
    ("optimus", "Optimus (Hybrid-Grafik)"),
    ("rm", "Resource Manager (Kernteil des Kerneltreibers)"),
    ("tdr", "Timeout Detection & Recovery"),
    ("preempt", "GPU-Preemption"),
    ("sched", "GPU-Scheduling"),
    ("hags", "Hardware Accelerated GPU Scheduling"),
    ("memory", "Speicherverwaltung"),
    ("mem", "Speicherverwaltung"),
    ("fb", "Framebuffer / VRAM"),
    ("vidmem", "Videospeicher"),
    ("bar1", "BAR1-Adressfenster"),
    ("rebar", "Resizable BAR"),
    ("cache", "Cache"),
    ("vulkan", "Vulkan-Treiber"),
    ("opengl", "OpenGL-Treiber"),
    ("ogl", "OpenGL-Treiber"),
    ("d3d", "Direct3D-Treiber"),
    ("dx", "DirectX"),
    ("cuda", "CUDA"),
    ("nvenc", "Video-Encoder"),
    ("nvdec", "Video-Decoder"),
    ("video", "Video"),
    ("audio", "Audio über HDMI/DP"),
    ("acpi", "ACPI (Firmware/Mainboard-Schnittstelle)"),
    ("msi", "Message Signaled Interrupts"),
    ("interrupt", "Interrupts"),
    ("sli", "SLI / Multi-GPU"),
    ("ecc", "ECC-Speicher"),
    ("session", "Sitzungsbezogene Einstellung"),
]


def split_name(name: str) -> list[str]:
    parts = re.findall(r"[A-Z]+(?=[A-Z][a-z]|\d|\b|_)|[A-Z]?[a-z]+|[A-Z]+|\d+", name)
    return [p.lower() for p in parts if p]


def name_hints(name: str) -> list[str]:
    tokens = split_name(name)
    low = name.lower()
    hints: list[str] = []
    seen: set[str] = set()
    for kw, desc in KEYWORDS:
        hit = kw in tokens or ((len(kw) >= 4 or any(c.isdigit() for c in kw)) and kw in low)
        if hit and desc not in seen:
            seen.add(desc)
            hints.append(f"„{kw}“ → {desc}")
    return hints


# ------------------------------------------------------------- Code-Analyse

_CALL_RE = re.compile(r"([A-Za-z_][\w:.]*)\s*\(")
_NUM_RE = re.compile(r"(?<![\w.])(-?0x[0-9a-fA-F]+|-?\d+)(?![\w.])")
_CMP_RE_TMPL = r"\b{v}\b\s*(==|!=|<=|>=|<|>)\s*(-?0x[0-9a-fA-F]+|-?\d+|[A-Za-z_]\w*)"
_CMP_REV_TMPL = r"(-?0x[0-9a-fA-F]+|-?\d+)\s*(==|!=|<=|>=|<|>)\s*\b{v}\b"
_MASK_TMPL = r"\b{v}\b\s*(?:&|>>|<<)\s*(0x[0-9a-fA-F]+|\d+)|(0x[0-9a-fA-F]+|\d+)\s*&\s*\b{v}\b"
_STORE_TMPL = r"((?:DAT|PTR|g_|_DAT)\w*|\*\([^;]*?\)\s*\([^;]*?\)|\*\s*\([^;]*?\)|\w+(?:->|\.)\w+)\s*=\s*[^=;]*\b{v}\b"
_BOOL_TMPL = r"if\s*\(\s*!?\s*\(?\s*\b{v}\b\s*\)?\s*\)"


@dataclass
class RefAnalysis:
    file: str
    function: str
    entry: str
    kind: str
    call_line: str = ""
    reader: str = ""                   # Funktion, die den Wert liest
    constants: list[str] = field(default_factory=list)
    out_var: str = ""
    comparisons: list[str] = field(default_factory=list)
    masks: list[str] = field(default_factory=list)
    stores: list[str] = field(default_factory=list)
    bool_test: bool = False
    snippet: str = ""
    code: str = ""
    lines: list[int] = field(default_factory=list)
    table: dict | None = None


def _find_out_var(call_line: str) -> str:
    # 1) Ergebnis wird zugewiesen: x = FUN(...L"Name"...)
    m = re.match(r"\s*(?:[\w\s\*]+\s)?(\w+)\s*=\s*\w+\s*\(", call_line)
    # 2) Ausgabeparameter: &local_28 / &DAT_... bevorzugt
    amp = re.findall(r"&(\w+)", call_line)
    if amp:
        return amp[-1]
    if m:
        return m.group(1)
    return ""


def analyze_code(code: str, lines_idx: list[int], name: str) -> dict:
    lines = code.split("\n")
    info: dict = {"call_line": "", "reader": "", "constants": [], "out_var": "",
                  "comparisons": [], "masks": [], "stores": [], "bool_test": False, "snippet": ""}
    if not lines:
        return info

    idx = [i for i in lines_idx if 0 <= i < len(lines)]
    if not idx:
        low = name.lower()
        idx = [i for i, l in enumerate(lines) if low in l.lower()]
    if not idx:
        return info

    first = idx[0]
    call_line = lines[first].strip()
    info["call_line"] = call_line

    calls = [c for c in _CALL_RE.findall(call_line) if c not in ("if", "while", "for", "switch", "return", "sizeof")]
    if calls:
        info["reader"] = calls[0]
    info["constants"] = _NUM_RE.findall(re.sub(r'[Lu]?"[^"]*"', "", call_line))[:8]
    out_var = _find_out_var(call_line)
    info["out_var"] = out_var

    start = max(0, first - 6)
    end = min(len(lines), max(idx) + 25)
    info["snippet"] = "\n".join(
        (">> " if i in idx else "   ") + lines[i] for i in range(start, end)
    )

    if out_var:
        v = re.escape(out_var)
        tail = "\n".join(lines[first + 1:first + 80])
        for m in re.finditer(_CMP_RE_TMPL.format(v=v), tail):
            s = f"{out_var} {m.group(1)} {m.group(2)}"
            if s not in info["comparisons"]:
                info["comparisons"].append(s)
        for m in re.finditer(_CMP_REV_TMPL.format(v=v), tail):
            s = f"{out_var} {m.group(2)} {m.group(1)}"
            if s not in info["comparisons"]:
                info["comparisons"].append(s)
        for m in re.finditer(_MASK_TMPL.format(v=v), tail):
            s = m.group(0).strip()
            if s not in info["masks"]:
                info["masks"].append(s)
        for m in re.finditer(_STORE_TMPL.format(v=v), tail):
            s = m.group(0).strip()
            if s not in info["stores"]:
                info["stores"].append(s[:120])
        info["bool_test"] = bool(re.search(_BOOL_TMPL.format(v=v), tail))

    # Wird eine Zeile mit dem Ergebnis des Aufrufs direkt in einem if geprüft?
    if call_line.startswith("if") and not info["comparisons"]:
        info["comparisons"].append("Rückgabewert des Lesezugriffs wird direkt geprüft (Wert vorhanden?)")
    for k in ("comparisons", "masks", "stores"):
        info[k] = info[k][:12]
    return info


# ------------------------------------------------------------ Zusammenfassen

def summarize(name: str, refs: list[RefAnalysis]) -> str:
    out: list[str] = []
    if not refs:
        out.append("Kein Code gefunden, der den Wert verwendet.")
    else:
        funcs = sorted({f"{r.function} ({r.file})" for r in refs if r.function})
        if funcs:
            out.append(f"Verwendet in {len(funcs)} Funktion(en): " + ", ".join(funcs[:6])
                       + (" …" if len(funcs) > 6 else ""))
        readers = sorted({r.reader for r in refs if r.reader})
        if readers:
            out.append("Gelesen über: " + ", ".join(readers[:5]))
        tables = [r for r in refs if r.table]
        if tables:
            out.append(f"{len(tables)} Verweis(e) aus einer Daten-/Registry-Tabelle "
                       "(Name, Typ, Standardwert, Zielvariable) – siehe Bytes im Detail.")
        consts = sorted({c for r in refs for c in r.constants})
        if consts:
            out.append("Konstanten im Aufruf (mögl. Typ/Standardwert/Größe): " + ", ".join(consts[:10]))
        cmps = [c for r in refs for c in r.comparisons]
        if cmps:
            out.append("Geprüft auf: " + "; ".join(list(dict.fromkeys(cmps))[:8]))
        masks = [m for r in refs for m in r.masks]
        if masks:
            out.append("Bitoperationen (Bitfeld?): " + "; ".join(list(dict.fromkeys(masks))[:6]))
        if any(r.bool_test for r in refs):
            out.append("Wird als Ja/Nein-Schalter verwendet (if (wert) …).")
        stores = [s for r in refs for s in r.stores]
        if stores:
            out.append("Gespeichert in: " + "; ".join(list(dict.fromkeys(stores))[:4]))
    hints = name_hints(name)
    if hints:
        out.append("Namensbasierte Einschätzung: " + "; ".join(hints))
    return "\n".join(out)


def confidence(refs: list[RefAnalysis]) -> str:
    if not refs:
        return "—"
    if any(r.comparisons or r.masks or r.bool_test for r in refs):
        return "hoch"
    if any(r.function for r in refs):
        return "mittel"
    return "niedrig"


def analyses_from_ghidra(result: dict) -> dict[str, list[RefAnalysis]]:
    """Wandelt das JSON aus RegValueFinder.java in RefAnalysis-Listen um."""
    funcs = result.get("functions", {})
    program = result.get("program", "")
    out: dict[str, list[RefAnalysis]] = {}
    for val in result.get("values", []):
        name = val["name"]
        lst = out.setdefault(name.lower(), [])
        for ref in val.get("refs", []):
            if "entry" in ref:
                fn = funcs.get(ref["entry"], {})
                code = fn.get("code", "")
                ra = RefAnalysis(program, ref.get("function", ""), ref["entry"], ref.get("kind", ""),
                                 code=code, lines=ref.get("lines", []))
                info = analyze_code(code, ra.lines, name)
                for k, v in info.items():
                    setattr(ra, k, v)
                lst.append(ra)
            elif "data" in ref:
                data = ref["data"]
                tfs = data.get("tableFunctions", [])
                ra = RefAnalysis(program, "", "", ref.get("kind", ""), table=data)
                ra.snippet = (f"Datenverweis bei {ref.get('from')} → String {ref.get('string')}\n"
                              f"Tabellenbasis: {data.get('tableBase') or '?'}\n"
                              f"Bytes davor : {data.get('bytesBefore', '')}\n"
                              f"Bytes danach: {data.get('bytesAfter', '')}")
                if data.get("container"):
                    ra.snippet += f"\nDatenstruktur: {data['container']}"
                lst.append(ra)
                for tf in tfs:
                    fn = funcs.get(tf["entry"], {})
                    code = fn.get("code", "")
                    ta = RefAnalysis(program, tf.get("function", ""), tf["entry"], "table-user",
                                     code=code, lines=tf.get("lines", []))
                    ta.snippet = analyze_code(code, ta.lines, name).get("snippet", "")
                    ta.table = data
                    lst.append(ta)
    return out
