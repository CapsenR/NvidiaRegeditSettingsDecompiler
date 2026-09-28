"""Tkinter-Oberfläche (mit Overlay-Modus) für den NVIDIA Registry Decompiler."""

from __future__ import annotations

import json
import os
import queue
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from . import __version__
from .csv_loader import load_csv
from .driver_finder import find_default_driver_dir, find_driver_dirs, list_binaries
from .explain import analyses_from_ghidra, confidence, name_hints, summarize
from .ghidra_runner import GhidraError, GhidraRunner, find_analyze_headless, ghidra_version
from .prescan import prescan
from .report import Record, export_csv, export_html, load_json, save_json

SETTINGS_FILE = os.path.join(os.path.expanduser("~"), ".nvregdecomp.json")
DEFAULT_WORKDIR = os.path.join(os.path.expanduser("~"), "NvRegDecomp")
BUNDLED_CSV = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "nvidia.csv")

COLUMNS = [
    ("name", "Wert", 260),
    ("total", "Zugriffe", 70),
    ("status", "Status", 150),
    ("conf", "Sicherheit", 80),
    ("files", "Datei(en)", 170),
    ("refs", "Refs", 50),
    ("short", "Kurzfassung", 420),
]


class App:
    def __init__(self, root: tk.Tk):
        self.root = root
        root.title(f"NVIDIA Registry Decompiler {__version__}")
        root.geometry("1400x860")
        root.minsize(900, 500)

        self.records: dict[str, Record] = {}
        self.order: list[str] = []
        self.file_hits: dict[str, set[str]] = {}
        self.ui_queue: queue.Queue = queue.Queue()
        self.worker: threading.Thread | None = None
        self.stop_flag = threading.Event()
        self.runner: GhidraRunner | None = None
        self.sort_col, self.sort_rev = "name", False
        self.current_key: str | None = None

        s = self._load_settings()
        self.v_ghidra = tk.StringVar(value=s.get("ghidra", ""))
        self.v_driver = tk.StringVar(value=s.get("driver", "") or find_default_driver_dir())
        self.v_csv = tk.StringVar(value=s.get("csv", "") or (BUNDLED_CSV if os.path.exists(BUNDLED_CSV) else ""))
        self.v_work = tk.StringVar(value=s.get("work", DEFAULT_WORKDIR))
        self.v_java = tk.StringVar(value=s.get("java", ""))
        self.v_mem = tk.StringVar(value=s.get("mem", "8G"))
        self.v_timeout = tk.StringVar(value=str(s.get("timeout", 0)))
        self.v_cpu = tk.StringVar(value=str(s.get("cpu", 0)))
        self.v_first = tk.BooleanVar(value=s.get("first", True))
        self.v_fast = tk.BooleanVar(value=s.get("fast", True))
        self.v_recursive = tk.BooleanVar(value=s.get("recursive", True))
        self.v_topmost = tk.BooleanVar(value=s.get("topmost", False))
        self.v_alpha = tk.DoubleVar(value=s.get("alpha", 1.0))
        self.v_compact = tk.BooleanVar(value=False)
        self.v_filter = tk.StringVar()
        self.v_status_filter = tk.StringVar(value="Alle")
        self.v_status = tk.StringVar(value="Bereit.")
        self.v_ghidra_info = tk.StringVar()

        self._build()
        self._apply_overlay()
        self._check_ghidra()
        self.root.after(100, self._poll_queue)
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        if self.v_csv.get() and os.path.exists(self.v_csv.get()):
            self.load_csv(self.v_csv.get())

    # ------------------------------------------------------------ settings
    def _load_settings(self) -> dict:
        try:
            with open(SETTINGS_FILE, encoding="utf-8") as fh:
                return json.load(fh)
        except (OSError, ValueError):
            return {}

    def _save_settings(self) -> None:
        data = {
            "ghidra": self.v_ghidra.get(), "driver": self.v_driver.get(), "csv": self.v_csv.get(),
            "work": self.v_work.get(), "java": self.v_java.get(), "mem": self.v_mem.get(),
            "timeout": self._int(self.v_timeout), "cpu": self._int(self.v_cpu),
            "first": self.v_first.get(), "fast": self.v_fast.get(), "recursive": self.v_recursive.get(),
            "topmost": self.v_topmost.get(), "alpha": self.v_alpha.get(),
        }
        try:
            with open(SETTINGS_FILE, "w", encoding="utf-8") as fh:
                json.dump(data, fh, indent=2)
        except OSError:
            pass

    @staticmethod
    def _int(var: tk.StringVar) -> int:
        try:
            return int(var.get().strip() or 0)
        except ValueError:
            return 0

    # --------------------------------------------------------------- layout
    def _build(self) -> None:
        style = ttk.Style()
        try:
            style.theme_use("vista" if os.name == "nt" else "clam")
        except tk.TclError:
            pass

        self.cfg = ttk.LabelFrame(self.root, text="Einstellungen", padding=6)
        self.cfg.pack(fill="x", padx=6, pady=(6, 2))
        self.cfg.columnconfigure(1, weight=1)

        def row(r, label, var, browse, extra=None):
            ttk.Label(self.cfg, text=label).grid(row=r, column=0, sticky="w", padx=(0, 6), pady=2)
            ttk.Entry(self.cfg, textvariable=var).grid(row=r, column=1, sticky="ew", pady=2)
            ttk.Button(self.cfg, text="Durchsuchen…", command=browse).grid(row=r, column=2, padx=3)
            if extra:
                ttk.Button(self.cfg, text=extra[0], command=extra[1]).grid(row=r, column=3, padx=3, sticky="w")

        row(0, "Ghidra-Installation:", self.v_ghidra, self._browse_ghidra, ("Prüfen", self._check_ghidra))
        ttk.Label(self.cfg, textvariable=self.v_ghidra_info, foreground="#666").grid(row=0, column=4, sticky="w")
        row(1, "NVIDIA-Treiberordner:", self.v_driver, self._browse_driver, ("Automatisch finden", self._auto_driver))
        row(2, "Registry-CSV (ProcMon):", self.v_csv, self._browse_csv, ("Laden", lambda: self.load_csv(self.v_csv.get())))
        row(3, "Arbeitsordner:", self.v_work, self._browse_work)
        row(4, "JDK (optional, JAVA_HOME):", self.v_java, self._browse_java)

        opts = ttk.Frame(self.cfg)
        opts.grid(row=5, column=0, columnspan=5, sticky="w", pady=(4, 0))
        ttk.Label(opts, text="Ghidra-RAM:").pack(side="left")
        ttk.Entry(opts, textvariable=self.v_mem, width=6).pack(side="left", padx=(2, 10))
        ttk.Label(opts, text="Analyse-Timeout/Datei (s, 0=aus):").pack(side="left")
        ttk.Entry(opts, textvariable=self.v_timeout, width=7).pack(side="left", padx=(2, 10))
        ttk.Label(opts, text="Max. CPU (0=alle):").pack(side="left")
        ttk.Entry(opts, textvariable=self.v_cpu, width=4).pack(side="left", padx=(2, 10))
        ttk.Checkbutton(opts, text="Nur erste Datei pro Wert", variable=self.v_first).pack(side="left", padx=4)
        ttk.Checkbutton(opts, text="Schnellanalyse", variable=self.v_fast).pack(side="left", padx=4)
        ttk.Checkbutton(opts, text="Unterordner", variable=self.v_recursive).pack(side="left", padx=4)

        # Aktionen + Overlay
        act = ttk.Frame(self.root, padding=(6, 2))
        act.pack(fill="x")
        self.btn_all = ttk.Button(act, text="▶ Alles (Vorscan + Ghidra)", command=self.run_all)
        self.btn_all.pack(side="left")
        self.btn_pre = ttk.Button(act, text="1. Vorscan", command=self.run_prescan)
        self.btn_pre.pack(side="left", padx=3)
        self.btn_ghidra = ttk.Button(act, text="2. Ghidra-Analyse", command=self.run_ghidra)
        self.btn_ghidra.pack(side="left", padx=3)
        self.btn_sel = ttk.Button(act, text="Nur Auswahl analysieren", command=self.run_selected)
        self.btn_sel.pack(side="left", padx=3)
        self.btn_stop = ttk.Button(act, text="■ Stopp", command=self.stop, state="disabled")
        self.btn_stop.pack(side="left", padx=3)
        ttk.Separator(act, orient="vertical").pack(side="left", fill="y", padx=6)
        ttk.Button(act, text="Export…", command=self.export).pack(side="left")
        ttk.Button(act, text="Ergebnisse laden…", command=self.load_results).pack(side="left", padx=3)

        ttk.Checkbutton(act, text="Overlay (kompakt)", variable=self.v_compact,
                        command=self._apply_overlay).pack(side="right", padx=4)
        ttk.Checkbutton(act, text="Immer im Vordergrund", variable=self.v_topmost,
                        command=self._apply_overlay).pack(side="right", padx=4)
        ttk.Scale(act, from_=0.35, to=1.0, variable=self.v_alpha, length=90,
                  command=lambda _=None: self._apply_overlay()).pack(side="right")
        ttk.Label(act, text="Deckkraft:").pack(side="right")

        prog = ttk.Frame(self.root, padding=(6, 0))
        prog.pack(fill="x")
        self.progress = ttk.Progressbar(prog, mode="determinate")
        self.progress.pack(fill="x", side="top")
        ttk.Label(prog, textvariable=self.v_status, anchor="w").pack(fill="x")

        # Tabelle + Details
        self.paned = ttk.PanedWindow(self.root, orient="vertical")
        self.paned.pack(fill="both", expand=True, padx=6, pady=6)

        top = ttk.Frame(self.paned)
        flt = ttk.Frame(top)
        flt.pack(fill="x", pady=(0, 3))
        ttk.Label(flt, text="Filter:").pack(side="left")
        ent = ttk.Entry(flt, textvariable=self.v_filter, width=30)
        ent.pack(side="left", padx=4)
        ent.bind("<KeyRelease>", lambda e: self._refresh_table())
        cb = ttk.Combobox(flt, textvariable=self.v_status_filter, state="readonly", width=22,
                          values=["Alle", "offen", "String gefunden", "dekompiliert", "nicht gefunden", "Fehler"])
        cb.pack(side="left", padx=4)
        cb.bind("<<ComboboxSelected>>", lambda e: self._refresh_table())
        self.v_count = tk.StringVar()
        ttk.Label(flt, textvariable=self.v_count).pack(side="right")

        tv_frame = ttk.Frame(top)
        tv_frame.pack(fill="both", expand=True)
        self.tree = ttk.Treeview(tv_frame, columns=[c[0] for c in COLUMNS], show="headings", selectmode="extended")
        for cid, text, width in COLUMNS:
            self.tree.heading(cid, text=text, command=lambda c=cid: self._sort(c))
            self.tree.column(cid, width=width, stretch=cid in ("short", "name"),
                             anchor="e" if cid in ("total", "refs") else "w")
        ysb = ttk.Scrollbar(tv_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=ysb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        ysb.pack(side="right", fill="y")
        self.tree.bind("<<TreeviewSelect>>", self._on_select)
        self.tree.tag_configure("dekompiliert", foreground="#0a6b0a")
        self.tree.tag_configure("nicht gefunden", foreground="#888")
        self.tree.tag_configure("String gefunden", foreground="#1f4e9e")
        self.tree.tag_configure("Fehler", foreground="#b00020")
        self.paned.add(top, weight=3)

        self.nb = ttk.Notebook(self.paned)
        self.txt_explain = self._text_tab("Erklärung")
        code_tab = ttk.Frame(self.nb)
        bar = ttk.Frame(code_tab)
        bar.pack(fill="x")
        ttk.Label(bar, text="Fundstelle:").pack(side="left")
        self.v_ref = tk.StringVar()
        self.cb_ref = ttk.Combobox(bar, textvariable=self.v_ref, state="readonly", width=110)
        self.cb_ref.pack(side="left", padx=4, fill="x", expand=True)
        self.cb_ref.bind("<<ComboboxSelected>>", lambda e: self._show_code())
        self.txt_code = self._make_text(code_tab)
        self.nb.add(code_tab, text="Dekompilierter Code")
        self.txt_log = self._text_tab("Log")
        self.paned.add(self.nb, weight=2)

        self.txt_code.tag_configure("hit", background="#fff3a0")
        self.txt_code.tag_configure("name", foreground="#b00020", font=("Consolas", 10, "bold"))

    def _make_text(self, parent) -> tk.Text:
        frame = ttk.Frame(parent)
        frame.pack(fill="both", expand=True)
        txt = tk.Text(frame, wrap="none", font=("Consolas", 10), undo=False)
        ys = ttk.Scrollbar(frame, orient="vertical", command=txt.yview)
        xs = ttk.Scrollbar(frame, orient="horizontal", command=txt.xview)
        txt.configure(yscrollcommand=ys.set, xscrollcommand=xs.set)
        ys.pack(side="right", fill="y")
        xs.pack(side="bottom", fill="x")
        txt.pack(fill="both", expand=True)
        return txt

    def _text_tab(self, title: str) -> tk.Text:
        tab = ttk.Frame(self.nb)
        txt = self._make_text(tab)
        self.nb.add(tab, text=title)
        return txt

    # -------------------------------------------------------------- overlay
    def _apply_overlay(self) -> None:
        try:
            self.root.attributes("-topmost", bool(self.v_topmost.get() or self.v_compact.get()))
            self.root.attributes("-alpha", float(self.v_alpha.get()))
        except tk.TclError:
            pass
        if self.v_compact.get():
            self.cfg.pack_forget()
            if not getattr(self, "_geom_before", None):
                self._geom_before = self.root.geometry()
            self.root.geometry("760x520")
        else:
            if not self.cfg.winfo_ismapped():
                self.cfg.pack(fill="x", padx=6, pady=(6, 2), before=self.root.pack_slaves()[0])
            if getattr(self, "_geom_before", None):
                self.root.geometry(self._geom_before)
                self._geom_before = None

    # --------------------------------------------------------------- browse
    def _browse_ghidra(self):
        d = filedialog.askdirectory(title="Ghidra-Installationsordner wählen (enthält support\\analyzeHeadless.bat)")
        if d:
            self.v_ghidra.set(d)
            self._check_ghidra()

    def _browse_driver(self):
        d = filedialog.askdirectory(title="NVIDIA-Treiberordner wählen", initialdir=self.v_driver.get() or None)
        if d:
            self.v_driver.set(d)

    def _browse_csv(self):
        f = filedialog.askopenfilename(title="Registry-CSV wählen",
                                       filetypes=[("CSV", "*.csv *.CSV"), ("Text", "*.txt"), ("Alle", "*.*")])
        if f:
            self.v_csv.set(f)
            self.load_csv(f)

    def _browse_work(self):
        d = filedialog.askdirectory(title="Arbeitsordner (Ghidra-Projekt, Ergebnisse)")
        if d:
            self.v_work.set(d)

    def _browse_java(self):
        d = filedialog.askdirectory(title="JDK-Ordner (z.B. C:\\Program Files\\Eclipse Adoptium\\jdk-21)")
        if d:
            self.v_java.set(d)

    def _check_ghidra(self):
        path = find_analyze_headless(self.v_ghidra.get())
        if path:
            self.v_ghidra_info.set(f"✔ Ghidra {ghidra_version(self.v_ghidra.get())}")
        elif self.v_ghidra.get():
            self.v_ghidra_info.set("✘ analyzeHeadless nicht gefunden")
        else:
            self.v_ghidra_info.set("Bitte Ghidra-Ordner wählen")
        return path

    def _auto_driver(self):
        dirs = find_driver_dirs()
        if not dirs:
            messagebox.showwarning("Treiber", "Kein NVIDIA-Treiber im DriverStore gefunden.\n"
                                   "Bitte den Ordner manuell wählen (z.B. C:\\Windows\\System32\\DriverStore\\"
                                   "FileRepository\\nv_dispi.inf_amd64_…).")
            return
        self.v_driver.set(dirs[0])
        self.log("Gefundene Treiberordner:\n  " + "\n  ".join(dirs))

    # ----------------------------------------------------------------- data
    def load_csv(self, path: str) -> None:
        if not path:
            return
        try:
            values = load_csv(path)
        except OSError as exc:
            messagebox.showerror("CSV", str(exc))
            return
        self.records = {v.name.lower(): Record(value=v) for v in values}
        self.order = list(self.records)
        self.file_hits = {}
        self._refresh_table()
        self.log(f"{len(values)} Registry-Werte aus {path} geladen.")
        self.v_status.set(f"{len(values)} Werte geladen.")

    def _row_values(self, r: Record) -> tuple:
        files = ", ".join(os.path.basename(f) for f in r.files[:3])
        short = r.summary.split("\n", 1)[0] if r.summary else "; ".join(name_hints(r.value.name)[:2])
        refs = len([a for a in r.analyses if a.function or a.table])
        return (r.value.name, r.value.total, r.status, r.confidence, files, refs or "", short)

    def _status_group(self, status: str) -> str:
        for g in ("dekompiliert", "String gefunden", "nicht gefunden", "Fehler", "offen"):
            if status.startswith(g):
                return g
        return status

    def _refresh_table(self) -> None:
        flt = self.v_filter.get().strip().lower()
        sflt = self.v_status_filter.get()
        keys = list(self.records)
        keyfunc = {
            "name": lambda k: k,
            "total": lambda k: self.records[k].value.total,
            "status": lambda k: self.records[k].status,
            "conf": lambda k: self.records[k].confidence,
            "files": lambda k: ",".join(self.records[k].files),
            "refs": lambda k: len(self.records[k].analyses),
            "short": lambda k: self.records[k].summary,
        }[self.sort_col]
        keys.sort(key=keyfunc, reverse=self.sort_rev)
        sel = set(self.tree.selection())
        self.tree.delete(*self.tree.get_children())
        shown = 0
        for k in keys:
            r = self.records[k]
            if flt and flt not in k and flt not in r.summary.lower():
                continue
            group = self._status_group(r.status)
            if sflt != "Alle" and group != sflt:
                continue
            self.tree.insert("", "end", iid=k, values=self._row_values(r), tags=(group,))
            shown += 1
        for k in sel:
            if self.tree.exists(k):
                self.tree.selection_add(k)
        done = sum(1 for r in self.records.values() if r.status.startswith("dekompiliert"))
        found = sum(1 for r in self.records.values() if r.hits)
        self.v_count.set(f"{shown} angezeigt · {len(self.records)} gesamt · {found} gefunden · {done} dekompiliert")

    def _update_row(self, key: str) -> None:
        r = self.records.get(key)
        if r and self.tree.exists(key):
            self.tree.item(key, values=self._row_values(r), tags=(self._status_group(r.status),))
        if key == self.current_key:
            self._show_details(key)

    def _sort(self, col: str) -> None:
        self.sort_rev = not self.sort_rev if self.sort_col == col else False
        self.sort_col = col
        self._refresh_table()

    # -------------------------------------------------------------- details
    def _on_select(self, _evt=None) -> None:
        sel = self.tree.selection()
        if sel:
            self.current_key = sel[0]
            self._show_details(sel[0])

    def _show_details(self, key: str) -> None:
        r = self.records[key]
        v = r.value
        t = self.txt_explain
        t.delete("1.0", "end")
        t.insert("end", f"{v.name}\n", ())
        t.insert("end", f"Schlüssel: {v.key}\nZugriffe laut ProcMon: {v.total} (Lesen {v.reads}, Schreiben {v.writes})\n")
        t.insert("end", f"Status: {r.status}    Sicherheit: {r.confidence or '—'}\n\n")
        t.insert("end", (r.summary or "Noch nicht analysiert.\n" + "\n".join(name_hints(v.name))) + "\n\n")
        if r.hits:
            t.insert("end", "String-Fundstellen (Vorscan):\n")
            for h in r.hits[:15]:
                t.insert("end", f"  {os.path.basename(h.file)} @0x{h.offset:x} [{h.encoding}{'' if h.exact else ', Teilstring'}] {h.text[:100]}\n")
            t.insert("end", "\n")
        for i, a in enumerate(r.analyses):
            t.insert("end", f"── Fundstelle {i + 1}: {a.file} · {a.function or 'Datenverweis'} {a.entry} [{a.kind}]\n")
            if a.reader:
                t.insert("end", f"   Lesefunktion: {a.reader}   Ergebnisvariable: {a.out_var or '?'}\n")
            if a.constants:
                t.insert("end", f"   Konstanten: {', '.join(a.constants)}\n")
            if a.comparisons:
                t.insert("end", f"   Vergleiche: {'; '.join(a.comparisons)}\n")
            if a.masks:
                t.insert("end", f"   Bitoperationen: {'; '.join(a.masks)}\n")
            if a.stores:
                t.insert("end", f"   Gespeichert in: {'; '.join(a.stores)}\n")
            if a.snippet:
                t.insert("end", a.snippet + "\n")
            t.insert("end", "\n")

        items = [f"{i + 1}: {a.file} · {a.function or 'Datenverweis'} {a.entry} [{a.kind}]" for i, a in enumerate(r.analyses)]
        self.cb_ref["values"] = items
        self.v_ref.set(items[0] if items else "")
        self._show_code()

    def _show_code(self) -> None:
        t = self.txt_code
        t.delete("1.0", "end")
        if not self.current_key:
            return
        r = self.records[self.current_key]
        idx = self.cb_ref.current()
        if idx < 0 or idx >= len(r.analyses):
            t.insert("end", "Keine dekompilierte Fundstelle vorhanden.")
            return
        a = r.analyses[idx]
        if not a.code:
            t.insert("end", a.snippet or "Kein Code (Datenverweis).")
            return
        t.insert("end", a.code)
        for ln in a.lines:
            t.tag_add("hit", f"{ln + 1}.0", f"{ln + 1}.end")
        name = r.value.name
        start = "1.0"
        while True:
            pos = t.search(name, start, stopindex="end", nocase=True)
            if not pos:
                break
            end = f"{pos}+{len(name)}c"
            t.tag_add("name", pos, end)
            start = end
        if a.lines:
            t.see(f"{a.lines[0] + 1}.0")

    # ------------------------------------------------------------------ log
    def log(self, msg: str) -> None:
        self.txt_log.insert("end", time.strftime("[%H:%M:%S] ") + msg + "\n")
        self.txt_log.see("end")

    def _post(self, fn, *args) -> None:
        self.ui_queue.put((fn, args))

    def _poll_queue(self) -> None:
        try:
            for _ in range(500):
                fn, args = self.ui_queue.get_nowait()
                fn(*args)
        except queue.Empty:
            pass
        self.root.after(100, self._poll_queue)

    # --------------------------------------------------------------- worker
    def _start(self, target, *args) -> None:
        if self.worker and self.worker.is_alive():
            messagebox.showinfo("Läuft", "Es läuft bereits ein Vorgang.")
            return
        if not self.records:
            messagebox.showwarning("CSV", "Bitte zuerst eine Registry-CSV laden.")
            return
        self._save_settings()
        self.stop_flag.clear()
        for b in (self.btn_all, self.btn_pre, self.btn_ghidra, self.btn_sel):
            b.configure(state="disabled")
        self.btn_stop.configure(state="normal")

        def wrapper():
            try:
                target(*args)
            except Exception as exc:  # noqa: BLE001 – Fehler in der GUI anzeigen
                self._post(self.log, f"FEHLER: {exc!r}")
                self._post(messagebox.showerror, "Fehler", str(exc))
            finally:
                self._post(self._finished)

        self.worker = threading.Thread(target=wrapper, daemon=True)
        self.worker.start()

    def _finished(self) -> None:
        for b in (self.btn_all, self.btn_pre, self.btn_ghidra, self.btn_sel):
            b.configure(state="normal")
        self.btn_stop.configure(state="disabled")
        self.runner = None
        self._refresh_table()
        self._autosave()

    def stop(self) -> None:
        self.stop_flag.set()
        if self.runner:
            self.runner.cancel()
        self.v_status.set("Wird abgebrochen…")

    def _progress(self, value: float, maximum: float, text: str) -> None:
        self.progress.configure(maximum=max(maximum, 1), value=value)
        self.v_status.set(text)

    def run_prescan(self) -> None:
        self._start(self._do_prescan)

    def run_ghidra(self) -> None:
        if not self._check_ghidra():
            messagebox.showwarning("Ghidra", "Bitte zuerst den Ghidra-Installationsordner wählen.")
            return
        self._start(self._do_ghidra, None)

    def run_all(self) -> None:
        if not self._check_ghidra():
            messagebox.showwarning("Ghidra", "Bitte zuerst den Ghidra-Installationsordner wählen.")
            return
        self._start(self._do_all)

    def run_selected(self) -> None:
        sel = list(self.tree.selection())
        if not sel:
            messagebox.showinfo("Auswahl", "Bitte in der Tabelle Werte markieren.")
            return
        if not self._check_ghidra():
            messagebox.showwarning("Ghidra", "Bitte zuerst den Ghidra-Installationsordner wählen.")
            return
        self._start(self._do_selected, sel)

    def _do_all(self) -> None:
        self._do_prescan()
        if not self.stop_flag.is_set():
            self._do_ghidra(None)

    def _do_selected(self, keys: list[str]) -> None:
        if not any(self.records[k].hits for k in keys):
            self._do_prescan(only=keys)
        if not self.stop_flag.is_set():
            self._do_ghidra(set(keys))

    def _do_prescan(self, only: list[str] | None = None) -> None:
        folder = self.v_driver.get().strip()
        if not folder or not os.path.exists(folder):
            raise RuntimeError(f"Treiberordner existiert nicht: {folder!r}")
        drivers_dir = os.path.normcase(os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "drivers"))
        nvidia_only = os.path.normcase(os.path.abspath(folder)) == drivers_dir
        files = list_binaries(folder, recursive=self.v_recursive.get(), nvidia_only=nvidia_only)
        self._post(self.log, f"Vorscan: {len(files)} Dateien in {folder}")
        keys = only or list(self.records)
        names = [self.records[k].value.name for k in keys]

        def progress(i, n, path):
            self._post(self._progress, i, n, f"Vorscan {i}/{n}: {os.path.basename(path)}")

        t0 = time.time()
        res = prescan(files, names, stop_at_first_file=self.v_first.get(),
                      progress=progress, should_stop=self.stop_flag.is_set)

        def apply():
            for k in keys:
                r = self.records[k]
                r.hits = res.hits.get(k, [])
                if r.status.startswith("dekompiliert"):
                    continue
                if r.hits:
                    exact = any(h.exact for h in r.hits)
                    r.status = "String gefunden" + ("" if exact else " (Teilstring)")
                else:
                    r.status = "nicht gefunden"
                    r.summary = ("Name kommt in keiner Treiberdatei als Klartext vor (evtl. verschlüsselt/"
                                 "zur Laufzeit zusammengesetzt oder von einer anderen Komponente gelesen).\n"
                                 + "\n".join(name_hints(r.value.name)))
                    r.confidence = "—"
            for f, ns in res.files_with_hits.items():
                self.file_hits.setdefault(f, set()).update(ns)
            self._refresh_table()
            found = sum(1 for k in keys if self.records[k].hits)
            self.log(f"Vorscan fertig in {time.time() - t0:.1f}s: {found}/{len(keys)} Werte gefunden, "
                     f"{len(res.files_with_hits)} Dateien mit Treffern:")
            for f, ns in sorted(res.files_with_hits.items(), key=lambda x: -len(x[1])):
                self.log(f"  {len(ns):5d}  {f}")
            self.v_status.set(f"Vorscan fertig: {found}/{len(keys)} Werte gefunden.")

        self._post(apply)
        # auf GUI-Thread warten, damit _do_ghidra die Treffer sieht
        ev = threading.Event()
        self._post(ev.set)
        ev.wait()

    def _do_ghidra(self, only: set[str] | None) -> None:
        if not self.file_hits:
            self._do_prescan(only=list(only) if only else None)
        runner = GhidraRunner(
            self.v_ghidra.get(), self.v_work.get(),
            max_mem=self.v_mem.get(), java_home=self.v_java.get(),
            analysis_timeout=self._int(self.v_timeout), max_cpu=self._int(self.v_cpu),
            fast_analysis=self.v_fast.get(), log=lambda m: self._post(self.log, m),
        )
        self.runner = runner

        # Dateien in Prioritätsreihenfolge (wie im Vorscan), Werte pro Datei
        files = [f for f in list_binaries_order(self.file_hits)]
        done_names: set[str] = set()
        for i, f in enumerate(files):
            if self.stop_flag.is_set():
                break
            names = sorted(self.file_hits[f])
            if only is not None:
                names = [n for n in names if n in only]
            if self.v_first.get():
                names = [n for n in names if n not in done_names
                         and not self.records[n].status.startswith("dekompiliert")]
            if not names:
                continue
            imported = runner.is_imported(f)
            self._post(self._progress, i, len(files),
                       f"Ghidra {i + 1}/{len(files)}: {os.path.basename(f)} – {len(names)} Werte"
                       + ("" if imported else " (Import + Autoanalyse, kann bei nvlddmkm.sys über eine Stunde dauern)"))
            try:
                result = runner.analyze(f, [self.records[n].value.name for n in names])
            except GhidraError as exc:
                self._post(self.log, f"{os.path.basename(f)}: {exc}")
                if self.stop_flag.is_set():
                    break
                for n in names:
                    self._post(self._mark_error, n, str(exc))
                continue
            analyses = analyses_from_ghidra(result)
            self._post(self._apply_ghidra, f, names, analyses)
            done_names.update(k for k, v in analyses.items() if v)
        self._post(self._progress, len(files), len(files), "Ghidra-Analyse beendet.")

    def _mark_error(self, key: str, msg: str) -> None:
        r = self.records[key]
        if not r.status.startswith("dekompiliert"):
            r.status = "Fehler"
            r.summary = msg
        self._update_row(key)

    def _apply_ghidra(self, file: str, names: list[str], analyses: dict) -> None:
        base = os.path.basename(file)
        for n in names:
            r = self.records[n]
            new = analyses.get(n, [])
            r.analyses = [a for a in r.analyses if a.file != base] + new
            if base not in r.analyzed_files:
                r.analyzed_files.append(base)
            if r.analyses:
                r.status = "dekompiliert"
            elif not r.status.startswith("dekompiliert"):
                r.status = "String gefunden (keine Referenz)"
            r.summary = summarize(r.value.name, r.analyses)
            r.confidence = confidence(r.analyses)
            self._update_row(n)
        self.log(f"{base}: {sum(1 for n in names if analyses.get(n))}/{len(names)} Werte mit Code-Referenzen.")
        self._refresh_table()
        self._autosave()

    # --------------------------------------------------------------- export
    def _ordered_records(self) -> list[Record]:
        return [self.records[k] for k in sorted(self.records)]

    def _autosave(self) -> None:
        try:
            os.makedirs(self.v_work.get(), exist_ok=True)
            save_json(os.path.join(self.v_work.get(), "letzte_ergebnisse.json"), self._ordered_records())
        except OSError as exc:
            self.log(f"Autosave fehlgeschlagen: {exc}")

    def export(self) -> None:
        f = filedialog.asksaveasfilename(
            title="Ergebnisse exportieren", defaultextension=".html",
            filetypes=[("HTML-Bericht", "*.html"), ("CSV (Excel)", "*.csv"), ("JSON (vollständig)", "*.json")])
        if not f:
            return
        recs = self._ordered_records()
        ext = os.path.splitext(f)[1].lower()
        if ext == ".csv":
            export_csv(f, recs)
        elif ext == ".json":
            save_json(f, recs)
        else:
            export_html(f, recs)
        self.log(f"Exportiert: {f}")

    def load_results(self) -> None:
        f = filedialog.askopenfilename(title="Ergebnisse laden", initialdir=self.v_work.get(),
                                       filetypes=[("JSON", "*.json")])
        if not f:
            return
        recs = load_json(f)
        self.records = {r.value.name.lower(): r for r in recs}
        self.file_hits = {}
        for k, r in self.records.items():
            for h in r.hits:
                self.file_hits.setdefault(h.file, set()).add(k)
        self._refresh_table()
        self.log(f"{len(recs)} Ergebnisse geladen: {f}")

    def _on_close(self) -> None:
        self._save_settings()
        if self.runner:
            self.runner.cancel()
        self.root.destroy()


def list_binaries_order(file_hits: dict[str, set[str]]) -> list[str]:
    from .driver_finder import _priority
    return sorted(file_hits, key=_priority)


def main() -> None:
    root = tk.Tk()
    App(root)
    root.mainloop()
