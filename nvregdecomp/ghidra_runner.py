"""Startet Ghidra headless (analyzeHeadless) mit RegValueFinder.java."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import threading
from typing import Callable

SCRIPTS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "ghidra_scripts")
PROJECT_NAME = "NvRegDecomp"


class GhidraError(RuntimeError):
    pass


def find_analyze_headless(ghidra_dir: str) -> str | None:
    """Akzeptiert den Ghidra-Installationsordner, den support-Ordner oder die Datei selbst."""
    if not ghidra_dir:
        return None
    ghidra_dir = os.path.expandvars(os.path.expanduser(ghidra_dir.strip().strip('"')))
    names = ["analyzeHeadless.bat", "analyzeHeadless"] if sys.platform == "win32" else ["analyzeHeadless", "analyzeHeadless.bat"]
    if os.path.isfile(ghidra_dir) and os.path.basename(ghidra_dir) in names:
        return ghidra_dir
    for sub in ("support", ""):
        for n in names:
            p = os.path.join(ghidra_dir, sub, n)
            if os.path.isfile(p):
                return p
    # z.B. C:\Tools\ghidra -> C:\Tools\ghidra\ghidra_11.x_PUBLIC\support
    try:
        for entry in sorted(os.listdir(ghidra_dir), reverse=True):
            full = os.path.join(ghidra_dir, entry)
            if entry.lower().startswith("ghidra") and os.path.isdir(full):
                found = find_analyze_headless(full)
                if found:
                    return found
    except OSError:
        pass
    return None


def ghidra_version(ghidra_dir: str) -> str:
    headless = find_analyze_headless(ghidra_dir)
    if not headless:
        return ""
    root = os.path.dirname(os.path.dirname(headless))
    props = os.path.join(root, "Ghidra", "application.properties")
    try:
        with open(props, encoding="utf-8") as fh:
            for line in fh:
                if line.startswith("application.version="):
                    return line.split("=", 1)[1].strip()
    except OSError:
        pass
    return "unbekannt"


def _file_key(path: str) -> str:
    st = os.stat(path)
    h = hashlib.sha1(f"{os.path.abspath(path).lower()}|{st.st_size}|{int(st.st_mtime)}".encode()).hexdigest()
    return h[:10]


class GhidraRunner:
    def __init__(
        self,
        ghidra_dir: str,
        work_dir: str,
        max_mem: str = "",
        java_home: str = "",
        analysis_timeout: int = 0,
        max_cpu: int = 0,
        fast_analysis: bool = True,
        max_refs: int = 40,
        log: Callable[[str], None] = print,
    ):
        headless = find_analyze_headless(ghidra_dir)
        if not headless:
            raise GhidraError(f"analyzeHeadless nicht gefunden in: {ghidra_dir}")
        self.headless = headless
        self.work_dir = os.path.abspath(work_dir)
        self.project_dir = os.path.join(self.work_dir, "ghidra_project")
        self.out_dir = os.path.join(self.work_dir, "results")
        self.state_file = os.path.join(self.work_dir, "imported.json")
        os.makedirs(self.project_dir, exist_ok=True)
        os.makedirs(self.out_dir, exist_ok=True)
        self.max_mem = max_mem.strip()
        self.java_home = java_home.strip()
        self.analysis_timeout = analysis_timeout
        self.max_cpu = max_cpu
        self.fast_analysis = fast_analysis
        self.max_refs = max_refs
        self.log = log
        self._proc: subprocess.Popen | None = None
        self._cancel = threading.Event()

    # ------------------------------------------------------------------ state
    def _load_state(self) -> dict:
        try:
            with open(self.state_file, encoding="utf-8") as fh:
                return json.load(fh)
        except (OSError, ValueError):
            return {}

    def _save_state(self, state: dict) -> None:
        with open(self.state_file, "w", encoding="utf-8") as fh:
            json.dump(state, fh, indent=2)

    def is_imported(self, binary: str) -> bool:
        return _file_key(binary) in self._load_state()

    # ---------------------------------------------------------------- process
    def cancel(self) -> None:
        self._cancel.set()
        proc = self._proc
        if proc and proc.poll() is None:
            if sys.platform == "win32":
                subprocess.call(
                    ["taskkill", "/T", "/F", "/PID", str(proc.pid)],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )
            else:
                proc.kill()

    def _env(self) -> dict:
        env = dict(os.environ)
        if self.max_mem:
            env["MAXMEM"] = self.max_mem
        if self.java_home:
            env["JAVA_HOME"] = self.java_home
            env["PATH"] = os.path.join(self.java_home, "bin") + os.pathsep + env.get("PATH", "")
        return env

    def _run(self, cmd: list[str]) -> int:
        self.log("> " + " ".join(f'"{c}"' if " " in c else c for c in cmd))
        kwargs = {}
        if sys.platform == "win32":
            kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        self._proc = subprocess.Popen(
            cmd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env=self._env(),
            cwd=self.work_dir,
            text=True,
            encoding="utf-8",
            errors="replace",
            **kwargs,
        )
        assert self._proc.stdout is not None
        for line in self._proc.stdout:
            line = line.rstrip()
            if line:
                self.log(line)
            if self._cancel.is_set():
                break
        rc = self._proc.wait()
        self._proc.stdout.close()
        self._proc = None
        return rc

    def analyze(self, binary: str, names: list[str]) -> dict:
        """Importiert/analysiert die Datei (einmalig) und führt RegValueFinder aus.

        Liefert das von RegValueFinder.java geschriebene JSON als dict.
        """
        if self._cancel.is_set():
            raise GhidraError("abgebrochen")
        key = _file_key(binary)
        base = os.path.basename(binary)
        stem = f"{base}_{key}"
        names_file = os.path.join(self.out_dir, stem + ".names.txt")
        out_file = os.path.join(self.out_dir, stem + ".json")
        log_file = os.path.join(self.out_dir, stem + ".ghidra.log")
        with open(names_file, "w", encoding="utf-8") as fh:
            fh.write("\n".join(names))
        if os.path.exists(out_file):
            os.remove(out_file)

        project = f"{PROJECT_NAME}/{key}"
        post = ["-postScript", "RegValueFinder.java", names_file, out_file, str(self.max_refs)]
        common = ["-scriptPath", SCRIPTS_DIR, "-log", log_file]
        if self.max_cpu > 0:
            common += ["-max-cpu", str(self.max_cpu)]

        state = self._load_state()
        imported = key in state
        if imported:
            cmd = [self.headless, self.project_dir, project, "-process", base, "-noanalysis"] + common + post
            rc = self._run(cmd)
            if not os.path.exists(out_file) and not self._cancel.is_set():
                self.log("Programm nicht im Projekt gefunden - importiere neu.")
                imported = False
                state.pop(key, None)
                self._save_state(state)
        if not imported:
            cmd = [self.headless, self.project_dir, project, "-import", binary, "-overwrite"] + common
            if self.analysis_timeout > 0:
                cmd += ["-analysisTimeoutPerFile", str(self.analysis_timeout)]
            if self.fast_analysis:
                cmd += ["-preScript", "NvFastAnalysis.java"]
            cmd += post
            rc = self._run(cmd)
            if os.path.exists(out_file):
                state[key] = {"file": binary, "program": base}
                self._save_state(state)

        if self._cancel.is_set():
            raise GhidraError("abgebrochen")
        if not os.path.exists(out_file):
            raise GhidraError(f"Ghidra lieferte kein Ergebnis (Exit-Code {rc}). Siehe {log_file}")
        with open(out_file, encoding="utf-8") as fh:
            return json.load(fh)
