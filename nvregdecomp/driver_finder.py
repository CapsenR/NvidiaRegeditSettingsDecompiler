"""Findet die installierten NVIDIA-Treiberdateien unter Windows."""

from __future__ import annotations

import glob
import os
import sys

DISPLAY_CLASS = r"SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}"
BINARY_EXTS = (".sys", ".dll", ".exe")

# Dateien, die erfahrungsgemäß die meisten Registry-Werte der Display-Klasse
# lesen. Sie werden zuerst gescannt.
PRIORITY = [
    "nvlddmkm.sys",   # Kernel-Treiber (Resource Manager, Display, Power)
    "nvldumdx.dll",   # User-Mode-Loader
    "nvwgf2umx.dll",  # D3D10/11/12 UMD
    "nvd3dumx.dll",   # D3D9 UMD
    "nvoglv64.dll",   # OpenGL
    "nvgpucomp64.dll",
    "nvcuda64.dll", "nvcuda.dll",
    "nvapi64.dll",
    "nvdlistx.dll",
    "nvppex.dll",
    "nvvkvk64.dll",
]


def _windir() -> str:
    return os.environ.get("SystemRoot") or os.environ.get("WINDIR") or r"C:\Windows"


def _dirs_from_registry() -> list[str]:
    """Liest UserModeDriverName der NVIDIA-Adapter aus der Registry."""
    if sys.platform != "win32":
        return []
    try:
        import winreg
    except ImportError:
        return []

    found: list[str] = []
    try:
        cls = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, DISPLAY_CLASS)
    except OSError:
        return []
    with cls:
        i = 0
        while True:
            try:
                sub = winreg.EnumKey(cls, i)
            except OSError:
                break
            i += 1
            try:
                with winreg.OpenKey(cls, sub) as k:
                    try:
                        provider, _ = winreg.QueryValueEx(k, "ProviderName")
                    except OSError:
                        provider = ""
                    if "nvidia" not in str(provider).lower():
                        continue
                    for vname in ("UserModeDriverName", "UserModeDriverNameWow"):
                        try:
                            val, _ = winreg.QueryValueEx(k, vname)
                        except OSError:
                            continue
                        items = val if isinstance(val, list) else [val]
                        for item in items:
                            d = os.path.dirname(str(item))
                            if d and os.path.isdir(d) and d not in found:
                                found.append(d)
            except OSError:
                continue
    return found


def find_driver_dirs() -> list[str]:
    """Alle plausiblen NVIDIA-Treiberordner, der aktuellste zuerst."""
    result = _dirs_from_registry()

    repo = os.path.join(_windir(), "System32", "DriverStore", "FileRepository")
    candidates = []
    for pattern in ("nv*.inf_amd64_*", "nv*.inf_arm64_*"):
        for d in glob.glob(os.path.join(repo, pattern)):
            if os.path.isfile(os.path.join(d, "nvlddmkm.sys")):
                candidates.append(d)
    candidates.sort(key=lambda d: os.path.getmtime(d), reverse=True)
    for d in candidates:
        if d not in result:
            result.append(d)
    return result


def find_default_driver_dir() -> str:
    dirs = find_driver_dirs()
    if dirs:
        return dirs[0]
    drivers = os.path.join(_windir(), "System32", "drivers")
    return drivers if os.path.isdir(drivers) else ""


def _priority(path: str) -> tuple[int, int]:
    base = os.path.basename(path).lower()
    try:
        rank = PRIORITY.index(base)
    except ValueError:
        rank = len(PRIORITY)
    try:
        size = os.path.getsize(path)
    except OSError:
        size = 0
    return rank, -size


def list_binaries(folder: str, recursive: bool = True, nvidia_only: bool = False) -> list[str]:
    """Alle .sys/.dll/.exe im Ordner, wichtige NVIDIA-Dateien zuerst.

    nvidia_only=True ist für C:\\Windows\\System32\\drivers gedacht, damit dort
    nicht jeder fremde Treiber gescannt wird.
    """
    files: list[str] = []
    if os.path.isfile(folder):
        return [folder]
    walker = os.walk(folder) if recursive else [(folder, [], os.listdir(folder))]
    for root, _dirs, names in walker:
        for n in names:
            if not n.lower().endswith(BINARY_EXTS):
                continue
            if nvidia_only and not n.lower().startswith("nv"):
                continue
            files.append(os.path.join(root, n))
    # nvlddmkm.sys in System32\drivers ergänzen, falls vorhanden
    sys_drv = os.path.join(_windir(), "System32", "drivers", "nvlddmkm.sys")
    if os.path.isfile(sys_drv) and not any(
        os.path.basename(f).lower() == "nvlddmkm.sys" for f in files
    ):
        files.append(sys_drv)
    files.sort(key=_priority)
    return files
