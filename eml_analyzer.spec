# -*- mode: python ; coding: utf-8 -*-
#
# PyInstaller spec for eml-analyzer.exe
# Build with:  pyinstaller eml_analyzer.spec --clean
#
from PyInstaller.utils.hooks import collect_all

block_cipher = None

datas = []
binaries = []
hiddenimports = [
    # All eml_analyzer modules (dynamic imports inside the package)
    "eml_analyzer",
    "eml_analyzer.cli",
    "eml_analyzer.analyzer",
    "eml_analyzer.config",
    "eml_analyzer.models",
    "eml_analyzer.eml_parser",
    "eml_analyzer.reporting",
    "eml_analyzer.correlation",
    "eml_analyzer.cache",
    "eml_analyzer.hashing",
    "eml_analyzer.ip_utils",
    "eml_analyzer.url_utils",
    "eml_analyzer.redirect_utils",
    "eml_analyzer.url_screenshot",
    "eml_analyzer.office_utils",
    "eml_analyzer.pdf_utils",
    "eml_analyzer.qr_utils",
    "eml_analyzer.log_utils",
    "eml_analyzer.virustotal_client",
    "eml_analyzer.abuseipdb_client",
    "eml_analyzer.urlscan_client",
    "eml_analyzer.hybrid_analysis_client",
    "eml_analyzer.mxtoolbox_client",
    "eml_analyzer.opentip_client",
    "eml_analyzer.ipinfo_client",
    # stdlib modules that PyInstaller sometimes misses
    "email",
    "email.parser",
    "email.policy",
    "email.message",
    "email.headerregistry",
    "email.contentmanager",
    "email.utils",
    "sqlite3",
    "zipfile",
    "zlib",
    "fnmatch",
    "html",
    "html.parser",
    "urllib",
    "urllib.parse",
    "urllib.request",
]

# Bundle pdf-parser.py from the tools directory so frozen exe can use it
import os as _os
_pdf_parser_src = _os.path.join("eml_analyzer", "tools", "pdf-parser.py")
if _os.path.exists(_pdf_parser_src):
    datas.append((_pdf_parser_src, "tools"))

# Collect optional packages — silently skip any that are not installed.
# Playwright is intentionally excluded: its browser binaries (~200 MB) cannot
# be self-contained inside the exe. Users who need URL screenshots must install
# playwright separately on the host: pip install playwright && playwright install chromium
for _pkg in ("oletools", "olefile", "peepdf", "pdfid", "PIL", "pyzbar", "fitz"):
    try:
        _d, _b, _h = collect_all(_pkg)
        datas += _d
        binaries += _b
        hiddenimports += _h
    except Exception:
        pass

# pdfid in-process hidden import
hiddenimports += ["pdfid.pdfid"]

a = Analysis(
    ["run.py"],
    pathex=["."],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        "tkinter",
        "_tkinter",
        "matplotlib",
        "numpy",
        "scipy",
        "PyQt5",
        "PyQt6",
        "wx",
        "test",
        "unittest",
        # Playwright excluded: browser binaries can't be bundled in a single exe.
        # The feature degrades gracefully with a clear install message.
        "playwright",
        "playwright.sync_api",
        "playwright.async_api",
        "playwright._impl",
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name="eml-analyzer",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
