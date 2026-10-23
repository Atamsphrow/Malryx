# Spec PyInstaller : backend Malryx en executable autonome.
#
# Construction (depuis la racine du depot, sur Debian) :
#     pyinstaller packaging/malryx-backend.spec --clean --noconfirm
#
# Produit dist/malryx-backend, sans dependance a un interpreteur Python
# installe sur la machine cible. C'est ce binaire que le .deb embarque, a cote
# du bundle Flutter (section 2 de la spec).
#
# Note : on reste en mode "onedir" plutot que "onefile". Un onefile se
# reextrait dans /tmp a chaque lancement, ce qui est lent et pose probleme quand
# /tmp est monte en noexec, situation courante sur une machine durcie.

import os

block_cipher = None

BACKEND = os.path.join(os.getcwd(), "backend")

a = Analysis(
    [os.path.join(BACKEND, "main.py")],
    pathex=[BACKEND],
    binaries=[],
    datas=[
        # Regles YARA et base de hash livrees avec l'application.
        (os.path.join(BACKEND, "rules"), "rules"),
        (os.path.join(BACKEND, "signatures"), "signatures"),
    ],
    hiddenimports=[
        # uvicorn charge ses implementations par nom, PyInstaller ne peut pas
        # les deduire de l'arbre d'imports.
        "uvicorn.logging",
        "uvicorn.loops.auto",
        "uvicorn.loops.uvloop",
        "uvicorn.protocols.http.auto",
        "uvicorn.protocols.http.httptools_impl",
        "uvicorn.protocols.websockets.auto",
        "uvicorn.protocols.websockets.websockets_impl",
        "uvicorn.lifespan.on",
        # Modules du backend atteints dynamiquement.
        "cli",  # atteint via `malryx-backend --cli`
        "api.scan_routes",
        "api.device_routes",
        "api.quarantine_routes",
        "engines.clamav_engine",
        "engines.yara_engine",
        "engines.hash_checker",
        "engines.heuristics",
        "devices.usb_scanner",
        "devices.android_scanner",
        "devices.windows_scanner",
        "devices.linux_remote_scanner",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        # Rien de graphique cote backend : on evite d'embarquer des megaoctets
        # inutiles.
        "tkinter",
        "matplotlib",
        "numpy",
        "PIL",
        "PyQt5",
        "PySide6",
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
    [],
    exclude_binaries=True,
    name="malryx-backend",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,  # UPX sur un binaire d'antivirus : les autres AV le flaggent
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name="malryx-backend",
)
