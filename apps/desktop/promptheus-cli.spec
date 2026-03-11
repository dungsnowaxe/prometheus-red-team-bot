# PyInstaller spec for Promptheus CLI (used by desktop app bundle).
# Run from repo root: pyinstaller apps/desktop/promptheus-cli.spec

import os
block_cipher = None

# SPECPATH is the directory containing this spec file (apps/desktop/).
# We resolve paths relative to the repo root.
_repo_root = os.path.abspath(os.path.join(SPECPATH, '..', '..'))

a = Analysis(
    [os.path.join(_repo_root, 'promptheus', '__main__.py')],
    pathex=[_repo_root],
    binaries=[],
    datas=[],
    hiddenimports=[
        'apps.cli.main',
        'apps.cli.wizard',
        'promptheus.adapters.rest',
        'promptheus.core.engine',
        'promptheus.core.attacks',
        'promptheus.core.judge',
        'promptheus.config',
        'promptheus.config_store',
        'typer',
        'rich',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
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
    name='promptheus',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
