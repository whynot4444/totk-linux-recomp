"""Where the installer finds what it runs: the one place that maps the release folder and a repository checkout.

Release (docs/installer.md "Release layout"), root = the unpacked folder:

    python/python.exe       runs every tool (numpy, lz4, cryptography, compression.zstd); its ._pth puts .., ../tools
                            and ../recomp on sys.path, so `python -m installer` imports from the release folder
    recomp/, tools/         the lifter and the scripts; recomp/patches-<v>.txt, tools/data/expected-v<version>.json for
                            each supported update (SUPPORTED)
    llvm/                   llvm-mingw (bin/clang.exe)
    runtime/                libtotkrt.a, the headers, install-side sources (romfs.c, patches.c, ov_zstd.c) and totk.ico; runtime/deps/ holds
                            include/ + lib/ of Vulkan, SDL3, Opus, libvpx and VMA (build_game.py --deps)
    bin/                    totk_xlate.exe (+ totk_xlate.id), hactool.exe, ninja.exe, SDL3.dll, libopus-0.dll
    data/shader_list.tsv    the MacNativeGames shader list
    totk.ini.example
    VERSION                 the release version, one line
    temp/                   the default temp folder (created)

Linux release (the AppImage's AppDir, mounted read-only, tools/make_appimage.py), root = the AppDir:

    python/bin/python3      python-build-standalone 3.14 with the same packages; AppRun puts .., tools and recomp on
                            PYTHONPATH
    llvm/                   clang, lld and llvm-ar (bin/) with clang's own headers (lib/clang/)
    sysroot/                glibc, libstdc++ and Linux headers and libraries the link needs (an older glibc than the
                            players' systems have, so totk runs on all of them)
    runtime/                as above; runtime/deps/ holds include/ + lib/ of SDL3, Opus, libvpx, zstd, Vulkan and VMA
    bin/                    totk_xlate (+ totk_xlate.id), hactool, ninja; bin/lib/ the shared libraries totk needs beside
                            it (copied into lib/ of the install folder: totk's run path is $ORIGIN/lib)
    data/, totk.ini.example, VERSION as above. The temp folder is $XDG_CACHE_HOME/totk-setup (the AppDir is read-only).

Dev mode, root = a repository checkout (no python/python.exe): build/py314-embed/py/python.exe (the embeddable
Python the release ships, with the same packages), else this Python; toolchain/llvm-mingw-*/ and toolchain/deps-mingw;
runtime/ as the sources with build/install-rtlib/libtotkrt.a (tools/build_game.py --make-runtime-lib --out
build/install-rtlib); MSYS2 UCRT64 ninja.exe; toolchain/hactool; build/xlate/totk_xlate.exe; the shader list from
refs/MacNativeGames; build/install-temp. The version is VERSION with -dev and the commit: 0.1.0-dev+973c626.
"""
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

EXE = '.exe' if os.name == 'nt' else ''
LINUX = sys.platform.startswith('linux')
LIB_DIR = 'lib' if LINUX else ''   # where the install folder keeps the shared libraries totk loads
UCRT = Path(r'C:\msys64\ucrt64\bin')
SUPPORTED = ('1.2.1', '1.4.3')   # updates the installer builds; the check identifies the player's by hash


def version_tag(version):
    """'1.4.3' -> 'v143': the version name of build_game.py, make_romfs_patches.py and the patch tables."""
    return 'v' + version.replace('.', '')


@dataclass(frozen=True)
class Layout:
    root: Path
    dev: bool
    release: str
    python: Path          # runs the tools
    tools: Path
    recomp: Path
    llvm: Path            # llvm-mingw tree
    deps: Path            # include/ and lib/ for the link
    runtime: Path         # runtime headers and install-side sources
    runtime_lib: Path     # libtotkrt.a
    ninja: Path
    hactool: Path
    xlate: Path           # totk_xlate.exe; a totk_xlate.id beside it is copied too
    dlls: tuple = field(default_factory=tuple)
    shader_list: Path | None = None   # None: dev, read from refs/MacNativeGames through git
    ini_example: Path | None = None
    temp: Path | None = None
    sysroot: Path | None = None   # Linux release: --sysroot for clang

    @property
    def clang(self):
        return self.llvm / 'bin' / ('clang' + EXE)

    def patches(self, version):
        """The code patch table for recomp/gen.py."""
        return self.recomp / f'patches-{version_tag(version)}.txt'

    def expected(self, version):
        """The expected hashes of the update."""
        return self.tools / 'data' / f'expected-v{version}.json'

    def missing(self):
        """Paths the steps need that do not exist."""
        need = [self.python, self.tools / 'extract.py', self.tools / 'build_game.py', self.tools / 'prepare_shaders.py',
                self.tools / 'make_romfs_patches.py', self.recomp / 'gen.py', self.clang,
                self.deps / 'include', self.deps / 'lib', self.runtime, self.runtime_lib, self.ninja, self.hactool,
                self.xlate, *self.dlls, *(f(v) for v in SUPPORTED for f in (self.patches, self.expected))]
        if self.sysroot:
            need.append(self.sysroot)
        if self.shader_list:
            need.append(self.shader_list)
        return [str(p) for p in need if not p.exists()]


def release_python(root):
    return root / 'python' / ('bin/python3' if LINUX else 'python' + EXE)


def is_release(root):
    return release_python(root).is_file()


def cache_home():
    return Path(os.environ.get('XDG_CACHE_HOME') or Path.home() / '.cache')


def release_layout(root):
    version = root / 'VERSION'
    if LINUX:
        return Layout(
            root=root, dev=False,
            release=version.read_text(encoding='utf-8').strip() if version.is_file() else 'unknown',
            python=release_python(root), tools=root / 'tools', recomp=root / 'recomp',
            llvm=root / 'llvm', deps=root / 'runtime' / 'deps', runtime=root / 'runtime',
            runtime_lib=root / 'runtime' / 'libtotkrt.a',
            ninja=root / 'bin' / 'ninja', hactool=root / 'bin' / 'hactool', xlate=root / 'bin' / 'totk_xlate',
            dlls=tuple(sorted((root / 'bin' / 'lib').glob('*.so*'))),
            shader_list=root / 'data' / 'shader_list.tsv', ini_example=root / 'totk.ini.example',
            temp=cache_home() / 'totk-setup', sysroot=root / 'sysroot')
    return Layout(
        root=root, dev=False,
        release=version.read_text(encoding='utf-8').strip() if version.is_file() else 'unknown',
        python=root / 'python' / ('python' + EXE),
        tools=root / 'tools', recomp=root / 'recomp',
        llvm=root / 'llvm', deps=root / 'runtime' / 'deps', runtime=root / 'runtime',
        runtime_lib=root / 'runtime' / 'libtotkrt.a',
        ninja=root / 'bin' / ('ninja' + EXE), hactool=root / 'bin' / ('hactool' + EXE),
        xlate=root / 'bin' / ('totk_xlate' + EXE),
        dlls=(root / 'bin' / 'SDL3.dll', root / 'bin' / 'libopus-0.dll'),
        shader_list=root / 'data' / 'shader_list.tsv', ini_example=root / 'totk.ini.example', temp=root / 'temp')


def dev_layout_linux(root, release):
    """A checkout on Linux: the system's clang, ninja and libraries (docs/linux.md); no sysroot."""
    clang = Path(shutil.which('clang') or '/usr/bin/clang')
    deps = root / 'toolchain' / 'deps-linux'   # optional: include/ and lib/ like build_game.py --deps
    return Layout(
        root=root, dev=True, release=release, python=Path(sys.executable),
        tools=root / 'tools', recomp=root / 'recomp', llvm=clang.parent.parent,
        deps=deps if deps.is_dir() else Path('/usr'), runtime=root / 'runtime',
        runtime_lib=root / 'build' / 'install-rtlib' / 'libtotkrt.a',
        ninja=Path(shutil.which('ninja') or '/usr/bin/ninja'), hactool=root / 'toolchain' / 'hactool' / 'hactool',
        xlate=root / 'build' / 'xlate' / 'totk_xlate', dlls=(),
        shader_list=None, ini_example=root / 'totk.ini.example', temp=root / 'build' / 'install-temp')


def dev_layout(root):
    commit = subprocess.run(['git', '-C', str(root), 'rev-parse', '--short', 'HEAD'], capture_output=True,
                            text=True).stdout.strip()
    embed = root / 'build' / 'py314-embed' / 'py' / ('python' + EXE)
    trees = sorted(p.parent.parent for p in (root / 'toolchain').glob('llvm-mingw-*/llvm-mingw-*/bin/clang' + EXE))
    deps = root / 'toolchain' / 'deps-mingw'
    semver = (root / 'VERSION').read_text(encoding='utf-8').strip()
    if LINUX:
        return dev_layout_linux(root, f'{semver}-dev+{commit or "unknown"}')
    return Layout(
        root=root, dev=True, release=f'{semver}-dev+{commit or "unknown"}',
        python=embed if embed.is_file() else Path(sys.executable),
        tools=root / 'tools', recomp=root / 'recomp',
        llvm=trees[-1] if trees else root / 'toolchain' / 'llvm-mingw-missing', deps=deps,
        runtime=root / 'runtime', runtime_lib=root / 'build' / 'install-rtlib' / 'libtotkrt.a',
        ninja=UCRT / ('ninja' + EXE), hactool=root / 'toolchain' / 'hactool' / ('hactool' + EXE),
        xlate=root / 'build' / 'xlate' / ('totk_xlate' + EXE),
        dlls=tuple(sorted((deps / 'bin').glob('*.dll'))),
        shader_list=None, ini_example=root / 'totk.ini.example', temp=root / 'build' / 'install-temp')


def find(root=None):
    """The layout of root (default: the folder above this package)."""
    root = Path(root or Path(__file__).resolve().parent.parent).resolve()
    return release_layout(root) if is_release(root) else dev_layout(root)
