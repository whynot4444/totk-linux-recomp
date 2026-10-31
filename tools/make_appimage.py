"""Assemble TotK-Setup for Linux as an AppImage: the installer of docs/installer.md with everything it runs inside.

    python3 tools/make_appimage.py --out build/appimage/AppDir --appimage build/appimage/TotK-Setup-x86_64.AppImage \\
        --python-tar cpython-3.14.*-x86_64-unknown-linux-gnu-install_only.tar.gz --llvm LLVM-<v>-Linux-X64 \\
        --sdl3 <SDL3 install prefix> --vulkan-headers <Vulkan-Headers checkout> --vma <VulkanMemoryAllocator checkout> \\
        --hactool toolchain/hactool/hactool --ninja <ninja> --xlate build/xlate/totk_xlate --appimagetool <appimagetool>

.github/workflows/appimage.yml runs it on Ubuntu 22.04 and downloads the inputs; any Linux x86-64 machine with the same
inputs works. The sysroot is copied from the building machine (its glibc is the oldest the AppImage runs on, 2.35 on
Ubuntu 22.04), as are the Opus, libvpx and zstd libraries and headers (libopus-dev, libvpx-dev, libzstd-dev).

The AppDir (installer/layout.py, "Linux release"):

    AppRun, totk-setup.desktop, totk-setup.png, .DirIcon
    python/     python-build-standalone 3.14 (Tk included) + tools/requirements-installer.txt
    llvm/       clang, ld.lld, llvm-ar and clang's headers, from an LLVM release
    sysroot/    glibc, libstdc++, libgcc and the kernel headers of the building machine
    runtime/    libtotkrt.a (built here with llvm/ and sysroot/), the runtime headers, the install-side sources, deps/
                (include/ and lib/ of SDL3, Vulkan, VMA, Opus, libvpx, zstd)
    bin/        hactool, ninja, totk_xlate (+ .id); bin/lib/ the libraries totk loads from lib/ of the install folder
    recomp/, tools/, data/, installer/, licenses/, THIRD_PARTY_NOTICES.md, totk.ini.example, VERSION

It holds nothing derived from the game: check_content runs over the AppDir before the image is written. --skip-pip and
--allow-missing make a partial AppDir for testing where PyPI or the translator are out of reach.
"""
import argparse
import os
import shutil
import struct
import subprocess
import sys
import tarfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import make_release  # noqa: E402  (build_sources, check_folder: shared with the Windows release)

ROOT = Path(__file__).resolve().parent.parent
TRIPLE = 'x86_64-linux-gnu'
# Libraries of the building machine that totk links and the install folder carries (Ubuntu packages libopus-dev,
# libvpx-dev, libzstd-dev); the Vulkan loader is linked but never carried: the player's driver stack provides it.
HOST_LIBS = ['libopus', 'libvpx', 'libzstd']
HOST_HEADERS = ['opus', 'vpx', 'zstd.h', 'zstd_errors.h', 'zdict.h']
HOST_PREFIXES = [Path('/usr')]   # where HOST_LIBS and HOST_HEADERS are looked for (--host-prefix adds one first)
MODULES = ['main', 'subsdk0', 'sdk']   # TotK's code modules in load order (both updates); rtld is dropped


def run(cmd, **kw):
    print('+', ' '.join(map(str, cmd)), flush=True)
    subprocess.run([str(c) for c in cmd], check=True, **kw)


def copy(src, dst):
    dst.parent.mkdir(parents=True, exist_ok=True)
    if src.is_dir():
        shutil.copytree(src, dst, symlinks=True, dirs_exist_ok=True)
    else:
        shutil.copy2(src, dst, follow_symlinks=True)


def elf_soname(path):
    """DT_SONAME of a 64-bit little-endian ELF shared library, else None."""
    data = Path(path).read_bytes()
    if data[:4] != b'\x7fELF' or data[4] != 2:
        return None
    shoff, = struct.unpack_from('<Q', data, 0x28)
    shentsize, shnum = struct.unpack_from('<HH', data, 0x3A)
    secs = [struct.unpack_from('<IIQQQQIIQQ', data, shoff + i * shentsize) for i in range(shnum)]
    dyn = next((s for s in secs if s[1] == 6), None)   # SHT_DYNAMIC
    if not dyn:
        return None
    strtab = secs[dyn[6]]                                 # sh_link: its string table
    for off in range(dyn[4], dyn[4] + dyn[5], 16):
        tag, val = struct.unpack_from('<qQ', data, off)
        if tag == 14:                                     # DT_SONAME
            start = strtab[4] + val
            return data[start:data.index(b'\0', start)].decode()
    return None


def host_lib(name):
    """The real file of lib<name>.so on the building machine."""
    dirs = [d for pre in HOST_PREFIXES for d in (pre / 'lib' / TRIPLE, pre / 'lib64', pre / 'lib')]
    for d in dirs + [Path('/lib') / TRIPLE]:
        p = d / f'{name}.so'
        if p.exists():
            return p.resolve()
    sys.exit(f'{name}.so not found on this machine: install its -dev package')


# ---- python/ -------------------------------------------------------------------------------------------------------

def build_python(out, tar, skip_pip):
    with tarfile.open(tar) as t:   # install_only archives hold python/
        t.extractall(out, filter='tar')
    py = out / 'python' / 'bin' / 'python3'
    if not skip_pip:
        run([py, '-m', 'pip', 'install', '--no-cache-dir', '--no-compile', '-r',
             ROOT / 'tools' / 'requirements-installer.txt'])
    mods = 'tkinter, compression.zstd' + ('' if skip_pip else ', numpy, lz4.block, cryptography')
    run([py, '-I', '-c', f'import {mods}; print("python ok")'])
    for junk in ('include', 'share/man'):   # headers and man pages: nothing at install time needs them
        shutil.rmtree(out / 'python' / junk, ignore_errors=True)


# ---- llvm/ ---------------------------------------------------------------------------------------------------------

def build_llvm(out, src):
    """clang, ld.lld and llvm-ar of an LLVM release tree, with the shared libraries they load from it."""
    dst = out / 'llvm'
    clang = (src / 'bin' / 'clang').resolve()
    major = clang.name.split('-')[-1] if '-' in clang.name else None
    (dst / 'bin').mkdir(parents=True)
    copy(clang, dst / 'bin' / clang.name)
    for link in ('clang', 'clang++'):
        if not (dst / 'bin' / link).exists():
            os.symlink(clang.name, dst / 'bin' / link)
    lld = (src / 'bin' / 'ld.lld').resolve()
    copy(lld, dst / 'bin' / lld.name)
    if lld.name != 'ld.lld':
        os.symlink(lld.name, dst / 'bin' / 'ld.lld')
    copy((src / 'bin' / 'llvm-ar').resolve(), dst / 'bin' / 'llvm-ar')
    for res in (src / 'lib' / 'clang').iterdir():   # lib/clang/<major>/include: the compiler's own headers
        copy(res / 'include', dst / 'lib' / 'clang' / res.name / 'include')
    # shared libraries the tools load from the release tree (a static LLVM build has none)
    for tool in (dst / 'bin').iterdir():
        if tool.is_symlink():
            continue
        r = subprocess.run(['ldd', str(tool)], capture_output=True, text=True)
        for line in r.stdout.splitlines():
            parts = line.split('=>')
            if len(parts) == 2 and str(src) in parts[1]:
                lib = Path(parts[1].split('(')[0].strip())
                copy(lib, dst / 'lib' / lib.name)
    run([dst / 'bin' / 'clang', '--version'])
    return dst, major


# ---- sysroot/ ------------------------------------------------------------------------------------------------------

def build_sysroot(out):
    """glibc, libstdc++ and libgcc of this machine: headers, start files and the libraries a link reads."""
    sr = out / 'sysroot'
    copy(Path('/usr/include'), sr / 'usr' / 'include')
    libdir = Path('/usr/lib') / TRIPLE
    keep = ('crt1.o', 'crti.o', 'crtn.o', 'Scrt1.o', 'gcrt1.o', 'libc_nonshared.a')
    stems = ('libc.', 'libm.', 'libm-', 'libmvec.', 'libpthread.', 'libdl.', 'librt.', 'libutil.', 'libresolv.',
             'ld-linux-x86-64', 'libgcc_s.', 'libstdc++.')
    for p in sorted(libdir.iterdir()):
        if p.name in keep or (p.name.startswith(stems) and p.suffix != '.py' and 'gdb' not in p.name):
            copy(p, sr / 'usr' / 'lib' / TRIPLE / p.name)   # linker scripts (libc.so, libm.so) stay text
    gcc = sorted((Path('/usr/lib/gcc') / TRIPLE).iterdir(), key=lambda p: int(p.name.split('.')[0]))[-1]
    for p in gcc.iterdir():
        if p.is_file() and (p.suffix in ('.o', '.a', '.so') or p.name.startswith('libstdc++')):
            copy(p, sr / 'usr' / 'lib' / 'gcc' / TRIPLE / gcc.name / p.name)
    # merged /usr: the absolute paths in libc.so's linker script (/lib/x86_64-linux-gnu/...) resolve in the sysroot
    os.symlink('usr/lib', sr / 'lib')
    (sr / 'lib64').mkdir()
    copy(Path('/lib64/ld-linux-x86-64.so.2'), sr / 'lib64' / 'ld-linux-x86-64.so.2')
    return sr


# ---- runtime/deps, bin/ --------------------------------------------------------------------------------------------

def build_deps(out, sdl3, vulkan_headers, vma):
    deps = out / 'runtime' / 'deps'
    inc, lib, carry = deps / 'include', deps / 'lib', out / 'bin' / 'lib'
    for d in (inc, lib, carry):
        d.mkdir(parents=True, exist_ok=True)
    copy(sdl3 / 'include' / 'SDL3', inc / 'SDL3')
    copy(vulkan_headers / 'include' / 'vulkan', inc / 'vulkan')
    copy(vulkan_headers / 'include' / 'vk_video', inc / 'vk_video')
    copy(vma / 'include' / 'vk_mem_alloc.h', inc / 'vma' / 'vk_mem_alloc.h')
    copy(vma / 'include' / 'vk_mem_alloc.h', inc / 'vk_mem_alloc.h')
    for h in HOST_HEADERS:
        src = next((pre / 'include' / h for pre in HOST_PREFIXES if (pre / 'include' / h).exists()), None)
        if not src:
            sys.exit(f'{h} not found under {", ".join(map(str, HOST_PREFIXES))}: install its -dev package')
        copy(src, inc / h)
    libs = {'libSDL3': next(p for p in sorted((sdl3 / 'lib').glob('libSDL3.so*')) if not p.is_symlink())}
    libs.update({n: host_lib(n) for n in HOST_LIBS})
    for name, real in libs.items():
        copy(real, lib / f'{name}.so')                    # what -l<name> finds at link time
        soname = elf_soname(real) or real.name
        copy(real, carry / soname)                        # what totk asks for at run time, from $ORIGIN/lib
    copy(host_lib('libvulkan'), lib / 'libvulkan.so')    # link only: the system's loader runs


def build_bin(out, hactool, ninja, xlate, allow_missing):
    b = out / 'bin'
    for src, name in ((hactool, 'hactool'), (ninja, 'ninja'), (xlate, 'totk_xlate')):
        if src and Path(src).is_file():
            copy(Path(src), b / name)
            os.chmod(b / name, 0o755)
        elif not allow_missing:
            sys.exit(f'missing {name}: {src}')
    if xlate and Path(xlate).with_suffix('.id').is_file():
        copy(Path(xlate).with_suffix('.id'), b / 'totk_xlate.id')


# ---- runtime/ ------------------------------------------------------------------------------------------------------

def stub_gen(work):
    """A generated-C directory without game code, for build_game.py --make-runtime-lib: the library uses only
    MOD_MAIN_BASE (a constant) and MOD_COUNT (an upper bound) of layout.h; the real layout is compiled at install time
    (modules.c, romfs.c, patches.c, ov_zstd.c)."""
    sys.path.insert(0, str(ROOT / 'recomp'))
    base, size = 0x7000000000, 0x200000
    mods = [(m, base + i * size, size) for i, m in enumerate(MODULES)]
    work.mkdir(parents=True, exist_ok=True)
    import json
    (work / 'layout.json').write_text(json.dumps([{'name': n, 'base': f'{b:#x}', 'size': f'{s:#x}'} for n, b, s in mods]))
    lines = ['#pragma once'] + [f'#define MOD_{n.upper()}_BASE {b:#x}ull\n#define MOD_{n.upper()}_SIZE {s:#x}ull'
                                for n, b, s in mods]
    lines += [f'#define MOD_COUNT {len(mods)}', '#define MOD_LIST(X) ' + ' '.join(f'X({n}, {n.upper()})' for n, _, _ in mods)]
    (work / 'layout.h').write_text('\n'.join(lines) + '\n')
    for n, _, _ in mods:
        (work / n).mkdir(exist_ok=True)
        (work / n / 'manifest.json').write_text('{"chunks": []}')
        (work / n / f'{n}_table.c').write_text('')
    return work


def runtime_lib(out, llvm, sysroot):
    work = ROOT / 'build' / 'appimage-work'
    gen = stub_gen(work / 'gen')
    build = work / 'rtlib'
    run([sys.executable, ROOT / 'tools' / 'build_game.py', '--make-runtime-lib', '--toolchain', llvm,
         '--sysroot', sysroot, '--deps', out / 'runtime' / 'deps', '--ninja', out / 'bin' / 'ninja',
         '--gen', gen, '--out', build])
    rt = out / 'runtime'
    copy(build / 'libtotkrt.a', rt / 'libtotkrt.a')
    for p in sorted((ROOT / 'runtime').rglob('*')):
        if p.suffix in make_release.RUNTIME_SUFFIXES and p.is_file():
            copy(p, rt / p.relative_to(ROOT / 'runtime'))
    for name in ('romfs.c', 'patches.c', 'ov_zstd.c'):   # build_game.py INSTALL_SIDE
        copy(ROOT / 'runtime' / name, rt / name)


# ---- the AppImage wrapping -----------------------------------------------------------------------------------------

APPRUN = r'''#!/bin/sh
# TotK-Setup AppImage: starts the installer window (python -m installer.gui); --cli runs the command-line installer
# (python -m installer --help).
HERE="$(dirname "$(readlink -f "$0")")"
export PYTHONNOUSERSITE=1 PYTHONDONTWRITEBYTECODE=1 PYTHONUTF8=1
export PYTHONPATH="$HERE:$HERE/tools:$HERE/recomp"
unset PYTHONHOME
if [ "$1" = "--cli" ]; then
    shift
    exec "$HERE/python/bin/python3" -m installer "$@"
fi
exec "$HERE/python/bin/python3" -m installer.gui "$@"
'''

DESKTOP = '''[Desktop Entry]
Type=Application
Name=TotK Recomp Setup
Comment=Builds TotK Recomp from your own game files
Exec=AppRun
Icon=totk-setup
Categories=Game;
Terminal=false
'''


def ico_png(ico):
    """The largest PNG image inside a .ico file."""
    d = ico.read_bytes()
    best = None
    for i in range(struct.unpack_from('<H', d, 4)[0]):
        w, h, _, _, _, _, size, off = struct.unpack_from('<BBBBHHII', d, 6 + 16 * i)
        img = d[off:off + size]
        if img[:4] == b'\x89PNG' and (best is None or (w or 256) > best[0]):
            best = (w or 256, img)
    if not best:
        sys.exit(f'{ico}: no PNG image inside')
    return best[1]


def wrap(out):
    (out / 'AppRun').write_text(APPRUN)
    os.chmod(out / 'AppRun', 0o755)
    (out / 'totk-setup.desktop').write_text(DESKTOP)
    png = ico_png(ROOT / 'runtime' / 'totk.ico')
    (out / 'totk-setup.png').write_bytes(png)
    (out / '.DirIcon').write_bytes(png)


def collect_licenses(out, llvm_src, sdl3, python_dir):
    lic = out / 'licenses'
    lic.mkdir(exist_ok=True)
    for src, name in ((llvm_src / 'LICENSE.TXT', 'llvm-LICENSE.txt'), (sdl3 / 'share' / 'licenses' / 'SDL3' / 'LICENSE.txt', 'SDL3-LICENSE.txt'),
                      (python_dir / 'lib' / 'python3.14' / 'LICENSE.txt', 'python-LICENSE.txt'),
                      (ROOT / 'toolchain' / 'hactool' / 'LICENSE', 'hactool-LICENSE.txt'),
                      (ROOT / 'LICENSE', 'totk-recomp-LICENSE.txt')):
        if src.is_file():
            copy(src, lic / name)
    for n in HOST_LIBS + ['libc6']:   # Debian copyright files of the carried libraries and the sysroot's glibc
        pkg = {'libopus': 'libopus0', 'libvpx': 'libvpx7', 'libzstd': 'libzstd1'}.get(n, n)
        cr = Path('/usr/share/doc') / pkg / 'copyright'
        if cr.is_file():
            copy(cr, lic / f'{pkg}-copyright.txt')


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('--out', type=Path, required=True, help='AppDir to write (replaced)')
    ap.add_argument('--appimage', type=Path, help='write the AppImage here (needs --appimagetool)')
    ap.add_argument('--appimagetool', type=Path)
    ap.add_argument('--python-tar', type=Path, required=True, help='python-build-standalone install_only archive')
    ap.add_argument('--llvm', type=Path, required=True, help='LLVM release tree (bin/clang, bin/ld.lld, lib/clang)')
    ap.add_argument('--sdl3', type=Path, required=True, help='SDL3 install prefix (include/, lib/)')
    ap.add_argument('--vulkan-headers', type=Path, required=True)
    ap.add_argument('--vma', type=Path, required=True, help='VulkanMemoryAllocator checkout')
    ap.add_argument('--hactool', type=Path, default=ROOT / 'toolchain' / 'hactool' / 'hactool')
    ap.add_argument('--ninja', type=Path, default=Path(shutil.which('ninja') or 'ninja'))
    ap.add_argument('--xlate', type=Path, default=ROOT / 'build' / 'xlate' / 'totk_xlate')
    ap.add_argument('--host-prefix', type=Path, help='look for the Opus, libvpx and zstd files here before /usr')
    ap.add_argument('--skip-pip', action='store_true', help='testing: no packages from PyPI')
    ap.add_argument('--allow-missing', action='store_true', help='testing: go on without the translator')
    a = ap.parse_args()
    if a.host_prefix:
        HOST_PREFIXES.insert(0, a.host_prefix.resolve())
    out = a.out.resolve()
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)
    build_python(out, a.python_tar, a.skip_pip)
    llvm, _ = build_llvm(out, a.llvm.resolve())
    sysroot = build_sysroot(out)
    build_deps(out, a.sdl3.resolve(), a.vulkan_headers.resolve(), a.vma.resolve())
    build_bin(out, a.hactool, a.ninja, a.xlate, a.allow_missing)
    runtime_lib(out, llvm, sysroot)
    make_release.build_sources(out)
    collect_licenses(out, a.llvm.resolve(), a.sdl3.resolve(), out / 'python')
    wrap(out)
    make_release.check_folder(out)
    size = sum(p.stat().st_size for p in out.rglob('*') if p.is_file() and not p.is_symlink())
    print(f'{out}: {size / 1e6:.0f} MB')
    if a.appimage:
        if not a.appimagetool:
            sys.exit('--appimage needs --appimagetool')
        env = dict(os.environ, ARCH='x86_64', APPIMAGE_EXTRACT_AND_RUN='1')   # no FUSE on build machines
        run([a.appimagetool, '--no-appstream', out, a.appimage], env=env)
        print(f'{a.appimage}: {a.appimage.stat().st_size / 1e6:.0f} MB')


if __name__ == '__main__':
    main()
