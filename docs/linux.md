# Linux

TotK Recomp builds and runs as a native Linux x86-64 program (`build/<ver>/totk`), on X11 or Wayland, from the same
sources as the Windows build. This page covers what differs from [building.md](building.md); the steps, settings and
checks are otherwise the same.

> [!NOTE]
> Status: the runtime compiles and links on Linux, and the checks that need no game files pass (see "Checks" below).
> The Linux port has not yet been played end to end; report problems as issues with `[linux]` in the title.

## TotK-Setup AppImage

Players need no toolchain: `TotK-Setup-x86_64.AppImage` is the installer of [installer.md](installer.md) with everything
it runs inside (Python, clang and lld with a glibc sysroot, SDL3, hactool, ninja, the shader translator, the prebuilt
runtime). It turns the player's own game files into the game, once:

```sh
chmod +x TotK-Setup-x86_64.AppImage
./TotK-Setup-x86_64.AppImage          # the setup window: game files, prod.keys, language, install folder, Start
./TotK-Setup-x86_64.AppImage --cli --help   # the same without a window
```

The install folder then holds `totk` (play it; on the Steam Deck add it to Steam as a non-Steam game) with the
libraries it needs in `lib/`. The setup's temp folder is `~/.cache/totk-setup`. The AppImage carries no game data, so it
can be published like the Windows `TotK-Setup` zip.

Building the AppImage: `.github/workflows/appimage.yml` (Actions tab, "Run workflow", or a `v*` tag) builds it on Ubuntu
22.04 and attaches it to the run, and to the release on a tag. Locally, `tools/make_appimage.py` with the same inputs
(its docstring lists them).

## Requirements

- An x86-64 CPU with AVX2, and a Vulkan 1.3 driver with `VK_EXT_external_memory_host` (Mesa RADV or ANV, or NVIDIA's
  driver).
- Linux 6.7 or later is recommended: write watching (how the renderer finds the guest memory the CPU changed) then uses
  userfaultfd write protection with `PAGEMAP_SCAN`, the mechanism Wine and Proton use for the same job. Older kernels
  fall back to `mprotect` and a fault per first write, which is slower; the log says so at start.
- `vm.max_map_count` of 1048576 or more. Each change of page protection can split a kernel mapping, and the guest
  address space has many. Fedora, Arch, SteamOS and Ubuntu 24.04 and later already ship 1048576; elsewhere:

  ```sh
  echo 'vm.max_map_count = 1048576' | sudo tee /etc/sysctl.d/80-totk.conf && sudo sysctl --system
  ```

## Toolchain

| Tool | Version | Used for |
|---|---|---|
| clang, lld | 18 or later (19+ embeds the menu font with `#embed`; 18 gets it from a generated include) | the generated C and the runtime |
| ninja | 1.10+ | the build |
| SDL3 | 3.2+ | window, keyboard, mouse, gamepads |
| Vulkan loader and headers, Vulkan Memory Allocator | 1.3+ | rendering |
| libopus, libvpx, libzstd | any current | audio, movies, patches |
| .NET SDK | 10.0 | the shader translator (NativeAOT, needs clang and zlib development files) |
| gcc, make, mbedtls | | hactool (NCA and update extraction) |
| uv | 0.13 | the two Python environments |

Packages:

```sh
# Arch, SteamOS (developer mode)
sudo pacman -S --needed clang lld ninja sdl3 vulkan-icd-loader vulkan-headers vulkan-memory-allocator opus libvpx zstd \
    gcc make mbedtls zlib dotnet-sdk shaderc spirv-tools
# Fedora 42+
sudo dnf install clang lld ninja-build SDL3-devel vulkan-loader-devel vulkan-headers VulkanMemoryAllocator-devel \
    opus-devel libvpx-devel libzstd-devel gcc make mbedtls-devel zlib-devel dotnet-sdk-10.0 glslc spirv-tools
# Debian 13, Ubuntu 25.04+
sudo apt install clang lld ninja-build libsdl3-dev libvulkan-dev libvulkan-memory-allocator-dev libopus-dev \
    libvpx-dev libzstd-dev gcc make libmbedtls-dev zlib1g-dev glslc spirv-tools
```

Ubuntu 24.04 has no SDL3 package: build SDL 3.2 from source (`cmake -S . -B build -G Ninja
-DCMAKE_INSTALL_PREFIX=$HOME/deps && ninja -C build install`), put Vulkan Memory Allocator's `vk_mem_alloc.h` in
`$HOME/deps/include`, and pass `--deps $HOME/deps` to `tools/build_game.py`; the built `totk` finds the libraries there
through its run path. Install the .NET 10 SDK from Microsoft's packages or `dotnet-install.sh`.

## Build

The steps of [building.md](building.md), with the Linux paths of the Python environments:

```sh
uv venv --python 3.12 .venv && uv pip install --python .venv/bin/python -r tools/requirements.txt
uv venv --python 3.14 .venv-py314 && uv pip install --python .venv-py314/bin/python -r tools/requirements-py314.txt
cp config.example.toml config.local.toml          # game, update and keys paths
.venv/bin/python tools/build_hactool.py            # toolchain/hactool/hactool
.venv-py314/bin/python tools/extract.py
.venv/bin/python tools/build_xlate.py              # build/xlate/totk_xlate
.venv/bin/python recomp/gen.py --exefs build/extracted/v121/exefs --out generated/v121 --patches recomp/patches-v121.txt
.venv-py314/bin/python tools/make_romfs_patches.py --version v121
.venv/bin/python tools/build_game.py --version v121   # add --deps DIR for libraries outside the system paths
.venv-py314/bin/python tools/prepare_shaders.py build/v121 --version v121
build/v121/totk
```

`totk.ini` sits next to `totk` and saves go where they go on Windows (`build/profile`, `build/profile-<ver>`).

## How the port works

The runtime calls the Win32 API in about forty files. Rather than rewrite them, Linux builds put
`runtime/platform/linux` first on the include path: its `windows.h` and the few other Windows headers stand in for the
subset of Win32 the runtime uses, implemented on POSIX threads, futexes, `mmap` and signals in `win32_*.c`, with the
same behaviour the runtime relies on. `platform_linux.c` implements `runtime/platform/platform.h`, the interface new code
uses. `tests/linux_shim_test.c` checks the stand-in on its own.

- Locks and condition variables: SRW locks, condition variables and critical sections are futex words, zero-initialised
  storage valid, as on Windows.
- Memory: `VirtualAlloc` reservations are `PROT_NONE` mappings with a byte of state per page, so commit, decommit (pages
  come back zeroed), protection changes and `VirtualQuery` answer as Windows does. `MEM_WRITE_WATCH` and `GetWriteWatch`
  use userfaultfd asynchronous write protection (`TOTK_WRITE_WATCH=mprotect` forces the fallback for testing).
- Faults: `SIGSEGV`, `SIGBUS`, `SIGILL` and `SIGFPE` reach the vectored exception handlers (the frozen-region thaw of
  `runtime/memory.c`, the crash report of `runtime/main.c`) with the same records and registers.
- Threads: `SuspendThread`, `GetThreadContext` and `SetThreadContext` (asynchronous preemption, the profiler) stop the
  target in a signal handler and edit the registers it returns with. The preemption stub in `runtime/kernel.c` has a
  System V version that keeps `rsi`, `rdi` and the red zone. Fibers are `ucontext` switches.
- Files: paths handed to the runtime use `\` as on Windows, since it cuts paths there; every call that reaches the
  system converts back, and a path that does not exist as spelled is matched again without regard to case, as Windows'
  file systems do. A read-only file cannot be written or replaced, as on Windows.
- Window and input: an SDL3 window (`runtime/gfx_window_sdl.inc`) replaces the Win32 one; the swapchain and present
  code are shared. Keyboard state comes from SDL, the mouse camera from SDL's relative mouse mode, the menu's events
  from `runtime/ui/menu_sdl.cpp`. Gamepads, rumble and gyro were SDL3 already.
- The game's text entry (naming a horse) uses `zenity`, else `kdialog`; without either the default name is taken.

## Differences from Windows

- The window opens in front where the window manager puts it (Windows opens it behind and flashes the taskbar
  button). F11 switches to borderless fullscreen; `TOTK_FULLSCREEN` still waits for the first focus.
- The text entry is the desktop's prompt rather than a dialog driven by the controller.
- `--probe-window` is Windows-only (it sends Win32 window messages).
- `TOTK_PROFILE` samples work; the call chains of `TOTK_PROFILE_RENDER` and `TOTK_PROFILE_CHAINS` stop at the sampled
  function (Linux has no `.pdata` unwind tables to walk). `perf record` is the better tool there.
- The performance overlay's GPU load and memory come from the amdgpu sysfs counters; other GPUs show none.
- Thread priorities above normal need `CAP_SYS_NICE` or an `RLIMIT_NICE`; without them threads stay at normal priority.
- The installer runs from the AppImage; its window is Tk's, with Tk's file pickers.

## Steam Deck

In desktop mode, run the AppImage from the file manager (Properties, Permissions, "Is executable" first) and pick an
install folder with room (the SD card is fine). Add `<install folder>/totk` to Steam as a non-Steam game to run it under
gamescope in game mode; the Deck's controls arrive as an SDL3 gamepad with gyro. Building from source on the Deck works
too, in a container such as distrobox with an Arch image for the toolchain.

## Checks

On top of the checks of [building.md](building.md):

```sh
clang -O1 -g -D_GNU_SOURCE -Iruntime/platform/linux -Iruntime/platform -Iruntime \
      -include runtime/platform/linux/crt_compat.h tests/linux_shim_test.c runtime/platform/linux/*.c \
      -ldl -lpthread -o build/linux_shim_test && build/linux_shim_test
TOTK_WRITE_WATCH=mprotect build/linux_shim_test   # the write-watch fallback
build/v121/totk --selftest
build/v121/totk --probe-gfx-abi                   # write watch and frozen regions through runtime/memory.c
build/v121/totk --probe-cfg
```
