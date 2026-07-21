# VaporWault — Vendor Setup

All third-party code lives under `third_party/` as git submodules.
Run the commands below from the repository root **before** your first CMake configure.

---

## Required third-party libraries

### 1. mbedTLS (TLS 1.3, crypto primitives)

```sh
git submodule add https://github.com/Mbed-TLS/mbedtls.git third_party/mbedtls
cd third_party/mbedtls && git checkout v3.6.2 && cd ../..
```

The project-specific config header is already in place at
`third_party/mbedtls_config.h`. CMake passes it to the mbedTLS build via
`MBEDTLS_CONFIG_FILE` (set in `third_party/CMakeLists.txt`) — no manual
copy step is required.

### 2. Argon2 reference implementation (password hashing)

```sh
git submodule add https://github.com/P-H-C/phc-winner-argon2.git third_party/argon2
```

HEAD is used; the reference implementation is stable and public-domain.
No tag pin is necessary, but re-pin if the upstream ever bumps the ABI.

### 3. Dear ImGui + SDL2 backend (GUI component only)

Dear ImGui is vendored from the `docking` branch, which enables dockable panels in
the file browser view. The API is backward-compatible with the master branch.

```sh
git submodule add --branch docking https://github.com/ocornut/imgui.git third_party/imgui
cd third_party/imgui && git checkout 81c008f90 && cd ../..
```

The commit above (`81c008f90`, `git describe`: `v1.92.8-docking-148-g81c008f90`) is
the version actually pinned in this repo's submodule reference — check it with
`git -C third_party/imgui describe --tags` if this drifts after a future bump.

**SDL2** (minimum version **2.26.0**) is the cross-platform windowing backend:

| Platform      | How to obtain                                                              |
|---------------|----------------------------------------------------------------------------|
| Ubuntu/Debian | `apt install libsdl2-dev`                                                  |
| Fedora        | `dnf install SDL2-devel`                                                   |
| macOS         | `brew install sdl2`                                                        |
| Windows       | Place the official SDL2 VC build (MSVC x64) in `third_party/SDL2/`. CMake picks it up automatically. See below. |

**Windows SDL2 vendoring:**
1. Download the SDL2 VC development build from https://github.com/libsdl-org/SDL/releases
   (filename: `SDL2-devel-<version>-VC.zip`).
2. Extract so the layout is:
   ```
   third_party/SDL2/
       include/SDL.h ...
       lib/x64/SDL2.lib
       lib/x64/SDL2.dll
   ```
3. Copy `SDL2.dll` next to your built executable (or add `third_party/SDL2/lib/x64` to
   `PATH`).

---

## Initialise submodules after a fresh clone

If you cloned the repo without `--recurse-submodules`:

```sh
git submodule update --init --recursive
```

Then pin each library to the required tag as shown above.

---

## Building after vendoring

### Linux / macOS

```sh
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Debug -DVW_BUILD_SERVER=ON -DVW_BUILD_CLIENT=ON
cmake --build . -j$(nproc)
```

Release build:

```sh
cmake .. -DCMAKE_BUILD_TYPE=Release -DVW_BUILD_SERVER=ON -DVW_BUILD_CLIENT=ON \
         -DVW_WERROR=ON
cmake --build . -j$(nproc)
```

### Windows (MSVC 2022)

```powershell
cmake .. -G "Visual Studio 17 2022" -A x64 `
         -DVW_BUILD_SERVER=ON -DVW_BUILD_CLIENT=ON
cmake --build . --config Release
```

Or with Ninja (faster incremental builds):

```powershell
cmake .. -G Ninja -DCMAKE_BUILD_TYPE=Release `
         -DVW_BUILD_SERVER=ON -DVW_BUILD_CLIENT=ON
cmake --build .
```

---

## Selective builds

| Flag                  | Default | Effect                                                          |
|-----------------------|---------|-----------------------------------------------------------------|
| `-DVW_BUILD_SERVER=ON`  | ON    | Builds `vapourwaultd` server binary                             |
| `-DVW_BUILD_CLIENT=ON`  | ON    | Builds `vapourwault-daemon` + `vapourwault-cli`                 |
| `-DVW_BUILD_GUI=ON`     | ON    | Builds GUI targets (requires Dear ImGui + SDL2 to be vendored)  |
| `-DVW_BUILD_TOOLS=ON`   | ON    | Builds `vwdump` admin tool                                      |
| `-DVW_BUILD_TESTS=ON`   | ON    | Builds unit + integration tests                                 |
| `-DVW_WERROR=ON`        | OFF   | Turns warnings into errors (used in CI)                         |

To build the GUI (ensure Dear ImGui and SDL2 are vendored first):

```sh
cmake .. -DVW_BUILD_SERVER=ON -DVW_BUILD_CLIENT=ON -DVW_BUILD_GUI=ON
cmake --build . -j$(nproc)
# On Windows, copy SDL2.dll next to the built executables:
cp third_party/SDL2/lib/x64/SDL2.dll build/bin/
```

To build the server only (no GUI, no tests):

```sh
cmake .. -DVW_BUILD_SERVER=ON -DVW_BUILD_CLIENT=OFF \
         -DVW_BUILD_GUI=OFF -DVW_BUILD_TOOLS=OFF -DVW_BUILD_TESTS=OFF
```
