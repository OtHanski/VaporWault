# VaporWault

[![CI](https://github.com/VaporWault/VaporWault/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/VaporWault/VaporWault/actions/workflows/ci.yml)

Cross-platform cloud file hosting with a pure-C server, a pure-C sync client, and a
Dear ImGui desktop GUI.

## Components

| Component | Language | Description |
|-----------|----------|-------------|
| Server    | C        | POSIX sockets, file storage, user auth, quota enforcement |
| Client    | C        | Sync engine, conflict resolution, background daemon |
| GUI       | C++      | Dear ImGui file browser, transfer queue, settings |

## Building

See [VENDOR_SETUP.md](VENDOR_SETUP.md) for vendoring instructions and full build options.

Quick start (Linux/macOS, no GUI):

```sh
git submodule update --init --recursive
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Debug -DVW_BUILD_GUI=OFF
cmake --build . -j$(nproc)
ctest --output-on-failure
```

## Architecture

See [ARCHITECTURE.md](ARCHITECTURE.md) for system design and API contracts.
