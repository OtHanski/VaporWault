# VaporWault

[![CI](https://github.com/OtHanski/VaporWault/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/OtHanski/VaporWault/actions/workflows/ci.yml)
[![Latest release](https://img.shields.io/github/v/release/OtHanski/VaporWault)](https://github.com/OtHanski/VaporWault/releases/latest)

**VaporWault is a self-hosted cloud file storage and sync system** — the
same idea as Dropbox or Google Drive, but you (or someone you trust) runs
the server. A pure-C backend stores and serves files; a pure-C client
daemon keeps local folders in sync with it; thin CLI and Dear ImGui GUI
front ends sit on top of both. An Android app (Kotlin + the same C core
via a JNI bridge) gives on-demand mobile browse/upload/download. Minimal
external dependencies — no database engine, no cloud SDKs, just mbedTLS
for TLS and a handful of small vendored libraries.

**Status: pre-1.0, actively developed.** Expect rough edges.

For the time being this is completely machine-written code, a sandbox for
testing and improving my AI programming workflow with an actually complex
real-world setting without screwing with actual production code at work.

---

## What it does

- **File sync** with block-level (4 MB, content-addressed) deduplication,
  version history, and a configurable trash/retention window.
- **Sharing** — per-user grants (view/edit) and unguessable public links,
  at file or folder granularity.
- **Optional end-to-end encryption** ("vaults") — envelope encryption with
  a passphrase the server never sees or can derive; the server only ever
  stores opaque ciphertext and wrapped keys.
- **Two-factor auth** (email OTP) and automatic TLS certificates via ACME
  (Let's Encrypt, DNS-01 or HTTP-01).
- **Cluster replication** — a primary plus one or more hot-standby
  replicas, for redundancy (no automatic failover — promotion is manual,
  by design; see [`ARCHITECTURE.md`](ARCHITECTURE.md)).
- **Admin tooling** — a CLI and desktop GUI for user/quota management, a
  filterable/exportable audit log, and cluster status.

## Platforms

| | Server | Client (daemon + CLI + GUI) |
|---|---|---|
| Linux | ✅ | ✅ |
| Windows | ⚠️ runs, but no admin CLI¹ | ✅ |
| macOS | ❌ deferred | ❌ deferred |
| Android | n/a | ✅ on-demand app² |

The client (background sync daemon, CLI, and GUI) runs on Linux and
Windows. macOS is not supported yet — a deliberate scoping decision, not
an oversight.

¹ The server itself (`vapourwaultd`) runs on Windows and serves files
fine, but `vapourwault-server-cli` — how you create users, set quotas, or
pair a cluster replica — has no working transport there yet (its admin
socket is POSIX-only). See the platform note in
[`docs/TUTORIAL.md`](docs/TUTORIAL.md).

² The Android app is a separate client, not a port of the desktop one —
on-demand browse/upload/download (Drive-app style), not continuous
background folder sync, since Android has no equivalent of a persistent
POSIX daemon. See [`ARCHITECTURE.md`](ARCHITECTURE.md) for the design and
[`docs/ANDROID_BUILD.md`](docs/ANDROID_BUILD.md) to build it. Debug-signed
APKs (no Play Store yet) are attached to
[releases](https://github.com/OtHanski/VaporWault/releases/latest).

---

## Getting started

Pick whichever of these matches what you're trying to do:

| I want to... | Start here |
|---|---|
| **Just use VaporWault** — someone gave me a server address, username, and password | [`docs/CLIENT_GETTING_STARTED.md`](docs/CLIENT_GETTING_STARTED.md) — plain-language, no command line required |
| **Set up and administer a server** | [`docs/TUTORIAL.md`](docs/TUTORIAL.md) — a from-scratch walkthrough: TLS, users, a hot-standby backup server |
| **Build from source / hack on the code** | keep reading below, then [`VENDOR_SETUP.md`](VENDOR_SETUP.md) |
| **Run an existing deployment day-to-day** (backups, upgrades, hardening) | [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md) |

### Building from source

Full instructions, dependency vendoring, and every CMake option are in
[`VENDOR_SETUP.md`](VENDOR_SETUP.md). Fastest path — server + client, no GUI,
on Linux (mbedTLS and Argon2 are fetched automatically by CMake; only Dear
ImGui needs a submodule, and only if you're building the GUI):

```sh
git clone https://github.com/OtHanski/VaporWault.git
cd VaporWault
cmake -B build -DCMAKE_BUILD_TYPE=Debug -DVW_BUILD_GUI=OFF
cmake --build build -j"$(nproc)"
ctest --test-dir build --output-on-failure
```

For the GUI, cluster setup, packaging, and Windows instructions, see
[`VENDOR_SETUP.md`](VENDOR_SETUP.md).

---

## Components

| Component | Language | What it does |
|---|---|---|
| Server (`vapourwaultd`) | C | Request dispatch, flat-file storage, auth, quotas, cluster replication |
| Client daemon (`vapourwault-daemon`) | C | Sync engine, local metadata cache, conflict handling, background service |
| CLIs (`vapourwault-cli`, `vapourwault-server-cli`) | C | Thin front ends over the daemon/server admin channel |
| GUIs (`vapourwault-gui`, `vapourwault-server-gui`) | C++ (Dear ImGui) | Desktop file browser, transfer queue, admin dashboard |
| Android app (`android/`) | Kotlin + C (JNI bridge) | On-demand mobile file browser, upload/download, E2EE vault support |

## Documentation map

| Document | Covers |
|---|---|
| [`ARCHITECTURE.md`](ARCHITECTURE.md) | System design, module map, on-disk formats, design decisions |
| [`docs/PROTOCOL.md`](docs/PROTOCOL.md) | The client↔server and cluster wire protocol specification |
| [`docs/TUTORIAL.md`](docs/TUTORIAL.md) | Standing up a server, TLS, users, cluster pairing |
| [`docs/CLIENT_GETTING_STARTED.md`](docs/CLIENT_GETTING_STARTED.md) | Using the desktop client or Android app as a non-technical end user |
| [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md) | Reference config, backup/restore, upgrades, hardening checklist |
| [`docs/RELEASE.md`](docs/RELEASE.md) | How tagged releases are built and published |
| [`docs/STYLE.md`](docs/STYLE.md) | C/C++ code style conventions |
| [`VENDOR_SETUP.md`](VENDOR_SETUP.md) | Dependency vendoring and every CMake build option |
| [`docs/ANDROID_BUILD.md`](docs/ANDROID_BUILD.md) | Android app toolchain (JDK/SDK/NDK) and local build steps |
