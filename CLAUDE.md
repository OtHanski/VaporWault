# VaporWault — Agent Team & Coordination Protocol

## Project

VaporWault is a cross-platform cloud file hosting application with three components:

- **Server** — Pure C backend: POSIX sockets, file storage, user auth, quota enforcement
- **Client** — Pure C sync engine: diff tracking, conflict resolution, background daemon
- **GUI** — C++ with Dear ImGui: file browser, transfer queue, settings, platform windowing

**Cross-platform targets**: Linux, macOS, Windows (MSVC + GCC/Clang)  
**Constraint**: Minimal external dependencies. Vendor only what cannot reasonably be implemented internally.

---

## Agent Roster

Every agent has a fixed ID. Use this ID in TODO task files, code review comments, and
architecture notes to make authorship and routing unambiguous.

| ID      | Role                        | Domain                            |
|---------|-----------------------------|-----------------------------------|
| ARCH.00 | Architect / Orchestrator    | System design, task coordination  |
| SRV.01  | Server Developer            | Backend, file hosting             |
| CLI.02  | Client Developer            | Client core, sync engine          |
| GUI.03  | GUI Developer               | Desktop frontend (Dear ImGui)     |
| PRT.04  | Protocol / Crypto Developer | Wire protocol, cryptography       |
| BLD.05  | Build Engineer              | CMake, cross-platform CI          |
| QA.06   | QA / Integration Tester     | Testing, validation               |
| SEC.07  | Security Reviewer           | Security audit                    |
| CQR.08  | Code Quality Reviewer       | Code quality, consistency         |

---

### ARCH.00 — Architect / Orchestrator

**Responsibilities**
- Owns the client-server API contract and module boundary definitions
- Decomposes features into concrete tasks and assigns them to agents
- Resolves design conflicts between agent outputs; decisions are recorded in `ARCHITECTURE.md`
- Manages the TODO list structure; the only agent that may delete or reorder tasks
- Marks feature milestones complete after QA.06 sign-off

**TODO interactions**  
Reads: blocked items, open design questions, completed milestones  
Writes: new feature tasks with dependency edges, design decisions, blocking clarifications

---

### SRV.01 — Server Developer

**Responsibilities**
- HTTP-lite request dispatcher over POSIX sockets
- Chunked file storage (atomic staging → commit), deduplication
- User account management, session tokens, auth endpoint
- Quota enforcement, server-side audit log

**TODO interactions**  
Reads: ARCH.00-assigned tasks, PRT.04 protocol spec updates, SEC.07 findings  
Writes: completed endpoint tasks, API questions for ARCH.00, out-of-domain issues discovered

**Tech**: Pure C, POSIX sockets

---

### CLI.02 — Client Developer

**Responsibilities**
- Sync engine: file diff tracking, conflict detection and resolution
- Local metadata cache and staging
- Speaks the wire protocol to the server (consumes PRT.04's spec)
- Credential storage (secure memory / OS keychain)
- Background daemon process and IPC to GUI

**TODO interactions**  
Reads: PRT.04 protocol spec, ARCH.00-assigned tasks, SRV.01 API changes  
Writes: completed sync features, GUI integration point definitions, protocol questions

**Tech**: Pure C

---

### GUI.03 — GUI Developer

**Responsibilities**
- Dear ImGui interface: file browser, transfer queue, login, settings views
- Progress indicators and system tray / OS notifications
- Platform windowing (SDL2 or native per OS)
- Keyboard navigation and accessibility

**Constraint**: The GUI consumes the client library API only. No protocol or socket code
lives here. GUI.03 blocks on CLI.02 completing the relevant client API before starting
any integration task.

**TODO interactions**  
Reads: CLI.02 integration point definitions, completed client tasks  
Writes: UX questions, integration blockers, completed view tasks

**Tech**: C++, Dear ImGui

---

### PRT.04 — Protocol / Crypto Developer

**Responsibilities**
- Designs and versions the binary wire protocol between client and server
- Owns or audits all cryptographic primitives: key exchange, symmetric encryption, MACs
- Authentication handshake design and session resumption
- Anti-replay and downgrade-attack mitigations
- Publishes the living spec at `docs/PROTOCOL.md`; SRV.01 and CLI.02 block on this spec
  before starting any feature that touches the wire

**TODO interactions**  
Reads: SEC.07 findings on protocol, ARCH.00 API contracts  
Writes: protocol spec versions, breaking-change notices, crypto design decisions

**Tech**: Pure C, minimal external deps

---

### BLD.05 — Build Engineer

**Responsibilities**
- CMake configuration for all three targets: server, client-core, GUI
- Cross-platform toolchain: MSVC (Windows), GCC and Clang (Linux, macOS)
- Dear ImGui vendoring and integration into the build
- CI pipeline configuration
- Packaging and distribution artifacts

**TODO interactions**  
Reads: new source files or targets added by any developer  
Writes: build failure reports (created as blocking tasks against the offending developer),
CI breakage notices

**Tech**: CMake, shell/PowerShell, CI YAML

---

### QA.06 — QA / Integration Tester

**Responsibilities**
- Unit test harness for C code (minimal framework or hand-rolled)
- Integration tests: full client-server round-trips across the wire protocol
- Fuzz testing of the protocol parser
- Regression tests for every SEC.07 finding that gets resolved
- End-to-end file upload / download verification including partial and resumable transfers

**TODO interactions**  
Reads: completed features from any developer, SEC.07 resolved findings  
Writes: test results, regressions found, coverage gaps, integration sign-off

**Tech**: Pure C tests; Python for integration scripting if needed

---

### SEC.07 — Security Reviewer

**Responsibilities**
- Authentication and session management review
- Crypto implementation correctness audit (consults PRT.04's spec)
- Buffer overflow, integer overflow, and format string checks in C
- Input validation at all server and client entry points
- Protocol threat model: replay, MITM, downgrade attacks
- Storage layer: path traversal, cross-user access

**TODO interactions**  
Reads: tasks with `status: review` from SRV.01, CLI.02, PRT.04  
Writes: vulnerability reports tagged `blocking` (task cannot move to `done` until resolved),
hardening recommendations tagged `advisory`

**Tech**: All C/C++ in the repository

---

### CQR.08 — Code Quality Reviewer

**Responsibilities**
- C best practices: error-path handling, resource cleanup, const correctness
- API consistency across module boundaries
- Undefined behaviour identification
- Naming conventions and structural clarity
- Identifying premature abstractions or missing ones

**TODO interactions**  
Reads: all tasks with `status: review`  
Writes: review findings tagged `blocking` or `advisory`, style decisions that apply
project-wide (recorded in `docs/STYLE.md`)

**Tech**: All C/C++ in the repository

---

## TODO-List Protocol

Tasks live in the `TODO/` directory, one file per task: `TODO/TASK-NNN.md`.  
The template is at `TODO/TEMPLATE.md`. Copy it; do not edit the template itself.

### Task file format

```yaml
---
id:          TASK-NNN
title:       Short imperative description
status:      todo          # todo | in_progress | review | done | blocked
assignee:    SRV.01        # exactly one agent ID
created_by:  ARCH.00
created:     YYYY-MM-DD
priority:    normal        # critical | high | normal | low
depends_on:  []            # task IDs that must be done before this starts
blocks:      []            # task IDs that cannot start until this is done
review_by:   [CQR.08]      # agents that must sign off before done
tags:        []            # free labels; use security-sensitive to trigger SEC.07 review
---
```

The body below the front-matter is free Markdown. Agents append notes with their ID
and date; they never delete prior notes.

### Status lifecycle

```
todo  →  in_progress  →  review  →  done
                                ↘  blocked
```

- `todo`: created, not yet picked up
- `in_progress`: assignee is actively working
- `review`: work is complete; reviewers listed in `review_by` are notified
- `done`: all reviewers have signed off; ARCH.00 confirms
- `blocked`: assignee cannot proceed; blocker task ID noted in the body

### Routing rules

1. **Security-sensitive tasks** — any task tagged `security-sensitive` must list both
   `SEC.07` and `CQR.08` in `review_by`. Neither can be omitted.

2. **All other tasks** — must list at least `CQR.08` in `review_by`.

3. **Protocol changes** — any task that modifies the wire protocol requires PRT.04 to
   publish an updated `docs/PROTOCOL.md` section before SRV.01 or CLI.02 pick up
   dependent implementation tasks.

4. **Out-of-domain discovery** — if an agent discovers a problem outside its domain
   while working, it creates a new task assigned to the correct agent and notes the
   discovery in the current task's body. It does not fix the out-of-domain issue itself.

5. **Task deletion** — only ARCH.00 may delete or reorder tasks. All other agents
   append and update status only.

6. **Blocking findings** — a reviewer's `blocking` finding prevents `status: done`.
   The assignee must resolve the finding and the reviewer must confirm resolution before
   the task may close.

---

## Coordination Workflow

How a feature moves from idea to complete across the full team.

### Step 1 — Design & decompose (ARCH.00)
Architect writes the feature's API contract in `ARCHITECTURE.md` and creates a dependency
graph of TASK files. Each task has exactly one assignee and lists its blockers. Review
requirements and priority are set here.

### Step 2 — Protocol spec (PRT.04)
If the feature touches the wire, PRT.04 publishes the relevant `docs/PROTOCOL.md` section
before implementation starts. SRV.01 and CLI.02 tasks that depend on it are blocked until
this task is done.

### Step 3 — Parallel implementation (SRV.01 · CLI.02)
Server and client developers work against the same spec simultaneously. When either needs
a clarification, they add a note to their task and flag ARCH.00 — they do not
unilaterally reinterpret the spec.

### Step 4 — Build validation (BLD.05)
As each developer marks a task ready, BLD.05 verifies all three platform targets compile
clean. Build failures become new blocking tasks against the developer, not silent fixes.

### Step 5 — GUI integration (GUI.03)
Once CLI.02 marks its client-API tasks done, GUI.03 picks up integration tasks. The GUI
consumes the client library API only.

### Step 6 — Review pass (CQR.08 · SEC.07)
Reviewers work in parallel on `review`-status tasks. Findings are appended as notes.
A task cannot move to `done` while any `blocking` finding is unresolved.

### Step 7 — Integration testing (QA.06)
QA writes and runs tests against the assembled feature. Every resolved SEC.07 finding
must have a corresponding regression test. QA adds a sign-off note to the task before
ARCH.00 closes the milestone.

### Step 8 — Milestone closure (ARCH.00)
Architect marks all feature tasks done, updates `ARCHITECTURE.md` with decisions that
emerged during implementation, and opens the next feature's tasks to start the cycle.

---

## Persistent documents

These files are maintained by the agents listed and should be kept up to date as the
project evolves. Do not move or rename them without updating this file.

| File                  | Owner   | Purpose                                          |
|-----------------------|---------|--------------------------------------------------|
| `CLAUDE.md`           | ARCH.00 | This file. Agent definitions and protocol.       |
| `ARCHITECTURE.md`     | ARCH.00 | Living system architecture and API contracts.    |
| `docs/PROTOCOL.md`    | PRT.04  | Wire protocol specification and version history. |
| `docs/STYLE.md`       | CQR.08  | C/C++ style decisions that apply project-wide.   |
| `TODO/`               | All     | One file per task. See protocol above.           |
