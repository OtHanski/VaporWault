---
id:          TASK-226
title:       "Full JNI bridge surface + Kotlin VwClient wrapper"
status:      todo
assignee:    MOB.10
created_by:  ARCH.00
created:     2026-08-31
priority:    high
depends_on:  [TASK-225]
blocks:      [TASK-228, TASK-229, TASK-230, TASK-231, TASK-232]
review_by:   [CQR.08]
tags:        []
---

Extend TASK-225's proof-of-life JNI bridge into the full surface the Android
app needs, per `docs/PROTOCOL.md`: session lifecycle (2FA challenge/response,
session resume, logout), file ops (list/stat/mkdir/delete/move,
chunk_query/chunk_upload/chunk_download, file_commit), version history
(list/restore/chunks), sharing (share grant/revoke/list, link
create/revoke/list), and account self-service (email, 2FA, notify_prefs).
Vault RPCs are TASK-230's job, not this one.

Binary fields (session tokens, hashes) cross the JNI boundary as
`jbyteArray`; text as `jstring`/UTF-8; chunk payloads as
`java.nio.DirectByteBuffer` (`GetDirectBufferAddress`) to avoid copying 4 MiB
chunks through a JVM byte array per transfer.

Add the Kotlin `VwClient` class: a thin 1:1 wrapper over the JNI bridge,
mirroring the relationship `src/gui/client/vw_gui_ipc.h`'s `VwGuiIpc` C++
class has to `vw_ipc.h` on desktop, except calling straight into linked-in
native code rather than over a socket to a separate daemon process.

## Acceptance criteria

- Every message type listed above is reachable from Kotlin via `VwClient`
  and round-trips correctly against a real `vapourwaultd` (list a directory,
  upload+commit a file, download it back, share it, revoke it).
- No JNI local-reference leaks under repeated calls (verify with `-Xcheck:jni`
  or equivalent during manual testing).

## Notes
