# Getting Started with VaporWault (for everyday users)

This guide is for you if someone else — a family member, a friend, whoever
runs your VaporWault server — has already set one up and given you:

- a **server address** (something like `vault.example.com`)
- a **username**
- a **password**
- possibly, a note that you'll also need a **6-digit code** each time you log
  in (this means your account has extra security turned on — more on that
  below)

You don't need to know anything about servers, command lines, or how any of
this works under the hood. This guide only covers the app you'll actually
use day to day: the **VaporWault client** — a small program that keeps a
folder on your computer in sync with your VaporWault account, the same idea
as Dropbox or Google Drive.

If you're the person setting up the *server* instead, this isn't the guide
you want — see `docs/TUTORIAL.md`.

---

## A few words you'll see

Just so nothing catches you off guard:

- **The daemon** — a small helper program that runs quietly in the
  background and does the actual file-syncing. You won't interact with it
  directly; it just needs to be running.
- **Sync** — copying files back and forth so your computer and the server
  agree on what's there. This mostly happens automatically, right after you
  save a change.
- **A sync folder** — a folder on your computer that VaporWault keeps
  matched up with a matching location on the server.

That's really all you need going in.

---

## Part 1 — One-time setup

This part is a little more technical than the rest of this guide — it's a
"do it once and forget about it" step. **If whoever administers your server
already did this for you, skip straight to [Part 2](#part-2--everyday-use).**
If not, here's the short version. (If any of this feels like too much, it's
completely reasonable to ask your admin to do it for you once — that's a
normal thing to ask.)

### 1a. Get the app

**Windows:**

1. Ask your admin for the VaporWault Windows download (a `.zip` file), or
   get it from the project's GitHub Releases page yourself
   (`vaporwault-<version>-windows-x86_64.zip`).
2. Extract the whole `.zip` into a folder you'll keep, e.g.
   `C:\VaporWault\`. Keep every extracted file together in that one folder —
   the app needs a couple of files that sit alongside it to work.

**Linux:**

1. Get `vaporwault-<version>-linux-x86_64.tar.gz` the same way, and extract
   it (right-click → Extract, or `tar xzf vaporwault-*.tar.gz` in a
   terminal if you're comfortable there).
2. You may also need SDL2 installed for the app window to open —
   `sudo apt install libsdl2-2.0-0` (Ubuntu/Debian) or the equivalent for
   your distribution. Your admin can confirm if this is already handled.

### 1b. Tell it which server and username to use

Before first use, one small text file needs three lines filled in. This is
the one genuinely technical step in this whole guide.

**Windows** — open **Notepad**, then open
`%APPDATA%\VaporWault\daemon.conf` (paste that path into Notepad's
File → Open box). If the file or folder doesn't exist yet, run the app
installer/setup script your admin gave you first — it creates this file
from a template.

**Linux** — open `~/.local/share/vapourwault/daemon.conf` in any text
editor.

Fill in the three lines your admin gave you the information for:

```ini
server_host = vault.example.com    # the address your admin gave you
server_port = 4430                 # usually fine as-is
username    = yourname             # the username your admin gave you
```

Leave everything else in the file as it is. Save and close it.

### 1c. Start the daemon

The daemon needs to be running for anything else to work — think of it as
turning on the "sync engine" so the app has something to talk to.

**Windows** (PowerShell, run once):

```powershell
Start-ScheduledTask -TaskName VaporWaultDaemon
```

It's registered to start automatically every time you log in after this, so
you shouldn't need to run that again.

**Linux** (terminal, run once):

```bash
systemctl --user enable --now vapourwault-daemon
```

Same idea — it'll auto-start from now on.

If either of those commands gives an error, the daemon likely isn't
installed yet — that's a step for whoever set up your account, not
something to troubleshoot yourself.

That's the whole one-time setup. Everything from here on is just using the
app.

---

## Part 2 — Everyday use

### Opening the app for the first time

Launch **VaporWault** (`vapourwault-gui.exe` on Windows, `vapourwault-gui`
on Linux — your admin may have put a shortcut somewhere more convenient).

You'll see a small login box asking for your **password**. Type it in and
either press Enter or click **Login**.

**If your account has the extra 6-digit-code security enabled:** after you
click Login the first time, the box will ask for a **2FA code** as well —
and you'll notice the password box is now empty again. That's expected, not
a glitch: type your password *and* your code together, then click Login
again.

If login doesn't work, see [Troubleshooting](#troubleshooting) below.

### The main window

Once you're logged in, you'll see a menu bar across the top with five
sections:

| Section | What it's for |
|---|---|
| **Files** | Browse the files and folders you're syncing, and see whether each one is up to date. |
| **Shared** | Files and folders other people have shared with you, or that you've shared with others. |
| **Vault** | Encrypted folders, if you or your admin set any up — most people won't need this. |
| **Queue** | A simple status screen: what's currently uploading/downloading, and whether anything's stuck. |
| **Settings** | Add or remove which folders get synced, and a few connection options. |

### Adding a folder to sync

This is the main thing you'll do once you're set up: telling VaporWault
which folder on your computer to keep in sync.

1. Go to **Settings**.
2. Under **Sync folders**, fill in:
   - **Local path** — the folder on *your* computer, e.g.
     `C:\Users\YourName\Documents\VaporWault` or `/home/yourname/vaporwault`.
     It doesn't need to exist yet with anything in it.
   - **Virtual path** — just a name for this folder on the server side.
     If you're not sure what to put, use something simple starting with a
     slash, like `/Documents` or `/Photos`. Unless your admin told you to
     match something specific, any name here is fine — think of it as a
     label, not something you need to get "right."
3. Click **Add folder**.

That's it — any file you put in that local folder will start uploading
automatically, and anything already on the server for that folder will
start downloading.

### Watching sync happen

Switch to **Files** to see what's synced so far. Each file shows a coloured
status on the right:

| Colour | Meaning |
|---|---|
| 🟢 **Synced** | Up to date — nothing to do. |
| 🟡 **Local mod** / **Remote mod** / **New** | A change is queued to go up or come down. This is completely normal right after you save something — it usually clears within moments. |
| 🔴 **Conflict** | See [below](#if-you-ever-see-a-conflict) — very rare, and nothing is ever lost when it happens. |
| ⚪ Anything else | A delete that's being processed. |

For a quicker overall picture, check **Queue** instead — it shows how many
uploads/downloads are still pending and when the last sync happened, without
needing to scroll through a file list.

There's also a **Sync Now** button (on both Files and Queue) if you don't
want to wait — VaporWault checks for changes on its own regularly, but this
forces it to check immediately.

### If you ever see a "Conflict"

This can happen if the same file gets changed in two places (say, on your
laptop and your desktop) before they've had a chance to sync with each
other. You don't need to do anything — VaporWault handles it automatically:

- **Your local copy is kept** as the "real" version going forward.
- The other version is saved right next to it, renamed to something like
  `MyFile.conflict.20260805T143000.docx` — same folder, same name, just with
  `.conflict.<date-and-time>` inserted before the extension.

If you want to double check nothing important was lost, open that
`.conflict.*` file and compare — otherwise it's safe to just leave it there
or delete it once you've checked.

### Pausing sync

If you need to temporarily stop syncing (e.g. you're about to move a huge
number of files around and don't want it fighting with you), click
**Pause** on the Files screen. Click **Resume** when you're done. Nothing
is lost while paused — VaporWault just picks up where it left off.

### Email notifications

VaporWault can send you an email for a few things worth knowing about
right away, instead of only finding out next time you open the app.
**Every one of these is off until you turn it on** — turning nothing on
means you'll never get an email from VaporWault at all.

To turn one on, go to **Settings** and find **Email notifications** (this
looks the same whether you're using the desktop app or the web version at
your admin's VaporWault address — just check the box for whichever ones
you want):

| Turn this on to get an email when... |
|---|
| **Someone shares something with me** — someone gives you access to one of their files or folders. |
| **My storage usage crosses 90% of quota** — you're close to running out of space. You won't get another email about it until your usage drops back down and crosses 90% again. |
| **A new login succeeds on my account** — useful as a heads-up in case it wasn't you. This never fires just from your own app reconnecting after a network hiccup, only an actual new login. |
| **My password or 2FA setting changes** — a heads-up in case you didn't make that change yourself. |

These are emailed to whatever address is on file for your account — the
same one your admin used when they set your account up. If you're not
sure what that address is, ask your admin.

---

## Troubleshooting

**"Daemon offline — retrying every 2 s" (banner across the top)**
The background helper program isn't running. This usually means it hasn't
been started yet (see [Part 1c](#1c-start-the-daemon)), or your computer
was restarted and it didn't come back automatically. Try the same start
command from Part 1c again; if that doesn't help, ask your admin.

**"Offline — daemon not connected to server" (message above the password box)**
The helper program is running fine, but it can't reach the VaporWault
server itself — most often your internet connection, or the server being
temporarily down. Wait a minute and check again; if it doesn't clear up,
check your internet connection, and if that's fine, ask your admin to check
the server.

**Wrong password (a message like "Login failed (code 300)")**
That specific code means the password wasn't accepted — double-check it
(passwords are case-sensitive). If you're sure it's right and it still
fails, ask your admin to confirm your account isn't locked.

**"Login failed (code 304)"**
This means too many wrong password attempts in a row have temporarily
locked your account. Wait a while and try again, or ask your admin.

**A file hasn't shown up yet**
Saving a file normally triggers an upload almost immediately. If it's been
more than a minute or two: check the **Queue** screen — if "Uploads
pending" or "Downloads pending" isn't dropping to zero, or "Errors" shows a
number greater than zero, something is stuck (often a storage-quota limit
on your account) — ask your admin to take a look rather than trying to
diagnose it yourself.

**A status icon shows red or the app says "Sync paused"**
Red on a specific file means a conflict (see
[above](#if-you-ever-see-a-conflict) — no action needed). "Sync paused"
just means someone clicked Pause — click **Resume** on the Files screen to
continue.

**Anything else**
VaporWault's error messages sometimes show a numeric "code" — that's meant
for your admin, not for you to decode. If something looks wrong and none of
the above matches, the fastest path is: tell your admin what you see on
screen (a screenshot helps) rather than trying to fix it yourself — issues
at this layer are almost always server/network-side, not something fixable
from the app.
