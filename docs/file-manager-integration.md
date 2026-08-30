# File-manager integration

The File Locker can be used without copying paths into a terminal. These entry
points call the same `phone-auth locker` CLI and therefore keep its request
limits, one-phone-approval-per-file rule, destination collision checks, and
atomic publication behavior.

File-manager actions deliberately use the reversible defaults:

- locking passes `--keep-original`;
- unlocking passes `--keep-container`;
- locking always asks where to save the offline recovery code (or a directory
  for one code per selected file).

After opening and checking the result, the user may remove the retained input.
The integration never silently trades recovery for convenience.

## Windows Explorer

The Windows installer registers per-user verbs only:

- **Lock with PhoneAuth…** on regular files;
- **Unlock with PhoneAuth** on `.balock` files;
- **Open with → BioAuth locked file** without replacing an existing default
  `.balock` application.

It also creates a **PhoneAuth File Locker** shortcut on the desktop and in the
Start menu. Dropping one or more ordinary files or `.balock` containers onto
that shortcut selects lock or unlock automatically. A mixed selection is
refused before any prompt. Uninstall removes only PhoneAuth's ProgID, verbs,
and shortcuts.

The launcher is
`resources/file-manager/phone-auth-file-manager.ps1`; its companion `.cmd` is
the drag-and-drop target. Paths are passed as an argument array rather than
concatenated into a command string, including paths containing spaces.

## Nautilus

From a source checkout:

```sh
desktop/file-manager/install-nautilus.sh
```

From the headless tarball, run the same script under its `file-manager/`
directory. Nix installs it under
`$out/share/phone-auth/file-manager/`. Electron packages carry it in their
resources directory.

The installer writes only below `$XDG_DATA_HOME` (default
`~/.local/share`): two Nautilus scripts, a `.balock` MIME declaration, and a
**PhoneAuth File Locker** desktop entry. The desktop entry accepts `%F`, so it
is also a multi-file drag-and-drop target. Restart Nautilus if its Scripts menu
was already open.

Remove the integration without touching containers or configuration:

```sh
desktop/file-manager/install-nautilus.sh --uninstall
```

Nautilus exposes selected local paths as newline-delimited data. Consequently,
the launcher refuses filenames containing a newline instead of splitting one
file into two operations. Non-regular files and mixed lock/unlock selections
also fail before the CLI or phone is contacted. `zenity` is used only for the
recovery destination and completion/error dialog; no secret is placed in its
arguments.

## Verification

`desktop/file-manager/tests/linux.sh` exercises dispatch, safe flags, mixed
selection refusal, install, and uninstall in a temporary XDG root. The Windows
test runs the PowerShell launcher's `-DryRun` plan and checks the same dispatch
and safety invariants. Both run in their native desktop CI jobs.
