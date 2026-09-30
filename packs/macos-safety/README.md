# macos-safety

Host-tampering guard rails for macOS: the changes to system-integrity,
Gatekeeper, disk encryption, backups, keychains and admin accounts that an
AI agent should never make on its own.

```yaml
version: 1
default: ask
packs: [floor, macos-safety]
```

Pair it with `floor`, which already covers the platform-independent
disasters this pack does not repeat: reboot/shutdown, launchd/cron
persistence, `dd`/`diskutil`-style raw disk writes via `dd of=/dev/…`,
recursive deletes of the home directory, force pushes and reverse shells.

| Rule | Verdict | Covers |
|---|---|---|
| `mac-sip-disable-denied` | deny | `csrutil disable`/`clear` (System Integrity Protection) |
| `mac-gatekeeper-disable-denied` | deny | `spctl --master-disable`/`--global-disable` |
| `mac-filevault-disable-denied` | deny | `fdesetup disable` |
| `mac-disk-erase-denied` | deny, irreversible | `diskutil eraseDisk`/`eraseVolume`/`secureErase`/`zeroDisk`/`randomDisk`/`reformat`/`partitionDisk`, `diskutil apfs deleteContainer`/`deleteVolume` |
| `mac-add-admin-denied` | deny | `dscl . -append/-create/-merge /Groups/admin`, `dseditgroup -o edit -a … admin` |
| `mac-keychain-delete-denied` | deny, irreversible | `security delete-keychain` |
| `mac-tcc-reset-asks` | ask | `tccutil reset` (privacy permissions) |
| `mac-time-machine-asks` | ask, irreversible | `tmutil delete`/`disable`/`deletelocalsnapshots`/`deleteinprogress` |
| `mac-quarantine-removal-asks` | ask | `xattr -d`/`-rd com.apple.quarantine`, `xattr -rc /Applications/…` |
| `mac-security-defaults-asks` | ask | `defaults write` of the application firewall (`com.apple.alf`), `LSQuarantine`, screen-lock password or auto-login |
| `mac-launchdaemon-asks` | ask | `launchctl unload`/`bootout`/`disable`/`remove` of a daemon under `/System/Library/LaunchDaemons` or `/Library/LaunchDaemons` |
| `mac-nvram-asks` | ask | `nvram <var>=…`, `nvram -c`/`-d` |
| `mac-softwareupdate-disable-asks` | ask | `softwareupdate --schedule off`/`--ignore` |

## What it deliberately does not cover

- **What a script, `.pkg` or app does once it runs.** The rules read the
  command line, not the behaviour of an installer or binary it starts.
- **Read-only forms are left alone.** `csrutil status`, `spctl --status`,
  `fdesetup status`, `diskutil list`/`info`, `dscl . -read`, `security
  list-keychains`, `tmutil status`/`listbackups`, `xattr -l`/`-p`,
  `defaults read`, `launchctl list` and `nvram -p` fall through to your
  default.
- **User LaunchAgents (`~/Library/LaunchAgents`)** are not gated here;
  autostart entries there are `floor`'s persistence rule when written.
- **XProtect / MRT removal by deleting system bundles** is not matched by
  name; deleting protected files needs SIP off (already denied) or a
  recursive delete `floor` catches.
- **Obfuscation.** Base64 or otherwise encoded commands are not decoded.

## Tests

`fixtures/macos-safety.yaml`: every rule with hits (with and without
`sudo`) plus near misses that must not fire - `csrutil status`, `spctl
--master-enable`, `diskutil list`, `dscl . -read`, `security
list-keychains`, `tmutil status`, `xattr -l`/`-p`, `defaults write
com.apple.dock`, `launchctl list`, a user-agent unload, `nvram -p`,
`softwareupdate --list`, and an `echo` that merely mentions `csrutil
disable`.
