# windows-safety

Host-tampering guard rails for Windows: the changes to security tooling,
backups, logs and accounts that an AI agent should never make on its own.
Commands are read whether they come through Git Bash or as PowerShell text
passed to the shell.

```yaml
version: 1
default: ask
packs: [floor, windows-safety]
```

Pair it with `floor`, which already covers the platform-independent
disasters this pack does not repeat: shutdown/reboot, scheduled-task and
Run-key persistence, disk formatting (`Format-Volume`, `diskpart`),
recursive deletes of the user profile or a drive root, force pushes and
reverse shells.

| Rule | Verdict | Covers |
|---|---|---|
| `win-defender-disable-denied` | deny | `Set-MpPreference`/`Add-MpPreference` disabling real-time or a scan feature, adding a scan exclusion, `-MAPSReporting Disabled`; `sc stop/config/delete WinDefend`/`Sense`/`WdNisSvc`; `Uninstall-WindowsFeature Windows-Defender` |
| `win-firewall-disable-denied` | deny | `netsh advfirewall set … state off`, `netsh firewall set opmode disable`, `Set-NetFirewallProfile -Enabled False`, `sc stop mpssvc`/`BFE` |
| `win-shadow-backup-wipe-denied` | deny, irreversible | `vssadmin delete shadows`/`resize shadowstorage`, `wmic shadowcopy delete`, `wbadmin delete catalog/backup/systemstatebackup` (the ransomware backup wipe) |
| `win-event-log-clear-denied` | deny, irreversible | `wevtutil cl`/`clear-log`, `Clear-EventLog`, `Remove-EventLog` |
| `win-cipher-wipe-denied` | deny, irreversible | `cipher /w` (free-space wipe) |
| `win-disable-system-restore-denied` | deny | `Disable-ComputerRestore`, `reg add … SystemRestore … DisableSR /d 1` |
| `win-uac-disable-denied` | deny | setting `EnableLUA=0` via `reg add` or `Set-ItemProperty` |
| `win-execution-policy-machine-denied` | deny | `Set-ExecutionPolicy Unrestricted/Bypass -Scope LocalMachine`/`MachinePolicy` |
| `win-add-admin-denied` | deny | `net localgroup administrators … /add`, `Add-LocalGroupMember -Group Administrators` |
| `win-system-file-delete-denied` | deny, irreversible | deleting a file under `Windows\System32` or `SysWOW64` (`del`, `erase`, `Remove-Item`) |
| `win-new-local-user-asks` | ask | `net user … /add`, `New-LocalUser` |
| `win-bcdedit-asks` | ask | `bcdedit /set` (and `/delete`, `/deletevalue`, `/import`) |
| `win-acl-weaken-asks` | ask | `takeown … /r`, `icacls … /grant Everyone/Users/Authenticated Users`, `cacls … Everyone` |
| `win-reg-delete-hklm-asks` | ask | `reg delete HKLM\…`, `Remove-Item HKLM:\…` |

## What it deliberately does not cover

- **What a script or installer does once it runs.** The rules read the
  command line, not the behaviour of an `.exe`, `.ps1` or `.msi` it starts.
- **Read-only forms are left alone.** `Get-MpPreference`, `vssadmin list
  shadows`, `wevtutil qe`/`Get-EventLog`, `bcdedit /enum`, `reg query`,
  `icacls <path>` (view), `Set-MpPreference -DisableRealtimeMonitoring
  $false` (re-enable) and `Set-ExecutionPolicy … -Scope Process` all fall
  through to your default.
- **Per-user (HKCU) registry edits and `-Scope CurrentUser` execution
  policy** are not gated - they do not weaken the machine for other users.
- **Persistence, shutdown and disk wipes** belong to `floor`; secret files
  and credential stores belong to `secrets-guard`. Add those packs too.
- **Obfuscation.** Base64-encoded (`powershell -enc …`) or otherwise
  encoded commands are not decoded by these regexes.

## Tests

`fixtures/windows-safety.yaml`: every rule with hits (including the `.exe`
and `powershell -Command "…"` spellings) plus near misses that must not
fire - re-enabling Defender, `netsh … state on`, `vssadmin list shadows`,
`Get-EventLog`, `cipher /e`, `Set-ExecutionPolicy … -Scope Process`,
`powershell -ExecutionPolicy Bypass -File`, `net user` (list),
`icacls <path>` and `reg query`/`reg delete HKCU`.
