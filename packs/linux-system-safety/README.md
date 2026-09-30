# linux-system-safety

Host-tampering guard rails for Linux: the changes to mandatory access
control, the account databases, the firewall, sshd, sudoers, the kernel and
the logs that an AI agent should never make on its own. Commands are read
from the bash tool, and file writes also from `fs.write` on `path`.

```yaml
version: 1
default: ask
packs: [floor, linux-system-safety]
```

Pair it with `floor`, which already covers the disasters this pack does not
repeat: recursive deletes of `/`, `/etc`, `/var`, `~`; `mkfs`/`dd`/`wipefs`;
cron and `systemctl --user enable` persistence; reverse shells; and reading
SSH/cloud keys and `/etc/shadow` (a read is `secrets-guard`'s job - this
pack gates *writes* to those files).

| Rule | Verdict | Covers |
|---|---|---|
| `linux-mac-disable-denied` | deny | `setenforce 0`/`Permissive`, `aa-teardown`, `aa-disable`, `systemctl stop/disable/mask apparmor` |
| `linux-ld-preload-denied` | deny | writing `/etc/ld.so.preload` (redirect, `tee`, `cp`/`mv`/`dd`/`sed -i`, or `fs.write`) |
| `linux-passwd-shadow-write-denied` | deny | writing `/etc/passwd`, `/etc/shadow`, `/etc/gshadow` |
| `linux-critical-package-removal-denied` | deny, irreversible | `apt/apt-get remove/purge`, `dnf/yum remove`, `dpkg -r/-P`, `pacman -R` of libc/systemd/coreutils/bash/sudo/openssh/the package manager; any `rpm -e --nodeps` |
| `linux-sshd-asks` | ask | `systemctl stop/disable/mask ssh[d]`, `service ssh stop`, writing `/etc/ssh/sshd_config` |
| `linux-firewall-disable-asks` | ask | `ufw disable`, `iptables/ip6tables -F`, `nft flush ruleset`, `iptables -P INPUT/FORWARD ACCEPT`, `systemctl stop/disable/mask firewalld/ufw/nftables` |
| `linux-sudoers-edit-asks` | ask | writing `/etc/sudoers` or `/etc/sudoers.d/*` |
| `linux-user-admin-asks` | ask | `useradd`/`adduser`/`userdel`/`deluser`/`groupadd`/`groupdel`/`chpasswd`/`newusers`, `usermod -aG sudo/wheel/admin/adm/root/docker`, `gpasswd -a`, `passwd <user>` |
| `linux-log-wipe-asks` | ask | `journalctl --vacuum-*`, `> /var/log/…`, `rm`/`shred /var/log/…`, `history -c`, `unset HISTFILE`/`HISTFILE=/dev/null` |
| `linux-kernel-boot-asks` | ask | `update-grub`, `grub-install`, `grub-mkconfig`, `mkinitcpio`, `dracut`, writing under `/boot` |
| `linux-sysctl-security-asks` | ask | `sysctl -w` of a kernel/net/fs security knob (ASLR, ptrace scope, kptr/dmesg restriction, ip_forward, protected links, …), writing `/etc/sysctl.conf` or `/etc/sysctl.d/*` |
| `linux-chattr-immutable-asks` | ask | `chattr +i`/`-i`/`+a`/`-a` |
| `linux-kernel-module-asks` | ask | `insmod`, `rmmod`, `modprobe -r` |
| `linux-hosts-write-asks` | ask | writing `/etc/hosts` |

## What it deliberately does not cover

- **What a script or installer does once it runs.** The rules read the
  command line, not the behaviour of a binary or package hook it starts.
- **Reads are left alone.** `getenforce`, `cat /etc/passwd`, `iptables -L`,
  `ufw status`, `journalctl -u`, `tail /var/log/…`, `sysctl -a`/`sysctl
  <key>`, `lsattr`, `lsmod`, `cat /etc/hosts`, `cat /etc/sshd_config` all
  fall through to your default. `fs.read` of `/etc/passwd`/`/etc/shadow` is
  `secrets-guard`'s job, not this pack's.
- **Non-critical package removal** (`apt remove nginx`) and plain
  `modprobe <module>` load are not gated - only the machine-critical set is.
- **`sysctl` keys outside the security list** (e.g. `vm.swappiness`) and
  `usermod` options other than group membership are not gated.
- **Obfuscation.** Base64 or otherwise encoded commands, and heredocs that
  build these files indirectly, are not decoded by these regexes; provio's
  script inspection and the kernel write boundary are the backstop.

## Tests

`fixtures/linux-system-safety.yaml`: every rule with hits (shell and, where
they apply, `fs.write`) plus near misses that must not fire - `setenforce
1`, `getenforce`, `cat /etc/ld.so.preload`, `grep /etc/passwd`, `apt remove
nginx`, `apt install sudo`, `systemctl restart sshd`, `iptables -L`, `ufw
status`, `usermod -s`, `id`, `journalctl -u`, `tail /var/log`, `ls /boot`,
`sysctl vm.swappiness`, `lsattr`, `modprobe overlay`, `lsmod` and `cat
/etc/hosts`.
