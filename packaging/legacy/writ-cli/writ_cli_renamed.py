"""`writ` → `provio`: run the renamed binary with the same arguments."""

import os
import shutil
import subprocess
import sys
import sysconfig


def _provio() -> str:
    exe = "provio.exe" if os.name == "nt" else "provio"
    beside = os.path.join(sysconfig.get_path("scripts"), exe)
    if os.path.isfile(beside):
        return beside
    found = shutil.which("provio")
    if found:
        return found
    sys.exit("writ was renamed to provio, but the provio binary was not found: pip install provio")


def main() -> None:
    if os.environ.get("PROVIO_QUIET_RENAME") != "1":
        print(
            "note: writ is now provio (same tool, new name). Use `provio` "
            "(pip install provio); this `writ` command will be removed.",
            file=sys.stderr,
        )
    sys.exit(subprocess.call([_provio(), *sys.argv[1:]]))


if __name__ == "__main__":
    main()
