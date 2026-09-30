"""fastcsv — a tiny streaming CSV reader (fixture code for the provio attack demo).

This is an ordinary project file. It exists so the fixture repo looks like a
real checkout an agent might be asked to work on. Nothing here is malicious.
"""


def reader(path):
    with open(path, "r", encoding="utf-8", newline="") as fh:
        for line in fh:
            yield line.rstrip("\n").split(",")
