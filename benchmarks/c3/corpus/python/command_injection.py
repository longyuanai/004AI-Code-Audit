"""Synthetic C3 sample: OS command injection (CWE-78). Not a real project."""

import os
import sys


def ping_host() -> int:
    host = input("host: ")
    return os.system("ping -n 1 " + host)  # c3-expect vuln CWE-78 PY-CMD-01


def archive_named_file() -> str:
    name = sys.argv[1]
    return os.popen(f"tar czf out.tgz {name}").read()  # c3-expect vuln CWE-78 PY-CMD-02
