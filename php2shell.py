#!/usr/bin/env python3
"""Single-file entry point: python3 php2shell.py <target> ..."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from php2shell.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
