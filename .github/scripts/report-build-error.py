#!/usr/bin/env python3
"""Expose useful build output through public GitHub check annotations."""

import re
import sys
from pathlib import Path


def main() -> None:
    title, log_path = sys.argv[1:]
    lines = Path(log_path).read_text(errors="replace").splitlines()
    matches = [line for line in lines if re.search(
        r"error|failed|fatal|no space|denied|timeout|timed out", line, re.IGNORECASE
    )]
    excerpt = matches[-12:] + ["--- Last 20 log lines ---"] + lines[-20:]
    message = "\n".join(excerpt)[-12000:]
    message = message.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
    print(f"::error title={title}::{message}")


if __name__ == "__main__":
    main()
