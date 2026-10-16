#!/usr/bin/env python3
"""Refuse unsupported tags or a release whose binary/plugin versions disagree."""

import json
from pathlib import Path
import re
import sys
import tomllib


def validate(tag, root):
    if not re.fullmatch(r"v\d+\.\d+\.\d+(?:-found\.[1-9]\d*)?", tag):
        raise ValueError("expected vX.Y.Z or vX.Y.Z-found.N")
    manifest = tomllib.loads((root / "Cargo.toml").read_text())
    plugin = json.loads((root / "plugins/.claude-plugin/plugin.json").read_text())
    if tag[1:] != manifest["package"]["version"] or tag[1:] != plugin["version"]:
        raise ValueError("tag, Cargo version, and plugin version must match")


if __name__ == "__main__":
    try:
        validate(sys.argv[1], Path(__file__).resolve().parents[1])
    except (IndexError, ValueError) as error:
        sys.exit(str(error))
