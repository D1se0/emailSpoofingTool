#!/usr/bin/env python3
"""Convenience launcher: ./mailforge.sh  →  runs the CLI."""
#!/bin/sh
DIR="$(cd "$(dirname "$0")" && pwd)"
exec python3 "$DIR/mailforge.py" "$@"
