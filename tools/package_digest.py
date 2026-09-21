#!/usr/bin/env python3
"""Print the digest line a HashGuard release publishes.

A release ships a ``SHA256SUMS.txt`` so that an operator can ask a question the
agent cannot answer about itself: *is the code running on this machine the code
that was published?* ``hashguard --self-audit --release-sums URL`` fetches that
file and compares. This script produces the line that goes into it.

    python3 tools/package_digest.py            # the installed package
    python3 tools/package_digest.py src/hashguard

The digest covers every ``.py`` file under the package directory, in sorted
relative-path order, each contributing its path, its length and its bytes -- so
renaming a file, or moving a byte from one file to the next, changes the
answer. It deliberately does not cover the wheel metadata, which differs
between build machines for reasons that have nothing to do with the code.
"""

from __future__ import annotations

import argparse
import sys


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="package_digest", description=__doc__)
    parser.add_argument(
        "package_dir",
        nargs="?",
        help="the hashguard package directory; default is the installed one",
    )
    parser.add_argument("--version", help="override the version in the label")
    args = parser.parse_args(argv)

    try:
        from hashguard import __version__
        from hashguard.selfaudit import digest_line, package_digest
    except ImportError as exc:  # pragma: no cover - only without the package installed
        print(f"hashguard is not importable from here: {exc}", file=sys.stderr)
        print("Run this from a checkout with 'pip install -e .', or point it at a "
              "package directory on sys.path.", file=sys.stderr)
        return 2

    version = args.version or __version__
    value, count = package_digest(args.package_dir)
    print(digest_line(version, args.package_dir))
    print(f"# {count} .py files, sha256 {value}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
