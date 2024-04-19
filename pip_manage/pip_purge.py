#!/usr/bin/env python3
"""pip-purge."""
from __future__ import annotations

__title__: Final[str] = "pip-purge"

import argparse
from typing import TYPE_CHECKING, Final

if TYPE_CHECKING:
    from collections.abc import Sequence


def _parse_args(
    args: Sequence[str] | None = None,
) -> argparse.Namespace:
    parser: argparse.ArgumentParser = argparse.ArgumentParser(
        description=__doc__,
    )
    parser.add_argument(
        "pkgs",
        action="append",
        default=[],
        help="Show more output",
    )
    return parser.parse_args(args)


def _get_dependencies(
    pkg: str,  # noqa: ARG001 # pylint: disable=W0613
) -> list[str]:
    raise NotImplementedError


def main(argv: Sequence[str] | None = None) -> int:
    args: argparse.Namespace = _parse_args(argv)
    for pkg in args.pkgs:
        _get_dependencies(pkg)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
