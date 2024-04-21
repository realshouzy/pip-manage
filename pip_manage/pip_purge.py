#!/usr/bin/env python3
"""pip-purge."""
from __future__ import annotations

__title__: Final[str] = "pip-purge"

import argparse
from typing import TYPE_CHECKING, Final

from pip_manage._logging import setup_logging
from pip_manage._pip_interface import (
    filter_forwards,
    get_dependencies_of_package,
    purge_packages,
)

if TYPE_CHECKING:
    import logging
    from collections.abc import Sequence

# parameters that pip uninstall supports
_UNINSTALL_ONLY: Final[frozenset[str]] = frozenset(
    (
        "r",
        "requirement",
        "y",
        "yes",
        "root-user-action",
        "break-system-packages",
    ),
)


def _parse_args(
    args: Sequence[str] | None = None,
) -> tuple[argparse.Namespace, list[str]]:
    parser: argparse.ArgumentParser = argparse.ArgumentParser(
        description=__doc__,
    )
    parser.add_argument(
        "pkgs",
        nargs="+",
        help="Packages to purge",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        default=False,
        help="Show more output",
    )
    return parser.parse_known_args(args)


# TODO: Implement purging
# TODO: Improve naming
def main(argv: Sequence[str] | None = None) -> int:
    args, forwarded = _parse_args(argv)
    uninstall_args: list[str] = filter_forwards(forwarded, set())
    logger: logging.Logger = setup_logging(__title__, verbose=args.verbose)
    logger.debug("Forwarded arguments: %s", forwarded)
    logger.debug("Arguments forwarded to 'pip uninstall': %s", uninstall_args)

    dct: dict[str, tuple[frozenset[str], frozenset[str]]] = {}
    for pkg in args.pkgs:
        dct[pkg] = get_dependencies_of_package(pkg)
    logger.debug(dct)

    pkgs_to_be_uninstalled: list[str] = []
    for pkg_name, pkg_info in dct.items():
        if not pkg_info[1] or all(pkg in dct for pkg in pkg_info[1]):
            pkgs_to_be_uninstalled.append(pkg_name)
        else:
            logger.info(
                "Cannot uninstall %s. Required by: %s",
                pkg_name,
                ", ".join(pkg_info[1].difference(dct)),
            )

    if pkgs_to_be_uninstalled:
        logger.info("Purging: %s", ", ".join(pkgs_to_be_uninstalled))
        purge_packages(pkgs_to_be_uninstalled, uninstall_args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
