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
    uninstall_packages,
)

if TYPE_CHECKING:
    import logging
    from collections.abc import Sequence


# TODO: Add 'exclude' argument
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


# TODO: Improve naming!!!
# TODO: Ask for conformation
# TODO: Actually use 'filter_forwards'
def main(argv: Sequence[str] | None = None) -> int:
    args, forwarded = _parse_args(argv)
    uninstall_args: list[str] = filter_forwards(forwarded, set())
    logger: logging.Logger = setup_logging(__title__, verbose=args.verbose)
    logger.debug("Forwarded arguments: %s", forwarded)
    logger.debug("Arguments forwarded to 'pip uninstall': %s", uninstall_args)

    dct: dict[str, tuple[frozenset[str], frozenset[str]]] = {}
    for pkg in args.pkgs:
        dct[pkg] = get_dependencies_of_package(pkg)
        for pkg_depd in dct[pkg][0]:
            dct[pkg_depd] = get_dependencies_of_package(pkg_depd)

    pkgs_to_not_be_uninstalled: list[str] = []
    pkgs_to_be_uninstalled: list[str] = []
    for pkg_name, pkg_info in dct.items():
        if not pkg_info[1] or all(pkg in dct for pkg in pkg_info[1]):
            pkgs_to_be_uninstalled.append(pkg_name)
        else:
            logger.info(
                "Cannot uninstall %s: Required by %s",
                pkg_name,
                ", ".join(pkg_info[1].difference(dct)),
            )
            pkgs_to_not_be_uninstalled.append(pkg_name)

    for pkg in pkgs_to_not_be_uninstalled:
        del dct[pkg]
    pkgs_to_be_uninstalled.clear()

    for pkg_name, pkg_info in dct.items():
        if not pkg_info[1] or all(pkg in dct for pkg in pkg_info[1]):
            pkgs_to_be_uninstalled.append(pkg_name)
        else:
            logger.info(
                "Cannot uninstall %s: Required by %s",
                pkg_name,
                ", ".join(pkg_info[1].difference(dct)),
            )

    if pkgs_to_be_uninstalled:
        logger.info("Purging: %s", ", ".join(pkgs_to_be_uninstalled))
        uninstall_packages(pkgs_to_be_uninstalled, uninstall_args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
