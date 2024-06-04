#!/usr/bin/env python3
"""pip-purge lets you smoothly uninstall packages and their dependencies."""
from __future__ import annotations

__title__: Final[str] = "pip-purge"

import argparse
import importlib.metadata
from pathlib import Path
from typing import TYPE_CHECKING, Final, NamedTuple

from pip_manage._logging import set_logging_level, setup_logging
from pip_manage._pip_interface import (
    PIP_CMD,
    UNINSTALL_ONLY,
    filter_forwards_include,
    uninstall_packages,
)

if TYPE_CHECKING:
    import logging
    from collections.abc import Sequence

_EPILOG: Final[str] = (
    """
Unrecognised arguments will be forwarded to 'pip uninstall' (if supported),
so you can pass things such as '--yes' and '--break-system-packages' and
they will do what you expect. See 'pip uninstall -h' for a full overview of the options.
"""
)

logger: logging.Logger = setup_logging(__title__)


def _parse_args(
    args: Sequence[str] | None = None,
) -> tuple[argparse.Namespace, list[str]]:
    parser: argparse.ArgumentParser = argparse.ArgumentParser(
        description=__doc__,
        epilog=_EPILOG,
    )
    parser.add_argument(
        "packages",
        nargs="*",
        default=[],
        help="Packages to purge",
    )
    parser.add_argument(
        "--requirement",
        "-r",
        dest="requirements",
        action="append",
        metavar="FILE_PATH",
        type=lambda path: Path(path.strip()).resolve(),
        default=[],
        help=(
            "Uninstall all the packages listed in the given requirements file "
            "(can be used multiple times)"
        ),
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        default=False,
        help="Show more output",
    )
    parser.add_argument(
        "--ignore-extra",
        action="store_true",
        default=False,
        help="Ignore extra dependencies",
    )
    parser.add_argument(
        "--continue-on-fail",
        "-C",
        action="store_true",
        default=False,
        help="Continue with other uninstalls when one fails",
    )
    parser.add_argument(
        "--exclude",
        action="append",
        default=[],
        help="Exclude package from the purge",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        default=False,
        help="Don't actually purge anything, just print what would be",
    )
    parser.add_argument(
        "--freeze-packages",
        action="store_true",
        default=False,
        help="Freeze all packages that will be purged",
    )
    parser.add_argument(
        "--freeze-file",
        "-f",
        metavar="FILE_PATH",
        type=lambda path: Path(path.strip()).resolve(),
        default=Path("backup.txt").resolve(),
        help="Specify the file path to store the frozen packages",
    )
    return parser.parse_known_args(args)


def _is_installed(package: str) -> bool:
    try:
        importlib.metadata.distribution(package)
    except importlib.metadata.PackageNotFoundError:
        return False
    return True


def _parse_requirements(
    requirements: list[str] | None,
    *,
    ignore_extra: bool,
) -> frozenset[str]:
    if not requirements:
        return frozenset()
    return frozenset(
        require
        for requirement in requirements
        if _is_installed(require := requirement.partition(" ")[0])
        and (
            (ignore_extra) ^ ("extra == " in requirement)  # xor
            or not ignore_extra
            and "extra == " not in requirement
        )
    )


def _get_required_by(package: str, *, ignore_extra: bool) -> frozenset[str]:
    return frozenset(
        dist_name
        for dist in importlib.metadata.distributions()
        if (dist_name := dist.name.partition(" ")[0]) != package
        and package in _parse_requirements(dist.requires, ignore_extra=ignore_extra)
    )


class _DependencyInfo(NamedTuple):
    dependencies: frozenset[str]
    dependents: frozenset[str]


def _get_dependencies_of_package(
    package: str,
    *,
    ignore_extra: bool,
) -> _DependencyInfo:
    dependencies: frozenset[str] = _parse_requirements(
        importlib.metadata.distribution(package).requires,
        ignore_extra=ignore_extra,
    )
    dependents: frozenset[str] = _get_required_by(package, ignore_extra=ignore_extra)
    return _DependencyInfo(dependencies, dependents)


def _read_from_requirements(requirements: list[Path]) -> list[str]:
    return [
        package.strip()
        for requirement in requirements
        for package in requirement.read_text(encoding="utf-8").splitlines()
    ]


def _freeze_packages(file: Path, packages: list[str]) -> None:
    frozen_packages: str = "\n".join(
        f"{package}=={importlib.metadata.distribution(package).version}"
        for package in packages
    )
    file.write_text(f"{frozen_packages}\n", encoding="utf-8")


def main(  # pylint: disable=R0914, R0915  # noqa: PLR0915
    argv: Sequence[str] | None = None,
) -> int:
    args, forwarded = _parse_args(argv)
    uninstall_args: list[str] = filter_forwards_include(forwarded, UNINSTALL_ONLY)
    set_logging_level(logger, verbose=args.verbose)
    logger.debug("Forwarded arguments: %s", forwarded)
    logger.debug("Arguments forwarded to 'pip uninstall': %s", uninstall_args)

    if unrecognized_args := set(forwarded).difference(uninstall_args):
        logger.warning(
            "Unrecognized arguments: %s",
            ", ".join(sorted(unrecognized_args)),
        )

    if not (packages := [*args.packages, *_read_from_requirements(args.requirements)]):
        logger.error("No packages provided")
        return 1

    package_dependencies: dict[str, _DependencyInfo] = {}
    for package in packages:
        if not _is_installed(package):
            logger.warning("%s is not installed", package)
            continue

        if package in args.exclude:
            continue

        package_dependencies[package] = dependency_info = _get_dependencies_of_package(
            package,
            ignore_extra=args.ignore_extra,
        )
        logger.debug(
            "%s requires: %s",
            package,
            dependency_info.dependencies,
        )
        logger.debug(
            "%s is required by: %s",
            package,
            dependency_info.dependents,
        )
        for dependent_package in dependency_info.dependencies.difference(
            args.exclude,
        ):
            package_dependencies[dependent_package] = (
                dependent_package_dependency_info
            ) = _get_dependencies_of_package(
                dependent_package,
                ignore_extra=args.ignore_extra,
            )
            logger.debug(
                "%s requires: %s",
                dependent_package,
                dependent_package_dependency_info.dependencies,
            )
            logger.debug(
                "%s is required by: %s",
                dependent_package,
                dependent_package_dependency_info.dependents,
            )

    # In the first iteration, it is determined which packages should be kept
    # and which should be uninstalled based on their dependencies.
    # If a package has dependents that are NOT supposed to also by uninstalled,
    # it removes the package from package_dependencies.
    for package_name, dependency_info in package_dependencies.copy().items():
        logger.debug("Checking %s", package_name)
        if dependency_info.dependents and not all(
            package in package_dependencies for package in dependency_info.dependents
        ):
            logger.info(
                "Cannot uninstall %s, required by: %s",
                package_name,
                ", ".join(dependency_info.dependents.difference(package_dependencies)),
            )
            del package_dependencies[package_name]

    # This second iteration ensures that any packages that were kept,
    # because they were dependencies of other packages being uninstalled
    # are also reconsidered.
    packages_to_uninstall: list[str] = []
    for package_name, dependency_info in package_dependencies.items():
        logger.debug("Checking %s again", package_name)
        if not dependency_info.dependents or all(
            package in package_dependencies for package in dependency_info.dependents
        ):
            packages_to_uninstall.append(package_name)
            logger.debug("%s will be uninstalled", package_name)
        else:
            logger.info(
                "Cannot uninstall %s, required by: %s",
                package_name,
                ", ".join(dependency_info.dependents.difference(package_dependencies)),
            )

    logger.debug("Finished checking packages")

    if not packages_to_uninstall:
        logger.info("No packages to purge")
        return 0

    packages_to_uninstall.sort()

    if args.freeze_packages:
        _freeze_packages(args.freeze_file, packages_to_uninstall)
        logger.debug("Wrote packages to %s", args.freeze_file)

    joined_pip_cmd: str = " ".join(PIP_CMD)
    joined_uninstall_args: str = " ".join(uninstall_args)
    joined_packages_to_uninstall: str = " ".join(packages_to_uninstall)
    running: str = "Running" if not args.dry_run else "Would run"
    msg: str
    if not uninstall_args:
        msg = f"{running}: '{joined_pip_cmd} {joined_packages_to_uninstall}'"
    else:
        msg = (
            f"{running}: '{joined_pip_cmd} {joined_uninstall_args} "
            f"{joined_packages_to_uninstall}'"
        )
    logger.info(msg)

    if not args.dry_run:
        uninstall_packages(
            packages_to_uninstall,
            uninstall_args,
            continue_on_fail=args.continue_on_fail,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())