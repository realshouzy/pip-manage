#!/usr/bin/env python3
"""pip-review lets you smoothly manage all available PyPI updates."""
from __future__ import annotations

__title__: Literal["pip-review"] = "pip-review"

import argparse
import logging
import os
from pathlib import Path
from typing import TYPE_CHECKING, Final, Literal, NamedTuple

from pip_manage._logging import setup_logging
from pip_manage._pip_interface import (
    COMMON_PARAMETERS,
    INSTALL_ONLY,
    LIST_ONLY,
    filter_forwards,
    get_outdated_packages,
    update_packages,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

    from pip_manage._pip_interface import _OutdatedPackage


_EPILOG: Final[str] = (
    """
Unrecognised arguments will be forwarded to 'pip list --outdated' and
'pip install' (if supported), so you can pass things such as '--user', '--pre'
and '--timeout' and they will do what you expect. See 'pip list -h' and 'pip install -h'
for a full overview of the options.
"""
)


def _parse_args(
    args: Sequence[str] | None = None,
) -> tuple[argparse.Namespace, list[str]]:
    parser: argparse.ArgumentParser = argparse.ArgumentParser(
        description=__doc__,
        epilog=_EPILOG,
    )
    parser.add_argument(
        "--debug",
        "-d",
        dest="debugging",
        action="store_true",
        default=False,
        help="Show debug information",
    )
    parser.add_argument(
        "--raw",
        "-r",
        action="store_true",
        default=False,
        help="Print raw lines (suitable for passing to pip install)",
    )
    parser.add_argument(
        "--interactive",
        "-i",
        action="store_true",
        default=False,
        help="Ask interactively to install updates",
    )
    parser.add_argument(
        "--auto",
        "-a",
        action="store_true",
        default=False,
        help="Automatically install every update found",
    )
    parser.add_argument(
        "--continue-on-fail",
        "-C",
        action="store_true",
        default=False,
        help="Continue with other installs when one fails",
    )
    parser.add_argument(
        "--freeze-outdated-packages",
        action="store_true",
        default=False,
        help="Freeze all outdated packages to a file before upgrading them",
    )
    parser.add_argument(
        "--freeze-file",
        "-f",
        metavar="FILE_PATH",
        type=lambda path: Path(path.strip()).resolve(),
        default=Path("backup.txt").resolve(),
        help=(
            "Specify the file path to store the frozen packages "
            "(default 'backup.txt')"
        ),
    )
    parser.add_argument(
        "--preview",
        "-p",
        action="store_true",
        default=False,
        help="Preview update target list before upgrading packages",
    )
    return parser.parse_known_args(args)


class _InteractiveAsker:
    def __init__(self, prompt: str) -> None:
        self.prompt: str = prompt
        self.cached_answer: str | None = None
        self.last_answer: str | None = None

    def ask(self) -> str:
        if self.cached_answer is not None:
            return self.cached_answer

        question_default: str = f"{self.prompt} [Y]es, [N]o, [A]ll, [Q]uit "
        answer: str | None = ""
        while answer not in {"y", "n", "a", "q"}:
            question_last: str = (
                f"{self.prompt} [Y]es, [N]o, [A]ll, [Q]uit ({self.last_answer}) "
            )
            answer = (
                input(question_last if self.last_answer else question_default)
                .strip()
                .casefold()
            )
            answer = self.last_answer if answer == "" else answer

        if answer in {"q", "a"}:
            self.cached_answer = answer
        self.last_answer = answer

        return answer


_upgrade_prompter: _InteractiveAsker = _InteractiveAsker("Upgrade now?")


def _freeze_outdated_packages(file: Path, packages: list[_OutdatedPackage]) -> None:
    outdated_packages: str = "\n".join(f"{pkg.name}=={pkg.version}" for pkg in packages)
    file.write_text(f"{outdated_packages}\n", encoding="utf-8")


def _get_constraints_files(
    args: list[str],
) -> list[Path]:
    constraints_files: list[Path] = _get_constraints_files_from_args(args)
    if (env_constraints_file := _get_constraints_files_from_env()) is not None:
        constraints_files.append(env_constraints_file)
    return constraints_files


def _get_constraints_files_from_env() -> Path | None:
    constraints_file: str | None = os.getenv("PIP_CONSTRAINT")
    return Path(constraints_file).resolve() if constraints_file is not None else None


def _get_constraints_files_from_args(args: list[str]) -> list[Path]:
    constraints_files: list[Path] = []

    for idx, arg in enumerate(args):
        if arg in {"--constraint", "-c"}:
            constraints_files.append(Path(args[idx + 1]).resolve())
        elif "--constraint=" in arg or "-c=" in arg:
            *_, constraints_file = arg.partition("=")
            constraints_files.append(Path(constraints_file).resolve())

    return constraints_files


def _set_constraints_of_outdated_pkgs(
    constraints_files: list[Path],
    outdated: list[_OutdatedPackage],
) -> None:
    for file in constraints_files:
        for line in file.read_text(encoding="utf-8").splitlines():
            if line.lstrip().startswith("#"):
                continue
            pkg_name, _, constraint_version = line.partition("#")[0].partition("==")
            for pkg in outdated:
                if pkg.name == pkg_name.strip():
                    pkg.constraints.add(constraint_version.strip())


class _ColumnSpec(NamedTuple):
    title: str
    field: str


# nicer headings for the columns in the oudated package table
_DEFAULT_COLUMN_SPECS: Final[tuple[_ColumnSpec, ...]] = (
    _ColumnSpec("Package", "name"),
    _ColumnSpec("Version", "version"),
    _ColumnSpec("Latest", "latest_version"),
    _ColumnSpec("Type", "latest_filetype"),
    _ColumnSpec("Constraints", "constraints_display"),
)

# Next two functions describe how to collect data for the table.
# Note how they are not concerned with columns widths.


def _extract_column(
    data: list[_OutdatedPackage],
    field: str,
    title: str,
) -> list[str]:
    return [title, *[getattr(item, field) for item in data]]


def _extract_table(
    outdated: list[_OutdatedPackage],
    column_specs: tuple[_ColumnSpec, ...] = _DEFAULT_COLUMN_SPECS,
) -> list[list[str]]:
    return [_extract_column(outdated, field, title) for title, field in column_specs]


# Next two functions describe how to format any table. Note that
# they make no assumptions about where the data come from.


def _column_width(column: list[str]) -> int:
    if not any(column):
        return 0
    return max(len(cell) for cell in column if cell)


def _format_table(columns: list[list[str]]) -> str:
    widths: list[int] = [_column_width(column) for column in columns]
    row_fmt: Callable[..., str] = " ".join(f"{{:<{width}}}" for width in widths).format
    ruler: str = "-" * (sum(widths) + len(widths) - 1)
    assert all(len(columns[0]) == len(column) for column in columns[1:])
    rows: list[str] = [row_fmt(*row) for row in zip(*columns)]
    head: str = rows[0]
    body: list[str] = rows[1:]
    return "\n".join([head, ruler, *body, ruler])


def main(  # pylint: disable=R0915  # noqa: PLR0915
    argv: Sequence[str] | None = None,
) -> int:
    args, forwarded = _parse_args(argv)
    list_args: list[str] = filter_forwards(
        forwarded,
        exclude=INSTALL_ONLY,
        include=LIST_ONLY.union(COMMON_PARAMETERS),
    )
    install_args: list[str] = filter_forwards(
        forwarded,
        exclude=LIST_ONLY,
        include=INSTALL_ONLY.union(COMMON_PARAMETERS),
    )
    setup_logging(__title__, debugging=args.debugging)
    logger: logging.Logger = logging.getLogger(__title__)

    logger.debug("Forwarded arguments: %s", forwarded)
    logger.debug("Arguments forwarded to 'pip list --outdated': %s", list_args)
    logger.debug("Arguments forwarded to 'pip install': %s", install_args)

    if unrecognized_args := set(forwarded).difference(list_args, install_args):
        formatted_unrecognized_arg: list[str] = [
            f"'{unrecognized_arg}'" for unrecognized_arg in sorted(unrecognized_args)
        ]
        logger.warning(
            "Unrecognized arguments: %s",
            ", ".join(formatted_unrecognized_arg),
        )

    if args.raw and args.auto:
        logger.error("'--raw' and '--auto' cannot be used together")
        return 1

    if args.raw and args.interactive:
        logger.error("'--raw' and '--interactive' cannot be used together")
        return 1

    if args.auto and args.interactive:
        logger.error("'--auto' and '--interactive' cannot be used together")
        return 1

    outdated: list[_OutdatedPackage] = get_outdated_packages(list_args)
    logger.debug("Outdated packages: %s", outdated)

    if not outdated and not args.raw:
        logger.info("Everything up-to-date")
        return 0

    if args.freeze_outdated_packages:
        try:
            _freeze_outdated_packages(args.freeze_file, outdated)
        except OSError as err:
            logger.error("Could not open requirements file: %s", err)
            return 1
        logger.debug("Wrote outdated packages to %s", args.freeze_file)

    if args.raw:
        for pkg in outdated:
            logger.info("%s==%s", pkg.name, pkg.latest_version)
        return 0

    constraints_files: list[Path] = _get_constraints_files(install_args)
    logger.debug("Constraints files: %s", constraints_files)
    try:
        _set_constraints_of_outdated_pkgs(constraints_files, outdated)
    except OSError as err:
        logger.error("Could not open requirements file: %s", err)
        return 1
    logger.debug(
        "Outdated packages with new set constraints: %s",
        outdated,
    )

    if args.preview and (args.auto or args.interactive):
        logger.info(_format_table(_extract_table(outdated)))

    if args.auto:
        update_packages(
            outdated,
            install_args,
            continue_on_fail=args.continue_on_fail,
        )
        return 0

    selected: list[_OutdatedPackage] = []
    for pkg in outdated:
        if pkg.constraints:
            logger.info(
                "%s==%s is available (you have %s) [Constraint to %s]",
                pkg.name,
                pkg.latest_version,
                pkg.version,
                pkg.constraints_display,
            )
        else:
            logger.info(
                "%s==%s is available (you have %s)",
                pkg.name,
                pkg.latest_version,
                pkg.version,
            )

        if args.interactive:
            answer: str = _upgrade_prompter.ask()
            if answer in {"y", "a"}:
                selected.append(pkg)

    logger.debug("Selected packages: %s", selected)
    if selected:
        update_packages(
            selected,
            install_args,
            continue_on_fail=args.continue_on_fail,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
