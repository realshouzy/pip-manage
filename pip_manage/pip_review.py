#!/usr/bin/env python3
"""pip-review lets you smoothly manage all available PyPI updates."""
from __future__ import annotations

__title__: Final[str] = "pip-review"

import argparse
import dataclasses
import json
import os
import subprocess  # nosec
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Final, NamedTuple

from pip_manage._logging import setup_logging
from pip_manage._prompting import InteractiveAsker

if sys.version_info >= (3, 11):  # pragma: >=3.11 cover
    from typing import Self
else:  # pragma: <3.11 cover
    from typing_extensions import Self

if TYPE_CHECKING:
    import logging
    from collections.abc import Callable, Sequence
    from collections.abc import Set as AbstractSet

_EPILOG: Final[
    str
] = """
Unrecognised arguments will be forwarded to 'pip list --outdated' and
pip install, so you can pass things such as '--user', '--pre' and '--timeout'
and they will do what you expect. See 'pip list -h' and 'pip install -h'
for a full overview of the options.
"""

# parameters that pip list supports but not pip install
_LIST_ONLY: Final[frozenset[str]] = frozenset(
    (
        "l",
        "local",
        "path",
        "pre",
        "format",
        "not-required",
        "exclude-editable",
        "include-editable",
        "exclude",
    ),
)

# parameters that pip install supports but not pip list
_INSTALL_ONLY: Final[frozenset[str]] = frozenset(
    (
        "c",
        "constraint",
        "no-deps",
        "dry-run",
        "t",
        "target",
        "platform",
        "python-version",
        "implementation",
        "abi",
        "root",
        "prefix",
        "b",
        "build",
        "src",
        "U",
        "upgrade",
        "upgrade-strategy",
        "force-reinstall",
        "I",
        "ignore-installed",
        "ignore-requires-python",
        "no-build-isolation",
        "use-pep517",
        "check-build-dependencies",
        "break-system-packages",
        "C",
        "config-settings",
        "global-option",
        "compile",
        "no-compile",
        "no-warn-script-location",
        "no-warn-conflicts",
        "no-binary",
        "only-binary",
        "prefer-binary",
        "require-hashes",
        "progress-bar",
        "root-user-action",
        "report",
        "no-clean",
    ),
)

# command that sets up the pip module of the current Python interpreter
_PIP_CMD: Final[tuple[str, ...]] = (sys.executable, "-m", "pip")


def _parse_args(
    args: Sequence[str] | None = None,
) -> tuple[argparse.Namespace, list[str]]:
    parser: argparse.ArgumentParser = argparse.ArgumentParser(
        description=__doc__,
        epilog=_EPILOG,
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        default=False,
        help="Show more output",
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
        default=Path("outdated.txt").resolve(),
        help="Specify the file path to store the frozen packages",
    )
    parser.add_argument(
        "--preview",
        "-p",
        action="store_true",
        default=False,
        help="Preview update target list before upgrading packages",
    )
    return parser.parse_known_args(args)


def _filter_forwards(args: list[str], exclude: AbstractSet[str]) -> list[str]:
    """Return only the parts of `args` that do not appear in `exclude`."""
    result: list[str] = []
    # Start with false, because an unknown argument not starting with a dash
    # probably would just trip pip.
    admitted: bool = False
    for arg in args:
        arg_name: str = arg.partition("=")[0].lstrip("-")

        if not arg.startswith("-") and admitted:
            # assume this belongs with the previous argument.
            result.append(arg)
        elif not arg.startswith("-") and not admitted:
            continue
        elif arg_name in exclude:
            admitted = False
        else:
            result.append(arg)
            admitted = True
    return result


@dataclasses.dataclass
class _OutdatedPackage:
    name: str
    version: str
    latest_version: str
    latest_filetype: str
    constraints: set[str] = dataclasses.field(default_factory=set)

    @property
    def constraints_display(self) -> str:
        return ", ".join(sorted(self.constraints)) if self.constraints else str(None)

    @classmethod
    def from_json(cls, json_obj: dict[str, str]) -> Self:
        return cls(
            json_obj.get("name", "Unknown"),
            json_obj.get("version", "Unknown"),
            json_obj.get("latest_version", "Unknown"),
            json_obj.get("latest_filetype", "Unknown"),
        )


def freeze_outdated_packages(file: Path, packages: list[_OutdatedPackage]) -> None:
    outdated_packages: str = "\n".join(f"{pkg.name}=={pkg.version}" for pkg in packages)
    file.write_text(f"{outdated_packages}\n", encoding="utf-8")


def update_packages(
    packages: list[_OutdatedPackage],
    forwarded: list[str],
    *,
    continue_on_fail: bool,
) -> None:
    upgrade_cmd: list[str] = [*_PIP_CMD, "install", "-U", *forwarded]

    if not continue_on_fail:
        upgrade_cmd.extend(pkg.name for pkg in packages)
        subprocess.call(upgrade_cmd, stdout=sys.stdout, stderr=sys.stderr)  # nosec
    else:
        for pkg in packages:
            subprocess.call(
                [*upgrade_cmd, pkg.name],
                stdout=sys.stdout,
                stderr=sys.stderr,
            )  # nosec


def _get_outdated_packages(
    forwarded: list[str],
) -> list[_OutdatedPackage]:
    command: list[str] = [
        *_PIP_CMD,
        "list",
        "--outdated",
        "--disable-pip-version-check",
        "--format=json",
        *forwarded,
    ]
    output: str = subprocess.check_output(command).decode("utf-8")  # nosec
    packages: list[_OutdatedPackage] = [
        _OutdatedPackage.from_json(json_obj) for json_obj in json.loads(output)
    ]
    return packages


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
            pkg_name, _, constraint_version = line.partition("==")
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


def format_table(columns: list[list[str]]) -> str:
    if any(len(columns[0]) != len(column) for column in columns[1:]):
        raise ValueError("Not all columns are the same length")

    widths: list[int] = [_column_width(column) for column in columns]
    row_fmt: Callable[..., str] = " ".join(f"{{:<{width}}}" for width in widths).format
    ruler: str = "-" * (sum(widths) + len(widths) - 1)
    rows: list[str] = [row_fmt(*row) for row in zip(*columns)]
    head: str = rows[0]
    body: list[str] = rows[1:]
    return "\n".join([head, ruler, *body, ruler])


def main(argv: Sequence[str] | None = None) -> int:
    args, forwarded = _parse_args(argv)
    list_args: list[str] = _filter_forwards(forwarded, _INSTALL_ONLY)
    install_args: list[str] = _filter_forwards(forwarded, _LIST_ONLY)
    logger: logging.Logger = setup_logging(__title__, verbose=args.verbose)

    logger.debug("Forwarded arguments: %s", forwarded)
    logger.debug("Arguments forwarded to 'pip list --outdated': %s", list_args)
    logger.debug("Arguments forwarded to 'pip install': %s", install_args)

    if args.raw and args.auto:
        logger.error("'--raw' and '--auto' cannot be used together")
        return 1

    if args.raw and args.interactive:
        logger.error("'--raw' and '--interactive' cannot be used together")
        return 1

    if args.auto and args.interactive:
        logger.error("'--auto' and '--interactive' cannot be used together")
        return 1

    outdated: list[_OutdatedPackage] = _get_outdated_packages(list_args)
    logger.debug("Outdated packages: %s", outdated)

    if not outdated and not args.raw:
        logger.info("Everything up-to-date")
        return 0

    if args.freeze_outdated_packages:
        freeze_outdated_packages(args.freeze_file, outdated)
        logger.debug("Wrote outdated packages to %s", args.freeze_file)

    if args.raw:
        for pkg in outdated:
            logger.info("%s==%s", pkg.name, pkg.latest_version)
        return 0

    constraints_files: list[Path] = _get_constraints_files(install_args)

    _set_constraints_of_outdated_pkgs(constraints_files, outdated)

    logger.debug("Constraints files: %s", constraints_files)
    logger.debug(
        "Outdated packages with new set constraints: %s",
        outdated,
    )

    if args.preview and (args.auto or args.interactive):
        logger.info(format_table(_extract_table(outdated)))

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

        upgrade_prompt: InteractiveAsker = InteractiveAsker("Upgrade now?")
        if args.interactive:
            answer: str = upgrade_prompt.ask()
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
