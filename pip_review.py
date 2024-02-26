#!/usr/bin/env python3
"""pip-review lets you smoothly manage all available PyPI updates."""
from __future__ import annotations

__version__: Final[str] = "1.4.0"
__title__: Final[str] = "pip-review"

import argparse
import json
import logging
import subprocess  # nosec
import sys
from functools import partial
from pathlib import Path
from typing import TYPE_CHECKING, Final, NamedTuple, TextIO

if sys.version_info >= (3, 12):  # pragma: >=3.12 cover
    from typing import Self, override
else:  # pragma: <3.12 cover
    from typing_extensions import Self, override


if TYPE_CHECKING:
    from collections.abc import Callable, Sequence
    from collections.abc import Set as AbstractSet

_EPILOG: Final[
    str
] = """
Unrecognised arguments will be forwarded to pip list --outdated and
pip install, so you can pass things such as --user, --pre and --timeout
and they will do what you expect. See pip list -h and pip install -h
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
        "--exclude",
        "-e",
        action="append",
        default=[],
        help="Exclude package from update",
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
        default=Path("requirements.txt").resolve(),
        help="Specify the file path to store the frozen packages",
    )
    parser.add_argument(
        "--preview",
        "-p",
        action="store_true",
        default=False,
        help="Preview update target list before execution",
    )
    parser.add_argument(
        "--preview-only",
        "-P",
        action="store_true",
        default=False,
        help="Preview only",
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


class _StdOutFilter(logging.Filter):
    @override
    def filter(self, record: logging.LogRecord) -> bool:
        return record.levelno in {logging.DEBUG, logging.INFO}


def _setup_logging(*, verbose: bool) -> logging.Logger:
    level: int = logging.DEBUG if verbose else logging.INFO

    format_: str = "%(message)s"

    logger: logging.Logger = logging.getLogger(__title__)

    stdout_handler: logging.StreamHandler[TextIO] = logging.StreamHandler(sys.stdout)
    stdout_handler.set_name("stdout")
    stdout_handler.addFilter(_StdOutFilter())
    stdout_handler.setFormatter(logging.Formatter(format_))
    stdout_handler.setLevel(logging.DEBUG)

    stderr_handler: logging.StreamHandler[TextIO] = logging.StreamHandler(sys.stderr)
    stderr_handler.set_name("stderr")
    stderr_handler.setFormatter(logging.Formatter(format_))
    stderr_handler.setLevel(logging.WARNING)

    logger.setLevel(level)
    logger.addHandler(stderr_handler)
    logger.addHandler(stdout_handler)
    return logger


class _InteractiveAsker:
    def __init__(self) -> None:
        self.cached_answer: str | None = None
        self.last_answer: str | None = None

    def ask(self, prompt: str) -> str:
        if self.cached_answer is not None:
            return self.cached_answer

        question_default: str = f"{prompt} [Y]es, [N]o, [A]ll, [Q]uit "
        answer: str | None = ""
        while answer not in {"y", "n", "a", "q"}:
            question_last: str = (
                f"{prompt} [Y]es, [N]o, [A]ll, [Q]uit ({self.last_answer}) "
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


_ask_to_install: partial[str] = partial(_InteractiveAsker().ask, prompt="Upgrade now?")


class _Package(NamedTuple):
    name: str
    version: str
    latest_version: str
    latest_filetype: str

    @classmethod
    def from_dct(cls, dct: dict[str, str]) -> Self:
        return cls(
            dct.get("name", "Unknown"),
            dct.get("version", "Unknown"),
            dct.get("latest_version", "Unknown"),
            dct.get("latest_filetype", "Unknown"),
        )


def freeze_outdated_packages(file: Path, packages: list[_Package]) -> None:
    outdated_packages: str = "\n".join(f"{pkg.name}=={pkg.version}" for pkg in packages)
    file.write_text(f"{outdated_packages}\n", encoding="utf-8")


def update_packages(
    packages: list[_Package],
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
    exclude: AbstractSet[str],
) -> list[_Package]:
    command: list[str] = [
        *_PIP_CMD,
        "list",
        "--outdated",
        "--disable-pip-version-check",
        "--format=json",
        *forwarded,
    ]
    output: str = subprocess.check_output(command).decode("utf-8")  # nosec
    packages: list[_Package] = [_Package.from_dct(pkg) for pkg in json.loads(output)]
    return [pkg for pkg in packages if pkg.name not in exclude] if exclude else packages


class _Column(NamedTuple):
    title: str
    field: str


# nicer headings for the columns in the oudated package table
_DEFAULT_COLUMNS: Final[tuple[_Column, ...]] = (
    _Column("Package", "name"),
    _Column("Version", "version"),
    _Column("Latest", "latest_version"),
    _Column("Type", "latest_filetype"),
)

# Next two functions describe how to collect data for the table.
# Note how they are not concerned with columns widths.


def _extract_column(data: list[_Package], field: str, title: str) -> list[str]:
    return [title, *[getattr(item, field) for item in data]]


def _extract_table(
    outdated: list[_Package],
    columns: tuple[_Column, ...] = _DEFAULT_COLUMNS,
) -> list[list[str]]:
    return [_extract_column(outdated, field, title) for title, field in columns]


# Next two functions describe how to format any table. Note that
# they make no assumptions about where the data come from.


def _column_width(column: list[str]) -> int:
    return max(len(cell) for cell in column if cell)


def format_table(columns: list[list[str]]) -> str:
    widths: list[int] = [_column_width(column) for column in columns]
    row_fmt: Callable[..., str] = " ".join(f"{{:<{width}}}" for width in widths).format
    ruler: str = "-" * (sum(widths) + len(widths) - 1)
    rows: list[str] = [row_fmt(*row) for row in zip(*columns, strict=True)]
    head: str = rows[0]
    body: list[str] = rows[1:]
    return "\n".join([head, ruler, *body, ruler])


def main(argv: Sequence[str] | None = None) -> int:
    args, forwarded = _parse_args(argv)
    list_args: list[str] = _filter_forwards(forwarded, _INSTALL_ONLY)
    install_args: list[str] = _filter_forwards(forwarded, _LIST_ONLY)
    logger: logging.Logger = _setup_logging(verbose=args.verbose)

    if args.raw and args.interactive:
        logger.error("--raw and --interactive cannot be used together")
        return 1

    outdated: list[_Package] = _get_outdated_packages(
        list_args,
        set(args.exclude),
    )

    if not outdated and not args.raw:
        logger.info("Everything up-to-date")
        return 0

    if args.preview or args.preview_only:
        logger.info(format_table(_extract_table(outdated)))
        if args.preview_only:
            return 0

    if args.freeze_outdated_packages:
        freeze_outdated_packages(args.freeze_file, outdated)

    if args.auto:
        update_packages(
            outdated,
            install_args,
            continue_on_fail=args.continue_on_fail,
        )
        return 0

    if args.raw:
        for pkg in outdated:
            logger.info("%s==%s", pkg.name, pkg.latest_version)
        return 0

    selected: list[_Package] = []
    for pkg in outdated:
        logger.info(
            "%s==%s is available (you have %s)",
            pkg.name,
            pkg.latest_version,
            pkg.version,
        )
        if args.interactive:
            answer: str = _ask_to_install()
            if answer in {"y", "a"}:
                selected.append(pkg)

    if selected:
        update_packages(
            selected,
            install_args,
            continue_on_fail=args.continue_on_fail,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
