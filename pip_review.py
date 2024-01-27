from __future__ import annotations

__version__: Final[str] = "1.4.0"
__title__: Final[str] = "pip-review"


import argparse
import json
import logging
import re
import subprocess  # nosec
import sys
from functools import partial
from typing import TYPE_CHECKING, Final, TextIO

import pip
from packaging import version

if sys.version_info >= (3, 12):  # pragma: >=3.12 cover
    from typing import override
else:  # pragma: <3.12 cover
    from typing_extensions import override

if TYPE_CHECKING:
    from collections.abc import Callable

VERSION_PATTERN: Final[re.Pattern[str]] = re.compile(
    version.VERSION_PATTERN,
    re.VERBOSE | re.IGNORECASE,  # necessary according to the `packaging` docs
)

NAME_PATTERN: Final[re.Pattern[str]] = re.compile(r"[a-z0-9_-]+", re.IGNORECASE)

EPILOG: Final[
    str
] = """
Unrecognised arguments will be forwarded to pip list --outdated and
pip install, so you can pass things such as --user, --pre and --timeout
and they will do what you expect. See pip list -h and pip install -h
for a full overview of the options.
"""

# parameters that pip list supports but not pip install
LIST_ONLY: Final[set[str]] = {
    "l",
    "local",
    "path",
    "pre",
    "format",
    "not-required",
    "exclude-editable",
    "include-editable",
}

# parameters that pip install supports but not pip list
INSTALL_ONLY: Final[set[str]] = {
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
}

# command that sets up the pip module of the current Python interpreter
PIP_CMD: Final[list[str]] = [sys.executable, "-m", "pip"]

# nicer headings for the columns in the oudated package table
COLUMNS: Final[dict[str, str]] = {
    "Package": "name",
    "Version": "version",
    "Latest": "latest_version",
    "Type": "latest_filetype",
}

DESCRIPTION: Final[str] = "Keeps your Python packages fresh."


def _parse_args() -> tuple[argparse.Namespace, list[str]]:
    parser: argparse.ArgumentParser = argparse.ArgumentParser(
        description=DESCRIPTION,
        epilog=EPILOG,
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
        help='Freeze all outdated packages to "requirements.txt" before upgrading them',
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
    return parser.parse_known_args()


def _filter_forwards(args: list[str], exclude: set[str]) -> list[str]:
    """Return only the parts of `args` that do not appear in `exclude`."""
    result: list[str] = []
    # Start with false, because an unknown argument not starting with a dash
    # probably would just trip pip.
    admitted: bool = False
    for arg in args:
        if not arg.startswith("-") and admitted:
            # assume this belongs with the previous argument.
            result.append(arg)
        elif arg.lstrip("-") in exclude:
            admitted = False
        else:
            result.append(arg)
            admitted = True
    return result


class StdOutFilter(logging.Filter):
    @override
    def filter(self, record: logging.LogRecord) -> bool:
        return record.levelno in {logging.DEBUG, logging.INFO}


def _setup_logging(*, verbose: bool) -> logging.Logger:
    level: int = logging.DEBUG if verbose else logging.INFO

    format_: str = "%(message)s"

    logger: logging.Logger = logging.getLogger("pip-review")

    stdout_handler: logging.StreamHandler[TextIO] = logging.StreamHandler(sys.stdout)
    stdout_handler.addFilter(StdOutFilter())
    stdout_handler.setFormatter(logging.Formatter(format_))
    stdout_handler.setLevel(logging.DEBUG)

    stderr_handler: logging.StreamHandler[TextIO] = logging.StreamHandler(sys.stderr)
    stderr_handler.setFormatter(logging.Formatter(format_))
    stderr_handler.setLevel(logging.WARNING)

    logger.setLevel(level)
    logger.addHandler(stderr_handler)
    logger.addHandler(stdout_handler)
    return logger


class InteractiveAsker:
    def __init__(self) -> None:
        self.cached_answer: str | None = None
        self.last_answer: str | None = None

    def ask(self, prompt: str) -> str:
        if self.cached_answer is not None:
            return self.cached_answer

        answer: str | None = ""
        while answer not in {"y", "n", "a", "q"}:
            question_last: str = (
                f"{prompt} [Y]es, [N]o, [A]ll, [Q]uit ({self.last_answer}) "
            )
            question_default: str = f"{prompt} [Y]es, [N]o, [A]ll, [Q]uit "
            answer = input(question_last if self.last_answer else question_default)
            answer = answer.strip().casefold()
            answer = self.last_answer if answer == "" else answer

        if answer in {"q", "a"}:
            self.cached_answer = answer
        self.last_answer = answer

        return answer


_ask_to_install: partial[str] = partial(InteractiveAsker().ask, prompt="Upgrade now?")


def update_packages(
    packages: list[dict[str, str]],
    forwarded: list[str],
    *,
    continue_on_fail: bool,
    freeze_outdated_packages: bool,
) -> None:
    upgrade_cmd: list[str] = [*PIP_CMD, "install", "-U", *forwarded]

    if freeze_outdated_packages:
        with open("requirements.txt", "w", encoding="utf-8") as f:
            for pkg in packages:
                f.write(f"{pkg['name']}=={pkg['version']}\n")

    if not continue_on_fail:
        upgrade_cmd.extend(pkg["name"] for pkg in packages)
        subprocess.call(upgrade_cmd, stdout=sys.stdout, stderr=sys.stderr)  # nosec
        return

    for pkg in packages:
        subprocess.call(
            [*upgrade_cmd, pkg["name"]],
            stdout=sys.stdout,
            stderr=sys.stderr,
        )  # nosec


def _parse_legacy(pip_output: str) -> list[dict[str, str]]:
    packages: list[dict[str, str]] = []
    for line in pip_output.splitlines():
        name_match: re.Match[str] | None = NAME_PATTERN.match(line)
        version_matches: list[str] = [
            match.group() for match in VERSION_PATTERN.finditer(line)
        ]
        if name_match and len(version_matches) == 2:
            packages.append(
                {
                    "name": name_match.group(),
                    "version": version_matches[0],
                    "latest_version": version_matches[1],
                },
            )
    return packages


def _get_outdated_packages(forwarded: list[str]) -> list[dict[str, str]]:
    command: list[str] = [*PIP_CMD, "list", "--outdated", *forwarded]
    pip_version: version.Version = version.parse(pip.__version__)
    if pip_version >= version.parse("6.0"):
        command.append("--disable-pip-version-check")
    if pip_version > version.parse("9.0"):
        command.append("--format=json")
        output: str = subprocess.check_output(command).decode("utf-8")  # nosec
        packages: list[dict[str, str]] = json.loads(output)
        return packages
    output = subprocess.check_output(command).decode("utf-8").strip()  # nosec
    return _parse_legacy(output)


# Next two functions describe how to collect data for the table.
# Note how they are not concerned with columns widths.


def _extract_column(data: list[dict[str, str]], field: str, title: str) -> list[str]:
    return [title, *[item[field] for item in data]]


def _extract_table(outdated: list[dict[str, str]]) -> list[list[str]]:
    return [_extract_column(outdated, field, title) for title, field in COLUMNS.items()]


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


def main() -> int:  # noqa: C901
    args, forwarded = _parse_args()
    list_args: list[str] = _filter_forwards(forwarded, INSTALL_ONLY)
    install_args: list[str] = _filter_forwards(forwarded, LIST_ONLY)
    logger: logging.Logger = _setup_logging(verbose=args.verbose)

    if args.raw and args.interactive:
        logger.error("--raw and --interactive cannot be used together")
        return 1

    outdated: list[dict[str, str]] = _get_outdated_packages(list_args)
    if not outdated and not args.raw:
        logger.info("Everything up-to-date")
        return 0
    if args.preview or args.preview_only:
        logger.info(format_table(_extract_table(outdated)))
        if args.preview_only:
            return 0
    if args.auto:
        update_packages(
            outdated,
            install_args,
            continue_on_fail=args.continue_on_fail,
            freeze_outdated_packages=args.freeze_outdated_packages,
        )
        return 0
    if args.raw:
        for pkg in outdated:
            logger.info("%s==%s", pkg["name"], pkg["latest_version"])
        return 0

    selected: list[dict[str, str]] = []
    for pkg in outdated:
        logger.info(
            "%s==%s is available (you have %s)",
            pkg["name"],
            pkg["latest_version"],
            pkg["version"],
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
            freeze_outdated_packages=args.freeze_outdated_packages,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
