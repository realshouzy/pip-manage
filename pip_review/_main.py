from __future__ import annotations

import argparse
import json
import logging
import subprocess
import sys
from functools import partial
from operator import itemgetter
from typing import TYPE_CHECKING, Any

import pip
from packaging import version

from pip_review._constants import (
    COLUMNS,
    DESCRIPTION,
    EPILOG,
    INSTALL_ONLY,
    LIST_ONLY,
    NAME_PATTERN,
    PIP_CMD,
    VERSION_EPILOG,
    VERSION_PATTERN,
)

if TYPE_CHECKING:
    import re


def check_output(*args: Any, **kwargs: Any) -> bytes:
    output: bytes
    process: subprocess.Popen[str] = subprocess.Popen(
        stdout=subprocess.PIPE, *args, **kwargs
    )
    output, _ = process.communicate()
    retcode: int | None = process.poll()
    if retcode:
        error = subprocess.CalledProcessError(retcode, args[0])
        error.output = output
        raise error
    return output


def _parse_args() -> tuple[argparse.Namespace, list[str]]:
    parser: argparse.ArgumentParser = argparse.ArgumentParser(
        description=DESCRIPTION,
        epilog=EPILOG + VERSION_EPILOG,
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true", default=False, help="Show more output"
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
        "--preview-only", "-P", action="store_true", default=False, help="Preview only"
    )
    return parser.parse_known_args()


def _filter_forwards(args: list[str], exclude: list[str]) -> list[str]:
    """Return only the parts of `args` that do not appear in `exclude`."""
    result: list[str] = []
    # Start with false, because an unknown argument not starting with a dash
    # probably would just trip pip.
    admitted: bool = False
    for arg in args:
        if not arg.startswith("-"):
            # assume this belongs with the previous argument.
            if admitted:
                result.append(arg)
        elif arg.lstrip("-") in exclude:
            admitted = False
        else:
            result.append(arg)
            admitted = True
    return result


class StdOutFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        return record.levelno in [logging.DEBUG, logging.INFO]


def _setup_logging(verbose: bool) -> logging.Logger:
    level: int
    if verbose:
        level = logging.DEBUG
    else:
        level = logging.INFO

    format_: str = "%(message)s"

    logger: logging.Logger = logging.getLogger("pip-review")

    stdout_handler = logging.StreamHandler(sys.stdout)
    stdout_handler.addFilter(StdOutFilter())
    stdout_handler.setFormatter(logging.Formatter(format_))
    stdout_handler.setLevel(logging.DEBUG)

    stderr_handler = logging.StreamHandler(sys.stderr)
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

        answer: str = ""
        while answer not in ["y", "n", "a", "q"]:
            question_last: str = (
                f"{prompt} [Y]es, [N]o, [A]ll, [Q]uit ({self.last_answer}) "
            )
            question_default: str = f"{prompt} [Y]es, [N]o, [A]ll, [Q]uit "
            answer = input(question_last if self.last_answer else question_default)
            answer = answer.strip().lower()
            answer = self.last_answer if answer == "" else answer

        if answer in {"q", "a"}:
            self.cached_answer = answer
        self.last_answer = answer

        return answer


ask_to_install = partial(InteractiveAsker().ask, prompt="Upgrade now?")


def update_packages(
    packages: list[dict[str, str]],
    forwarded: list[str],
    continue_on_fail: bool,
    freeze_outdated_packages: bool,
) -> None:
    upgrade_cmd: list[str] = PIP_CMD + ["install", "-U"] + forwarded

    if freeze_outdated_packages:
        with open("requirements.txt", "w", encoding="utf-8") as f:
            for pkg in packages:
                f.write(f"{pkg['name']}=={pkg['version']}\n")

    if not continue_on_fail:
        upgrade_cmd += [f"{pkg['name']}" for pkg in packages]
        subprocess.call(upgrade_cmd, stdout=sys.stdout, stderr=sys.stderr)
        return

    for pkg in packages:
        upgrade_cmd += [f"{pkg['name']}"]
        subprocess.call(upgrade_cmd, stdout=sys.stdout, stderr=sys.stderr)
        upgrade_cmd.pop()


# def _confirm(question: str) -> bool:
#     answer: str = ""
#     while answer not in ["y", "n"]:
#         answer = input(question)
#         answer = answer.strip().lower()
#     return answer == "y"


def parse_legacy(pip_output: str) -> list[dict[str, str]]:
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
                }
            )
    return packages


def get_outdated_packages(forwarded: list[str]) -> list[dict[str, str]]:
    command: list[str] = PIP_CMD + ["list", "--outdated"] + forwarded
    pip_version: version.Version = version.parse(pip.__version__)
    if pip_version >= version.parse("6.0"):
        command.append("--disable-pip-version-check")
    if pip_version > version.parse("9.0"):
        command.append("--format=json")
        output: str = check_output(command).decode("utf-8")
        packages: list[dict[str, str]] = json.loads(output)
        return packages
    output = check_output(command).decode("utf-8").strip()
    packages = parse_legacy(output)
    return packages


# Next two functions describe how to collect data for the
# table. Note how they are not concerned with columns widths.


def extract_column(data: list[dict[str, str]], field: str, title: str) -> list[str]:
    return [title] + list(map(itemgetter(field), data))


def extract_table(outdated: list[dict[str, str]]) -> list[list[str]]:
    return [extract_column(outdated, field, title) for title, field in COLUMNS.items()]


# Next two functions describe how to format any table. Note that
# they make no assumptions about where the data come from.


def column_width(column) -> int:
    return max(map(len, filter(None, column)))


def format_table(columns: list[list[str]]) -> str:
    widths: list[int] = list(map(column_width, columns))
    row_fmt = " ".join(map("{{:<{}}}".format, widths)).format
    ruler: str = "-" * (sum(widths) + len(widths) - 1)
    rows = list(map(row_fmt, *columns))
    head = rows[0]
    body = rows[1:]
    return "\n".join([head, ruler] + body + [ruler])


def main() -> int:
    args, forwarded = _parse_args()
    list_args: list[str] = _filter_forwards(forwarded, INSTALL_ONLY)
    install_args: list[str] = _filter_forwards(forwarded, LIST_ONLY)
    logger: logging.Logger = _setup_logging(args.verbose)

    if args.raw and args.interactive:
        # raise SystemExit("--raw and --interactive cannot be used together")
        return 0

    outdated: list[dict[str, str]] = get_outdated_packages(list_args)
    if not outdated and not args.raw:
        logger.info("Everything up-to-date")
        return 0
    if args.preview or args.preview_only:
        logger.info(format_table(extract_table(outdated)))
        if args.preview_only:
            return 0
    if args.auto:
        update_packages(
            outdated, install_args, args.continue_on_fail, args.freeze_outdated_packages
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
            answer = ask_to_install()
            if answer in ["y", "a"]:
                selected.append(pkg)
    if selected:
        update_packages(
            selected, install_args, args.continue_on_fail, args.freeze_outdated_packages
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
