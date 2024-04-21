from __future__ import annotations

__all__: Final[tuple[str, ...]] = (
    "update_packages",
    "get_outdated_packages",
    "get_dependencies_of_package",
    "purge_packages",
    "filter_forwards",
)

import dataclasses
import json
import subprocess  # nosec
import sys
from typing import TYPE_CHECKING, Final

if sys.version_info >= (3, 11):  # pragma: >=3.11 cover
    from typing import Self
else:  # pragma: <3.11 cover
    from typing_extensions import Self

if TYPE_CHECKING:
    from collections.abc import Set as AbstractSet

# command that sets up the pip module of the current Python interpreter
_PIP_CMD: Final[tuple[str, str, str]] = (sys.executable, "-m", "pip")


def filter_forwards(args: list[str], exclude: AbstractSet[str]) -> list[str]:
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


def update_packages(
    packages: list[_OutdatedPackage],
    forwarded: list[str],
    *,
    continue_on_fail: bool,
) -> None:
    command: list[str] = [*_PIP_CMD, "install", "-U", *forwarded]

    if not continue_on_fail:
        command.extend(pkg.name for pkg in packages)
        subprocess.call(command, stdout=sys.stdout, stderr=sys.stderr)  # nosec
    else:
        for pkg in packages:
            subprocess.call(
                [*command, pkg.name],
                stdout=sys.stdout,
                stderr=sys.stderr,
            )  # nosec


def get_outdated_packages(forwarded: list[str]) -> list[_OutdatedPackage]:
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


def get_dependencies_of_package(
    pkg_name: str,
) -> tuple[frozenset[str], frozenset[str]]:
    command: list[str] = [
        *_PIP_CMD,
        "show",
        pkg_name,
    ]
    output: str = subprocess.check_output(command).decode("utf-8")  # nosec
    pkg_info: list[str] = output.split("\r\n")

    if requires_part := pkg_info[-3][10:]:
        requires: frozenset[str] = frozenset(requires_part.split(", "))
    else:
        requires = frozenset()

    if required_by_part := pkg_info[-2][13:]:
        required_by: frozenset[str] = frozenset(required_by_part.split(", "))
    else:
        required_by = frozenset()

    return requires, required_by


def purge_packages(pkgs: list[str], forwarded: list[str]) -> None:
    command: list[str] = [
        *_PIP_CMD,
        "uninstall",
        *pkgs,
        *forwarded,
    ]
    subprocess.call(command, stdout=sys.stdout, stderr=sys.stderr)  # nosec
