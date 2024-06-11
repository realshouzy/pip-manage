from __future__ import annotations

__all__: list[str] = [
    "update_packages",
    "get_outdated_packages",
    "uninstall_packages",
    "PIP_CMD",
    "LIST_ONLY",
    "INSTALL_ONLY",
    "UNINSTALL_ONLY",
    "COMMON_PARAMETERS",
]

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
PIP_CMD: Final[tuple[str, str, str]] = (sys.executable, "-m", "pip")

# parameters that only pip list supports
LIST_ONLY: Final[frozenset[str]] = frozenset(
    (
        "l",
        "local",
        "path",
        "pre",
        "not-required",
        "exclude-editable",
        "include-editable",
        "exclude",
    ),
)

# parameters that only pip install supports
INSTALL_ONLY: Final[frozenset[str]] = frozenset(
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

# parameters that only pip uninstall supports
UNINSTALL_ONLY: Final[frozenset[str]] = frozenset(
    (
        "y",
        "yes",
        "root-user-action",
        "break-system-packages",
    ),
)

COMMON_PARAMETERS: Final[frozenset[str]] = frozenset(
    (
        "isolated",
        "require-virtualenv",
        "python",
        "v",
        "verbose",
        "q",
        "quiet",
        "log",
        "no-input",
        "keyring-provider",
        "proxy",
        "retries",
        "timeout",
        "exists-action",
        "trusted-host",
        "cert",
        "client-cert",
        "cache-dir",
        "no-cache-dir",
        "disable-pip-version-check",
        "no-color",
        "no-python-version-warning",
        "use-feature",
        "use-deprecated",
    ),
)


def filter_forwards_exclude(args: list[str], exclude: AbstractSet[str]) -> list[str]:
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


def filter_forwards_include(args: list[str], include: AbstractSet[str]) -> list[str]:
    """Return only the parts of `args` that do appear in `include`."""
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
        elif arg_name in include:
            result.append(arg)
            admitted = True
        else:
            admitted = False
    return result


def filter_forwards(
    args: list[str],
    *,
    include: AbstractSet[str],
    exclude: AbstractSet[str],
) -> list[str]:
    return filter_forwards_exclude(filter_forwards_include(args, include), exclude)


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
    command: list[str] = [*PIP_CMD, "install", "-U", *forwarded]

    if not continue_on_fail:
        command.extend(package.name for package in packages)
        subprocess.call(command, stdout=sys.stdout, stderr=sys.stderr)  # nosec
    else:
        for package in packages:
            subprocess.call(
                [*command, package.name],
                stdout=sys.stdout,
                stderr=sys.stderr,
            )  # nosec


def get_outdated_packages(forwarded: list[str]) -> list[_OutdatedPackage]:
    command: list[str] = [
        *PIP_CMD,
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


def uninstall_packages(
    packages: list[str],
    forwarded: list[str],
    *,
    continue_on_fail: bool,
) -> None:
    command: list[str] = [
        *PIP_CMD,
        "uninstall",
        *forwarded,
    ]
    if not continue_on_fail:
        command.extend(packages)
        subprocess.call(command, stdout=sys.stdout, stderr=sys.stderr)  # nosec
    else:
        for package in packages:
            subprocess.call(
                [*command, package],
                stdout=sys.stdout,
                stderr=sys.stderr,
            )  # nosec
