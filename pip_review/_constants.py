"""Module defining and containing global constants."""
from __future__ import annotations

__all__: tuple[str, ...] = (
    "VERSION_PATTERN",
    "NAME_PATTERN",
    "EPILOG",
    "LIST_ONLY",
    "INSTALL_ONLY",
    "PIP_CMD",
    "COLUMNS",
)

import re
import sys
from typing import Final

from packaging import version

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
    "install-option",
    "global-option",
    "compile",
    "no-compile",
    "no-warn-script-location",
    "no-warn-conflicts",
    "no-binary",
    "only-binary",
    "prefer-binary",
    "no-clean",
    "require-hashes",
    "progress-bar",
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
