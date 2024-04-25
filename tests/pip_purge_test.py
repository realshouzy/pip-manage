#!/usr/bin/env python3
from __future__ import annotations

import pytest

from pip_manage import pip_purge


@pytest.mark.parametrize(
    ("constant", "expected"),
    [
        pytest.param(
            pip_purge._EPILOG,
            """
Unrecognised arguments will be forwarded to 'pip uninstall ' (if supported),
so you can pass things such as '--yes' and '--break-system-packages' and
they will do what you expect. See 'pip uninstall -h' for a full overview of the options.
""",
            id="_EPILOG",
        ),
    ],
)
def test_constants(
    constant: str | frozenset[str] | tuple[str, ...],
    expected: str | frozenset[str] | tuple[str, ...],
) -> None:
    assert constant == expected


if __name__ == "__main__":
    raise SystemExit(pytest.main())
