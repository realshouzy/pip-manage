from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from pip_manage._logging import setup_logging
from pip_manage._pip_interface import _OutdatedPackage

if TYPE_CHECKING:
    import logging


@pytest.fixture()
def sample_packages() -> list[_OutdatedPackage]:
    return [
        _OutdatedPackage("test1", "1.0.0", "1.1.0", "wheel"),
        _OutdatedPackage("test2", "1.9.9", "2.0.0", "wheel"),
    ]


@pytest.fixture()
def sample_subprocess_output() -> bytes:
    # pylint: disable=C0301
    return (
        b'[{"name": "test1", "version": "1.0.0", "latest_version": "1.1.0", "latest_filetype": "wheel"}, '  # noqa: E501
        b'{"name": "test2", "version": "1.9.9", "latest_version": "2.0.0", "latest_filetype": "wheel"}]\r\n'  # noqa: E501
    )


@pytest.fixture(scope="session")
def logger() -> logging.Logger:
    return setup_logging("test")
