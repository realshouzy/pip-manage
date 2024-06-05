from __future__ import annotations

from types import SimpleNamespace
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


@pytest.fixture()
def dummy_dependencies() -> list[SimpleNamespace]:
    package_a: SimpleNamespace = SimpleNamespace(
        name="package_a",
        version="1.0.0",
        requires=["package_b <2.0,>=1.4", "package_e ; extra == 'testing'"],
    )
    package_b: SimpleNamespace = SimpleNamespace(
        name="package_b",
        version="1.5.0",
        requires=["package_e ; extra == 'testing'"],
    )
    package_c: SimpleNamespace = SimpleNamespace(
        name="package_c",
        version="1.3.0",
        requires=["package_y"],
    )
    package_d: SimpleNamespace = SimpleNamespace(
        name="package_d",
        version="1.3.0",
        requires=[],
    )
    package_e: SimpleNamespace = SimpleNamespace(
        name="package_e",
        version="1.3.0",
        requires=['package_a ; python_version < "3.11"'],
    )
    package_f: SimpleNamespace = SimpleNamespace(
        name="package_f",
        version="1.2.0",
        requires=["package_g"],
    )
    package_g: SimpleNamespace = SimpleNamespace(
        name="package_g",
        version="1.2.5",
        requires=["package_f"],
    )
    package_h: SimpleNamespace = SimpleNamespace(
        name="package_h",
        version="1.2.5",
        requires=["package_g"],
    )
    return [
        package_a,
        package_b,
        package_c,
        package_d,
        package_e,
        package_f,
        package_g,
        package_h,
    ]
