from __future__ import annotations

import logging
import logging.config
from functools import wraps
from types import SimpleNamespace
from typing import Callable, ParamSpec, TypeVar

import pytest

from pip_manage._pip_interface import _OutdatedPackage

_P = ParamSpec("_P")
_R = TypeVar("_R")


# https://github.com/pytest-dev/pytest/discussions/11618
def retain_pytest_handlers(f: Callable[_P, _R]) -> Callable[_P, _R]:
    @wraps(f)
    def wrapper(*args: _P.args, **kwargs: _P.kwargs) -> _R:
        pytest_handlers: list[logging.Handler] = [
            handler
            for handler in logging.root.handlers
            if handler.__module__ == "_pytest.logging"
        ]
        ret: _R = f(*args, **kwargs)
        for handler in pytest_handlers:
            if handler not in logging.root.handlers:
                logging.root.addHandler(handler)
        return ret

    return wrapper


@pytest.fixture(autouse=True)
def _keep_pytest_handlers_during_dict_config(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        logging.config,
        "dictConfig",
        retain_pytest_handlers(logging.config.dictConfig),
    )


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
