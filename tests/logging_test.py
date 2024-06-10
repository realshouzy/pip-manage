#!/usr/bin/env python3
from __future__ import annotations

import logging

import pytest

from pip_manage._logging import _ColoredFormatter, _NonErrorFilter, setup_logging


def test_stdout_filter_is_subclass_of_logging_filter() -> None:
    assert issubclass(_NonErrorFilter, logging.Filter)


def test_stdout_filter_override() -> None:
    assert getattr(_NonErrorFilter().filter, "__override__", False)


@pytest.mark.parametrize(
    "record",
    [
        pytest.param(
            logging.LogRecord(
                "test",
                logging.DEBUG,
                "test",
                0,
                "test",
                None,
                None,
            ),
            id="DEBUG",
        ),
        pytest.param(
            logging.LogRecord(
                "test",
                logging.INFO,
                "test",
                0,
                "test",
                None,
                None,
            ),
            id="INFO",
        ),
    ],
)
def test_stdout_filter_passes(record: logging.LogRecord) -> None:
    assert _NonErrorFilter().filter(record)


@pytest.mark.parametrize(
    "record",
    [
        pytest.param(
            logging.LogRecord(
                "test",
                logging.WARNING,
                "test",
                0,
                "test",
                None,
                None,
            ),
            id="WARNING",
        ),
        pytest.param(
            logging.LogRecord(
                "test",
                logging.ERROR,
                "test",
                0,
                "test",
                None,
                None,
            ),
            id="ERROR",
        ),
        pytest.param(
            logging.LogRecord(
                "test",
                logging.CRITICAL,
                "test",
                0,
                "test",
                None,
                None,
            ),
            id="CRITICAL",
        ),
    ],
)
def test_stdout_filter_no_passes(record: logging.LogRecord) -> None:
    assert not _NonErrorFilter().filter(record)


def test_colored_formatter_is_subclass_of_logging_formatter() -> None:
    assert issubclass(_ColoredFormatter, logging.Formatter)


def test_colored_formatter_override() -> None:
    assert getattr(_ColoredFormatter().format, "__override__", False)


def test_colored_formatter_class_vars() -> None:
    assert {
        "DEBUG": "\x1b[0;37m",
        "INFO": "\x1b[0;32m",
        "WARNING": "\x1b[0;33m",
        "ERROR": "\x1b[0;31m",
        "CRITICAL": "\x1b[1;31m",
    } == _ColoredFormatter.COLORS
    assert _ColoredFormatter.RESET == "\x1b[0m"


@pytest.mark.parametrize(
    ("level", "prefix"),
    [
        (logging.DEBUG, "\x1b[0;37mDEBUG"),
        (logging.INFO, "\x1b[0;32mINFO"),
        (logging.WARNING, "\x1b[0;33mWARNING"),
        (logging.ERROR, "\x1b[0;31mERROR"),
        (logging.CRITICAL, "\x1b[1;31mCRITICAL"),
    ],
)
def test_colored_formatter_format(level: int, prefix: str) -> None:
    test_record: logging.LogRecord = logging.LogRecord(
        "test",
        level,
        "test",
        0,
        "test",
        None,
        None,
    )
    assert _ColoredFormatter().format(test_record) == f"{prefix}: test\x1b[0m"


@pytest.mark.parametrize(
    ("verbose", "level"),
    [
        pytest.param(True, logging.DEBUG, id="verbose"),
        pytest.param(False, logging.INFO, id="non_verbose"),
    ],
)
def test_setup_logging(verbose: bool, level: int) -> None:  # noqa: FBT001
    setup_logging("test", verbose=verbose)
    root_logger: logging.Logger = logging.getLogger()
    assert root_logger.level == logging.DEBUG
    assert len(root_logger.handlers) == 2

    stdout_handler: logging.Handler = root_logger.handlers[0]
    assert stdout_handler.name == "stdout"
    assert stdout_handler.level == logging.DEBUG
    assert isinstance(stdout_handler.formatter, logging.Formatter)
    assert stdout_handler.formatter._fmt == "%(message)s"
    assert len(stdout_handler.filters) == 1
    assert isinstance(stdout_handler.filters[0], _NonErrorFilter)

    stderr_handler: logging.Handler = root_logger.handlers[1]
    assert stderr_handler.name == "stderr"
    assert stderr_handler.level == logging.WARNING
    assert isinstance(stderr_handler.formatter, _ColoredFormatter)
    assert stderr_handler.formatter._fmt == "%(message)s"
    assert not stderr_handler.filters

    test_logger: logging.Logger = logging.getLogger("test")
    assert test_logger.level == level
    assert test_logger.propagate
    assert not test_logger.handlers
    assert not test_logger.filters


if __name__ == "__main__":
    raise SystemExit(pytest.main())
