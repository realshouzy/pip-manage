#!/usr/bin/env python3
from __future__ import annotations

import logging

import pytest

from pip_manage._logging import _StdOutFilter, setup_logging


def test_stdout_filter_is_subclass_of_logging_filter() -> None:
    assert issubclass(_StdOutFilter, logging.Filter)


def test_stdout_filter_override() -> None:
    assert _StdOutFilter().filter.__override__


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
                (None, None, None),
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
                (None, None, None),
            ),
            id="INFO",
        ),
    ],
)
def test_stdout_filter_passes(record: logging.LogRecord) -> None:
    assert _StdOutFilter().filter(record)


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
                (None, None, None),
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
                (None, None, None),
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
                (None, None, None),
            ),
            id="CRITICAL",
        ),
    ],
)
def test_stdout_filter_no_passes(record: logging.LogRecord) -> None:
    assert not _StdOutFilter().filter(record)


# tests for _setup_logging have to run before the tests for main,
# because the handlers need to be cleared,
# otherwise the tests for _setup_logging fail
@pytest.mark.parametrize(
    ("verbose", "logger_level"),
    [
        pytest.param(True, logging.DEBUG, id="verbose"),
        pytest.param(False, logging.INFO, id="non_verbose"),
    ],
)
def test_setup_logging(verbose: bool, logger_level: int) -> None:  # noqa: FBT001
    logger: logging.Logger = setup_logging("test", verbose=verbose)
    assert logger.name == "test"
    assert logger.level == logger_level
    assert len(logger.handlers) == 2

    stderr_handler: logging.Handler = logger.handlers[0]
    assert stderr_handler.name == "stderr"
    assert stderr_handler.level == logging.WARNING
    assert stderr_handler.formatter._fmt == "%(message)s"  # type: ignore[union-attr]

    stdout_handler: logging.Handler = logger.handlers[1]
    assert stdout_handler.name == "stdout"
    assert stdout_handler.level == logging.DEBUG
    assert stdout_handler.formatter._fmt == "%(message)s"  # type: ignore[union-attr]
    assert len(stdout_handler.filters) == 1
    assert isinstance(stdout_handler.filters[0], _StdOutFilter)

    logger.handlers.clear()


if __name__ == "__main__":
    raise SystemExit(pytest.main())
