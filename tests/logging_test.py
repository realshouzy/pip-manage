#!/usr/bin/env python3
from __future__ import annotations

import logging

import pytest

from pip_manage._logging import _StdOutFilter, set_logging_level
from tests.fixtures import logger  # pylint: disable=W0611


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


def test_setup_logging(logger: logging.Logger) -> None:
    assert logger.name == "test"
    assert logger.level == logging.NOTSET
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


@pytest.mark.parametrize(
    ("verbose", "logger_level"),
    [
        pytest.param(True, logging.DEBUG, id="verbose"),
        pytest.param(False, logging.INFO, id="non_verbose"),
    ],
)
def test_set_logging_level(
    logger: logging.Logger,
    verbose: bool,  # noqa: FBT001
    logger_level: int,
) -> None:
    set_logging_level(logger, verbose=verbose)
    assert logger.level == logger_level


if __name__ == "__main__":
    raise SystemExit(pytest.main())
