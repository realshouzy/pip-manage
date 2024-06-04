from __future__ import annotations

__all__: list[str] = ["setup_logging", "set_logging_level"]

import logging
import sys
from typing import TextIO

if sys.version_info >= (3, 12):  # pragma: >=3.12 cover
    from typing import override
else:  # pragma: <3.12 cover
    from typing_extensions import override


class _StdOutFilter(logging.Filter):
    @override
    def filter(self, record: logging.LogRecord) -> bool:
        return record.levelno <= logging.INFO


def setup_logging(logger_name: str) -> logging.Logger:
    logger: logging.Logger = logging.getLogger(logger_name)
    formatter: logging.Formatter = logging.Formatter("%(message)s")

    stdout_handler: logging.StreamHandler[TextIO] = logging.StreamHandler(sys.stdout)
    stdout_handler.set_name("stdout")
    stdout_handler.addFilter(_StdOutFilter())
    stdout_handler.setFormatter(formatter)
    stdout_handler.setLevel(logging.DEBUG)

    stderr_handler: logging.StreamHandler[TextIO] = logging.StreamHandler(sys.stderr)
    stderr_handler.set_name("stderr")
    stderr_handler.setFormatter(formatter)
    stderr_handler.setLevel(logging.WARNING)

    logger.addHandler(stderr_handler)
    logger.addHandler(stdout_handler)
    return logger


def set_logging_level(logger: logging.Logger, *, verbose: bool) -> None:
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
