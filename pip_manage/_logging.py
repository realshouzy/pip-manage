from __future__ import annotations

__all__: Final[tuple[str, ...]] = ("setup_logging",)

import logging
import sys
from typing import Final, TextIO

if sys.version_info >= (3, 12):  # pragma: >=3.12 cover
    from typing import override
else:  # pragma: <3.12 cover
    from typing_extensions import override


class _StdOutFilter(logging.Filter):
    @override
    def filter(self, record: logging.LogRecord) -> bool:
        return record.levelno in {logging.DEBUG, logging.INFO}


def setup_logging(name: str, *, verbose: bool) -> logging.Logger:
    level: int = logging.DEBUG if verbose else logging.INFO

    format_: str = "%(message)s"

    logger: logging.Logger = logging.getLogger(name)

    formatter: logging.Formatter = logging.Formatter(format_)

    stdout_handler: logging.StreamHandler[TextIO] = logging.StreamHandler(sys.stdout)
    stdout_handler.set_name("stdout")
    stdout_handler.addFilter(_StdOutFilter())
    stdout_handler.setFormatter(formatter)
    stdout_handler.setLevel(logging.DEBUG)

    stderr_handler: logging.StreamHandler[TextIO] = logging.StreamHandler(sys.stderr)
    stderr_handler.set_name("stderr")
    stderr_handler.setFormatter(formatter)
    stderr_handler.setLevel(logging.WARNING)

    logger.setLevel(level)
    logger.addHandler(stderr_handler)
    logger.addHandler(stdout_handler)
    return logger
