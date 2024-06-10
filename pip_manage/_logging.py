from __future__ import annotations

__all__: list[str] = ["setup_logging"]

import logging
import logging.config
import sys
from typing import ClassVar, Literal

if sys.version_info >= (3, 12):  # pragma: >=3.12 cover
    from typing import override
else:  # pragma: <3.12 cover
    from typing_extensions import override


class _StdOutFilter(logging.Filter):
    @override
    def filter(self, record: logging.LogRecord) -> bool:
        return record.levelno <= logging.INFO


class _ColoredFormatter(logging.Formatter):
    COLORS: ClassVar[dict[str, str]] = {
        "DEBUG": "\033[0;37m",
        "INFO": "\033[0;32m",
        "WARNING": "\033[0;33m",
        "ERROR": "\033[0;31m",
        "CRITICAL": "\033[1;31m",
    }
    RESET: ClassVar[Literal["\033[0m"]] = "\033[0m"

    @override
    def format(self, record: logging.LogRecord) -> str:
        log_color: str = self.COLORS.get(record.levelname, self.RESET)
        record.msg = f"{log_color}{record.levelname}: {record.msg}{self.RESET}"
        return super().format(record)


def setup_logging(*, verbose: bool) -> None:
    level: Literal["DEBUG", "INFO"] = "DEBUG" if verbose else "INFO"
    logging.config.dictConfig(
        {
            "version": 1,
            "disable_existing_loggers": False,
            "formatters": {
                "simple": {
                    "format": "%(message)s",
                },
                "colored": {
                    "()": _ColoredFormatter,
                },
            },
            "filters": {
                "StdOutFilter": {
                    "()": _StdOutFilter,
                },
            },
            "handlers": {
                "stdout": {
                    "class": "logging.StreamHandler",
                    "stream": "ext://sys.stdout",
                    "formatter": "simple",
                    "filters": ["StdOutFilter"],
                    "level": "DEBUG",
                },
                "stderr": {
                    "class": "logging.StreamHandler",
                    "stream": "ext://sys.stderr",
                    "formatter": "colored",
                    "level": "WARNING",
                },
            },
            "loggers": {
                "root": {
                    "level": level,
                    "handlers": ["stdout", "stderr"],
                    "propagate": True,
                },
            },
        },
    )
