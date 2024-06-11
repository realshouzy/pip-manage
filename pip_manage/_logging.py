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


class _NonErrorFilter(logging.Filter):
    @override
    def filter(self, record: logging.LogRecord) -> bool:
        return record.levelno <= logging.INFO


class _ColoredFormatter(logging.Formatter):
    COLORS: ClassVar[dict[str, str]] = {
        "DEBUG": "\x1b[0;37m",
        "INFO": "\x1b[0;32m",
        "WARNING": "\x1b[0;33m",
        "ERROR": "\x1b[0;31m",
        "CRITICAL": "\x1b[1;31m",
    }
    RESET: ClassVar[Literal["\x1b[0m"]] = "\x1b[0m"

    @override
    def format(self, record: logging.LogRecord) -> str:
        log_color: str = self.COLORS.get(record.levelname, self.RESET)
        record.msg = f"{log_color}{record.levelname}: {record.msg}{self.RESET}"
        return super().format(record)


def setup_logging(
    logger_name: Literal["pip-review", "pip-purge"],
    *,
    debugging: bool,
) -> None:
    level: Literal["DEBUG", "INFO"] = "DEBUG" if debugging else "INFO"
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
                "no_errors": {
                    "()": _NonErrorFilter,
                },
            },
            "handlers": {
                "stdout": {
                    "class": "logging.StreamHandler",
                    "stream": "ext://sys.stdout",
                    "formatter": "simple",
                    "filters": ["no_errors"],
                    "level": "DEBUG",
                },
                "stderr": {
                    "class": "logging.StreamHandler",
                    "stream": "ext://sys.stderr",
                    "formatter": "colored",
                    "level": "WARNING",
                },
            },
            "root": {
                "level": "DEBUG",
                "handlers": ["stdout", "stderr"],
            },
            "loggers": {
                logger_name: {"level": level, "propagate": True},
            },
        },
    )
