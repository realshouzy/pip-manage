#!/usr/bin/env python3
from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path
from unittest import mock

import pytest

import pip_review

# pylint: disable=W0212, E1101, W0621, C0302


@pytest.fixture()
def test_packages() -> list[pip_review._OutdatedPackageInfo]:
    return [
        pip_review._OutdatedPackageInfo("test1", "1.0.0", "1.1.0", "wheel"),
        pip_review._OutdatedPackageInfo("test2", "1.9.9", "2.0.0", "wheel"),
    ]


@pytest.fixture()
def test_subprocess_output() -> bytes:
    # pylint: disable=C0301
    return (
        b'[{"name": "test1", "version": "1.0.0", "latest_version": "1.1.0", "latest_filetype": "wheel"}, '  # noqa: E501
        b'{"name": "test2", "version": "1.9.9", "latest_version": "2.0.0", "latest_filetype": "wheel"}]\r\n'  # noqa: E501
    )


@pytest.mark.parametrize(
    ("constant", "expected"),
    [
        pytest.param(
            pip_review._EPILOG,
            """
Unrecognised arguments will be forwarded to 'pip list --outdated' and
pip install, so you can pass things such as '--user', '--pre' and '--timeout'
and they will do what you expect. See 'pip list -h' and 'pip install -h'
for a full overview of the options.
""",
            id="_EPILOG",
        ),
        pytest.param(
            pip_review._LIST_ONLY,
            frozenset(
                (
                    "l",
                    "local",
                    "path",
                    "pre",
                    "format",
                    "not-required",
                    "exclude-editable",
                    "include-editable",
                    "exclude",
                ),
            ),
            id="_LIST_ONLY",
        ),
        pytest.param(
            pip_review._INSTALL_ONLY,
            frozenset(
                (
                    "c",
                    "constraint",
                    "no-deps",
                    "dry-run",
                    "t",
                    "target",
                    "platform",
                    "python-version",
                    "implementation",
                    "abi",
                    "root",
                    "prefix",
                    "b",
                    "build",
                    "src",
                    "U",
                    "upgrade",
                    "upgrade-strategy",
                    "force-reinstall",
                    "I",
                    "ignore-installed",
                    "ignore-requires-python",
                    "no-build-isolation",
                    "use-pep517",
                    "check-build-dependencies",
                    "break-system-packages",
                    "C",
                    "config-settings",
                    "global-option",
                    "compile",
                    "no-compile",
                    "no-warn-script-location",
                    "no-warn-conflicts",
                    "no-binary",
                    "only-binary",
                    "prefer-binary",
                    "require-hashes",
                    "progress-bar",
                    "root-user-action",
                    "report",
                    "no-clean",
                ),
            ),
            id="_INSTALL_ONLY",
        ),
        pytest.param(
            pip_review._PIP_CMD,
            (sys.executable, "-m", "pip"),
            id="_PIP_CMD",
        ),
        pytest.param(
            pip_review._DEFAULT_COLUMN_SPECS,
            (
                pip_review._ColumnSpec("Package", "name"),
                pip_review._ColumnSpec("Version", "version"),
                pip_review._ColumnSpec("Latest", "latest_version"),
                pip_review._ColumnSpec("Type", "latest_filetype"),
            ),
            id="_DEFAULT_COLUMNS",
        ),
    ],
)
def test_constants(
    constant: (
        str | frozenset[str] | tuple[str, ...] | tuple[pip_review._ColumnSpec, ...]
    ),
    expected: (
        str | frozenset[str] | tuple[str, ...] | tuple[pip_review._ColumnSpec, ...]
    ),
) -> None:
    assert constant == expected


def test_parse_args_empty_args() -> None:
    assert pip_review._parse_args([]) == (
        argparse.Namespace(
            verbose=False,
            raw=False,
            interactive=False,
            auto=False,
            continue_on_fail=False,
            freeze_outdated_packages=False,
            freeze_file=Path("requirements.txt").resolve(),
            preview=False,
        ),
        [],
    )


@pytest.mark.parametrize(
    ("args", "field"),
    [
        pytest.param(["--verbose"], "verbose", id="--verbose"),
        pytest.param(["-v"], "verbose", id="-v"),
        pytest.param(["--raw"], "raw", id="--raw"),
        pytest.param(["-r"], "raw", id="-r"),
        pytest.param(["--interactive"], "interactive", id="--interactive"),
        pytest.param(["-i"], "interactive", id="-i"),
        pytest.param(["--auto"], "auto", id="--auto"),
        pytest.param(["-a"], "auto", id="-a"),
        pytest.param(
            ["--continue-on-fail"],
            "continue_on_fail",
            id="--continue-on-fail",
        ),
        pytest.param(
            ["--freeze-outdated-packages"],
            "freeze_outdated_packages",
            id="--freeze-outdated-packages",
        ),
        pytest.param(["--preview"], "preview", id="--preview"),
        pytest.param(["-p"], "preview", id="-p"),
    ],
)
def test_parse_args_flag(
    args: list[str],
    field: str,
) -> None:
    assert getattr(
        pip_review._parse_args(args)[0],
        field,
    )


@pytest.mark.parametrize("arg", ["--freeze-file", "-f"])
def test_parse_args_freeze_file(tmp_path: Path, arg: str) -> None:
    tmp_file: str = str(tmp_path / "outdated.txt")
    args: list[str] = [f"{arg}={tmp_file}"]
    assert pip_review._parse_args(args)[0].freeze_file == tmp_path / "outdated.txt"


@pytest.mark.parametrize("arg", ["--freeze-file", "-f"])
def test_parse_args_freeze_file_separated_args(tmp_path: Path, arg: str) -> None:
    tmp_file: str = str(tmp_path / "outdated.txt")
    args: list[str] = [arg, tmp_file]
    assert pip_review._parse_args(args)[0].freeze_file == tmp_path / "outdated.txt"


@pytest.mark.parametrize(
    ("args", "expected"),
    [
        pytest.param([], []),
        pytest.param(["--auto"], []),
        pytest.param(["--test"], ["--test"]),
        pytest.param(["--auto", "--test"], ["--test"]),
        pytest.param(["--test1", "--test2"], ["--test1", "--test2"]),
        pytest.param(["--test2", "--test1"], ["--test2", "--test1"]),
    ],
)
def test_parse_args_unknown_args(args: list[str], expected: list[str]) -> None:
    assert pip_review._parse_args(args)[1] == expected


@pytest.mark.parametrize(
    "args_to_pass",
    [
        [],
        ["--pass"],
        ["--pass-pass"],
        ["-p"],
        ["--pass=arg"],
        ["--pass-pass=arg"],
        ["-p=arg"],
        ["--pass", "arg"],
        ["--pass-pass", "arg"],
        ["-p", "arg"],
    ],
)
@pytest.mark.parametrize(
    "args_to_filter",
    [
        [],
        ["--filter"],
        ["--filter-filter"],
        ["-f"],
        ["--filter=arg"],
        ["--filter-filter=arg"],
        ["-f=arg"],
        ["--filter", "arg"],
        ["--filter-filter", "arg"],
        ["-f", "arg"],
    ],
)
def test_filter_forwards(
    args_to_filter: list[str],
    args_to_pass: list[str],
) -> None:
    assert (
        pip_review._filter_forwards(
            [*args_to_pass, *args_to_filter],
            {"filter", "filter-filter", "f"},
        )
        == args_to_pass
    )


def test_stdout_filter_is_subclass_of_logging_filter() -> None:
    assert issubclass(pip_review._StdOutFilter, logging.Filter)


def test_stdout_filter_override() -> None:
    assert pip_review._StdOutFilter().filter.__override__


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
    assert pip_review._StdOutFilter().filter(record)


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
    assert not pip_review._StdOutFilter().filter(record)


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
    logger: logging.Logger = pip_review._setup_logging(verbose=verbose)
    assert logger.name == "pip-review"
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
    assert isinstance(stdout_handler.filters[0], pip_review._StdOutFilter)

    logger.handlers.clear()


@pytest.mark.parametrize("user_input", ["y", "n", "a", "q"])
def test_ask_returns_with_valid_input(user_input: str) -> None:
    asker = pip_review._InteractiveAsker()
    with mock.patch("builtins.input", return_value=user_input):
        assert asker.ask("Test prompt") == user_input


@pytest.mark.parametrize("cached_answer", ["a", "q"])
@pytest.mark.parametrize("user_input", ["y", "n", "a", "q"])
def test_ask_returns_with_cached_answer(cached_answer: str, user_input: str) -> None:
    asker = pip_review._InteractiveAsker()

    with mock.patch("builtins.input", return_value=cached_answer):
        assert asker.ask("Test prompt") == cached_answer

    with mock.patch("builtins.input", return_value=user_input):
        for _ in range(10):
            assert asker.ask("Test prompt") == cached_answer


def test_ask_to_install_meta() -> None:
    assert len(pip_review._ask_to_install.keywords) == 1
    assert pip_review._ask_to_install.keywords["prompt"] == "Upgrade now?"
    assert pip_review._ask_to_install.func.__name__ == "ask"


@pytest.mark.parametrize("user_input", ["y", "n"])
def test_ask_to_install_with_valid_input(user_input: str) -> None:
    with mock.patch("builtins.input", return_value=user_input):
        assert pip_review._ask_to_install() == user_input


@pytest.mark.parametrize("user_input", ["y", "n", "a", "q"])
def test_ask_to_install_with_cached_answer_a(user_input: str) -> None:
    with mock.patch("builtins.input", return_value="a"):
        assert pip_review._ask_to_install() == "a"

    with mock.patch("builtins.input", return_value=user_input):
        for _ in range(10):
            assert pip_review._ask_to_install() == "a"


@pytest.mark.parametrize("last_answer", ["y", "n", "a", "q"])
def test_ask_to_install_with_last_answer_and_invalid_input(last_answer: str) -> None:
    asker = pip_review._InteractiveAsker()
    asker.last_answer = last_answer
    with mock.patch("builtins.input", return_value=""):
        assert asker.ask("Test prompt") == last_answer


def test_package_is_tuple() -> None:
    assert issubclass(pip_review._OutdatedPackageInfo, tuple)


def test_package_fields() -> None:
    assert pip_review._OutdatedPackageInfo._fields == (
        "name",
        "version",
        "latest_version",
        "latest_filetype",
    )


@pytest.mark.parametrize(
    ("dct", "expected"),
    [
        pytest.param(
            {
                "name": "name",
                "version": "version",
                "latest_version": "version",
                "latest_filetype": "latest_filetype",
            },
            ("name", "version", "version", "latest_filetype"),
            id="complete-dct",
        ),
        pytest.param(
            {
                "version": "version",
                "latest_version": "version",
                "latest_filetype": "latest_filetype",
            },
            ("Unknown", "version", "version", "latest_filetype"),
            id="missing-name",
        ),
        pytest.param(
            {
                "name": "name",
                "latest_version": "version",
                "latest_filetype": "latest_filetype",
            },
            ("name", "Unknown", "version", "latest_filetype"),
            id="missing-version",
        ),
        pytest.param(
            {
                "name": "name",
                "version": "version",
                "latest_filetype": "latest_filetype",
            },
            ("name", "version", "Unknown", "latest_filetype"),
            id="missing-latest_version",
        ),
        pytest.param(
            {
                "name": "name",
                "version": "version",
                "latest_version": "version",
            },
            ("name", "version", "version", "Unknown"),
            id="missing-latest_filetype",
        ),
    ],
)
def test_package_from_dct(dct: dict[str, str], expected: tuple[str, ...]) -> None:
    assert pip_review._OutdatedPackageInfo.from_dct(dct) == expected


def test_freeze_outdated_packages(
    tmp_path: Path,
    test_packages: list[pip_review._OutdatedPackageInfo],
) -> None:
    tmp_file: Path = tmp_path / "outdated.txt"
    pip_review.freeze_outdated_packages(tmp_file, test_packages)
    assert tmp_file.read_text(encoding="utf-8") == "test1==1.0.0\ntest2==1.9.9\n"


@pytest.mark.parametrize(
    "forwarded",
    [[], ["--forwarded"], ["--forwarded1", "--forwarded2"]],
)
def test_update_packages_continue_on_fail_set_to_false(
    forwarded: list[str],
    test_packages: list[pip_review._OutdatedPackageInfo],
) -> None:
    with mock.patch("subprocess.call") as mock_subprocess_call:
        pip_review.update_packages(
            test_packages,
            forwarded,
            continue_on_fail=False,
        )

    expected_cmd: list[str] = [
        *pip_review._PIP_CMD,
        "install",
        "-U",
        *forwarded,
        "test1",
        "test2",
    ]
    mock_subprocess_call.assert_called_once_with(
        expected_cmd,
        stdout=sys.stdout,
        stderr=sys.stderr,
    )


@pytest.mark.parametrize(
    "forwarded",
    [[], ["--forwarded"], ["--forwarded1", "--forwarded2"]],
)
def test_update_packages_continue_on_fail_set_to_true(
    forwarded: list[str],
    test_packages: list[pip_review._OutdatedPackageInfo],
) -> None:
    with mock.patch("subprocess.call") as mock_subprocess_call:
        pip_review.update_packages(
            test_packages,
            forwarded,
            continue_on_fail=True,
        )

    expected_calls: list[mock._Call] = [
        mock.call(
            [
                *pip_review._PIP_CMD,
                "install",
                "-U",
                *forwarded,
                "test1",
            ],
            stdout=sys.stdout,
            stderr=sys.stderr,
        ),
        mock.call(
            [
                *pip_review._PIP_CMD,
                "install",
                "-U",
                *forwarded,
                "test2",
            ],
            stdout=sys.stdout,
            stderr=sys.stderr,
        ),
    ]
    mock_subprocess_call.assert_has_calls(expected_calls)


def test_get_outdated_packages(
    test_packages: list[pip_review._OutdatedPackageInfo],
    test_subprocess_output: bytes,
) -> None:
    with mock.patch(
        "subprocess.check_output",
        return_value=test_subprocess_output,
    ):
        outdated_packages: list[pip_review._OutdatedPackageInfo] = (
            pip_review._get_outdated_packages([])
        )
    assert outdated_packages == test_packages


def test_get_constraint_file_constraint_file_found(tmp_path: Path) -> None:
    test_constraint_file: Path = tmp_path / "constraint.txt"
    with mock.patch("os.getenv", return_value=str(test_constraint_file)):
        constraint_file: Path | None = pip_review._get_constraint_file()
    assert test_constraint_file == constraint_file


def test_get_constraint_file_no_constraint_file_found() -> None:
    with mock.patch("os.getenv", return_value=None):
        constraint_file: Path | None = pip_review._get_constraint_file()
    assert constraint_file is None


def test_get_constraint_packages_with_constraint_file(tmp_path: Path) -> None:
    test_constraint_file: Path = tmp_path / "constraint.txt"
    test_constraint_file.write_text("test1==1.0.0\ntest2=1.9.9\n", encoding="utf-8")

    constraint_packages: set[str] = pip_review._get_constraint_packages(
        test_constraint_file,
    )
    assert constraint_packages == {"test1", "test2"}


def test_get_constraint_packages_no_constraint_file() -> None:
    constraint_packages: set[str] = pip_review._get_constraint_packages(
        None,
    )
    assert constraint_packages == set()


def test_column_fields() -> None:
    assert pip_review._ColumnSpec._fields == (
        "title",
        "field",
    )


@pytest.mark.parametrize(
    "field",
    [
        "name",
        "version",
        "latest_version",
        "latest_filetype",
    ],
)
def test_extract_column(
    test_packages: list[pip_review._OutdatedPackageInfo],
    field: str,
) -> None:
    assert pip_review._extract_column(test_packages, field, "TEST") == [
        "TEST",
        getattr(test_packages[0], field),
        getattr(test_packages[1], field),
    ]


def test_extract_table(test_packages: list[pip_review._OutdatedPackageInfo]) -> None:
    expected_result: list[list[str]] = [
        ["Package", "test1", "test2"],
        ["Version", "1.0.0", "1.9.9"],
        ["Latest", "1.1.0", "2.0.0"],
        ["Type", "wheel", "wheel"],
    ]
    assert pip_review._extract_table(test_packages) == expected_result


@pytest.mark.parametrize(
    ("column", "expected_width"),
    [
        (["test"], 4),
        (["testtest", "test"], 8),
        (["testtest", ""], 8),
        (["", "test", ""], 4),
        (["", "", ""], 0),
    ],
)
def test_column_width(column: list[str], expected_width: int) -> None:
    assert pip_review._column_width(column) == expected_width


def test_format_table() -> None:
    # pylint: disable=C0301
    test_columns: list[list[str]] = [
        ["Package", "test1", "test2"],
        ["Version", "1.0.0", "1.9.9"],
        ["Latest", "1.1.0", "2.0.0"],
        ["Type", "wheel", "wheel"],
    ]
    expected_result: str = (
        "Package Version Latest Type \n----------------------------\ntest1   1.0.0   1.1.0  wheel\ntest2   1.9.9   2.0.0  wheel\n----------------------------"  # noqa: E501
    )
    assert pip_review.format_table(test_columns) == expected_result


def test_format_table_value_error_when_columns_are_not_the_same_length() -> None:
    test_columns: list[list[str]] = [
        ["Package", "test1", "test2"],
        ["Version", "1.0.0", "1.9.9"],
        ["Latest", "1.1.0", "2.0.0"],
        ["Type", "wheel"],
    ]
    with pytest.raises(ValueError, match=r"\bNot all columns are the same length\b"):
        pip_review.format_table(test_columns)


@pytest.mark.parametrize(
    ("args", "err_msg"),
    [
        (["--raw", "--auto"], "'--raw' and '--auto' cannot be used together\n"),
        (
            ["--raw", "--interactive"],
            "'--raw' and '--interactive' cannot be used together\n",
        ),
        (
            ["--auto", "--interactive"],
            "'--auto' and '--interactive' cannot be used together\n",
        ),
    ],
)
def test_main_mutually_exclusive_args_error(
    capsys: pytest.CaptureFixture[str],
    args: list[str],
    err_msg: str,
) -> None:
    exit_code: int = pip_review.main(args)
    assert exit_code == 1
    assert err_msg in capsys.readouterr().err


@pytest.mark.parametrize(
    "args",
    [
        "--preview",
        "-p",
        "--freeze-outdated-packages",
        "--auto",
        "-a",
        "--raw",
        "-r",
        "--interactive",
        "-i",
    ],
)
def test_main_no_outdated_packages(
    capsys: pytest.CaptureFixture[str],
    args: list[str],
) -> None:
    with mock.patch(
        "subprocess.check_output",
        return_value=b"{}",
    ):
        exit_code: int = pip_review.main(args)

    assert "Everything up-to-date" in capsys.readouterr().out
    assert exit_code == 0


def test_main_default_output_with_outdated_packages(
    capsys: pytest.CaptureFixture[str],
    test_subprocess_output: bytes,
) -> None:
    with mock.patch(
        "subprocess.check_output",
        return_value=test_subprocess_output,
    ):
        exit_code: int = pip_review.main([])

    assert (
        "test1==1.1.0 is available (you have 1.0.0)\n"
        "test2==2.0.0 is available (you have 1.9.9)\n" in capsys.readouterr().out
    )
    assert exit_code == 0


def test_main_default_output_with_outdated_packages_and_constraints(
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
    test_subprocess_output: bytes,
) -> None:
    test_constraint_file: Path = tmp_path / "constraint.txt"
    test_constraint_file.write_text("test2=1.9.9\n", encoding="utf-8")

    with mock.patch(
        "subprocess.check_output",
        return_value=test_subprocess_output,
    ), mock.patch("os.getenv", return_value=str(test_constraint_file)):
        exit_code: int = pip_review.main([])

    assert (
        "test1==1.1.0 is available (you have 1.0.0)\n"
        "test2==2.0.0 is available (you have 1.9.9, constraint)\n"
        in capsys.readouterr().out
    )
    assert exit_code == 0


def test_main_freeze_outdated_packages(
    tmp_path: Path,
    test_subprocess_output: bytes,
) -> None:
    tmp_file: Path = tmp_path / "outdated.txt"

    with mock.patch(
        "subprocess.check_output",
        return_value=test_subprocess_output,
    ):
        exit_code: int = pip_review.main(
            ["--freeze-outdated-packages", "--freeze-file", str(tmp_file)],
        )

    assert tmp_file.read_text(encoding="utf-8") == "test1==1.0.0\ntest2==1.9.9\n"
    assert exit_code == 0


@pytest.mark.parametrize("arg", ["--raw", "-r"])
def test_main_with_raw(
    capsys: pytest.CaptureFixture[str],
    test_subprocess_output: bytes,
    arg: str,
) -> None:
    with mock.patch(
        "subprocess.check_output",
        return_value=test_subprocess_output,
    ):
        exit_code: int = pip_review.main([arg])

    assert "test1==1.1.0\ntest2==2.0.0\n" in capsys.readouterr().out
    assert exit_code == 0


@pytest.mark.parametrize("upgrade_arg", ["--auto", "-a", "-i", "--interactive"])
@pytest.mark.parametrize("preview_arg", ["--preview", "-p"])
def test_main_preview_runs_when_upgrading(
    capsys: pytest.CaptureFixture[str],
    test_subprocess_output: bytes,
    preview_arg: str,
    upgrade_arg: str,
) -> None:
    # pylint: disable=C0301
    with mock.patch(
        "subprocess.check_output",
        return_value=test_subprocess_output,
    ), mock.patch("subprocess.call") as mock_subprocess_call:
        exit_code: int = pip_review.main([preview_arg, upgrade_arg])

    expected_result: str = (
        "Package Version Latest Type \n----------------------------\ntest1   1.0.0   1.1.0  wheel\ntest2   1.9.9   2.0.0  wheel\n----------------------------"  # noqa: E501
    )
    assert expected_result in capsys.readouterr().out
    expected_cmd: list[str] = [
        *pip_review._PIP_CMD,
        "install",
        "-U",
        "test1",
        "test2",
    ]
    mock_subprocess_call.assert_called_once_with(
        expected_cmd,
        stdout=sys.stdout,
        stderr=sys.stderr,
    )
    assert exit_code == 0


@pytest.mark.parametrize("preview_arg", ["--preview", "-p"])
def test_main_preview_does_not_run_when_not_upgrading(
    capsys: pytest.CaptureFixture[str],
    test_subprocess_output: bytes,
    preview_arg: str,
) -> None:
    # pylint: disable=C0301
    with mock.patch(
        "subprocess.check_output",
        return_value=test_subprocess_output,
    ):
        exit_code: int = pip_review.main([preview_arg])

    expected_result: str = (
        "Package Version Latest Type \n----------------------------\ntest1   1.0.0   1.1.0  wheel\ntest2   1.9.9   2.0.0  wheel\n----------------------------"  # noqa: E501
    )
    assert expected_result not in capsys.readouterr().out
    assert exit_code == 0


@pytest.mark.parametrize("arg", ["--auto", "-a"])
def test_main_auto_continue_on_fail_set_to_false(
    test_subprocess_output: bytes,
    arg: str,
) -> None:
    # pylint: disable=C0301
    with mock.patch(
        "subprocess.check_output",
        return_value=test_subprocess_output,
    ), mock.patch("subprocess.call") as mock_subprocess_call:
        exit_code: int = pip_review.main([arg])

    expected_cmd: list[str] = [
        *pip_review._PIP_CMD,
        "install",
        "-U",
        "test1",
        "test2",
    ]
    mock_subprocess_call.assert_called_once_with(
        expected_cmd,
        stdout=sys.stdout,
        stderr=sys.stderr,
    )
    assert exit_code == 0


@pytest.mark.parametrize("arg", ["--auto", "-a"])
def test_main_auto_continue_on_fail_set_to_true(
    test_subprocess_output: bytes,
    arg: str,
) -> None:
    # pylint: disable=C0301
    with mock.patch(
        "subprocess.check_output",
        return_value=test_subprocess_output,
    ), mock.patch("subprocess.call") as mock_subprocess_call:
        exit_code: int = pip_review.main([arg, "--continue-on-fail"])

    expected_calls: list[mock._Call] = [
        mock.call(
            [
                *pip_review._PIP_CMD,
                "install",
                "-U",
                "test1",
            ],
            stdout=sys.stdout,
            stderr=sys.stderr,
        ),
        mock.call(
            [
                *pip_review._PIP_CMD,
                "install",
                "-U",
                "test2",
            ],
            stdout=sys.stdout,
            stderr=sys.stderr,
        ),
    ]
    mock_subprocess_call.assert_has_calls(expected_calls)
    assert exit_code == 0


@pytest.mark.parametrize("user_input", ["y", "a"])
@pytest.mark.parametrize("arg", ["--interactive", "-i"])
def test_main_interactive_confirm_all_continue_on_fail_set_to_false(
    capsys: pytest.CaptureFixture[str],
    test_subprocess_output: bytes,
    user_input: str,
    arg: str,
) -> None:
    with mock.patch(
        "subprocess.check_output",
        return_value=test_subprocess_output,
    ), mock.patch("pip_review._ask_to_install", return_value=user_input), mock.patch(
        "subprocess.call",
    ) as mock_subprocess_call:
        exit_code: int = pip_review.main([arg])

    assert (
        "test1==1.1.0 is available (you have 1.0.0)\n"
        "test2==2.0.0 is available (you have 1.9.9)\n" in capsys.readouterr().out
    )
    expected_cmd: list[str] = [
        *pip_review._PIP_CMD,
        "install",
        "-U",
        "test1",
        "test2",
    ]
    mock_subprocess_call.assert_called_once_with(
        expected_cmd,
        stdout=sys.stdout,
        stderr=sys.stderr,
    )
    assert exit_code == 0


@pytest.mark.parametrize("user_input", ["y", "a"])
@pytest.mark.parametrize("arg", ["--interactive", "-i"])
def test_main_interactive_confirm_all_continue_on_fail_set_to_true(
    capsys: pytest.CaptureFixture[str],
    test_subprocess_output: bytes,
    user_input: str,
    arg: str,
) -> None:
    with mock.patch(
        "subprocess.check_output",
        return_value=test_subprocess_output,
    ), mock.patch("pip_review._ask_to_install", return_value=user_input), mock.patch(
        "subprocess.call",
    ) as mock_subprocess_call:
        exit_code: int = pip_review.main([arg, "--continue-on-fail"])

    assert (
        "test1==1.1.0 is available (you have 1.0.0)\n"
        "test2==2.0.0 is available (you have 1.9.9)\n" in capsys.readouterr().out
    )
    expected_calls: list[mock._Call] = [
        mock.call(
            [
                *pip_review._PIP_CMD,
                "install",
                "-U",
                "test1",
            ],
            stdout=sys.stdout,
            stderr=sys.stderr,
        ),
        mock.call(
            [
                *pip_review._PIP_CMD,
                "install",
                "-U",
                "test2",
            ],
            stdout=sys.stdout,
            stderr=sys.stderr,
        ),
    ]
    mock_subprocess_call.assert_has_calls(expected_calls)
    assert exit_code == 0


@pytest.mark.parametrize("user_input", ["n", "q"])
@pytest.mark.parametrize("arg", ["--interactive", "-i"])
def test_main_interactive_deny_all(
    capsys: pytest.CaptureFixture[str],
    test_subprocess_output: bytes,
    user_input: str,
    arg: str,
) -> None:
    with mock.patch(
        "subprocess.check_output",
        return_value=test_subprocess_output,
    ), mock.patch("pip_review._ask_to_install", return_value=user_input), mock.patch(
        "subprocess.call",
    ) as mock_subprocess_call:
        exit_code: int = pip_review.main([arg])

    assert (
        "test1==1.1.0 is available (you have 1.0.0)\n"
        "test2==2.0.0 is available (you have 1.9.9)\n" in capsys.readouterr().out
    )
    mock_subprocess_call.assert_not_called()
    assert exit_code == 0


@pytest.mark.parametrize("user_input", ["y", "a"])
@pytest.mark.parametrize("arg", ["--interactive", "-i"])
def test_main_interactive_confirm_all_continue_on_fail_set_to_false_with_constraints(
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
    test_subprocess_output: bytes,
    user_input: str,
    arg: str,
) -> None:
    test_constraint_file: Path = tmp_path / "constraint.txt"
    test_constraint_file.write_text("test2=1.9.9\n", encoding="utf-8")

    with mock.patch(
        "subprocess.check_output",
        return_value=test_subprocess_output,
    ), mock.patch("pip_review._ask_to_install", return_value=user_input), mock.patch(
        "os.getenv",
        return_value=str(test_constraint_file),
    ), mock.patch(
        "subprocess.call",
    ) as mock_subprocess_call:
        exit_code: int = pip_review.main([arg])

    assert (
        "test1==1.1.0 is available (you have 1.0.0)\n"
        "test2==2.0.0 is available (you have 1.9.9, constraint)\n"
        in capsys.readouterr().out
    )
    expected_cmd: list[str] = [
        *pip_review._PIP_CMD,
        "install",
        "-U",
        "test1",
        "test2",
    ]
    mock_subprocess_call.assert_called_once_with(
        expected_cmd,
        stdout=sys.stdout,
        stderr=sys.stderr,
    )
    assert exit_code == 0


@pytest.mark.parametrize("user_input", ["y", "a"])
@pytest.mark.parametrize("arg", ["--interactive", "-i"])
def test_main_interactive_confirm_all_continue_on_fail_set_to_true_with_constraints(
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
    test_subprocess_output: bytes,
    user_input: str,
    arg: str,
) -> None:
    test_constraint_file: Path = tmp_path / "constraint.txt"
    test_constraint_file.write_text("test2=1.9.9\n", encoding="utf-8")

    with mock.patch(
        "subprocess.check_output",
        return_value=test_subprocess_output,
    ), mock.patch("pip_review._ask_to_install", return_value=user_input), mock.patch(
        "os.getenv",
        return_value=str(test_constraint_file),
    ), mock.patch(
        "subprocess.call",
    ) as mock_subprocess_call:
        exit_code: int = pip_review.main([arg, "--continue-on-fail"])

    assert (
        "test1==1.1.0 is available (you have 1.0.0)\n"
        "test2==2.0.0 is available (you have 1.9.9, constraint)\n"
        in capsys.readouterr().out
    )
    expected_calls: list[mock._Call] = [
        mock.call(
            [
                *pip_review._PIP_CMD,
                "install",
                "-U",
                "test1",
            ],
            stdout=sys.stdout,
            stderr=sys.stderr,
        ),
        mock.call(
            [
                *pip_review._PIP_CMD,
                "install",
                "-U",
                "test2",
            ],
            stdout=sys.stdout,
            stderr=sys.stderr,
        ),
    ]
    mock_subprocess_call.assert_has_calls(expected_calls)
    assert exit_code == 0


@pytest.mark.parametrize("user_input", ["n", "q"])
@pytest.mark.parametrize("arg", ["--interactive", "-i"])
def test_main_interactive_deny_all_with_constraints(
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
    test_subprocess_output: bytes,
    user_input: str,
    arg: str,
) -> None:
    test_constraint_file: Path = tmp_path / "constraint.txt"
    test_constraint_file.write_text("test2=1.9.9\n", encoding="utf-8")

    with mock.patch(
        "subprocess.check_output",
        return_value=test_subprocess_output,
    ), mock.patch("pip_review._ask_to_install", return_value=user_input), mock.patch(
        "os.getenv",
        return_value=str(test_constraint_file),
    ), mock.patch(
        "subprocess.call",
    ) as mock_subprocess_call:
        exit_code: int = pip_review.main([arg])

    assert (
        "test1==1.1.0 is available (you have 1.0.0)\n"
        "test2==2.0.0 is available (you have 1.9.9, constraint)\n"
        in capsys.readouterr().out
    )
    mock_subprocess_call.assert_not_called()
    assert exit_code == 0


if __name__ == "__main__":
    raise SystemExit(pytest.main())
