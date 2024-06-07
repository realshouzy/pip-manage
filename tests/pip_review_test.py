#!/usr/bin/env python3
from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path
from unittest import mock

import pytest

from pip_manage import pip_review
from pip_manage._pip_interface import PIP_CMD, _OutdatedPackage
from tests.fixtures import sample_packages, sample_subprocess_output

# pylint: disable=W0212, E1101, W0621, C0302, R0913, C0301


@pytest.mark.parametrize(
    ("constant", "expected"),
    [
        pytest.param(
            pip_review._EPILOG,
            """
Unrecognised arguments will be forwarded to 'pip list --outdated' and
'pip install' (if supported), so you can pass things such as '--user', '--pre'
and '--timeout' and they will do what you expect. See 'pip list -h' and 'pip install -h'
for a full overview of the options.
""",
            id="_EPILOG",
        ),
        pytest.param(
            pip_review._DEFAULT_COLUMN_SPECS,
            (
                pip_review._ColumnSpec("Package", "name"),
                pip_review._ColumnSpec("Version", "version"),
                pip_review._ColumnSpec("Latest", "latest_version"),
                pip_review._ColumnSpec("Type", "latest_filetype"),
                pip_review._ColumnSpec(
                    "Constraints",
                    "constraints_display",
                ),
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


def test_default_settings_pip_review_logger() -> None:
    assert pip_review._logger.name == "pip-review"
    assert len(pip_review._logger.handlers) == 2


def test_parse_args_empty_args() -> None:
    assert pip_review._parse_args([]) == (
        argparse.Namespace(
            verbose=False,
            raw=False,
            interactive=False,
            auto=False,
            continue_on_fail=False,
            freeze_outdated_packages=False,
            freeze_file=Path("backup.txt").resolve(),
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
def test_parse_args_flags_with_set_to_true(args: list[str], field: str) -> None:
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


@pytest.mark.parametrize("user_input", ["y", "n", "a", "q"])
def test_ask_returns_with_valid_input(user_input: str) -> None:
    asker: pip_review._InteractiveAsker = pip_review._InteractiveAsker("Test prompt")
    with mock.patch("builtins.input", return_value=user_input):
        assert asker.ask() == user_input


@pytest.mark.parametrize("cached_answer", ["a", "q"])
@pytest.mark.parametrize("user_input", ["y", "n", "a", "q"])
def test_ask_returns_with_cached_answer(cached_answer: str, user_input: str) -> None:
    asker: pip_review._InteractiveAsker = pip_review._InteractiveAsker("Test prompt")

    with mock.patch("builtins.input", return_value=cached_answer):
        assert asker.ask() == cached_answer

    with mock.patch("builtins.input", return_value=user_input):
        for _ in range(10):
            assert asker.ask() == cached_answer


@pytest.mark.parametrize("last_answer", ["y", "n", "a", "q"])
def test_ask_to_install_with_last_answer_and_invalid_input(last_answer: str) -> None:
    asker: pip_review._InteractiveAsker = pip_review._InteractiveAsker("Test prompt")
    asker.last_answer = last_answer
    with mock.patch("builtins.input", return_value=""):
        assert asker.ask() == last_answer


def test_freeze_outdated_packages(
    tmp_path: Path,
    sample_packages: list[_OutdatedPackage],
) -> None:
    tmp_file: Path = tmp_path / "outdated.txt"
    tmp_file.touch()
    pip_review._freeze_outdated_packages(tmp_file, sample_packages)
    assert tmp_file.read_text(encoding="utf-8") == "test1==1.0.0\ntest2==1.9.9\n"


def test_get_constraints_files_from_env_constraint_file_found(tmp_path: Path) -> None:
    constraints_file: Path = tmp_path / "constraint.txt"
    with mock.patch("os.getenv", return_value=str(constraints_file)):
        constraint_file: Path | None = pip_review._get_constraints_files_from_env()
    assert constraints_file == constraint_file


def test_get_constraints_files_from_env_no_constraint_file_found() -> None:
    with mock.patch("os.getenv", return_value=None):
        constraint_file: Path | None = pip_review._get_constraints_files_from_env()
    assert constraint_file is None


@pytest.mark.parametrize("arg", ["--constraint", "-c"])
def test_get_constraints_files_from_args_with_named_args(
    tmp_path: Path,
    arg: str,
) -> None:
    constraints_file: Path = tmp_path / "constraints.txt"

    assert pip_review._get_constraints_files_from_args(
        [f"{arg}={constraints_file}"],
    ) == [constraints_file]


@pytest.mark.parametrize("arg", ["--constraint", "-c"])
def test_get_constraints_files_from_args_with_positional_args(
    tmp_path: Path,
    arg: str,
) -> None:
    constraints_file: Path = tmp_path / "constraints.txt"

    assert pip_review._get_constraints_files_from_args(
        [arg, str(constraints_file)],
    ) == [constraints_file]


def test_get_constraints_files_from_args_with_no_args() -> None:
    assert not pip_review._get_constraints_files_from_args([])


def test_get_constraints_files_no_args_and_no_env_var() -> None:
    with mock.patch("os.getenv", return_value=None):
        assert not pip_review._get_constraints_files([])


@pytest.mark.parametrize("arg", ["--constraint", "-c"])
def test_get_constraints_files_with_positional_args_and_no_env_var(
    tmp_path: Path,
    arg: str,
) -> None:
    constraints_file: Path = tmp_path / "constraints.txt"
    with mock.patch("os.getenv", return_value=None):
        assert pip_review._get_constraints_files([arg, str(constraints_file)]) == [
            constraints_file,
        ]


@pytest.mark.parametrize("arg", ["--constraint", "-c"])
def test_get_constraints_files_with_named_args_and_no_env_var(
    tmp_path: Path,
    arg: str,
) -> None:
    constraints_file: Path = tmp_path / "constraints.txt"
    with mock.patch("os.getenv", return_value=None):
        assert pip_review._get_constraints_files([f"{arg}={constraints_file}"]) == [
            constraints_file,
        ]


def test_get_constraints_files_no_args_and_dont_ignore_constraints_env_var(
    tmp_path: Path,
) -> None:
    constraints_file: Path = tmp_path / "constraints.txt"
    with mock.patch("os.getenv", return_value=str(constraints_file)):
        assert pip_review._get_constraints_files([]) == [constraints_file]


@pytest.mark.parametrize("arg", ["--constraint", "-c"])
def test_get_constraints_files_with_positional_args_and_dont_ignore_constraints_env_var(
    tmp_path: Path,
    arg: str,
) -> None:
    constraints_file1: Path = tmp_path / "constraints1.txt"
    constraints_file2: Path = tmp_path / "constraints2.txt"
    with mock.patch("os.getenv", return_value=str(constraints_file1)):
        assert pip_review._get_constraints_files([arg, str(constraints_file2)]) == [
            constraints_file2,
            constraints_file1,
        ]


@pytest.mark.parametrize("arg", ["--constraint", "-c"])
def test_get_constraints_files_with_named_args_and_dont_ignore_constraints_env_var(
    tmp_path: Path,
    arg: str,
) -> None:
    constraints_file1: Path = tmp_path / "constraints1.txt"
    constraints_file2: Path = tmp_path / "constraints2.txt"
    with mock.patch("os.getenv", return_value=str(constraints_file1)):
        assert pip_review._get_constraints_files([f"{arg}={constraints_file2}"]) == [
            constraints_file2,
            constraints_file1,
        ]


def test_set_constraints_of_outdated_pkgs(
    tmp_path: Path,
    sample_packages: list[_OutdatedPackage],
) -> None:
    constraints_file: Path = tmp_path / "constraints_file.txt"
    constraints_file.write_text("test2==1.9.9.9", encoding="utf-8")

    assert not sample_packages[0].constraints
    assert not sample_packages[1].constraints
    pip_review._set_constraints_of_outdated_pkgs(
        [constraints_file],
        sample_packages,
    )
    assert not sample_packages[0].constraints
    assert sample_packages[1].constraints == {"1.9.9.9"}


def test_set_constraints_of_outdated_pkgs_multiple_constraints(
    tmp_path: Path,
    sample_packages: list[_OutdatedPackage],
) -> None:
    constraints_file1: Path = tmp_path / "constraints_file1.txt"
    constraints_file1.write_text("test2==1.9.9.8", encoding="utf-8")
    constraints_file2: Path = tmp_path / "constraints_file2.txt"
    constraints_file2.write_text("test2==1.9.9.9", encoding="utf-8")

    assert not sample_packages[0].constraints
    assert not sample_packages[1].constraints
    pip_review._set_constraints_of_outdated_pkgs(
        [constraints_file1, constraints_file2],
        sample_packages,
    )
    assert not sample_packages[0].constraints
    assert sample_packages[1].constraints == {"1.9.9.8", "1.9.9.9"}


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
    sample_packages: list[_OutdatedPackage],
    field: str,
) -> None:
    assert pip_review._extract_column(sample_packages, field, "TEST") == [
        "TEST",
        getattr(sample_packages[0], field),
        getattr(sample_packages[1], field),
    ]


def test_extract_table_without_constraints(
    sample_packages: list[_OutdatedPackage],
) -> None:
    expected_result: list[list[str]] = [
        ["Package", "test1", "test2"],
        ["Version", "1.0.0", "1.9.9"],
        ["Latest", "1.1.0", "2.0.0"],
        ["Type", "wheel", "wheel"],
        ["Constraints", "None", "None"],
    ]
    assert pip_review._extract_table(sample_packages) == expected_result


def test_extract_table_with_constraints(
    sample_packages: list[_OutdatedPackage],
) -> None:
    sample_packages[1].constraints = {"1.9.9.9"}
    expected_result: list[list[str]] = [
        ["Package", "test1", "test2"],
        ["Version", "1.0.0", "1.9.9"],
        ["Latest", "1.1.0", "2.0.0"],
        ["Type", "wheel", "wheel"],
        ["Constraints", "None", "1.9.9.9"],
    ]
    assert pip_review._extract_table(sample_packages) == expected_result


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
        ["Constraints", "None", "1.1.0"],
    ]
    expected_result: str = (
        "Package Version Latest Type  Constraints\n----------------------------------------\ntest1   1.0.0   1.1.0  wheel None       \ntest2   1.9.9   2.0.0  wheel 1.1.0      \n----------------------------------------"
    )
    assert pip_review._format_table(test_columns) == expected_result


def test_format_table_value_error_when_columns_are_not_the_same_length() -> None:
    test_columns: list[list[str]] = [
        ["Package", "test1", "test2"],
        ["Version", "1.0.0", "1.9.9"],
        ["Latest", "1.1.0", "2.0.0"],
        ["Type", "wheel"],
        ["Constraints", "None", "1.1.0"],
    ]
    with pytest.raises(ValueError, match=r"\bNot all columns are the same length\b"):
        pip_review._format_table(test_columns)


@pytest.mark.parametrize("arg", ["--verbose", "-v"])
def test_main_verbose_flag_sets_logger_level_to_debug(
    sample_subprocess_output: bytes,
    arg: str,
) -> None:
    with mock.patch(
        "subprocess.check_output",
        return_value=sample_subprocess_output,
    ), mock.patch(
        "pip_manage.pip_review._upgrade_prompter.ask",
        return_value="a",
    ), mock.patch(
        "os.getenv",
        return_value=None,
    ), mock.patch(
        "subprocess.call",
    ) as mock_subprocess_call:
        exit_code: int = pip_review.main([arg])
    assert pip_review._logger.level == logging.DEBUG
    mock_subprocess_call.assert_not_called()
    assert exit_code == 0


def test_main_no_verbose_flag_sets_logger_level_to_info(
    sample_subprocess_output: bytes,
) -> None:
    with mock.patch(
        "subprocess.check_output",
        return_value=sample_subprocess_output,
    ), mock.patch(
        "pip_manage.pip_review._upgrade_prompter.ask",
        return_value="a",
    ), mock.patch(
        "os.getenv",
        return_value=None,
    ), mock.patch(
        "subprocess.call",
    ) as mock_subprocess_call:
        exit_code: int = pip_review.main([])
    assert pip_review._logger.level == logging.INFO
    mock_subprocess_call.assert_not_called()
    assert exit_code == 0


@pytest.mark.parametrize(
    ("args", "err_msg"),
    [
        (["--raw", "--auto"], "'--raw' and '--auto' cannot be used together"),
        (
            ["--raw", "--interactive"],
            "'--raw' and '--interactive' cannot be used together",
        ),
        (
            ["--auto", "--interactive"],
            "'--auto' and '--interactive' cannot be used together",
        ),
    ],
)
def test_main_mutually_exclusive_args_error(
    caplog: pytest.LogCaptureFixture,
    args: list[str],
    err_msg: str,
) -> None:
    exit_code: int = pip_review.main(args)
    assert caplog.record_tuples == [("pip-review", 40, err_msg)]
    assert exit_code == 1


def test_main_warn_about_unrecognized_args(
    caplog: pytest.LogCaptureFixture,
    sample_subprocess_output: bytes,
) -> None:
    with mock.patch(
        "subprocess.check_output",
        return_value=sample_subprocess_output,
    ), mock.patch(
        "pip_manage.pip_review._upgrade_prompter.ask",
        return_value="a",
    ), mock.patch(
        "os.getenv",
        return_value=None,
    ), mock.patch(
        "subprocess.call",
    ) as mock_subprocess_call:
        exit_code: int = pip_review.main(["-x", "-v", "-a"])

    assert (
        "pip-review",
        30,
        "Unrecognized arguments: '-x'",
    ) in caplog.record_tuples
    expected_cmd: list[str] = [
        *PIP_CMD,
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


@pytest.mark.parametrize(
    ("args", "err_msg"),
    [
        (["--raw", "--auto"], "'--raw' and '--auto' cannot be used together"),
        (
            ["--raw", "--interactive"],
            "'--raw' and '--interactive' cannot be used together",
        ),
        (
            ["--auto", "--interactive"],
            "'--auto' and '--interactive' cannot be used together",
        ),
    ],
)
def test_main_mutually_warn_about_unrecognized_args_before_exclusive_args_error(
    caplog: pytest.LogCaptureFixture,
    args: list[str],
    err_msg: str,
) -> None:
    exit_code: int = pip_review.main([*args, "-x"])
    assert caplog.record_tuples == [
        (
            "pip-review",
            30,
            "Unrecognized arguments: '-x'",
        ),
        ("pip-review", 40, err_msg),
    ]
    assert exit_code == 1


@pytest.mark.parametrize(
    "arg",
    [
        "--preview",
        "-p",
        "--freeze-outdated-packages",
        "--auto",
        "-a",
        "--interactive",
        "-i",
    ],
)
def test_main_no_outdated_packages(
    caplog: pytest.LogCaptureFixture,
    arg: str,
) -> None:
    with mock.patch(
        "subprocess.check_output",
        return_value=b"{}",
    ), mock.patch("os.getenv", return_value=None):
        exit_code: int = pip_review.main([arg])

    assert [("pip-review", 20, "Everything up-to-date")] == caplog.record_tuples
    assert exit_code == 0


def test_main_default_output_with_outdated_packages(
    caplog: pytest.LogCaptureFixture,
    sample_subprocess_output: bytes,
) -> None:
    with mock.patch(
        "subprocess.check_output",
        return_value=sample_subprocess_output,
    ), mock.patch("os.getenv", return_value=None):
        exit_code: int = pip_review.main([])
    assert caplog.record_tuples == [
        (
            "pip-review",
            20,
            "test1==1.1.0 is available (you have 1.0.0)",
        ),
        (
            "pip-review",
            20,
            "test2==2.0.0 is available (you have 1.9.9)",
        ),
    ]
    assert exit_code == 0


def test_main_default_output_with_outdated_packages_and_constraints_env_var(
    caplog: pytest.LogCaptureFixture,
    tmp_path: Path,
    sample_subprocess_output: bytes,
) -> None:
    constraints_file: Path = tmp_path / "constraint.txt"
    constraints_file.write_text("test2==1.9.9.9\n", encoding="utf-8")

    with mock.patch(
        "subprocess.check_output",
        return_value=sample_subprocess_output,
    ), mock.patch("os.getenv", return_value=str(constraints_file)):
        exit_code: int = pip_review.main([])

    assert caplog.record_tuples == [
        (
            "pip-review",
            20,
            "test1==1.1.0 is available (you have 1.0.0)",
        ),
        (
            "pip-review",
            20,
            "test2==2.0.0 is available (you have 1.9.9) [Constraint to 1.9.9.9]",
        ),
    ]
    assert exit_code == 0


@pytest.mark.parametrize("constraint_arg", ["--constraint", "-c"])
def test_main_default_output_with_outdated_packages_and_positional_arg_constraints_file(
    caplog: pytest.LogCaptureFixture,
    tmp_path: Path,
    sample_subprocess_output: bytes,
    constraint_arg: str,
) -> None:
    constraints_file: Path = tmp_path / "constraint.txt"
    constraints_file.write_text("test2==1.9.9.9\n", encoding="utf-8")

    with mock.patch(
        "subprocess.check_output",
        return_value=sample_subprocess_output,
    ), mock.patch("os.getenv", return_value=None):
        exit_code: int = pip_review.main([constraint_arg, str(constraints_file)])
    assert caplog.record_tuples == [
        (
            "pip-review",
            20,
            "test1==1.1.0 is available (you have 1.0.0)",
        ),
        (
            "pip-review",
            20,
            "test2==2.0.0 is available (you have 1.9.9) [Constraint to 1.9.9.9]",
        ),
    ]
    assert exit_code == 0


@pytest.mark.parametrize("constraint_arg", ["--constraint", "-c"])
def test_main_default_output_with_outdated_packages_and_positional_arg_constraints_file_and_constraints_env_var(
    caplog: pytest.LogCaptureFixture,
    tmp_path: Path,
    sample_subprocess_output: bytes,
    constraint_arg: str,
) -> None:
    constraints_file1: Path = tmp_path / "constraint1.txt"
    constraints_file1.write_text("test2==1.9.9.8\n", encoding="utf-8")
    constraints_file2: Path = tmp_path / "constraint2.txt"
    constraints_file2.write_text("test2==1.9.9.9\n", encoding="utf-8")

    with mock.patch(
        "subprocess.check_output",
        return_value=sample_subprocess_output,
    ), mock.patch("os.getenv", return_value=str(constraints_file1)):
        exit_code: int = pip_review.main(
            [constraint_arg, str(constraints_file2)],
        )

    assert caplog.record_tuples == [
        ("pip-review", 20, "test1==1.1.0 is available (you have 1.0.0)"),
        (
            "pip-review",
            20,
            "test2==2.0.0 is available (you have 1.9.9) [Constraint to 1.9.9.8, 1.9.9.9]",
        ),
    ]
    assert exit_code == 0


@pytest.mark.parametrize("constraint_arg", ["--constraint", "-c"])
def test_main_default_output_with_outdated_packages_and_named_arg_constraints_file(
    caplog: pytest.LogCaptureFixture,
    tmp_path: Path,
    sample_subprocess_output: bytes,
    constraint_arg: str,
) -> None:
    constraints_file: Path = tmp_path / "constraint.txt"
    constraints_file.write_text("test2==1.9.9.9\n", encoding="utf-8")

    with mock.patch(
        "subprocess.check_output",
        return_value=sample_subprocess_output,
    ), mock.patch("os.getenv", return_value=None):
        exit_code: int = pip_review.main([f"{constraint_arg}={constraints_file}"])

    assert caplog.record_tuples == [
        ("pip-review", 20, "test1==1.1.0 is available (you have 1.0.0)"),
        (
            "pip-review",
            20,
            "test2==2.0.0 is available (you have 1.9.9) [Constraint to 1.9.9.9]",
        ),
    ]
    assert exit_code == 0


@pytest.mark.parametrize("constraint_arg", ["--constraint", "-c"])
def test_main_default_output_with_outdated_packages_and_named_arg_constraints_file_and_constraints_env_var(
    caplog: pytest.LogCaptureFixture,
    tmp_path: Path,
    sample_subprocess_output: bytes,
    constraint_arg: str,
) -> None:
    constraints_file1: Path = tmp_path / "constraint1.txt"
    constraints_file1.write_text("test2==1.9.9.8\n", encoding="utf-8")
    constraints_file2: Path = tmp_path / "constraint2.txt"
    constraints_file2.write_text("test2==1.9.9.9\n", encoding="utf-8")

    with mock.patch(
        "subprocess.check_output",
        return_value=sample_subprocess_output,
    ), mock.patch("os.getenv", return_value=str(constraints_file1)):
        exit_code: int = pip_review.main(
            [f"{constraint_arg}={constraints_file2}"],
        )

    assert caplog.record_tuples == [
        ("pip-review", 20, "test1==1.1.0 is available (you have 1.0.0)"),
        (
            "pip-review",
            20,
            "test2==2.0.0 is available (you have 1.9.9) [Constraint to 1.9.9.8, 1.9.9.9]",
        ),
    ]
    assert exit_code == 0


def test_main_freeze_outdated_packages(
    tmp_path: Path,
    sample_subprocess_output: bytes,
) -> None:
    tmp_file: Path = tmp_path / "outdated.txt"

    with mock.patch(
        "subprocess.check_output",
        return_value=sample_subprocess_output,
    ), mock.patch("os.getenv", return_value=None):
        exit_code: int = pip_review.main(
            ["--freeze-outdated-packages", "--freeze-file", str(tmp_file)],
        )

    assert tmp_file.read_text(encoding="utf-8") == "test1==1.0.0\ntest2==1.9.9\n"
    assert exit_code == 0


@pytest.mark.parametrize("arg", ["--raw", "-r"])
def test_main_with_raw(
    caplog: pytest.LogCaptureFixture,
    sample_subprocess_output: bytes,
    arg: str,
) -> None:
    with mock.patch(
        "subprocess.check_output",
        return_value=sample_subprocess_output,
    ):
        exit_code: int = pip_review.main([arg])

    assert caplog.record_tuples == [
        (
            "pip-review",
            20,
            "test1==1.1.0",
        ),
        (
            "pip-review",
            20,
            "test2==2.0.0",
        ),
    ]
    assert exit_code == 0


@pytest.mark.parametrize("upgrade_arg", ["--auto", "-a", "-i", "--interactive"])
@pytest.mark.parametrize("preview_arg", ["--preview", "-p"])
def test_main_preview_runs_when_upgrading_without_constraints(
    caplog: pytest.LogCaptureFixture,
    sample_subprocess_output: bytes,
    preview_arg: str,
    upgrade_arg: str,
) -> None:
    # pylint: disable=C0301
    with mock.patch(
        "subprocess.check_output",
        return_value=sample_subprocess_output,
    ), mock.patch(
        "pip_manage.pip_review._upgrade_prompter.ask",
        return_value="a",
    ), mock.patch(
        "os.getenv",
        return_value=None,
    ), mock.patch(
        "subprocess.call",
    ) as mock_subprocess_call:
        exit_code: int = pip_review.main([preview_arg, upgrade_arg])

    expected_result: str = (
        "Package Version Latest Type  Constraints\n----------------------------------------\ntest1   1.0.0   1.1.0  wheel None       \ntest2   1.9.9   2.0.0  wheel None       \n----------------------------------------"
    )
    assert ("pip-review", 20, expected_result) in caplog.record_tuples
    expected_cmd: list[str] = [
        *PIP_CMD,
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


@pytest.mark.parametrize("upgrade_arg", ["--auto", "-a", "-i", "--interactive"])
@pytest.mark.parametrize("preview_arg", ["--preview", "-p"])
def test_main_preview_runs_when_upgrading_with_constraints(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
    sample_subprocess_output: bytes,
    preview_arg: str,
    upgrade_arg: str,
) -> None:
    # pylint: disable=C0301
    constraints_file: Path = tmp_path / "constraints.txt"
    constraints_file.write_text("test2==1.9.9.9\n", encoding="utf-8")

    with mock.patch(
        "subprocess.check_output",
        return_value=sample_subprocess_output,
    ), mock.patch(
        "pip_manage.pip_review._upgrade_prompter.ask",
        return_value="a",
    ), mock.patch(
        "os.getenv",
        return_value=str(constraints_file),
    ), mock.patch(
        "subprocess.call",
    ) as mock_subprocess_call:
        exit_code: int = pip_review.main([preview_arg, upgrade_arg])

    expected_result: str = (
        "Package Version Latest Type  Constraints\n----------------------------------------\ntest1   1.0.0   1.1.0  wheel None       \ntest2   1.9.9   2.0.0  wheel 1.9.9.9    \n----------------------------------------"
    )
    assert ("pip-review", 20, expected_result) in caplog.record_tuples
    expected_cmd: list[str] = [
        *PIP_CMD,
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
    caplog: pytest.LogCaptureFixture,
    sample_subprocess_output: bytes,
    preview_arg: str,
) -> None:
    # pylint: disable=C0301
    with mock.patch(
        "subprocess.check_output",
        return_value=sample_subprocess_output,
    ), mock.patch(
        "pip_manage.pip_review._upgrade_prompter.ask",
        return_value="q",
    ), mock.patch(
        "os.getenv",
        return_value=None,
    ):
        exit_code: int = pip_review.main([preview_arg])

    expected_result: str = (
        "Package Version Latest Type  Constraints\n----------------------------------------\ntest1   1.0.0   1.1.0  wheel None       \ntest2   1.9.9   2.0.0  wheel None       \n----------------------------------------"
    )
    assert ("pip-review", 20, expected_result) not in caplog.record_tuples
    assert exit_code == 0


@pytest.mark.parametrize("arg", ["--auto", "-a"])
def test_main_auto_continue_on_fail_set_to_false(
    sample_subprocess_output: bytes,
    arg: str,
) -> None:
    # pylint: disable=C0301
    with mock.patch(
        "subprocess.check_output",
        return_value=sample_subprocess_output,
    ), mock.patch(
        "pip_manage.pip_review._upgrade_prompter.ask",
        return_value="a",
    ), mock.patch(
        "os.getenv",
        return_value=None,
    ), mock.patch(
        "subprocess.call",
    ) as mock_subprocess_call:
        exit_code: int = pip_review.main([arg])

    expected_cmd: list[str] = [
        *PIP_CMD,
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
    sample_subprocess_output: bytes,
    arg: str,
) -> None:
    # pylint: disable=C0301
    with mock.patch(
        "subprocess.check_output",
        return_value=sample_subprocess_output,
    ), mock.patch(
        "pip_manage.pip_review._upgrade_prompter.ask",
        return_value="a",
    ), mock.patch(
        "os.getenv",
        return_value=None,
    ), mock.patch(
        "subprocess.call",
    ) as mock_subprocess_call:
        exit_code: int = pip_review.main([arg, "--continue-on-fail"])

    expected_calls: list[mock._Call] = [
        mock.call(
            [
                *PIP_CMD,
                "install",
                "-U",
                "test1",
            ],
            stdout=sys.stdout,
            stderr=sys.stderr,
        ),
        mock.call(
            [
                *PIP_CMD,
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
    caplog: pytest.LogCaptureFixture,
    sample_subprocess_output: bytes,
    user_input: str,
    arg: str,
) -> None:
    with mock.patch(
        "subprocess.check_output",
        return_value=sample_subprocess_output,
    ), mock.patch(
        "pip_manage.pip_review._upgrade_prompter.ask",
        return_value=user_input,
    ), mock.patch(
        "os.getenv",
        return_value=None,
    ), mock.patch(
        "subprocess.call",
    ) as mock_subprocess_call:
        exit_code: int = pip_review.main([arg])

    assert caplog.record_tuples == [
        ("pip-review", 20, "test1==1.1.0 is available (you have 1.0.0)"),
        (
            "pip-review",
            20,
            "test2==2.0.0 is available (you have 1.9.9)",
        ),
    ]
    expected_cmd: list[str] = [
        *PIP_CMD,
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
    caplog: pytest.LogCaptureFixture,
    sample_subprocess_output: bytes,
    user_input: str,
    arg: str,
) -> None:
    with mock.patch(
        "subprocess.check_output",
        return_value=sample_subprocess_output,
    ), mock.patch(
        "pip_manage.pip_review._upgrade_prompter.ask",
        return_value=user_input,
    ), mock.patch(
        "os.getenv",
        return_value=None,
    ), mock.patch(
        "subprocess.call",
    ) as mock_subprocess_call:
        exit_code: int = pip_review.main([arg, "--continue-on-fail"])

    assert caplog.record_tuples == [
        ("pip-review", 20, "test1==1.1.0 is available (you have 1.0.0)"),
        (
            "pip-review",
            20,
            "test2==2.0.0 is available (you have 1.9.9)",
        ),
    ]
    expected_calls: list[mock._Call] = [
        mock.call(
            [
                *PIP_CMD,
                "install",
                "-U",
                "test1",
            ],
            stdout=sys.stdout,
            stderr=sys.stderr,
        ),
        mock.call(
            [
                *PIP_CMD,
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
    caplog: pytest.LogCaptureFixture,
    sample_subprocess_output: bytes,
    user_input: str,
    arg: str,
) -> None:
    with mock.patch(
        "subprocess.check_output",
        return_value=sample_subprocess_output,
    ), mock.patch(
        "pip_manage.pip_review._upgrade_prompter.ask",
        return_value=user_input,
    ), mock.patch(
        "os.getenv",
        return_value=None,
    ), mock.patch(
        "subprocess.call",
    ) as mock_subprocess_call:
        exit_code: int = pip_review.main([arg])

    assert caplog.record_tuples == [
        ("pip-review", 20, "test1==1.1.0 is available (you have 1.0.0)"),
        (
            "pip-review",
            20,
            "test2==2.0.0 is available (you have 1.9.9)",
        ),
    ]
    mock_subprocess_call.assert_not_called()
    assert exit_code == 0


@pytest.mark.parametrize("user_input", ["y", "a"])
@pytest.mark.parametrize("arg", ["--interactive", "-i"])
def test_main_interactive_confirm_all_continue_on_fail_set_to_false_with_constraints_env_var(
    caplog: pytest.LogCaptureFixture,
    tmp_path: Path,
    sample_subprocess_output: bytes,
    user_input: str,
    arg: str,
) -> None:
    constraints_file: Path = tmp_path / "constraint.txt"
    constraints_file.write_text("test2==1.9.9.9\n", encoding="utf-8")

    with mock.patch(
        "subprocess.check_output",
        return_value=sample_subprocess_output,
    ), mock.patch(
        "pip_manage.pip_review._upgrade_prompter.ask",
        return_value=user_input,
    ), mock.patch(
        "os.getenv",
        return_value=str(constraints_file),
    ), mock.patch(
        "subprocess.call",
    ) as mock_subprocess_call:
        exit_code: int = pip_review.main([arg])

    assert caplog.record_tuples == [
        ("pip-review", 20, "test1==1.1.0 is available (you have 1.0.0)"),
        (
            "pip-review",
            20,
            "test2==2.0.0 is available (you have 1.9.9) [Constraint to 1.9.9.9]",
        ),
    ]
    expected_cmd: list[str] = [
        *PIP_CMD,
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
def test_main_interactive_confirm_all_continue_on_fail_set_to_true_with_constraints_env_var(
    caplog: pytest.LogCaptureFixture,
    tmp_path: Path,
    sample_subprocess_output: bytes,
    user_input: str,
    arg: str,
) -> None:
    constraints_file: Path = tmp_path / "constraint.txt"
    constraints_file.write_text("test2==1.9.9.9\n", encoding="utf-8")

    with mock.patch(
        "subprocess.check_output",
        return_value=sample_subprocess_output,
    ), mock.patch(
        "pip_manage.pip_review._upgrade_prompter.ask",
        return_value=user_input,
    ), mock.patch(
        "os.getenv",
        return_value=str(constraints_file),
    ), mock.patch(
        "subprocess.call",
    ) as mock_subprocess_call:
        exit_code: int = pip_review.main([arg, "--continue-on-fail"])

    assert caplog.record_tuples == [
        ("pip-review", 20, "test1==1.1.0 is available (you have 1.0.0)"),
        (
            "pip-review",
            20,
            "test2==2.0.0 is available (you have 1.9.9) [Constraint to 1.9.9.9]",
        ),
    ]
    expected_calls: list[mock._Call] = [
        mock.call(
            [
                *PIP_CMD,
                "install",
                "-U",
                "test1",
            ],
            stdout=sys.stdout,
            stderr=sys.stderr,
        ),
        mock.call(
            [
                *PIP_CMD,
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
def test_main_interactive_deny_all_with_constraints_env_var(
    caplog: pytest.LogCaptureFixture,
    tmp_path: Path,
    sample_subprocess_output: bytes,
    user_input: str,
    arg: str,
) -> None:
    constraints_file: Path = tmp_path / "constraint.txt"
    constraints_file.write_text("test2==1.9.9.9\n", encoding="utf-8")

    with mock.patch(
        "subprocess.check_output",
        return_value=sample_subprocess_output,
    ), mock.patch(
        "pip_manage.pip_review._upgrade_prompter.ask",
        return_value=user_input,
    ), mock.patch(
        "os.getenv",
        return_value=str(constraints_file),
    ), mock.patch(
        "subprocess.call",
    ) as mock_subprocess_call:
        exit_code: int = pip_review.main([arg])

    assert caplog.record_tuples == [
        ("pip-review", 20, "test1==1.1.0 is available (you have 1.0.0)"),
        (
            "pip-review",
            20,
            "test2==2.0.0 is available (you have 1.9.9) [Constraint to 1.9.9.9]",
        ),
    ]
    mock_subprocess_call.assert_not_called()
    assert exit_code == 0


@pytest.mark.parametrize("user_input", ["y", "a"])
@pytest.mark.parametrize("interactive_arg", ["--interactive", "-i"])
@pytest.mark.parametrize("constraint_arg", ["--constraint", "-c"])
def test_main_interactive_confirm_all_continue_on_fail_set_to_false_with_positional_arg_constraints_file(
    caplog: pytest.LogCaptureFixture,
    tmp_path: Path,
    sample_subprocess_output: bytes,
    user_input: str,
    interactive_arg: str,
    constraint_arg: str,
) -> None:
    constraints_file: Path = tmp_path / "constraint.txt"
    constraints_file.write_text("test2==1.9.9.9\n", encoding="utf-8")

    with mock.patch(
        "subprocess.check_output",
        return_value=sample_subprocess_output,
    ), mock.patch(
        "pip_manage.pip_review._upgrade_prompter.ask",
        return_value=user_input,
    ), mock.patch(
        "os.getenv",
        return_value=None,
    ), mock.patch(
        "subprocess.call",
    ) as mock_subprocess_call:
        exit_code: int = pip_review.main(
            [interactive_arg, constraint_arg, str(constraints_file)],
        )

    assert caplog.record_tuples == [
        ("pip-review", 20, "test1==1.1.0 is available (you have 1.0.0)"),
        (
            "pip-review",
            20,
            "test2==2.0.0 is available (you have 1.9.9) [Constraint to 1.9.9.9]",
        ),
    ]
    expected_cmd: list[str] = [
        *PIP_CMD,
        "install",
        "-U",
        constraint_arg,
        str(constraints_file),
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
@pytest.mark.parametrize("interactive_arg", ["--interactive", "-i"])
@pytest.mark.parametrize("constraint_arg", ["--constraint", "-c"])
def test_main_interactive_confirm_all_continue_on_fail_set_to_true_with_positional_arg_constraints_file(
    caplog: pytest.LogCaptureFixture,
    tmp_path: Path,
    sample_subprocess_output: bytes,
    user_input: str,
    interactive_arg: str,
    constraint_arg: str,
) -> None:
    constraints_file: Path = tmp_path / "constraint.txt"
    constraints_file.write_text("test2==1.9.9.9\n", encoding="utf-8")

    with mock.patch(
        "subprocess.check_output",
        return_value=sample_subprocess_output,
    ), mock.patch(
        "pip_manage.pip_review._upgrade_prompter.ask",
        return_value=user_input,
    ), mock.patch(
        "os.getenv",
        return_value=None,
    ), mock.patch(
        "subprocess.call",
    ) as mock_subprocess_call:
        exit_code: int = pip_review.main(
            [
                "--continue-on-fail",
                interactive_arg,
                constraint_arg,
                str(constraints_file),
            ],
        )

    assert caplog.record_tuples == [
        ("pip-review", 20, "test1==1.1.0 is available (you have 1.0.0)"),
        (
            "pip-review",
            20,
            "test2==2.0.0 is available (you have 1.9.9) [Constraint to 1.9.9.9]",
        ),
    ]
    expected_calls: list[mock._Call] = [
        mock.call(
            [
                *PIP_CMD,
                "install",
                "-U",
                constraint_arg,
                str(constraints_file),
                "test1",
            ],
            stdout=sys.stdout,
            stderr=sys.stderr,
        ),
        mock.call(
            [
                *PIP_CMD,
                "install",
                "-U",
                constraint_arg,
                str(constraints_file),
                "test2",
            ],
            stdout=sys.stdout,
            stderr=sys.stderr,
        ),
    ]
    mock_subprocess_call.assert_has_calls(expected_calls)
    assert exit_code == 0


@pytest.mark.parametrize("user_input", ["n", "q"])
@pytest.mark.parametrize("interactive_arg", ["--interactive", "-i"])
@pytest.mark.parametrize("constraint_arg", ["--constraint", "-c"])
def test_main_interactive_deny_all_with_positional_arg_constraints_file(
    caplog: pytest.LogCaptureFixture,
    tmp_path: Path,
    sample_subprocess_output: bytes,
    user_input: str,
    interactive_arg: str,
    constraint_arg: str,
) -> None:
    constraints_file: Path = tmp_path / "constraint.txt"
    constraints_file.write_text("test2==1.9.9.9\n", encoding="utf-8")

    with mock.patch(
        "subprocess.check_output",
        return_value=sample_subprocess_output,
    ), mock.patch(
        "pip_manage.pip_review._upgrade_prompter.ask",
        return_value=user_input,
    ), mock.patch(
        "os.getenv",
        return_value=str(constraints_file),
    ), mock.patch(
        "subprocess.call",
    ) as mock_subprocess_call:
        exit_code: int = pip_review.main(
            [
                interactive_arg,
                constraint_arg,
                str(constraints_file),
            ],
        )

    assert caplog.record_tuples == [
        ("pip-review", 20, "test1==1.1.0 is available (you have 1.0.0)"),
        (
            "pip-review",
            20,
            "test2==2.0.0 is available (you have 1.9.9) [Constraint to 1.9.9.9]",
        ),
    ]
    mock_subprocess_call.assert_not_called()
    assert exit_code == 0


@pytest.mark.parametrize("user_input", ["y", "a"])
@pytest.mark.parametrize("interactive_arg", ["--interactive", "-i"])
@pytest.mark.parametrize("constraint_arg", ["--constraint", "-c"])
def test_main_interactive_confirm_all_continue_on_fail_set_to_false_with_named_arg_constraints_file(
    caplog: pytest.LogCaptureFixture,
    tmp_path: Path,
    sample_subprocess_output: bytes,
    user_input: str,
    interactive_arg: str,
    constraint_arg: str,
) -> None:
    constraints_file: Path = tmp_path / "constraint.txt"
    constraints_file.write_text("test2==1.9.9.9\n", encoding="utf-8")

    with mock.patch(
        "subprocess.check_output",
        return_value=sample_subprocess_output,
    ), mock.patch(
        "pip_manage.pip_review._upgrade_prompter.ask",
        return_value=user_input,
    ), mock.patch(
        "os.getenv",
        return_value=None,
    ), mock.patch(
        "subprocess.call",
    ) as mock_subprocess_call:
        exit_code: int = pip_review.main(
            [interactive_arg, f"{constraint_arg}={constraints_file}"],
        )

    assert caplog.record_tuples == [
        ("pip-review", 20, "test1==1.1.0 is available (you have 1.0.0)"),
        (
            "pip-review",
            20,
            "test2==2.0.0 is available (you have 1.9.9) [Constraint to 1.9.9.9]",
        ),
    ]
    expected_cmd: list[str] = [
        *PIP_CMD,
        "install",
        "-U",
        f"{constraint_arg}={constraints_file}",
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
@pytest.mark.parametrize("interactive_arg", ["--interactive", "-i"])
@pytest.mark.parametrize("constraint_arg", ["--constraint", "-c"])
def test_main_interactive_confirm_all_continue_on_fail_set_to_true_with_named_arg_constraints_file(
    caplog: pytest.LogCaptureFixture,
    tmp_path: Path,
    sample_subprocess_output: bytes,
    user_input: str,
    interactive_arg: str,
    constraint_arg: str,
) -> None:
    constraints_file: Path = tmp_path / "constraint.txt"
    constraints_file.write_text("test2==1.9.9.9\n", encoding="utf-8")

    with mock.patch(
        "subprocess.check_output",
        return_value=sample_subprocess_output,
    ), mock.patch(
        "pip_manage.pip_review._upgrade_prompter.ask",
        return_value=user_input,
    ), mock.patch(
        "os.getenv",
        return_value=None,
    ), mock.patch(
        "subprocess.call",
    ) as mock_subprocess_call:
        exit_code: int = pip_review.main(
            [
                "--continue-on-fail",
                interactive_arg,
                f"{constraint_arg}={constraints_file}",
            ],
        )

    assert caplog.record_tuples == [
        ("pip-review", 20, "test1==1.1.0 is available (you have 1.0.0)"),
        (
            "pip-review",
            20,
            "test2==2.0.0 is available (you have 1.9.9) [Constraint to 1.9.9.9]",
        ),
    ]
    expected_calls: list[mock._Call] = [
        mock.call(
            [
                *PIP_CMD,
                "install",
                "-U",
                f"{constraint_arg}={constraints_file}",
                "test1",
            ],
            stdout=sys.stdout,
            stderr=sys.stderr,
        ),
        mock.call(
            [
                *PIP_CMD,
                "install",
                "-U",
                f"{constraint_arg}={constraints_file}",
                "test2",
            ],
            stdout=sys.stdout,
            stderr=sys.stderr,
        ),
    ]
    mock_subprocess_call.assert_has_calls(expected_calls)
    assert exit_code == 0


@pytest.mark.parametrize("user_input", ["n", "q"])
@pytest.mark.parametrize("interactive_arg", ["--interactive", "-i"])
@pytest.mark.parametrize("constraint_arg", ["--constraint", "-c"])
def test_main_interactive_deny_all_with_named_arg_constraints_file(
    caplog: pytest.LogCaptureFixture,
    tmp_path: Path,
    sample_subprocess_output: bytes,
    user_input: str,
    interactive_arg: str,
    constraint_arg: str,
) -> None:
    constraints_file: Path = tmp_path / "constraint.txt"
    constraints_file.write_text("test2==1.9.9.9\n", encoding="utf-8")

    with mock.patch(
        "subprocess.check_output",
        return_value=sample_subprocess_output,
    ), mock.patch(
        "pip_manage.pip_review._upgrade_prompter.ask",
        return_value=user_input,
    ), mock.patch(
        "os.getenv",
        return_value=str(constraints_file),
    ), mock.patch(
        "subprocess.call",
    ) as mock_subprocess_call:
        exit_code: int = pip_review.main(
            [
                interactive_arg,
                f"{constraint_arg}={constraints_file}",
            ],
        )

    assert caplog.record_tuples == [
        ("pip-review", 20, "test1==1.1.0 is available (you have 1.0.0)"),
        (
            "pip-review",
            20,
            "test2==2.0.0 is available (you have 1.9.9) [Constraint to 1.9.9.9]",
        ),
    ]
    mock_subprocess_call.assert_not_called()
    assert exit_code == 0


@pytest.mark.parametrize("user_input", ["y", "a"])
@pytest.mark.parametrize("interactive_arg", ["--interactive", "-i"])
@pytest.mark.parametrize("constraint_arg", ["--constraint", "-c"])
def test_main_interactive_confirm_all_continue_on_fail_set_to_false_with_positional_arg_constraints_file_and_constraints_env_var(
    caplog: pytest.LogCaptureFixture,
    tmp_path: Path,
    sample_subprocess_output: bytes,
    user_input: str,
    interactive_arg: str,
    constraint_arg: str,
) -> None:
    constraints_file1: Path = tmp_path / "constraint1.txt"
    constraints_file1.write_text("test2==1.9.9.8\n", encoding="utf-8")
    constraints_file2: Path = tmp_path / "constraint2.txt"
    constraints_file2.write_text("test2==1.9.9.9\n", encoding="utf-8")

    with mock.patch(
        "subprocess.check_output",
        return_value=sample_subprocess_output,
    ), mock.patch(
        "pip_manage.pip_review._upgrade_prompter.ask",
        return_value=user_input,
    ), mock.patch(
        "os.getenv",
        return_value=str(constraints_file1),
    ), mock.patch(
        "subprocess.call",
    ) as mock_subprocess_call:
        exit_code: int = pip_review.main(
            [interactive_arg, constraint_arg, str(constraints_file2)],
        )

    assert caplog.record_tuples == [
        ("pip-review", 20, "test1==1.1.0 is available (you have 1.0.0)"),
        (
            "pip-review",
            20,
            "test2==2.0.0 is available (you have 1.9.9) [Constraint to 1.9.9.8, 1.9.9.9]",
        ),
    ]
    expected_cmd: list[str] = [
        *PIP_CMD,
        "install",
        "-U",
        constraint_arg,
        str(constraints_file2),
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
@pytest.mark.parametrize("interactive_arg", ["--interactive", "-i"])
@pytest.mark.parametrize("constraint_arg", ["--constraint", "-c"])
def test_main_interactive_confirm_all_continue_on_fail_set_to_true_with_positional_arg_constraints_file_and_constraints_env_var(
    caplog: pytest.LogCaptureFixture,
    tmp_path: Path,
    sample_subprocess_output: bytes,
    user_input: str,
    interactive_arg: str,
    constraint_arg: str,
) -> None:
    constraints_file1: Path = tmp_path / "constraint1.txt"
    constraints_file1.write_text("test2==1.9.9.8\n", encoding="utf-8")
    constraints_file2: Path = tmp_path / "constraint2.txt"
    constraints_file2.write_text("test2==1.9.9.9\n", encoding="utf-8")

    with mock.patch(
        "subprocess.check_output",
        return_value=sample_subprocess_output,
    ), mock.patch(
        "pip_manage.pip_review._upgrade_prompter.ask",
        return_value=user_input,
    ), mock.patch(
        "os.getenv",
        return_value=str(constraints_file1),
    ), mock.patch(
        "subprocess.call",
    ) as mock_subprocess_call:
        exit_code: int = pip_review.main(
            [
                "--continue-on-fail",
                interactive_arg,
                constraint_arg,
                str(constraints_file2),
            ],
        )

    assert caplog.record_tuples == [
        ("pip-review", 20, "test1==1.1.0 is available (you have 1.0.0)"),
        (
            "pip-review",
            20,
            "test2==2.0.0 is available (you have 1.9.9) [Constraint to 1.9.9.8, 1.9.9.9]",
        ),
    ]
    expected_calls: list[mock._Call] = [
        mock.call(
            [
                *PIP_CMD,
                "install",
                "-U",
                constraint_arg,
                str(constraints_file2),
                "test1",
            ],
            stdout=sys.stdout,
            stderr=sys.stderr,
        ),
        mock.call(
            [
                *PIP_CMD,
                "install",
                "-U",
                constraint_arg,
                str(constraints_file2),
                "test2",
            ],
            stdout=sys.stdout,
            stderr=sys.stderr,
        ),
    ]
    mock_subprocess_call.assert_has_calls(expected_calls)
    assert exit_code == 0


@pytest.mark.parametrize("user_input", ["n", "q"])
@pytest.mark.parametrize("interactive_arg", ["--interactive", "-i"])
@pytest.mark.parametrize("constraint_arg", ["--constraint", "-c"])
def test_main_interactive_deny_all_with_positional_arg_constraints_file_and_constraints_env_var(
    caplog: pytest.LogCaptureFixture,
    tmp_path: Path,
    sample_subprocess_output: bytes,
    user_input: str,
    interactive_arg: str,
    constraint_arg: str,
) -> None:
    constraints_file1: Path = tmp_path / "constraint1.txt"
    constraints_file1.write_text("test2==1.9.9.8\n", encoding="utf-8")
    constraints_file2: Path = tmp_path / "constraint2.txt"
    constraints_file2.write_text("test2==1.9.9.9\n", encoding="utf-8")

    with mock.patch(
        "subprocess.check_output",
        return_value=sample_subprocess_output,
    ), mock.patch(
        "pip_manage.pip_review._upgrade_prompter.ask",
        return_value=user_input,
    ), mock.patch(
        "os.getenv",
        return_value=str(constraints_file1),
    ), mock.patch(
        "subprocess.call",
    ) as mock_subprocess_call:
        exit_code: int = pip_review.main(
            [
                interactive_arg,
                constraint_arg,
                str(constraints_file2),
            ],
        )

    assert caplog.record_tuples == [
        ("pip-review", 20, "test1==1.1.0 is available (you have 1.0.0)"),
        (
            "pip-review",
            20,
            "test2==2.0.0 is available (you have 1.9.9) [Constraint to 1.9.9.8, 1.9.9.9]",
        ),
    ]
    mock_subprocess_call.assert_not_called()
    assert exit_code == 0


@pytest.mark.parametrize("user_input", ["y", "a"])
@pytest.mark.parametrize("interactive_arg", ["--interactive", "-i"])
@pytest.mark.parametrize("constraint_arg", ["--constraint", "-c"])
def test_main_interactive_confirm_all_continue_on_fail_set_to_false_with_named_arg_constraints_file_and_constraints_env_var(
    caplog: pytest.LogCaptureFixture,
    tmp_path: Path,
    sample_subprocess_output: bytes,
    user_input: str,
    interactive_arg: str,
    constraint_arg: str,
) -> None:
    constraints_file1: Path = tmp_path / "constraint1.txt"
    constraints_file1.write_text("test2==1.9.9.8\n", encoding="utf-8")
    constraints_file2: Path = tmp_path / "constraint2.txt"
    constraints_file2.write_text("test2==1.9.9.9\n", encoding="utf-8")

    with mock.patch(
        "subprocess.check_output",
        return_value=sample_subprocess_output,
    ), mock.patch(
        "pip_manage.pip_review._upgrade_prompter.ask",
        return_value=user_input,
    ), mock.patch(
        "os.getenv",
        return_value=str(constraints_file1),
    ), mock.patch(
        "subprocess.call",
    ) as mock_subprocess_call:
        exit_code: int = pip_review.main(
            [interactive_arg, f"{constraint_arg}={constraints_file2}"],
        )

    assert caplog.record_tuples == [
        ("pip-review", 20, "test1==1.1.0 is available (you have 1.0.0)"),
        (
            "pip-review",
            20,
            "test2==2.0.0 is available (you have 1.9.9) [Constraint to 1.9.9.8, 1.9.9.9]",
        ),
    ]
    expected_cmd: list[str] = [
        *PIP_CMD,
        "install",
        "-U",
        f"{constraint_arg}={constraints_file2}",
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
@pytest.mark.parametrize("interactive_arg", ["--interactive", "-i"])
@pytest.mark.parametrize("constraint_arg", ["--constraint", "-c"])
def test_main_interactive_confirm_all_continue_on_fail_set_to_true_with_named_arg_constraints_file_and_constraints_env_var(
    caplog: pytest.LogCaptureFixture,
    tmp_path: Path,
    sample_subprocess_output: bytes,
    user_input: str,
    interactive_arg: str,
    constraint_arg: str,
) -> None:
    constraints_file1: Path = tmp_path / "constraint1.txt"
    constraints_file1.write_text("test2==1.9.9.8\n", encoding="utf-8")
    constraints_file2: Path = tmp_path / "constraint2.txt"
    constraints_file2.write_text("test2==1.9.9.9\n", encoding="utf-8")

    with mock.patch(
        "subprocess.check_output",
        return_value=sample_subprocess_output,
    ), mock.patch(
        "pip_manage.pip_review._upgrade_prompter.ask",
        return_value=user_input,
    ), mock.patch(
        "os.getenv",
        return_value=str(constraints_file1),
    ), mock.patch(
        "subprocess.call",
    ) as mock_subprocess_call:
        exit_code: int = pip_review.main(
            [
                "--continue-on-fail",
                interactive_arg,
                f"{constraint_arg}={constraints_file2}",
            ],
        )

    assert caplog.record_tuples == [
        ("pip-review", 20, "test1==1.1.0 is available (you have 1.0.0)"),
        (
            "pip-review",
            20,
            "test2==2.0.0 is available (you have 1.9.9) [Constraint to 1.9.9.8, 1.9.9.9]",
        ),
    ]
    expected_calls: list[mock._Call] = [
        mock.call(
            [
                *PIP_CMD,
                "install",
                "-U",
                f"{constraint_arg}={constraints_file2}",
                "test1",
            ],
            stdout=sys.stdout,
            stderr=sys.stderr,
        ),
        mock.call(
            [
                *PIP_CMD,
                "install",
                "-U",
                f"{constraint_arg}={constraints_file2}",
                "test2",
            ],
            stdout=sys.stdout,
            stderr=sys.stderr,
        ),
    ]
    mock_subprocess_call.assert_has_calls(expected_calls)
    assert exit_code == 0


@pytest.mark.parametrize("user_input", ["n", "q"])
@pytest.mark.parametrize("interactive_arg", ["--interactive", "-i"])
@pytest.mark.parametrize("constraint_arg", ["--constraint", "-c"])
def test_main_interactive_deny_all_with_named_arg_constraints_file_and_constraints_env_var(
    caplog: pytest.LogCaptureFixture,
    tmp_path: Path,
    sample_subprocess_output: bytes,
    user_input: str,
    interactive_arg: str,
    constraint_arg: str,
) -> None:
    constraints_file1: Path = tmp_path / "constraint1.txt"
    constraints_file1.write_text("test2==1.9.9.8\n", encoding="utf-8")
    constraints_file2: Path = tmp_path / "constraint2.txt"
    constraints_file2.write_text("test2==1.9.9.9\n", encoding="utf-8")

    with mock.patch(
        "subprocess.check_output",
        return_value=sample_subprocess_output,
    ), mock.patch(
        "pip_manage.pip_review._upgrade_prompter.ask",
        return_value=user_input,
    ), mock.patch(
        "os.getenv",
        return_value=str(constraints_file1),
    ), mock.patch(
        "subprocess.call",
    ) as mock_subprocess_call:
        exit_code: int = pip_review.main(
            [
                interactive_arg,
                f"{constraint_arg}={constraints_file2}",
            ],
        )

    assert caplog.record_tuples == [
        ("pip-review", 20, "test1==1.1.0 is available (you have 1.0.0)"),
        (
            "pip-review",
            20,
            "test2==2.0.0 is available (you have 1.9.9) [Constraint to 1.9.9.8, 1.9.9.9]",
        ),
    ]
    mock_subprocess_call.assert_not_called()
    assert exit_code == 0


if __name__ == "__main__":
    raise SystemExit(pytest.main())
