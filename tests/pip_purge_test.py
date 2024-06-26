#!/usr/bin/env python3
from __future__ import annotations

import argparse
import importlib.metadata
import logging
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import pytest

from pip_manage import pip_purge
from pip_manage._pip_interface import PIP_CMD
from tests.fixtures import (  # pylint: disable=W0611
    _keep_pytest_handlers_during_dict_config,
    dummy_dependencies,
)

# pylint: disable=C0302


def _raise_package_not_found_error_when_package_c(package: str) -> None:
    if package == "package_c":
        raise importlib.metadata.PackageNotFoundError


def _custom_importlib_metadata_distribution(
    package: str,
    dummy: list[SimpleNamespace],
) -> SimpleNamespace:
    for dummy_package in dummy:
        if dummy_package.name == package:
            return dummy_package
    raise importlib.metadata.PackageNotFoundError


@pytest.mark.parametrize(
    ("constant", "expected"),
    [
        pytest.param(
            pip_purge._EPILOG,
            """
Unrecognised arguments will be forwarded to 'pip uninstall' (if supported),
so you can pass things such as '--yes' and '--break-system-packages' and
they will do what you expect. See 'pip uninstall -h' for a full overview of the options.
""",
            id="_EPILOG",
        ),
    ],
)
def test_constants(
    constant: str | frozenset[str] | tuple[str, ...],
    expected: str | frozenset[str] | tuple[str, ...],
) -> None:
    assert constant == expected


def test_parse_args_empty_args() -> None:
    assert pip_purge._parse_args([]) == (
        argparse.Namespace(
            packages=[],
            requirements=[],
            debugging=False,
            ignore_extra=False,
            continue_on_fail=False,
            exclude=[],
            dry_run=False,
            freeze_purged_packages=False,
            freeze_file=Path("backup.txt").resolve(),
        ),
        [],
    )


@pytest.mark.parametrize(
    ("args", "field"),
    [
        pytest.param(["--debug"], "debugging", id="--debug"),
        pytest.param(["-d"], "debugging", id="-d"),
        pytest.param(["--ignore-extra"], "ignore_extra", id="--ignore-extra"),
        pytest.param(
            ["--continue-on-fail"],
            "continue_on_fail",
            id="--continue-on-fail",
        ),
        pytest.param(["--dry-run"], "dry_run", id="--dry-run"),
        pytest.param(
            ["--freeze-purged-packages"],
            "freeze_purged_packages",
            id="--freeze-purged-packages",
        ),
    ],
)
def test_parse_args_flags_with_set_to_true(args: list[str], field: str) -> None:
    assert getattr(
        pip_purge._parse_args(args)[0],
        field,
    )


@pytest.mark.parametrize(("field"), ["packages", "requirements", "exclude"])
def test_parse_args_list_args_with_bo_args(
    field: str,
) -> None:
    assert getattr(pip_purge._parse_args([])[0], field) == []


@pytest.mark.parametrize(
    ("args", "field", "expected"),
    [
        (["test"], "packages", ["test"]),
        (["test1", "test2"], "packages", ["test1", "test2"]),
        (["--requirement", "test.txt"], "requirements", [Path("test.txt").resolve()]),
        (["-r", "test.txt"], "requirements", [Path("test.txt").resolve()]),
        (
            ["--requirement", "test1.txt", "--requirement", "test2.txt"],
            "requirements",
            [Path("test1.txt").resolve(), Path("test2.txt").resolve()],
        ),
        (
            ["-r", "test1.txt", "-r", "test2.txt"],
            "requirements",
            [Path("test1.txt").resolve(), Path("test2.txt").resolve()],
        ),
        (["--exclude", "test"], "exclude", ["test"]),
        (["--exclude", "test1", "--exclude", "test2"], "exclude", ["test1", "test2"]),
    ],
)
def test_parse_args_list_args(
    args: list[str],
    field: str,
    expected: list[str] | list[Path],
) -> None:
    assert getattr(pip_purge._parse_args(args)[0], field) == expected


@pytest.mark.parametrize("arg", ["--freeze-file", "-f"])
def test_parse_args_freeze_file(tmp_path: Path, arg: str) -> None:
    tmp_file: str = str(tmp_path / "backup.txt")
    args: list[str] = [f"{arg}={tmp_file}"]
    assert pip_purge._parse_args(args)[0].freeze_file == tmp_path / "backup.txt"


@pytest.mark.parametrize("arg", ["--freeze-file", "-f"])
def test_parse_args_freeze_file_separated_args(tmp_path: Path, arg: str) -> None:
    tmp_file: str = str(tmp_path / "backup.txt")
    args: list[str] = [arg, tmp_file]
    assert pip_purge._parse_args(args)[0].freeze_file == tmp_path / "backup.txt"


@pytest.mark.parametrize(
    ("args", "expected"),
    [
        pytest.param([], []),
        pytest.param(["--ignore-extra"], []),
        pytest.param(["--test"], ["--test"]),
        pytest.param(["--ignore-extra", "--test"], ["--test"]),
        pytest.param(["--test1", "--test2"], ["--test1", "--test2"]),
        pytest.param(["--test2", "--test1"], ["--test2", "--test1"]),
    ],
)
def test_parse_args_unknown_args(args: list[str], expected: list[str]) -> None:
    assert pip_purge._parse_args(args)[1] == expected


def test_is_installed_with_mocked_package_not_found_error() -> None:
    with mock.patch("importlib.metadata.distribution") as mock_distribution:
        mock_distribution.side_effect = importlib.metadata.PackageNotFoundError
        assert not pip_purge._is_installed("test")


def test_is_installed_with_mocked_package_found() -> None:
    with mock.patch("importlib.metadata.distribution"):
        assert pip_purge._is_installed("test")


def test_parse_distribution_requirements_without_ignoring_extra() -> None:
    with mock.patch(
        "importlib.metadata.distribution",
        side_effect=_raise_package_not_found_error_when_package_c,
    ):
        assert pip_purge._get_distribution_requirements(
            [
                "package_a",
                "package_b <2.0,>=1.4",
                'package_c ; python_version < "3.11"',
                "package_d ; extra == 'testing'",
            ],
            ignore_extra=False,
        ) == frozenset(("package_a", "package_b", "package_d"))


def test_parse_distribution_requirements_ignoring_extra() -> None:
    with mock.patch(
        "importlib.metadata.distribution",
        side_effect=_raise_package_not_found_error_when_package_c,
    ):
        assert pip_purge._get_distribution_requirements(
            [
                "package_a",
                "package_b <2.0,>=1.4",
                'package_c ; python_version < "3.11"',
                "package_d ; extra == 'testing'",
            ],
            ignore_extra=True,
        ) == frozenset(("package_a", "package_b"))


def test_get_required_by_without_ignoring_extra(
    dummy_dependencies: list[SimpleNamespace],
) -> None:
    with mock.patch(
        "importlib.metadata.distributions",
        return_value=dummy_dependencies,
    ), mock.patch(
        "importlib.metadata.distribution",
        side_effect=_raise_package_not_found_error_when_package_c,
    ):
        assert pip_purge._get_required_by(
            dummy_dependencies[0].name,
            ignore_extra=False,
        ) == frozenset(("package_e",))
        assert pip_purge._get_required_by(
            dummy_dependencies[1].name,
            ignore_extra=False,
        ) == frozenset(("package_a",))
        assert (
            pip_purge._get_required_by(
                dummy_dependencies[2].name,
                ignore_extra=False,
            )
            == frozenset()
        )
        assert (
            pip_purge._get_required_by(
                dummy_dependencies[3].name,
                ignore_extra=False,
            )
            == frozenset()
        )
        assert pip_purge._get_required_by(
            dummy_dependencies[4].name,
            ignore_extra=False,
        ) == frozenset(("package_a", "package_b"))


def test_get_required_by_with_ignoring_extra(
    dummy_dependencies: list[SimpleNamespace],
) -> None:
    with mock.patch(
        "importlib.metadata.distributions",
        return_value=dummy_dependencies,
    ), mock.patch(
        "importlib.metadata.distribution",
        side_effect=_raise_package_not_found_error_when_package_c,
    ):
        assert pip_purge._get_required_by(
            dummy_dependencies[0].name,
            ignore_extra=True,
        ) == frozenset(("package_e",))
        assert pip_purge._get_required_by(
            dummy_dependencies[1].name,
            ignore_extra=True,
        ) == frozenset(("package_a",))
        assert (
            pip_purge._get_required_by(
                dummy_dependencies[2].name,
                ignore_extra=True,
            )
            == frozenset()
        )
        assert (
            pip_purge._get_required_by(
                dummy_dependencies[3].name,
                ignore_extra=True,
            )
            == frozenset()
        )
        assert pip_purge._get_required_by(
            dummy_dependencies[4].name,
            ignore_extra=True,
        ) == frozenset(())


def test_get_dependencies_of_package_without_ignoring_extra(
    dummy_dependencies: list[SimpleNamespace],
) -> None:
    with mock.patch(
        "importlib.metadata.distributions",
        return_value=dummy_dependencies,
    ), mock.patch(
        "importlib.metadata.distribution",
        side_effect=lambda package: _custom_importlib_metadata_distribution(
            package,
            dummy_dependencies,
        ),
    ):
        assert pip_purge._get_dependencies_of_package(
            dummy_dependencies[0].name,
            ignore_extra=False,
        ) == pip_purge._DependencyInfo(
            dependencies=frozenset({"package_e", "package_b"}),
            dependents=frozenset({"package_e"}),
        )
        assert pip_purge._get_dependencies_of_package(
            dummy_dependencies[1].name,
            ignore_extra=False,
        ) == pip_purge._DependencyInfo(
            dependencies=frozenset({"package_e"}),
            dependents=frozenset({"package_a"}),
        )
        assert pip_purge._get_dependencies_of_package(
            dummy_dependencies[2].name,
            ignore_extra=False,
        ) == pip_purge._DependencyInfo(
            dependencies=frozenset(),
            dependents=frozenset(),
        )
        assert pip_purge._get_dependencies_of_package(
            dummy_dependencies[3].name,
            ignore_extra=False,
        ) == pip_purge._DependencyInfo(
            dependencies=frozenset(),
            dependents=frozenset(),
        )
        assert pip_purge._get_dependencies_of_package(
            dummy_dependencies[4].name,
            ignore_extra=False,
        ) == pip_purge._DependencyInfo(
            dependencies=frozenset({"package_a"}),
            dependents=frozenset({"package_a", "package_b"}),
        )


def test_get_dependencies_of_package_with_ignoring_extra(
    dummy_dependencies: list[SimpleNamespace],
) -> None:
    with mock.patch(
        "importlib.metadata.distributions",
        return_value=dummy_dependencies,
    ), mock.patch(
        "importlib.metadata.distribution",
        side_effect=lambda package: _custom_importlib_metadata_distribution(
            package,
            dummy_dependencies,
        ),
    ):
        assert pip_purge._get_dependencies_of_package(
            dummy_dependencies[0].name,
            ignore_extra=True,
        ) == pip_purge._DependencyInfo(
            dependencies=frozenset({"package_b"}),
            dependents=frozenset({"package_e"}),
        )
        assert pip_purge._get_dependencies_of_package(
            dummy_dependencies[1].name,
            ignore_extra=True,
        ) == pip_purge._DependencyInfo(
            dependencies=frozenset(),
            dependents=frozenset({"package_a"}),
        )
        assert pip_purge._get_dependencies_of_package(
            dummy_dependencies[2].name,
            ignore_extra=True,
        ) == pip_purge._DependencyInfo(
            dependencies=frozenset(),
            dependents=frozenset(),
        )
        assert pip_purge._get_dependencies_of_package(
            dummy_dependencies[3].name,
            ignore_extra=True,
        ) == pip_purge._DependencyInfo(
            dependencies=frozenset(),
            dependents=frozenset(),
        )
        assert pip_purge._get_dependencies_of_package(
            dummy_dependencies[4].name,
            ignore_extra=True,
        ) == pip_purge._DependencyInfo(
            dependencies=frozenset({"package_a"}),
            dependents=frozenset(),
        )


def test_freeze_packages(tmp_path: Path) -> None:
    packages: list[str] = ["package_a", "package_b"]
    tmp_file: Path = tmp_path / "requirements.txt"
    tmp_file.touch()
    with mock.patch(
        "importlib.metadata.distribution",
        return_value=SimpleNamespace(version="1.0.0"),
    ):
        pip_purge._freeze_packages(tmp_file, packages)
    assert (
        tmp_file.read_text(encoding="utf-8") == "package_a==1.0.0\npackage_b==1.0.0\n"
    )


@pytest.mark.parametrize(
    ("requirement", "package_name"),
    [
        ("package_a", "package_a"),
        ("package_b <2.0,>=1.4", "package_b"),
        ("package_c <2.0,>=1.4;python_version<'3.11'", "package_c"),
        ("package_d!=3.0", "package_d"),
        ("package_e  # comment", "package_e"),
        ("  package_f  ", "package_f"),
    ],
)
def test_extract_package_from_requirements_file_line(
    requirement: str,
    package_name: str,
) -> None:
    assert (
        pip_purge._extract_package_from_requirements_file_line(requirement)
        == package_name
    )


def test_read_requirements(tmp_path: Path) -> None:
    tmp_file1: Path = tmp_path / "requirements1.txt"
    tmp_file1.write_text("package_a<2.0,>=1.4\npackage_b;python_version<'3.11'\n")
    tmp_file2: Path = tmp_path / "requirements2.txt"
    tmp_file2.write_text("package_c\n#test\npackage_d!=3.0\n")
    assert pip_purge._read_from_requirements([tmp_file1, tmp_file2]) == [
        "package_a",
        "package_b",
        "package_c",
        "package_d",
    ]


@pytest.mark.parametrize("arg", ["--debug", "-d"])
def test_main_verbose_flag_sets_logger_level_to_debug(
    dummy_dependencies: list[SimpleNamespace],
    arg: str,
) -> None:
    with mock.patch(
        "importlib.metadata.distribution",
        side_effect=lambda package: _custom_importlib_metadata_distribution(
            package,
            dummy_dependencies,
        ),
    ), mock.patch(
        "importlib.metadata.distributions",
        return_value=dummy_dependencies,
    ), mock.patch(
        "subprocess.call",
    ) as mock_subprocess_call:
        exit_code: int = pip_purge.main(["package_a", arg])
    assert logging.getLogger("pip-purge").level == logging.DEBUG
    mock_subprocess_call.assert_called_once_with(
        [*PIP_CMD, "uninstall", "package_a", "package_b", "package_e"],
        stdout=sys.stdout,
        stderr=sys.stderr,
    )
    assert exit_code == 0


def test_main_no_verbose_flag_sets_logger_level_to_info(
    dummy_dependencies: list[SimpleNamespace],
) -> None:
    with mock.patch(
        "importlib.metadata.distribution",
        side_effect=lambda package: _custom_importlib_metadata_distribution(
            package,
            dummy_dependencies,
        ),
    ), mock.patch(
        "importlib.metadata.distributions",
        return_value=dummy_dependencies,
    ), mock.patch(
        "subprocess.call",
    ) as mock_subprocess_call:
        exit_code: int = pip_purge.main(["package_a"])
    assert logging.getLogger("pip-purge").level == logging.INFO
    mock_subprocess_call.assert_called_once_with(
        [*PIP_CMD, "uninstall", "package_a", "package_b", "package_e"],
        stdout=sys.stdout,
        stderr=sys.stderr,
    )
    assert exit_code == 0


def test_main_error_exit_when_no_packages_provided(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with mock.patch(
        "importlib.metadata.distribution",
    ), mock.patch(
        "importlib.metadata.distributions",
    ), mock.patch(
        "subprocess.call",
    ) as mock_subprocess_call:
        exit_code: int = pip_purge.main([])
    assert caplog.record_tuples == [
        (
            "pip-purge",
            40,
            "\x1b[0;31mERROR: You must give at least one requirement to "
            "uninstall\x1b[0m",
        ),
    ]
    mock_subprocess_call.assert_not_called()
    assert exit_code == 1


def test_main_warn_about_unrecognized_args_before_error_exit_when_no_packages_provided(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with mock.patch(
        "importlib.metadata.distribution",
    ), mock.patch(
        "importlib.metadata.distributions",
    ), mock.patch(
        "subprocess.call",
    ) as mock_subprocess_call:
        exit_code: int = pip_purge.main(["-d", "-a", "-b", "-y"])
    assert (
        "pip-purge",
        30,
        "\x1b[0;33mWARNING: Unrecognized arguments: '-a', '-b'\x1b[0m",
    ) in caplog.record_tuples
    assert (
        "pip-purge",
        40,
        "\x1b[0;31mERROR: You must give at least one requirement to "
        "uninstall\x1b[0m",
    ) in caplog.record_tuples
    mock_subprocess_call.assert_not_called()
    assert exit_code == 1


def test_main_warn_about_unrecognized_args(
    caplog: pytest.LogCaptureFixture,
    dummy_dependencies: list[SimpleNamespace],
) -> None:
    with mock.patch(
        "importlib.metadata.distribution",
        side_effect=lambda package: _custom_importlib_metadata_distribution(
            package,
            dummy_dependencies,
        ),
    ), mock.patch(
        "importlib.metadata.distributions",
        return_value=dummy_dependencies,
    ), mock.patch(
        "subprocess.call",
    ) as mock_subprocess_call:
        exit_code: int = pip_purge.main(["package_a", "-d", "-a", "-b", "-y"])
    assert (
        "pip-purge",
        30,
        "\x1b[0;33mWARNING: Unrecognized arguments: '-a', '-b'\x1b[0m",
    ) in caplog.record_tuples
    mock_subprocess_call.assert_called_once_with(
        [*PIP_CMD, "uninstall", "-y", "package_a", "package_b", "package_e"],
        stdout=sys.stdout,
        stderr=sys.stderr,
    )
    assert exit_code == 0


def test_main_warn_about_not_installed_packages(
    caplog: pytest.LogCaptureFixture,
    dummy_dependencies: list[SimpleNamespace],
) -> None:
    with mock.patch(
        "importlib.metadata.distribution",
        side_effect=lambda package: _custom_importlib_metadata_distribution(
            package,
            dummy_dependencies,
        ),
    ), mock.patch(
        "importlib.metadata.distributions",
        return_value=dummy_dependencies,
    ), mock.patch(
        "subprocess.call",
    ):
        exit_code: int = pip_purge.main(["package_a", "package_x"])
    assert caplog.record_tuples == [
        (
            "pip-purge",
            30,
            "\x1b[0;33mWARNING: Skipping package_x as it is not installed\x1b[0m",
        ),
        (
            "pip-purge",
            20,
            "The following packages will be uninstalled: "
            "package_a, package_b, package_e",
        ),
        (
            "pip-purge",
            20,
            f"Running: '{' '.join(PIP_CMD)} uninstall package_a package_b package_e'",
        ),
    ]
    assert exit_code == 0


def test_main_only_package(
    caplog: pytest.LogCaptureFixture,
    dummy_dependencies: list[SimpleNamespace],
) -> None:
    with mock.patch(
        "importlib.metadata.distribution",
        side_effect=lambda package: _custom_importlib_metadata_distribution(
            package,
            dummy_dependencies,
        ),
    ), mock.patch(
        "importlib.metadata.distributions",
        return_value=dummy_dependencies,
    ), mock.patch(
        "subprocess.call",
    ) as mock_subprocess_call:
        exit_code: int = pip_purge.main(["package_a"])
    assert caplog.record_tuples == [
        (
            "pip-purge",
            20,
            "The following packages will be uninstalled: "
            "package_a, package_b, package_e",
        ),
        (
            "pip-purge",
            20,
            f"Running: '{' '.join(PIP_CMD)} uninstall package_a package_b package_e'",
        ),
    ]
    mock_subprocess_call.assert_called_once_with(
        [*PIP_CMD, "uninstall", "package_a", "package_b", "package_e"],
        stdout=sys.stdout,
        stderr=sys.stderr,
    )
    assert exit_code == 0


def test_main_exclude_package(
    caplog: pytest.LogCaptureFixture,
    dummy_dependencies: list[SimpleNamespace],
) -> None:
    with mock.patch(
        "importlib.metadata.distribution",
        side_effect=lambda package: _custom_importlib_metadata_distribution(
            package,
            dummy_dependencies,
        ),
    ), mock.patch(
        "importlib.metadata.distributions",
        return_value=dummy_dependencies,
    ), mock.patch(
        "subprocess.call",
    ) as mock_subprocess_call:
        exit_code: int = pip_purge.main(
            ["package_a", "package_e", "--exclude", "package_e"],
        )
    assert caplog.record_tuples == [
        ("pip-purge", 20, "Cannot uninstall package_a, required by: package_e"),
        ("pip-purge", 20, "Cannot uninstall package_b, required by: package_a"),
        ("pip-purge", 20, "No packages to purge"),
    ]
    mock_subprocess_call.assert_not_called()
    assert exit_code == 0


def test_main_with_uninstall_args(
    caplog: pytest.LogCaptureFixture,
    dummy_dependencies: list[SimpleNamespace],
) -> None:
    with mock.patch(
        "importlib.metadata.distribution",
        side_effect=lambda package: _custom_importlib_metadata_distribution(
            package,
            dummy_dependencies,
        ),
    ), mock.patch(
        "importlib.metadata.distributions",
        return_value=dummy_dependencies,
    ), mock.patch(
        "subprocess.call",
    ) as mock_subprocess_call:
        exit_code: int = pip_purge.main(
            ["package_a", "-y"],
        )
    assert caplog.record_tuples == [
        (
            "pip-purge",
            20,
            "The following packages will be uninstalled: "
            "package_a, package_b, package_e",
        ),
        (
            "pip-purge",
            20,
            f"Running: '{' '.join(PIP_CMD)} uninstall -y "
            "package_a package_b package_e'",
        ),
    ]
    mock_subprocess_call.assert_called_once_with(
        [*PIP_CMD, "uninstall", "-y", "package_a", "package_b", "package_e"],
        stdout=sys.stdout,
        stderr=sys.stderr,
    )
    assert exit_code == 0


def test_main_dry_run(
    caplog: pytest.LogCaptureFixture,
    dummy_dependencies: list[SimpleNamespace],
) -> None:
    with mock.patch(
        "importlib.metadata.distribution",
        side_effect=lambda package: _custom_importlib_metadata_distribution(
            package,
            dummy_dependencies,
        ),
    ), mock.patch(
        "importlib.metadata.distributions",
        return_value=dummy_dependencies,
    ), mock.patch(
        "subprocess.call",
    ) as mock_subprocess_call:
        exit_code: int = pip_purge.main(
            ["package_a", "--dry-run"],
        )
    assert caplog.record_tuples == [
        (
            "pip-purge",
            20,
            "The following packages will be uninstalled: "
            "package_a, package_b, package_e",
        ),
        (
            "pip-purge",
            20,
            f"Would run: '{' '.join(PIP_CMD)} uninstall package_a package_b package_e'",
        ),
    ]
    mock_subprocess_call.assert_not_called()
    assert exit_code == 0


@pytest.mark.parametrize("arg", ["--continue-on-fail", "-C"])
def test_main_continue_on_fail(
    caplog: pytest.LogCaptureFixture,
    dummy_dependencies: list[SimpleNamespace],
    arg: str,
) -> None:
    with mock.patch(
        "importlib.metadata.distribution",
        side_effect=lambda package: _custom_importlib_metadata_distribution(
            package,
            dummy_dependencies,
        ),
    ), mock.patch(
        "importlib.metadata.distributions",
        return_value=dummy_dependencies,
    ), mock.patch(
        "subprocess.call",
    ) as mock_subprocess_call:
        exit_code: int = pip_purge.main(
            ["package_a", arg],
        )
    assert caplog.record_tuples == [
        (
            "pip-purge",
            20,
            "The following packages will be uninstalled: "
            "package_a, package_b, package_e",
        ),
        (
            "pip-purge",
            20,
            f"Running: '{' '.join(PIP_CMD)} uninstall package_a package_b package_e'",
        ),
    ]
    expected_calls: list[mock._Call] = [
        mock.call(
            [*PIP_CMD, "uninstall", "package_a"],
            stdout=sys.stdout,
            stderr=sys.stderr,
        ),
        mock.call(
            [*PIP_CMD, "uninstall", "package_b"],
            stdout=sys.stdout,
            stderr=sys.stderr,
        ),
        mock.call(
            [*PIP_CMD, "uninstall", "package_e"],
            stdout=sys.stdout,
            stderr=sys.stderr,
        ),
    ]
    mock_subprocess_call.assert_has_calls(expected_calls)
    assert exit_code == 0


@pytest.mark.parametrize("arg", ["--freeze-file", "-f"])
def test_main_freeze_packages(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
    dummy_dependencies: list[SimpleNamespace],
    arg: str,
) -> None:
    test_freeze_file: Path = tmp_path / "freeze.txt"

    with mock.patch(
        "importlib.metadata.distribution",
        side_effect=lambda package: _custom_importlib_metadata_distribution(
            package,
            dummy_dependencies,
        ),
    ), mock.patch(
        "importlib.metadata.distributions",
        return_value=dummy_dependencies,
    ), mock.patch(
        "subprocess.call",
    ) as mock_subprocess_call:
        exit_code: int = pip_purge.main(
            [
                "package_a",
                "--freeze-purged-packages",
                arg,
                str(test_freeze_file),
            ],
        )
    assert caplog.record_tuples == [
        (
            "pip-purge",
            20,
            "The following packages will be uninstalled: "
            "package_a, package_b, package_e",
        ),
        (
            "pip-purge",
            20,
            f"Running: '{' '.join(PIP_CMD)} uninstall package_a package_b package_e'",
        ),
    ]
    assert (
        test_freeze_file.read_text(encoding="utf-8")
        == "package_a==1.0.0\npackage_b==1.5.0\npackage_e==1.3.0\n"
    )
    mock_subprocess_call.assert_called_once_with(
        [*PIP_CMD, "uninstall", "package_a", "package_b", "package_e"],
        stdout=sys.stdout,
        stderr=sys.stderr,
    )
    assert exit_code == 0


@pytest.mark.parametrize("arg", ["--freeze-file", "-f"])
def test_main_freeze_packages_fail(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
    dummy_dependencies: list[SimpleNamespace],
    arg: str,
) -> None:
    test_freeze_file: Path = tmp_path / "freeze.txt"
    test_freeze_file.touch(0o000)
    with mock.patch(
        "importlib.metadata.distribution",
        side_effect=lambda package: _custom_importlib_metadata_distribution(
            package,
            dummy_dependencies,
        ),
    ), mock.patch(
        "importlib.metadata.distributions",
        return_value=dummy_dependencies,
    ), mock.patch(
        "subprocess.call",
    ) as mock_subprocess_call:
        exit_code: int = pip_purge.main(
            [
                "package_a",
                "--freeze-purged-packages",
                arg,
                str(test_freeze_file),
            ],
        )
    assert len(caplog.record_tuples) == 2
    assert caplog.record_tuples[0] == (
        "pip-purge",
        20,
        "The following packages will be uninstalled: "
        "package_a, package_b, package_e",
    )
    assert caplog.record_tuples[1][0] == "pip-purge"
    assert caplog.record_tuples[1][1] == 40
    assert caplog.record_tuples[1][2].startswith("\x1b[0;31mERROR: ")
    assert caplog.record_tuples[1][2].endswith("\x1b[0m")
    assert "Could not open requirements file:" in caplog.record_tuples[1][2]
    mock_subprocess_call.assert_not_called()
    assert exit_code == 1


def test_main_double_check(
    caplog: pytest.LogCaptureFixture,
    dummy_dependencies: list[SimpleNamespace],
) -> None:
    with mock.patch(
        "importlib.metadata.distribution",
        side_effect=lambda package: _custom_importlib_metadata_distribution(
            package,
            dummy_dependencies,
        ),
    ), mock.patch(
        "importlib.metadata.distributions",
        return_value=dummy_dependencies,
    ), mock.patch(
        "subprocess.call",
    ) as mock_subprocess_call:
        exit_code: int = pip_purge.main(["package_f"])
    assert caplog.record_tuples == [
        ("pip-purge", 20, "Cannot uninstall package_g, required by: package_h"),
        ("pip-purge", 20, "Cannot uninstall package_f, required by: package_g"),
        ("pip-purge", 20, "No packages to purge"),
    ]
    mock_subprocess_call.assert_not_called()
    assert exit_code == 0


def test_main_ignore_extra(
    caplog: pytest.LogCaptureFixture,
    dummy_dependencies: list[SimpleNamespace],
) -> None:
    with mock.patch(
        "importlib.metadata.distribution",
        side_effect=lambda package: _custom_importlib_metadata_distribution(
            package,
            dummy_dependencies,
        ),
    ), mock.patch(
        "importlib.metadata.distributions",
        return_value=dummy_dependencies,
    ), mock.patch(
        "subprocess.call",
    ) as mock_subprocess_call:
        exit_code: int = pip_purge.main(["package_a", "--ignore-extra"])
    assert caplog.record_tuples == [
        ("pip-purge", 20, "Cannot uninstall package_a, required by: package_e"),
        ("pip-purge", 20, "Cannot uninstall package_b, required by: package_a"),
        ("pip-purge", 20, "No packages to purge"),
    ]
    mock_subprocess_call.assert_not_called()
    assert exit_code == 0


@pytest.mark.parametrize("arg", ["--requirement", "-r"])
def test_main_requirement(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
    dummy_dependencies: list[SimpleNamespace],
    arg: str,
) -> None:
    test_requirement_file: Path = tmp_path / "requirement.txt"
    test_requirement_file.touch()
    test_requirement_file.write_text("package_a", encoding="utf-8")
    with mock.patch(
        "importlib.metadata.distribution",
        side_effect=lambda package: _custom_importlib_metadata_distribution(
            package,
            dummy_dependencies,
        ),
    ), mock.patch(
        "importlib.metadata.distributions",
        return_value=dummy_dependencies,
    ), mock.patch(
        "subprocess.call",
    ) as mock_subprocess_call:
        exit_code: int = pip_purge.main(
            [
                arg,
                str(test_requirement_file),
            ],
        )
    assert caplog.record_tuples == [
        (
            "pip-purge",
            20,
            "The following packages will be uninstalled: "
            "package_a, package_b, package_e",
        ),
        (
            "pip-purge",
            20,
            f"Running: '{' '.join(PIP_CMD)} uninstall package_a package_b package_e'",
        ),
    ]
    mock_subprocess_call.assert_called_once_with(
        [*PIP_CMD, "uninstall", "package_a", "package_b", "package_e"],
        stdout=sys.stdout,
        stderr=sys.stderr,
    )
    assert exit_code == 0


@pytest.mark.parametrize("arg", ["--requirement", "-r"])
def test_main_requirement_fail(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
    dummy_dependencies: list[SimpleNamespace],
    arg: str,
) -> None:
    test_requirement_file: Path = tmp_path / "requirement.txt"
    with mock.patch(
        "importlib.metadata.distribution",
    ), mock.patch(
        "importlib.metadata.distributions",
        return_value=dummy_dependencies,
    ), mock.patch(
        "subprocess.call",
    ) as mock_subprocess_call:
        exit_code: int = pip_purge.main(
            [
                arg,
                str(test_requirement_file),
            ],
        )
    assert len(caplog.record_tuples) == 1
    assert caplog.record_tuples[0][0] == "pip-purge"
    assert caplog.record_tuples[0][1] == 40
    assert caplog.record_tuples[0][2].startswith("\x1b[0;31mERROR: ")
    assert caplog.record_tuples[0][2].endswith("\x1b[0m")
    assert "Could not open requirements file:" in caplog.record_tuples[0][2]
    mock_subprocess_call.assert_not_called()
    assert exit_code == 1


if __name__ == "__main__":
    raise SystemExit(pytest.main())
