#!/usr/bin/env python3
from __future__ import annotations

import sys
from unittest import mock

import pytest

from pip_manage._pip_interface import (
    COMMON_PARAMETERS,
    INSTALL_ONLY,
    LIST_ONLY,
    PIP_CMD,
    UNINSTALL_ONLY,
    _OutdatedPackage,
    filter_forwards,
    filter_forwards_exclude,
    filter_forwards_include,
    get_outdated_packages,
    uninstall_packages,
    update_packages,
)
from tests.fixtures import sample_packages, sample_subprocess_output


@pytest.mark.parametrize(
    ("constant", "expected"),
    [
        pytest.param(
            LIST_ONLY,
            frozenset(
                (
                    "l",
                    "local",
                    "path",
                    "pre",
                    "not-required",
                    "exclude-editable",
                    "include-editable",
                    "exclude",
                ),
            ),
            id="LIST_ONLY",
        ),
        pytest.param(
            INSTALL_ONLY,
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
            id="INSTALL_ONLY",
        ),
        pytest.param(
            UNINSTALL_ONLY,
            frozenset(
                (
                    "y",
                    "yes",
                    "root-user-action",
                    "break-system-packages",
                ),
            ),
            id="UNINSTALL_ONLY",
        ),
        pytest.param(
            COMMON_PARAMETERS,
            frozenset(
                (
                    "isolated",
                    "require-virtualenv",
                    "python",
                    "v",
                    "verbose",
                    "q",
                    "quiet",
                    "log",
                    "no-input",
                    "keyring-provider",
                    "proxy",
                    "retries",
                    "timeout",
                    "exists-action",
                    "trusted-host",
                    "cert",
                    "client-cert",
                    "cache-dir",
                    "no-cache-dir",
                    "disable-pip-version-check",
                    "no-color",
                    "no-python-version-warning",
                    "use-feature",
                    "use-deprecated",
                ),
            ),
            id="COMMON_PARAMETERS",
        ),
        pytest.param(
            PIP_CMD,
            (sys.executable, "-m", "pip"),
            id="PIP_CMD",
        ),
    ],
)
def test_constants(
    constant: str | frozenset[str] | tuple[str, ...],
    expected: str | frozenset[str] | tuple[str, ...],
) -> None:
    assert constant == expected


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
def test_filter_forwards_exclude(
    args_to_filter: list[str],
    args_to_pass: list[str],
) -> None:
    assert (
        filter_forwards_exclude(
            [*args_to_pass, *args_to_filter],
            {"filter", "filter-filter", "f"},
        )
        == args_to_pass
    )


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
def test_filter_forwards_include(
    args_to_filter: list[str],
    args_to_pass: list[str],
) -> None:
    assert (
        filter_forwards_include(
            [*args_to_pass, *args_to_filter],
            {"pass", "pass-pass", "p"},
        )
        == args_to_pass
    )


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
        filter_forwards(
            [*args_to_pass, *args_to_filter],
            include={"pass", "pass-pass", "p"},
            exclude={"filter", "filter-filter", "f"},
        )
        == args_to_pass
    )


@pytest.mark.parametrize(
    ("outdated_package", "expected"),
    [
        (
            _OutdatedPackage(
                "test",
                "1.0.0",
                "1.1.0",
                "wheel",
                {"1.0.0", "1.1.0"},
            ),
            ", ".join(sorted({"1.0.0", "1.1.0"})),
        ),
        (_OutdatedPackage("test", "1.0.0", "1.1.0", "wheel"), "None"),
    ],
)
def test_outdated_package_constraints_display(
    outdated_package: _OutdatedPackage,
    expected: str,
) -> None:
    assert outdated_package.constraints_display == expected


@pytest.mark.parametrize(
    ("json_obj", "expected"),
    [
        pytest.param(
            {
                "name": "name",
                "version": "version",
                "latest_version": "latest_version",
                "latest_filetype": "latest_filetype",
            },
            _OutdatedPackage(
                "name",
                "version",
                "latest_version",
                "latest_filetype",
            ),
            id="complete-dct",
        ),
        pytest.param(
            {
                "version": "version",
                "latest_version": "latest_version",
                "latest_filetype": "latest_filetype",
            },
            _OutdatedPackage(
                "Unknown",
                "version",
                "latest_version",
                "latest_filetype",
            ),
            id="missing-name",
        ),
        pytest.param(
            {
                "name": "name",
                "latest_version": "latest_version",
                "latest_filetype": "latest_filetype",
            },
            _OutdatedPackage(
                "name",
                "Unknown",
                "latest_version",
                "latest_filetype",
            ),
            id="missing-version",
        ),
        pytest.param(
            {
                "name": "name",
                "version": "version",
                "latest_filetype": "latest_filetype",
            },
            _OutdatedPackage(
                "name",
                "version",
                "Unknown",
                "latest_filetype",
            ),
            id="missing-latest_version",
        ),
        pytest.param(
            {
                "name": "name",
                "version": "version",
                "latest_version": "latest_version",
            },
            _OutdatedPackage("name", "version", "latest_version", "Unknown"),
            id="missing-latest_filetype",
        ),
    ],
)
def test_outdated_package_from_json_obj(
    json_obj: dict[str, str],
    expected: _OutdatedPackage,
) -> None:
    assert _OutdatedPackage.from_json(json_obj) == expected


@pytest.mark.parametrize(
    "forwarded",
    [[], ["--forwarded"], ["--forwarded1", "--forwarded2"]],
)
def test_update_packages_continue_on_fail_set_to_false(
    forwarded: list[str],
    sample_packages: list[_OutdatedPackage],
) -> None:
    with mock.patch("subprocess.call") as mock_subprocess_call:
        update_packages(
            sample_packages,
            forwarded,
            continue_on_fail=False,
        )

    expected_cmd: list[str] = [
        *PIP_CMD,
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
    sample_packages: list[_OutdatedPackage],
) -> None:
    with mock.patch("subprocess.call") as mock_subprocess_call:
        update_packages(
            sample_packages,
            forwarded,
            continue_on_fail=True,
        )

    expected_calls: list[mock._Call] = [
        mock.call(
            [
                *PIP_CMD,
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
                *PIP_CMD,
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
    sample_packages: list[_OutdatedPackage],
    sample_subprocess_output: bytes,
) -> None:
    with mock.patch(
        "subprocess.check_output",
        return_value=sample_subprocess_output,
    ):
        outdated_packages: list[_OutdatedPackage] = get_outdated_packages([])
    assert outdated_packages == sample_packages


@pytest.mark.parametrize(
    "forwarded",
    [[], ["--forwarded"], ["--forwarded1", "--forwarded2"]],
)
def test_uninstall_packages_continue_on_fail_set_to_false(forwarded: list[str]) -> None:
    packages: list[str] = ["test1", "test2"]
    with mock.patch("subprocess.call") as mock_subprocess_call:
        uninstall_packages(packages, forwarded, continue_on_fail=False)

    expected_cmd: list[str] = [
        *PIP_CMD,
        "uninstall",
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
def test_uninstall_packages_continue_on_fail_set_to_true(forwarded: list[str]) -> None:
    packages: list[str] = ["test1", "test2"]
    with mock.patch("subprocess.call") as mock_subprocess_call:
        uninstall_packages(packages, forwarded, continue_on_fail=True)

    expected_calls: list[mock._Call] = [
        mock.call(
            [
                *PIP_CMD,
                "uninstall",
                *forwarded,
                "test1",
            ],
            stdout=sys.stdout,
            stderr=sys.stderr,
        ),
        mock.call(
            [
                *PIP_CMD,
                "uninstall",
                *forwarded,
                "test2",
            ],
            stdout=sys.stdout,
            stderr=sys.stderr,
        ),
    ]
    mock_subprocess_call.assert_has_calls(expected_calls)


if __name__ == "__main__":
    raise SystemExit(pytest.main())
