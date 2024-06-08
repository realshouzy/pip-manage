# pip-manage

[![pre-commit.ci status](https://results.pre-commit.ci/badge/github/realshouzy/pip-manage/main.svg)](https://results.pre-commit.ci/latest/github/realshouzy/pip-manage/main)
[![pylint status](https://github.com/realshouzy/pip-manage/actions/workflows/pylint.yaml/badge.svg)](https://github.com/realshouzy/pip-manage/actions/workflows/pylint.yaml)
[![tests status](https://github.com/realshouzy/pip-manage/actions/workflows/test.yaml/badge.svg)](https://github.com/realshouzy/pip-manage/actions/workflows/test.yaml)
[![CodeQL](https://github.com/realshouzy/pip-manage/actions/workflows/codeql.yaml/badge.svg)](https://github.com/realshouzy/pip-manage/actions/workflows/codeql.yaml)
[![PyPI - Version](https://img.shields.io/pypi/v/pip-manage)](https://github.com/realshouzy/pip-manage/releases/latest)
[![Python versions](https://img.shields.io/pypi/pyversions/pip-manage.svg)](https://pypi.org/project/pip-manage/)
[![Licens](https://img.shields.io/pypi/l/pip-manage)](https://github.com/realshouzy/pip-review/blob/main/LICENSE)
[![semantic-release](https://img.shields.io/badge/%F0%9F%93%A6%F0%9F%9A%80-semantic--release-e10079.svg)](https://github.com/realshouzy/pip-manage/releases)
[![PyPI - Format](https://img.shields.io/pypi/format/pip-manage)](https://pypi.org/project/pip-manage/)
[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)
[![Style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![Imports: isort](https://img.shields.io/badge/%20imports-isort-%231674b1?style=flat&labelColor=ef8336)](https://pycqa.github.io/isort/)

**`pip-manage` lets you smoothly manage your installed packages.**

## Installation

To install, simply use pip:

```shell
pip install pip-manage
```

Alternatively:

```shell
pip install git+https://github.com/realshouzy/pip-manage
```

Decide for yourself whether you want to install the tool system-wide, or
inside a virtual env. Both are supported.

## Documentation

`pip-manage` includes two tools [`pip-review`](#pip-review) and [`pip-purge`](#pip-purge).

### pip-review

`pip-review` is a convenience wrapper around `pip`. It can list
available updates by deferring to `pip list --outdated`. It can also
automatically or interactively install available updates for you by
deferring to `pip install`.

Example, report-only:

```console
$ pip-review
requests==0.13.4 is available (you have 0.13.2)
redis==2.4.13 is available (you have 2.4.9)
rq==0.3.2 is available (you have 0.3.0)
```

You can also print raw lines:

```console
$ pip-review --raw
requests==0.13.4
redis==2.4.13
rq==0.3.2
```

Example, actually install everything:

```console
$ pip-review --auto
... <pip install output>
```

Example, run interactively, ask to upgrade for each package:

```console
$ pip-review --interactive
requests==0.14.0 is available (you have 0.13.2)
Upgrade now? [Y]es, [N]o, [A]ll, [Q]uit y
...
redis==2.6.2 is available (you have 2.4.9)
Upgrade now? [Y]es, [N]o, [A]ll, [Q]uit n
rq==0.3.2 is available (you have 0.3.0)
Upgrade now? [Y]es, [N]o, [A]ll, [Q]uit y
...
```

Example, preview for update target list by `pip list --outdated` format,
with run interactively or install everything:

```console
$ pip-review --interactive --preview
Package  Version Latest Type
-----------------------------
redis    2.4.9   2.6.2  wheel
requests 0.13.2  0.14.0 wheel
rq       0.3.0   0.3.4  wheel
-----------------------------
... < --interactive processing >
```

You can also freeze the packages that will be upgraded to a file before actually upgrading them.

```console
$ pip-review --auto --freeze-outdated-packages
... <pip install output>
```

By default it will safe them to `backup.txt` in the current directory, but you can specify the file path using the `--freeze-file` option.

Run `pip-review -h` for a complete overview of the options.

Note: If you want to pin specific packages to prevent them from
automatically being upgraded, you can use a constraint file (similar to
`requirements.txt`):

```console
$ export PIP_CONSTRAINT="${HOME}/constraints.txt"
$ cat $PIP_CONSTRAINT
pyarrow==0.14.1
pandas<0.24.0

$ pip-review --auto
...
```

Set this variable in `.bashrc` or `.zshenv` to make it persistent.

- Linux:

```console
$ cat ~/.config/pip/pip.conf
[global]
constraint = /home/username/constraints.txt
```

- Windows:

```console
$ cat $HOME\AppData\Roaming\pip\pip.ini
[global]
constraint = '$HOME\Roaming\pip\constraints.txt'
```

The conf file are dependent of the user, so If you use multiple users
you must define config file for each of them.
<https://pip.pypa.io/en/stable/user_guide/#constraints-files>

Alternatively, since arguments that are also options for `pip install` or `pip list --outdated` will be forwarded,
you can pass the constraint files directly as an argument using the `--constraint` option of `pip install`.

Like `pip`, `pip-review` updates **all** upgradeable packages, including `pip` and
`pip-manage`.

### pip-purge

`pip-purge` enables you to uninstall a package along with all its dependencies that are not required by any other packages.
Simply specify the packages you want to purge, and `pip-purge` will handle the dependency resolution for you, ensuring that no other packages are broken in the process.
It uses the `importlib.metadata` module to resolve the dependencies and then deferres to `pip uninstall`.

Example:

```console
$ pip-purge requests
The following packages will be uninstalled: certifi, charset-normalizer, idna, requests, urllib3
Running: ...
```

You can also read from a requirements file. The read packages will be purged:

```console
$ pip-purge --requirement requirements.txt
...
```

If you want to exclude certain packages, you can do that as follows:

```console
$ pip-purge requests --exclude urllib3
The following packages will be uninstalled: certifi, charset-normalizer, idna, requests
Running: ...
```

Sometimes packages have extra / optional dependencies. These are considered by default, but can be ignored:

```console
$ pip-purge requests --ignore-extra
...
```

It's recommended to do a dry run first, which performs all operations normally but doesn't defer to `pip uninstall`:

```console
$ pip-purge requests --dry-run
The following packages will be uninstalled: certifi, charset-normalizer, idna, requests, urllib3
Would run: ...
```

You can also freeze the packages that will be uninstalled to a file before actually purging them.

```console
$ pip-review requests --freeze-purged-packages
...
```

By default it will safe them to `backup.txt` in the current directory, but you can specify the file path using the `--freeze-file` option.

Run `pip-purge -h` for a complete overview of the options.

## Contributing

If you are interested in contributing to this project, please refer [here](/CONTRIBUTING.md) for more information.

## Origins and credit

`pip-review` is derived from the original project of the same name created by Julian Gonggrijp. This fork is a refactored and enhanced version of the [original](https://github.com/jgonggrijp/pip-review).

Included from the original project:
`pip-review` was originally part of
[pip-tools](https://github.com/nvie/pip-tools/) but has been
[discontinued](https://github.com/nvie/pip-tools/issues/185) as such.
See [Pin Your Packages](http://nvie.com/posts/pin-your-packages/) by
Vincent Driessen for the original introduction. Since there are still
use cases, the tool now lives on as a separate package.
