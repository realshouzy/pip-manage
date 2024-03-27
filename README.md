[![pre-commit.ci status](https://results.pre-commit.ci/badge/github/realshouzy/pip-review/main.svg)](https://results.pre-commit.ci/latest/github/realshouzy/pip-review/main)
[![pylint status](https://github.com/realshouzy/pip-review/actions/workflows/pylint.yaml/badge.svg)](https://github.com/realshouzy/pip-review/actions/workflows/pylint.yaml)
[![tests status](https://github.com/realshouzy/pip-review/actions/workflows/test.yaml/badge.svg)](https://github.com/realshouzy/pip-review/actions/workflows/test.yaml)
[![CodeQL](https://github.com/realshouzy/pip-review/actions/workflows/codeql.yaml/badge.svg)](https://github.com/realshouzy/pip-review/actions/workflows/codeql.yaml)
[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)
[![Style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![Imports: isort](https://img.shields.io/badge/%20imports-isort-%231674b1?style=flat&labelColor=ef8336)](https://pycqa.github.io/isort/)

**This `README.md` is not up to date!**

# pip-review

`pip-review` is a convenience wrapper around `pip`. It can list
available updates by deferring to `pip list --outdated`. It can also
automatically or interactively install available updates for you by
deferring to `pip install`.

Example, report-only:

``` shell
$ pip-review
requests==0.13.4 is available (you have 0.13.2)
redis==2.4.13 is available (you have 2.4.9)
rq==0.3.2 is available (you have 0.3.0)
```

Example, actually install everything:

``` shell
$ pip-review --auto
... <pip install output>
```

Example, run interactively, ask to upgrade for each package:

``` shell
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

``` shell
$ pip-review --interactive --preview
Package  Version Latest Type
-----------------------------
redis    2.4.9   2.6.2  wheel
requests 0.13.2  0.14.0 wheel
rq       0.3.0   0.3.4  wheel
-----------------------------
... < --interactive processing >
```

``` shell
$ pip-review --auto --preview
... <same above and pip install output>
```

Example, only preview for update target list:

``` shell
$ pip-review --preview-only
Package  Version Latest Type
-----------------------------
redis    2.4.9   2.6.2  wheel
requests 0.13.2  0.14.0 wheel
rq       0.3.0   0.3.4  wheel
-----------------------------
```

Run `pip-review -h` for a complete overview of the options.

Note: If you want to pin specific packages to prevent them from
automatically being upgraded, you can use a constraint file (similar to
`requirements.txt`):

``` shell
$ export PIP_CONSTRAINT="${HOME}/constraints.txt"
$ cat $PIP_CONSTRAINT
pyarrow==0.14.1
pandas<0.24.0

$ pip-review --auto
...
```

Set this variable in `.bashrc` or `.zshenv` to make it persistent.
Alternatively, this option can be specified in `pip.conf`, e.g.:

- Linux:

``` shell
$ cat ~/.config/pip/pip.conf
[global]
constraint = /home/username/constraints.txt
```

- Windows:

``` shell
$ cat $HOME\AppData\Roaming\pip\pip.ini
[global]
constraint = '$HOME\Roaming\pip\constraints.txt'
```

The conf file are dependent of the user, so If you use multiple users
you must define config file for each of them.
<https://pip.pypa.io/en/stable/user_guide/#constraints-files>

Since version 0.5, you can also invoke pip-review as
`python -m pip_review`. This can be useful if you are using multiple
versions of Python next to each other.

Before version 1.0, `pip-review` had its own logic for finding package
updates instead of relying on `pip list --outdated`.

Like `pip`, `pip-review` updates **all** packages, including `pip` and
`pip-review`.

# Installation

To install, simply use pip:

``` shell
pip install pip-review
```

Decide for yourself whether you want to install the tool system-wide, or
inside a virtual env. Both are supported.

# Testing

To test with your active Python version:

``` shell
./run-tests.sh
```

To test under all (supported) Python versions:

``` shell
tox
```

The tests run quite slow, since they actually interact with PyPI, which
involves downloading packages, etc. So please be patient.

# Origins

`pip-review` was originally part of
[pip-tools](https://github.com/nvie/pip-tools/) but has been
[discontinued](https://github.com/nvie/pip-tools/issues/185) as such.
See [Pin Your Packages](http://nvie.com/posts/pin-your-packages/) by
Vincent Driessen for the original introduction. Since there are still
use cases, the tool now lives on as a separate package.
