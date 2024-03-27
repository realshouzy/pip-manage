**This file serves as a historical record but is no longer actively maintained or updated.**

History
=======

0.5.1 (2017-01-21)
------------------

Please see the [release notes on GitHub](https://github.com/jgonggrijp/pip-review/releases/tag/0.5.1) for details about this release. The [GitHub release list](https://github.com/jgonggrijp/pip-review/releases) will be the single source of truth about releases from now on. This is the final version of this file; it will be removed in a future release.

0.5 (2016-10-10)
----------------

- Should work under Windows from now on
- Now also invokable as `python -m pip_review`
- Should be compatible with older version of pip
- Should be compatible with systems that don't include pip
- Lists Python 3 as supported on the Python Package Index

0.4 (2015-11-21)
----------------

- Show and install only release updates by default (Rick Vause)
- Enable pre-release versions using the --pre flag (Rick Vause)

0.3.7 (2015-10-06)
------------------

- Redistribute pip-review as a standalone package (Julian Gonggrijp)

0.3.4 (2013-05-27)
------------------

- Fix bug where non-PyPI packages inside .pipignore broke things when
     running pip-review

0.3.3 (2013-05-27)
------------------

- Bugfixes related to non-existing requirements files
- Add unofficial Python3 compatibility

0.3.2 (2013-05-27)
------------------

- Improve logging semantics (John Mark Schofield)
- Remove ``verlib`` dependency (it's officially unmaintained)
     (Vladimir Rudnyh)
- Adds package name guessing using PyPI's ``/simple`` API endpoint
     (Vladimir Rudnyh)

0.3.1 (2013-03-20)
------------------

- Add ``--local`` flag, to only review packages from the virtual env,
     ignoring globally installed packages

0.3 (2013-03-20)
----------------

- Compares versions, so version numbers reported are always higher than the
     current versions (assumes PEP 386 compliance)
- Detects more filename patterns for requirements files

0.2.1 (2012-10-26)
------------------

- Python 2.6 support

0.2 (2012-09-26)
----------------

- Fix --editables support

0.1 (2012-09-26)
----------------

- Initial release
