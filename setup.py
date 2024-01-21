"""pip-review lets you smoothly manage all available PyPI updates."""
from __future__ import annotations

from setuptools import setup

from pip_review import __title__, __version__

setup(
    name=__title__,
    version=__version__,
    url="https://github.com/realshouzy/pip-review",
    license="BSD",
    author="Julian Gonggrijp, Vincent Driessen",
    author_email="j.gonggrijp@gmail.com",
    description=__doc__.strip("\n"),
    long_description=open("README.rst", encoding="utf-8").read(),
    long_description_content_type="text/x-rst",
    packages=[
        "pip_review",
    ],
    entry_points={
        "console_scripts": [
            "pip-review = pip_review._main:main",
        ],
    },
    # include_package_data=True,
    zip_safe=False,
    platforms="any",
    install_requires=[
        "packaging",
    ],
    python_requires=">=3.9",
    classifiers=[
        # As from https://pypi.python.org/pypi?%3Aaction=list_classifiers
        # 'Development Status :: 1 - Planning',
        # 'Development Status :: 2 - Pre-Alpha',
        # 'Development Status :: 3 - Alpha',
        # 'Development Status :: 4 - Beta',
        "Development Status :: 5 - Production/Stable",
        # 'Development Status :: 6 - Mature',
        # 'Development Status :: 7 - Inactive',
        "Programming Language :: Python",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: BSD License",
        "Operating System :: OS Independent",
        "Topic :: System :: Systems Administration",
    ],
)
