# Release process setup see:
# https://github.com/pypa/twine
#
# Upgrade twine
#     python3 -m pip install --user --upgrade twine
#
# Run this to build the `dist/PACKAGE_NAME-xxx.tar.gz` file
#     rm -rf ./dist && python3 setup.py sdist
#
# Check dist/*
#     python3 -m twine check dist/*
#
# Run this to build & upload it to `pypi`, type your account name when prompted.
#     python3 -m twine upload dist/*
#
# In one command line:
#     rm -rf ./dist && python3 setup.py sdist bdist_wheel && python3 -m twine check dist/*
#     rm -rf ./dist && python3 setup.py sdist bdist_wheel && python3 -m twine upload dist/*
#

from setuptools import setup

# Usage: python setup.py sdist bdist_wheel

links = []  # for repo urls (dependency_links)

with open("requirements.txt") as fp:
    install_requires = fp.read().splitlines()

# Test dependencies (install with: pip install -e '.[test]')
test_requires = [
    'pytest>=6.0.0',
    'pytest-cov>=2.8.0',
    'pytest-mock>=3.3.0',
    'pytest-xdist>=2.0.0',
    'pytest-asyncio>=0.15.0',
    'responses>=0.13.0',
    'black>=22.0.0',
    'isort>=5.0.0',
    'mypy>=0.900',
    'types-requests>=0.1.0',
    'types-python-dateutil>=2.0.0',
]

DESCRIPTION = "A python client for Passbolt."
VERSION = "0.3.8"

with open("README.md", "r") as fh:
    LONG_DESCRIPTION = fh.read()

setup(
    name="passbolt-python-api",
    version=VERSION,
    author="Shubham Dipt",
    author_email="shubham.dipt@gmail.com",
    description=DESCRIPTION,
    long_description=LONG_DESCRIPTION,
    long_description_content_type="text/markdown",
    url="https://github.com/shubhamdipt/passbolt-python-api",
    license="MIT",
    packages=["passboltapi"],
    platforms=["any"],
    python_requires='>=3.7',
    extras_require={
        'test': test_requires + install_requires,  # Include main dependencies for tests
    },
    # For backward compatibility with pip < 18.1
    tests_require=test_requires + install_requires,  # Include main dependencies for tests
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    install_requires=install_requires,
    dependency_links=links,
)
