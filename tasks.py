#!/usr/bin/env python
import sys
import os
import logging
from invoke import task, Collection, UnexpectedExit, Failure

logger = logging.getLogger(__name__)
# Create the necessary collections (namespaces)
ns = Collection()

test = Collection("test")
ns.add_collection(test)

unit = Collection("unit")
ns.add_collection(unit)

build = Collection("build")
ns.add_collection(build)


# Build
@task
def build_package(c):
    """Build the package from the current directory contents for use with PyPi"""
    c.run("python -m pip install --upgrade setuptools wheel")
    c.run("python setup.py -q sdist bdist_wheel")


@task(pre=[build_package])
def install_package(c):
    """Install the package built from the current directory contents (not PyPi)"""
    c.run("pip3 install -q dist/cloudtracker-*.tar.gz")


@task
def uninstall_package(c):
    """Uninstall the package"""
    c.run('echo "y" | pip3 uninstall cloudtracker', pty=True)
    c.run("rm -rf dist/*", pty=True)


@task(pre=[install_package])
def help_check(c):
    """Print the version to make sure the package installation didn't irrationally break"""
    try:
        c.run("./bin/cloudtracker --help", pty=True)
    except UnexpectedExit as u_e:
        logger.critical(f"FAIL! UnexpectedExit: {u_e}")
        sys.exit(1)
    except Failure as f_e:
        logger.critical(f"FAIL: Failure: {f_e}")
        sys.exit(1)


# TEST - format
@task
def fmt(c):
    """Auto format code with Python autopep8"""
    try:
        c.run("autopep8 cloudtracker/")
    except UnexpectedExit as u_e:
        logger.critical(f"FAIL! UnexpectedExit: {u_e}")
        sys.exit(1)
    except Failure as f_e:
        logger.critical(f"FAIL: Failure: {f_e}")
        sys.exit(1)


# TEST - LINT
@task
def run_linter(c):
    """Lint the code"""
    try:
        c.run("pylint cloudtracker/", warn=False)
    except UnexpectedExit as u_e:
        logger.critical(f"FAIL! UnexpectedExit: {u_e}")
        sys.exit(1)
    except Failure as f_e:
        logger.critical(f"FAIL: Failure: {f_e}")
        sys.exit(1)


# TEST - SECURITY
@task
def security_scan(c):
    """Runs `bandit` and `safety check`"""
    try:
        c.run("bandit -r cloudtracker/")
        # c.run("safety check")
    except UnexpectedExit as u_e:
        logger.critical(f"FAIL! UnexpectedExit: {u_e}")
        sys.exit(1)
    except Failure as f_e:
        logger.critical(f"FAIL: Failure: {f_e}")
        sys.exit(1)


# UNIT TESTING
@task
def run_nosetests(c):
    """Unit testing: Runs unit tests using `nosetests`"""
    c.run('echo "Running Unit tests"')
    try:
        c.run("nosetests -v  --logging-level=CRITICAL")
    except UnexpectedExit as u_e:
        logger.critical(f"FAIL! UnexpectedExit: {u_e}")
        sys.exit(1)
    except Failure as f_e:
        logger.critical(f"FAIL: Failure: {f_e}")
        sys.exit(1)


@task
def run_pytest(c):
    """Unit testing: Runs unit tests with pytest and coverage"""
    c.run('echo "Running Unit tests"')
    try:
        c.run("python -m coverage run -m pytest -v")
        c.run("python -m coverage report -m")
    except UnexpectedExit as u_e:
        logger.critical(f"FAIL! UnexpectedExit: {u_e}")
        sys.exit(1)
    except Failure as f_e:
        logger.critical(f"FAIL: Failure: {f_e}")
        sys.exit(1)


build.add_task(build_package, "build")
build.add_task(install_package, "install")
build.add_task(uninstall_package, "uninstall")

unit.add_task(run_nosetests, "nose")
unit.add_task(run_pytest, "pytest")

test.add_task(run_linter, "lint")
test.add_task(fmt, "format")
test.add_task(security_scan, "security")

test.add_task(help_check, "help")
