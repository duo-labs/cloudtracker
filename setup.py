"""Setup script for cloudtracker"""
import os
import re

from setuptools import find_packages, setup


HERE = os.path.dirname(__file__)
VERSION_RE = re.compile(r'''__version__ = ['"]([0-9.]+)['"]''')
TESTS_REQUIRE = [
    'coverage',
    'nose'
]


def get_version():
    init = open(os.path.join(HERE, 'cloudtracker', '__init__.py')).read()
    return VERSION_RE.search(init).group(1)


setup(
    name='cloudtracker',
    version=get_version(),
    author='Duo Security',
    description=(
        'CloudTracker helps you find over-privileged IAM users and '
        'roles by comparing CloudTrail logs with current IAM policies'
    ),
    long_description=open(os.path.join(HERE, 'README.md')).read(),
    url='https://github.com/duo-labs/cloudtracker',
    entry_points={
        'console_scripts': 'cloudtracker=cloudtracker.cli:main'
    },
    test_suite='tests/unit',
    tests_require=TESTS_REQUIRE,
    extras_require={
        'dev': TESTS_REQUIRE + ['autoflake', 'autopep8', 'pylint'],
        'es1': ['elasticsearch==1.9.0', 'elasticsearch_dsl==0.0.11'],
        'es6': ['elasticsearch==6.1.1', 'elasticsearch_dsl==6.1.0']
    },
    install_requires=[
        'ansicolors==1.1.8',
        'boto3==1.5.32',
        'jmespath==0.9.3',
        'pyyaml==3.12'
    ],
    setup_requires=['nose'],
    packages=find_packages(exclude=['tests*']),
    package_data={'cloudtracker': ['data/*.txt']},
    zip_safe=True,
    license=open(os.path.join(HERE, 'LICENSE')).read(),
    keywords='aws cloudtracker cloudtrail privileged iam user roles policy policies',
    classifiers=[
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3 :: Only',
        'Development Status :: 5 - Production/Stable'
    ]
)
