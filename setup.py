#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Setup script for par2ools."""

from setuptools import setup, find_packages
import sys, os

version = '0.1'

# some trove classifiers:

# License :: OSI Approved :: MIT License
# Intended Audience :: Developers
# Operating System :: POSIX

setup(
    name='par2ools',
    version=version,
    description="par2 tools",
    long_description=open('README.rst').read(),
    # Get strings from http://pypi.python.org/pypi?%3Aaction=list_classifiers
    classifiers=[
        'Development Status :: 4 - Beta',
        'License :: OSI Approved :: MIT License',
    ],
    keywords='par2',
    author='Jason Moiron',
    author_email='jmoiron@jmoiron.net',
    url='http://github.com/jmoiron/par2ools',
    license='MIT',
    packages=find_packages(exclude=['ez_setup', 'examples', 'tests']),
    scripts=['bin/par2unrar', 'bin/par2ls', 'bin/par2mv'],
    include_package_data=True,
    zip_safe=False,
    test_suite="tests",
    install_requires=[
      # -*- Extra requirements: -*-
    ],
    entry_points="""
    # -*- Entry points: -*-
    """,
)
