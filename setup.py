#!/usr/bin/env python3
# -*- coding:utf-8 -*-

import os
import re
from setuptools import setup, find_packages

# Meta information
dirname = os.path.dirname(__file__)

# Retrieve all metadata from project
with open(os.path.join(dirname, "__metadata.py"), "rt") as meta_file:
    metadata = dict(
        re.findall(r"^__([a-z]+)__ = ['\"]([^'\"]*)['\"]", meta_file.read(), re.M)
    )

# Get required packages from requirements.txt
# Make it compatible with setuptools and pip
with open(os.path.join(dirname, "requirements.txt")) as f:
    requirements = f.read().splitlines()

setup(
    name="uPKI",
    description="µPKI Certification Authority",
    long_description=open("README.md").read(),
    author=metadata["author"],
    author_email=metadata["authoremail"],
    version=metadata["version"],
    classifiers=[
        "Development Status :: 3 - Alpha",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "Intended Audience :: System Administrators",
    ],
    url=metadata["url"],
    packages=find_packages(),
    license="MIT",
    install_requires=requirements,
    python_requires=">=3.11",
)
