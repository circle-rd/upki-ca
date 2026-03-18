"""
Setup script for uPKI CA Server.

Author: uPKI Team
License: MIT
"""

from setuptools import find_packages, setup

with open("README.md", encoding="utf-8") as f:
    long_description = f.read()

setup(
    name="upki-ca",
    version="0.1.0",
    author="uPKI Team",
    author_email="info@upki.io",
    description="uPKI CA Server - Certificate Authority for PKI operations",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/upki/upki-ca",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
    python_requires=">=3.11",
    install_requires=[
        "cryptography>=41.0.0",
        "pyyaml>=6.0",
        "tinydb>=4.7.0",
        "zmq>=24.0.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.4.0",
            "pytest-cov>=4.1.0",
            "black>=23.0.0",
            "mypy>=1.4.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "upki-ca-server=ca_server:main",
        ],
    },
)
