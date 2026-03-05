#!/usr/bin/env python3
"""
Setup script for Timestomping Detection Tool
"""

from setuptools import setup, find_packages
import os

# Read README file
def read_readme():
    with open("README.md", "r", encoding="utf-8") as fh:
        return fh.read()

# Read requirements
def read_requirements():
    with open("requirements.txt", "r", encoding="utf-8") as fh:
        return [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="timestomp-detector",
    version="1.0.0",
    author="Forensics Team",
    author_email="forensics@example.com",
    description="Python-based forensic tool to detect timestomping on NTFS file systems",
    long_description=read_readme(),
    long_description_content_type="text/markdown",
    url="https://github.com/forensics/timestomp-detector",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Topic :: Security :: Forensics",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Operating System :: Microsoft :: Windows",
    ],
    python_requires=">=3.8",
    install_requires=read_requirements(),
    entry_points={
        "console_scripts": [
            "timestomp-detector=timestomp_detector:main",
            "timestomp-viz=timeline_viz:main",
            "timestomp-demo=demo:main",
            "timestomp-gui=gui_detector:main",
        ],
    },
    include_package_data=True,
    package_data={
        "": ["*.md", "*.txt", "*.json"],
    },
)
