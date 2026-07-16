from setuptools import find_packages, setup

setup(
    name="logsentinel",
    version="0.1.0",
    description="Lightweight log analysis and threat-detection toolkit",
    packages=find_packages(exclude=["tests", "tests.*"]),
    python_requires=">=3.9",
    entry_points={
        "console_scripts": [
            "logsentinel=logsentinel.cli:main",
        ],
    },
)
