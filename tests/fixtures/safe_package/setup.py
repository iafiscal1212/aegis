"""Safe setup.py — test fixture for AEGIS static analysis."""
from setuptools import setup, find_packages

setup(
    name="safe-package",
    version="1.0.0",
    description="A perfectly safe package",
    author="Safe Author",
    author_email="safe@example.com",
    packages=find_packages(),
    install_requires=[
        "requests>=2.28.0",
        "click>=8.0",
    ],
    python_requires=">=3.8",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "License :: OSI Approved :: MIT License",
    ],
)
