from setuptools import setup
from fwhunt_scan import __author__, __email__, __version__

with open("requirements.txt") as f:
    REQUIRED = f.readlines()

with open("README.md", "r") as f:
    README = f.read()

setup(
    name="fwhunt_scan",
    version=__version__,
    author=__author__,
    author_email=__email__,
    packages=["fwhunt_scan"],
    license="GPL-3.0",
    url="https://github.com/binarly-io/fwhunt-scan",
    install_requires=REQUIRED,
    description="Tools for analyzing UEFI firmware and checking UEFI modules with FwHunt rules",
    long_description=README,
    long_description_content_type="text/markdown",
    platforms=["Platform Independent"],
    classifiers=[
        "Development Status :: 3 - Alpha",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
    ],
    include_package_data=True,
    zip_safe=False,
    package_data={
        "fwhunt_scan": [
            "py.typed",
            "uefi_analyzer.pyi",
            "uefi_protocols.pyi",
            "uefi_tables.pyi",
            "uefi_scanner.pyi",
            "uefi_te.pyi",
            "__init__.pyi",
        ]
    },
)
