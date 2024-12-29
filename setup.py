from setuptools import setup

with open("requirements.txt") as f:
    REQUIRED = f.readlines()

with open("README.md", "r") as f:
    README = f.read()

setup(
    name="fwhunt_scan",
    version="2.3.7",
    author="FwHunt team",
    author_email="fwhunt@binarly.io",
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
            "uefi_extractor.pyi",
            "uefi_protocols.pyi",
            "uefi_scanner.pyi",
            "uefi_smm.pyi",
            "uefi_tables.pyi",
            "uefi_te.pyi",
            "uefi_types.pyi",
            "uefi_utils.pyi",
            "__init__.pyi",
        ]
    },
    scripts=["fwhunt_scan_analyzer.py", "fwhunt_scan_docker.py"],
)
