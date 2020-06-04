from setuptools import setup
from uefi_r2 import __author__, __email__, __version__

with open('requirements.txt') as f:
    REQUIRED = f.readlines()

with open('README.md', 'r') as f:
    README = f.read()

setup(name='uefi_r2',
      version=__version__,
      author=__author__,
      author_email=__email__,
      packages=['uefi_r2'],
      install_requires=REQUIRED,
      description='Tools for analyzing UEFI firmware using radare2',
      long_description=README,
      classifiers=[
          'Development Status :: 3 - Alpha',
          'Operating System :: OS Independent',
          'Programming Language :: Python :: 3',
      ])
