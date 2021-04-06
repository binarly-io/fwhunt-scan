# Copyright (C) 2019 Richard Hughes <richard@hughsie.com>
# SPDX-License-Identifier: GPL-3.0+

VENV=./env
PYTHON=$(VENV)/bin/python
PYTEST=$(VENV)/bin/pytest
BLACK=$(VENV)/bin/black
FLAKE8=$(VENV)/bin/flake8
MYPY=$(VENV)/bin/mypy
STUBGEN=$(VENV)/bin/stubgen

setup: requirements.txt
	virtualenv ./env
	$(VENV)/bin/pip install -r requirements.txt

clean:
	rm -rf ./build
	rm -rf ./htmlcov

blacken:
	find uefi_r2 -name '*.py' -exec $(BLACK) {} \;

check: $(PYTEST)
	$(PYTEST)
	$(MYPY) uefi_r2
	$(FLAKE8)

pkg: $(STUBGEN)
	$(STUBGEN) --output . --package uefi_r2
	$(PYTHON) setup.py sdist bdist_wheel
