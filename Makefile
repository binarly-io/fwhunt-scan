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
	$(VENV)/bin/pip install -r requirements.txt

clean:
	rm -rf ./build
	rm -rf ./htmlcov
	rm -rf ./dist

blacken:
	find fwhunt_scan -name '*.py' -exec $(BLACK) {} \;

check: $(PYTEST)
	$(PYTEST)
	$(MYPY) fwhunt_scan
	$(FLAKE8)

pkg: $(STUBGEN)
	$(STUBGEN) --output . --package fwhunt_scan
	$(PYTHON) setup.py sdist bdist_wheel
