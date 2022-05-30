[![License: GPL v3](https://img.shields.io/badge/License-GPL%20v3-blue.svg)](http://www.gnu.org/licenses/gpl-3.0)
[![fwhunt_scan CI](https://github.com/binarly-io/fwhunt_scan/actions/workflows/ci.yml/badge.svg)](https://github.com/binarly-io/fwhunt_scan/actions)
[![fwhunt_scan pypi](https://img.shields.io/pypi/v/fwhunt_scan.svg)](https://pypi.org/project/fwhunt_scan)

<p align="center">
  <img alt="fwhunt Logo" src="https://raw.githubusercontent.com/binarly-io/fwhunt_scan/master/pics/fwhunt_logo.png" width="20%">
</p>

# FwHunt Community Scanner

Tools for analyzing UEFI firmware and checking UEFI modules with [FwHunt rules](https://github.com/binarly-io/fwhunt).

# Dependencies

## rizin

```
min commit: d5f1aea5953fb7cbc59d219d7fa13d20390089f7
max commit: c09ff31205f18f478234249fc76b101ebb101663 (v0.3.3)
```

# Installation

Install with `pip` (tested on `python3.6` and above):

```
$ python -m pip install fwhunt-scan
```

Install manually:

```
$ git clone https://github.com/binarly-io/fwhunt_scan.git && cd fwhunt_scan
$ python setup.py install
```

# Example

### With script

```
./fwhunt_scan_analyzer.py analyze-image {image_path} -o out.json
./fwhunt_scan_analyzer.py scan --rule {rule_path} {image_path}
```

### From code

#### UefiAnalyzer

Basic usage examples:

```python
from fwhunt_scan.uefi_analyzer import UefiAnalyzer

...
uefi_analyzer = UefiAnalyzer(image_path=image_path)
print(uefi_analyzer.get_summary())
uefi_analyzer.close()
```

```python
from fwhunt_scan.uefi_analyzer import UefiAnalyzer

...
with UefiAnalyzer(image_path=image_path) as uefi_analyzer:
    print(uefi_analyzer.get_summary())
```

On Linux platforms, you can pass blob for analysis instead of file:

```python
from fwhunt_scan.uefi_analyzer import UefiAnalyzer

...
with UefiAnalyzer(blob=data) as uefi_analyzer:
    print(uefi_analyzer.get_summary())
```

#### UefiScanner

```python
from fwhunt_scan.uefi_analyzer import UefiAnalyzer
from fwhunt_scan.uefi_scanner import UefiRule, UefiScanner

...
uefi_analyzer = UefiAnalyzer(image_path)

# rule1 and rule2 - contents of the rules on YAML format
uefi_rules = [UefiRule(rule1), UefiRule(rule2)]

scanner = UefiScanner(uefi_analyzer, uefi_rules)
result = scanner.result
```
