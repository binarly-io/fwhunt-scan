[![License: GPL v3](https://img.shields.io/badge/License-GPL%20v3-blue.svg)](http://www.gnu.org/licenses/gpl-3.0)
[![uefi_r2 CI](https://github.com/binarly-io/uefi_r2/actions/workflows/ci.yml/badge.svg)](https://github.com/binarly-io/uefi_r2/actions)
[![uefi_r2 pypi](https://img.shields.io/pypi/v/uefi_r2.svg)](https://pypi.org/project/uefi_r2)

<p align="center">
  <img alt="fwhunt Logo" src="https://raw.githubusercontent.com/binarly-io/uefi_r2/master/pics/fwhunt_logo.png" width="20%">
</p>

# FwHunt Community Scanner

Tools for analyzing UEFI firmware and checking UEFI modules with [FwHunt rules](https://github.com/binarly-io/fwhunt).

# Dependencies

## rizin

```
commit: d5f1aea5953fb7cbc59d219d7fa13d20390089f7
```

# Installation

Install with `pip`:

```bash
$ python -m pip install uefi-r2
```

Install manually:

```bash
$ git clone https://github.com/binarly-io/uefi_r2.git && cd uefi_r2
$ python setup.py install
```

# Example

### With script

```
./uefi_r2_analyzer.py analyze-image {image_path} -o out.json
./uefi_r2_analyzer.py scan --rule {rule_path} {image_path}
```

### From code

#### UefiAnalyzer

Basic usage examples:

```python
from uefi_r2.uefi_analyzer import UefiAnalyzer

...
uefi_analyzer = UefiAnalyzer(image_path=image_path)
print(uefi_analyzer.get_summary())
uefi_analyzer.close()
```

```python
from uefi_r2.uefi_analyzer import UefiAnalyzer

...
with UefiAnalyzer(image_path=image_path) as uefi_analyzer:
    print(uefi_analyzer.get_summary())
```

On Linux platforms, you can pass blob for analysis instead of file:

```python
from uefi_r2.uefi_analyzer import UefiAnalyzer

...
with UefiAnalyzer(blob=data) as uefi_analyzer:
    print(uefi_analyzer.get_summary())
```

#### UefiScanner

```python
from uefi_r2.uefi_analyzer import UefiAnalyzer
from uefi_r2.uefi_scanner import UefiRule, UefiScanner

...
uefi_analyzer = UefiAnalyzer(image_path)

# rule1 and rule2 - contents of the rules on YAML format
uefi_rules = [UefiRule(rule1), UefiRule(rule2)]

scanner = UefiScanner(uefi_analyzer, uefi_rules)
result = scanner.result
```
