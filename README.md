[![License: GPL v3](https://img.shields.io/badge/License-GPL%20v3-blue.svg)](http://www.gnu.org/licenses/gpl-3.0)
[![uefi_r2 CI](https://github.com/binarly-io/uefi_r2/actions/workflows/ci.yml/badge.svg)](https://github.com/binarly-io/uefi_r2/actions)

# uefi_r2

Tools for analyzing UEFI firmware using radare2/rizin

# Dependencies

## rizin

```
commit: d5f1aea5953fb7cbc59d219d7fa13d20390089f7
```

# Installation

```bash
python setup.py install
```

# Example

### With script

```
./uefi_r2_analyzer.py analyze-image {image_path} -o out.json
./uefi_r2_analyzer.py scan --rule {rule_path} {image_path}
```

### From code

```python
from uefi_r2.uefi_analyzer import UefiAnalyzer

uefi_analyzer = UefiAnalyzer(blob=data)
...
uefi_analyzer.close()
```

```python
from uefi_r2.uefi_analyzer import UefiAnalyzer

uefi_analyzer = UefiAnalyzer(image_path=image_path)
...
uefi_analyzer.close()
```

```python
from uefi_r2.uefi_analyzer import UefiAnalyzer
from uefi_r2.uefi_scanner import UefiRule, UefiScanner

...
uefi_analyzer = UefiAnalyzer(image_path)
uefi_rule = UefiRule(rule)
scanner = UefiScanner(uefi_analyzer, uefi_rule)
result = scanner.result
```
