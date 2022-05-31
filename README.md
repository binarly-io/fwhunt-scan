[![License: GPL v3](https://img.shields.io/badge/License-GPL%20v3-blue.svg)](http://www.gnu.org/licenses/gpl-3.0)
[![fwhunt-scan CI](https://github.com/binarly-io/fwhunt-scan/actions/workflows/ci.yml/badge.svg)](https://github.com/binarly-io/fwhunt-scan/actions)
[![fwhunt-scan pypi](https://img.shields.io/pypi/v/fwhunt-scan.svg)](https://pypi.org/project/fwhunt-scan)

<p align="center">
  <img alt="fwhunt Logo" src="https://raw.githubusercontent.com/binarly-io/fwhunt-scan/master/pics/fwhunt_logo.png" width="20%">
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
$ git clone https://github.com/binarly-io/fwhunt-scan.git && cd fwhunt_scan
$ python setup.py install
```

# Example

### With script

```
./fwhunt_scan_analyzer.py analyze-image {image_path} -o out.json
./fwhunt_scan_analyzer.py scan --rule {rule_path} {image_path}
```

### With docker

To avoid installing dependencies, you can use the docker image.

You can build a docker image locally:

```
docker build -t ghcr.io/binarly-io/fwhunt_scan:latest .
```

Or pull it from `ghcr`:

```
docker pull ghcr.io/binarly-io/fwhunt_scan:latest # pull docker image from ghcr
```

Example of use:

```
docker run --rm -it -v {module_path}:/tmp/image:ro \
  ghcr.io/binarly-io/fwhunt_scan:latest \
  analyze-image /tmp/image # to analyze image

docker run --rm -it -v {module_path}:/tmp/image:ro -v {rule_path}:/tmp/rule.yml:ro \
  ghcr.io/binarly-io/fwhunt_scan:latest \
  scan /tmp/image -r /tmp/rule.yml # to scan image with specified FwHunt rule
```

All these steps are automated in the `fwhunt_scan_docker.py` script.

### From code

#### UefiAnalyzer

Basic usage examples:

```python
from fwhunt_scan import UefiAnalyzer

...
uefi_analyzer = UefiAnalyzer(image_path=image_path)
print(uefi_analyzer.get_summary())
uefi_analyzer.close()
```

```python
from fwhunt_scan import UefiAnalyzer

...
with UefiAnalyzer(image_path=image_path) as uefi_analyzer:
    print(uefi_analyzer.get_summary())
```

On Linux platforms, you can pass blob for analysis instead of file:

```python
from fwhunt_scan import UefiAnalyzer

...
with UefiAnalyzer(blob=data) as uefi_analyzer:
    print(uefi_analyzer.get_summary())
```

#### UefiScanner

```python
from fwhunt_scan import UefiAnalyzer, UefiRule, UefiScanner

...
uefi_analyzer = UefiAnalyzer(image_path)

# rule1 and rule2 - contents of the rules on YAML format
uefi_rules = [UefiRule(rule1), UefiRule(rule2)]

scanner = UefiScanner(uefi_analyzer, uefi_rules)
result = scanner.result
```
