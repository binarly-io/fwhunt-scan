# uefi_r2: tools for analyzing UEFI firmware using radare2
#
# SPDX-License-Identifier: GPL-3.0+
#
# pylint: disable=missing-module-docstring

__author__ = "yeggor"
__email__ = "yegor@binarly.io"
__version__ = "1.0.0"

from .uefi_analyzer import UefiAnalyzer

__all__ = [
    "UefiAnalyzer",
]
