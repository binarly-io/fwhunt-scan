# SPDX-License-Identifier: GPL-3.0+

"""
Tools for analyzing UEFI firmware using radare2
"""

__author__ = "yeggor"
__email__ = "yegor@binarly.io"
__version__ = "1.0.0"

from .uefi_analyzer import UefiAnalyzer

__all__ = [
    "UefiAnalyzer",
]
