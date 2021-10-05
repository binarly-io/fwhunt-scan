#!/usr/bin/env python3
#
# SPDX-License-Identifier: GPL-3.0+
#
# pylint: disable=invalid-name,missing-module-docstring,missing-function-docstring

# uefi_r2: tools for analyzing UEFI firmware using radare2/rizin

import json
import os
from typing import List

import click

from uefi_r2 import UefiAnalyzer, UefiRule, UefiScanner


@click.group()
def cli():
    pass


@click.command()
@click.argument("image_path")
@click.option("-o", "--out", help="Output JSON file.")
def analyze_image(image_path: str, out: str) -> bool:
    """Analyze input UEFI image."""

    if not os.path.isfile(image_path):
        print("{} check image path".format(click.style("ERROR", fg="red", bold=True)))
        return False

    # on linux platforms you can pass blob via shm://
    # uefi_analyzer = UefiAnalyzer(blob=data)

    uefi_analyzer = UefiAnalyzer(image_path=image_path)

    summary = uefi_analyzer.get_summary()
    uefi_analyzer.close()

    if out:
        with open(out, "w") as f:
            json.dump(summary, f, indent=4)
    else:
        print(json.dumps(summary, indent=4))

    return True


@click.command()
@click.argument("image_path")
@click.option("-r", "--rule", help="The path to the rule.")
def scan(image_path: str, rule: str) -> bool:
    """Scan input UEFI image."""

    if not os.path.isfile(image_path):
        print("{} check image path".format(click.style("ERROR", fg="red", bold=True)))
        return False
    if not (rule and os.path.isfile(rule)):
        print("{} check rule path".format(click.style("ERROR", fg="red", bold=True)))
        return False

    # on linux platforms you can pass blob via shm://
    # uefi_analyzer = UefiAnalyzer(blob=data)

    uefi_analyzer = UefiAnalyzer(image_path=image_path)

    with open(rule, "r") as f:
        rule_content = f.read()

    uefi_rule = UefiRule(rule_content=rule_content)
    prefix = click.style("UEFI rule", fg="green")
    if len(uefi_rule.nvram_vars):
        print(f"{prefix} nvram: {[x.__dict__ for x in uefi_rule.nvram_vars]}")
    if len(uefi_rule.protocols):
        print(f"{prefix} protocols: {[x.__dict__ for x in uefi_rule.protocols]}")
    if len(uefi_rule.ppi_list):
        print(f"{prefix} ppi: {[x.__dict__ for x in uefi_rule.ppi_list]}")
    if len(uefi_rule.protocol_guids):
        print(f"{prefix} guids: {[x.__dict__ for x in uefi_rule.protocol_guids]}")
    if len(uefi_rule.esil_rules):
        print(f"{prefix} esil: {uefi_rule.esil_rules}")
    if len(uefi_rule.strings):
        print(f"{prefix} strings: {uefi_rule.strings}")
    if len(uefi_rule.wide_strings):
        print(f"{prefix} wide_strings: {uefi_rule.wide_strings}")
    if len(uefi_rule.hex_strings):
        print(f"{prefix} hex_strings: {uefi_rule.hex_strings}")
    if len(uefi_rule.code):
        for code in uefi_rule.code:
            print(f"{prefix} code: {code.__dict__}")

    scanner = UefiScanner(uefi_analyzer, uefi_rule)
    prefix = click.style("Scanner result", fg="green")
    res = click.style("No threats detected", fg="green")
    if scanner.result:
        res = click.style(
            "FwHunt rule has been triggered and threat detected!", fg="red"
        )
    print(f"{prefix} {uefi_rule.name} {res}")

    uefi_analyzer.close()

    return True


cli.add_command(analyze_image)
cli.add_command(scan)

if __name__ == "__main__":
    cli()
