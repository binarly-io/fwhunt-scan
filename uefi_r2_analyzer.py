#!/usr/bin/env python3
#
# SPDX-License-Identifier: GPL-3.0+
#
# pylint: disable=invalid-name,missing-module-docstring,missing-function-docstring

# uefi_r2: tools for analyzing UEFI firmware using radare2

import json
import os

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
    summary = UefiAnalyzer.get_summary(image_path)
    if out:
        with open(out, "w") as f:
            json.dump(summary, f, indent=4)
    else:
        print(json.dumps(summary, indent=4))
    return True


@click.command()
@click.argument("image_path")
def parse_te(image_path: str) -> bool:
    """Parse input TE file."""

    if not os.path.isfile(image_path):
        print("{} check image path".format(click.style("ERROR", fg="red", bold=True)))
        return False
    print(TerseExecutableParser(image_path))
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

    uefi_analyzer = UefiAnalyzer(image_path)
    prefix = click.style("UEFI analyzer", fg="green")
    print(f"{prefix} nvram: {[x.__dict__ for x in uefi_analyzer.nvram_vars]}")
    print(f"{prefix} protocols: {[x.__dict__ for x in uefi_analyzer.protocols]}")
    print(f"{prefix} guids: {[x.__dict__ for x in uefi_analyzer.protocol_guids]}")

    uefi_rule = UefiRule(rule)
    prefix = click.style("UEFI rule", fg="green")
    print(f"{prefix} nvram: {[x.__dict__ for x in uefi_rule.nvram_vars]}")
    print(f"{prefix} protocols: {[x.__dict__ for x in uefi_rule.protocols]}")
    print(f"{prefix} guids: {[x.__dict__ for x in uefi_rule.protocol_guids]}")
    print(f"{prefix} esil: {uefi_rule.esil_rules}")

    scanner = UefiScanner(uefi_analyzer, uefi_rule)
    prefix = click.style("Scanner result", fg="green")
    print(f"{prefix} {uefi_rule.name} {scanner.result}")

    return True


cli.add_command(analyze_image)
cli.add_command(parse_te)
cli.add_command(scan)

if __name__ == "__main__":
    cli()
