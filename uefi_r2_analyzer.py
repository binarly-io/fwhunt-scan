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

    summary = None
    with UefiAnalyzer(image_path=image_path) as uefi_analyzer:
        summary = uefi_analyzer.get_summary()

    if out:
        with open(out, "w") as f:
            json.dump(summary, f, indent=4)
    else:
        print(json.dumps(summary, indent=4))

    return True


@click.command()
@click.argument("image_path")
@click.option("-r", "--rule", help="The path to the rule.", multiple=True)
def scan(image_path: str, rule: List[str]) -> bool:
    """Scan input UEFI image."""

    rules = rule

    if not os.path.isfile(image_path):
        print("{} check image path".format(click.style("ERROR", fg="red", bold=True)))
        return False
    if not all(rule and os.path.isfile(rule) for rule in rules):
        print("{} check rule(s) path".format(click.style("ERROR", fg="red", bold=True)))
        return False

    # on linux platforms you can pass blob via shm://
    # uefi_analyzer = UefiAnalyzer(blob=data)

    uefi_analyzer = UefiAnalyzer(image_path=image_path)

    uefi_rules: List[UefiRule] = list()

    for r in rules:
        with open(r, "r") as f:
            rule_content = f.read()
            uefi_rule = UefiRule(rule_content=rule_content)
            uefi_rules.append(uefi_rule)

    scanner = UefiScanner(uefi_analyzer, uefi_rules)
    prefix = click.style("Scanner result", fg="green")

    no_threat = click.style("No threat detected", fg="green")
    threat = click.style(
        "FwHunt rule has been triggered and threat detected!", fg="red"
    )

    for result in scanner.results:
        msg = threat if result.res else no_threat
        print(
            f"{prefix} {result.rule.name} (variant: {result.variant_label}) {msg} ({image_path})"
        )

    uefi_analyzer.close()

    return True


cli.add_command(analyze_image)
cli.add_command(scan)

if __name__ == "__main__":
    cli()
