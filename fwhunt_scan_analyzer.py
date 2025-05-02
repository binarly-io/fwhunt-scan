#!/usr/bin/env python3
#
# SPDX-License-Identifier: GPL-3.0+
#
# pylint: disable=invalid-name,missing-module-docstring,missing-function-docstring

# fwhunt_scan: tools for analyzing UEFI firmware and checking UEFI modules with FwHunt rules

import json
import logging
import os
import pathlib
import tempfile
from typing import Dict, List

import click

from fwhunt_scan import UefiAnalyzer, UefiExtractor, UefiRule, UefiScanner

logging.basicConfig(
    format="%(name)s %(asctime)s %(levelname)s: %(message)s",
    datefmt="%m/%d/%Y %I:%M:%S %p",
)
logger = logging.getLogger("fwhunt_scan")


@click.group()
def cli():
    pass


@click.command()
@click.argument("path")
@click.option("-o", "--out", help="Output JSON file.")
def analyze(path: str, out: str) -> bool:
    """Analyze single EFI file."""

    if not os.path.isfile(path):
        click.echo(
            "{} check module path".format(click.style("ERROR", fg="red", bold=True))
        )
        return False

    # on linux platforms you can pass blob via shm://
    # uefi_analyzer = UefiAnalyzer(blob=data)

    summary = None
    with UefiAnalyzer(image_path=path) as uefi_analyzer:
        summary = uefi_analyzer.get_summary()

    if out:
        with open(out, "w") as f:
            json.dump(summary, f, indent=4)
    else:
        click.echo(json.dumps(summary, indent=4))

    return True


@click.command()
@click.argument("path")
@click.option("-r", "--rule", help="The path to the rule.", multiple=True)
def scan(path: str, rule: List[str]) -> bool:
    """Scan single EFI file."""

    rules = rule

    if not os.path.isfile(path):
        click.echo(
            "{} check module path".format(click.style("ERROR", fg="red", bold=True))
        )
        return False
    if not all(rule and os.path.isfile(rule) for rule in rules):
        click.echo(
            "{} check rule(s) path".format(click.style("ERROR", fg="red", bold=True))
        )
        return False

    # on linux platforms you can pass blob via shm://
    # uefi_analyzer = UefiAnalyzer(blob=data)

    uefi_analyzer = UefiAnalyzer(image_path=path)

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
        click.echo(
            f"{prefix} {result.rule.name} (variant: {result.variant_label}) {msg} ({path})"
        )

    uefi_analyzer.close()

    return True


@click.command()
@click.argument("image_path")
@click.option("-r", "--rule", help="The path to the rule.", multiple=True)
@click.option("-d", "--rules_dir", help="The path to the rules directory.")
@click.option(
    "-f",
    "--force",
    help="Enforcing the use of rules without specified volume guids.",
    is_flag=True,
)
def scan_firmware(
    image_path: str, rule: List[str], rules_dir: str, force: bool
) -> bool:
    """Scan UEFI firmware image."""

    rules = list(rule)
    error_prefix = click.style("ERROR", fg="red", bold=True)
    if not rules_dir:
        if not all(rules and os.path.isfile(rule) for rule in rules):
            click.echo(f"{error_prefix} check rule(s) path")
            return False
    else:
        rules += list(map(str, pathlib.Path(rules_dir).rglob("*.yml")))

    if not os.path.isfile(image_path):
        click.echo(f"{error_prefix} check image path")
        return False

    prefix = click.style("Scanner result", fg="green")
    no_threat = click.style("No threat detected", fg="green")
    threat = click.style(
        "FwHunt rule has been triggered and threat detected!", fg="red"
    )

    # on linux platforms you can pass blob via shm://
    # uefi_analyzer = UefiAnalyzer(blob=data)

    uefi_rules: List[UefiRule] = list()

    for r in rules:
        with open(r, "r") as f:
            uefi_rules.append(UefiRule(rule_content=f.read()))

    # Select the rules with `target: firmware`
    uefi_rules_fw: List[UefiRule] = list(
        filter(lambda rule: rule.target == "firmware", uefi_rules)
    )
    if len(uefi_rules_fw):
        with UefiAnalyzer(image_path=image_path) as uefi_analyzer_fw:
            scanner_fw = UefiScanner(uefi_analyzer_fw, uefi_rules_fw)
            for result in scanner_fw.results:
                msg = threat if result.res else no_threat
                click.echo(
                    f"{prefix} {result.rule.name} (variant: {result.variant_label}) {msg}"
                )

    # Group rules by guids
    rules_guids: Dict[str, List[UefiRule]] = dict()
    rules_universal: List[UefiRule] = list()
    for uefi_rule in set(uefi_rules) - set(uefi_rules_fw):
        if uefi_rule.target not in (None, "module"):
            logger.debug(
                f"The rule {uefi_rule.name} incompatible with scan-firmware command (target: {uefi_rule.target})"
            )
            continue
        if not len(uefi_rule.volume_guids) and not force:
            logger.warning(
                f"Specify volume_guids in {uefi_rule.name} or run command with --force flag"
            )
            continue
        elif not len(uefi_rule.volume_guids):
            rules_universal.append(uefi_rule)
        for guid in [g.lower() for g in uefi_rule.volume_guids]:
            lower_guid = guid.lower()
            if lower_guid not in rules_guids:
                rules_guids[lower_guid] = list()
            rules_guids[lower_guid].append(uefi_rule)

    if not rules_guids.keys() and not force:
        click.echo(
            f"{error_prefix} None of the rules specify volume_guids (use scan-module command)"
        )
        return False

    with open(image_path, "rb") as f:
        firmware_data = f.read()

    extractor = UefiExtractor(
        firmware_data, list(rules_guids.keys()) if not force else list()
    )
    extractor.extract_all(ignore_guid=force)

    if not len(extractor.binaries):
        click.echo("No modules were found for scanning")
        return False

    for binary in extractor.binaries:
        if not binary.is_ok:
            continue

        rules_scan = rules_universal + (
            rules_guids[binary.guid] if binary.guid in rules_guids else list()
        )

        if not len(rules_scan):
            continue

        fpath = os.path.join(tempfile.gettempdir(), f"{binary.name}{binary.ext}")
        with open(fpath, "wb") as f:
            f.write(binary.content)

        logger.debug(f"Scanning the module {binary.name}{binary.ext}")

        with UefiAnalyzer(image_path=fpath) as uefi_analyzer:
            scanner = UefiScanner(uefi_analyzer, rules_scan)
            for result in scanner.results:
                msg = threat if result.res else no_threat
                click.echo(
                    f"{prefix} {result.rule.name} (variant: {result.variant_label}) {msg} ({binary.name})"
                )

        os.remove(fpath)

    return True


@click.command()
@click.argument(
    "image_path", type=click.Path(exists=True, dir_okay=False, file_okay=True)
)
@click.argument("extract_path", type=click.Path(dir_okay=True, file_okay=False))
def extract(image_path: str, extract_path: str) -> bool:
    """Extract all modules from UEFI firmware image."""

    if not os.path.isdir(extract_path):
        os.mkdir(extract_path)

    with open(image_path, "rb") as f:
        firmware_data = f.read()

    extractor = UefiExtractor(firmware_data, list())
    extractor.extract_all(ignore_guid=True)

    if not len(extractor.binaries):
        click.echo("No modules found", err=True)
        return False

    for binary in extractor.binaries:
        if not binary.is_ok:
            continue
        fpath = os.path.join(extract_path, f"{binary.name}-{binary.guid}{binary.ext}")
        with open(fpath, "wb") as f:
            f.write(binary.content)

        click.echo(f"{binary.guid}: {fpath}")

    return True


cli.add_command(analyze)
cli.add_command(analyze, "analyze-module")
cli.add_command(analyze, "analyze-bootloader")
cli.add_command(scan)
cli.add_command(scan, "scan-module")
cli.add_command(scan, "scan-bootloader")
cli.add_command(scan_firmware)
cli.add_command(extract)

if __name__ == "__main__":
    cli()
