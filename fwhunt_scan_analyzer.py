#!/usr/bin/env python3
#
# SPDX-License-Identifier: GPL-3.0+
#
# pylint: disable=invalid-name,missing-module-docstring,missing-function-docstring

# fwhunt_scan: tools for analyzing UEFI firmware and checking UEFI modules with FwHunt rules

import json
import os
import tempfile
from typing import Any, Dict, List, Optional

import click
import uefi_firmware

from fwhunt_scan import UefiAnalyzer, UefiRule, UefiScanner


class UefiBinary:
    def __init__(
        self,
        content: Optional[bytes],
        name: Optional[str],
        guid: str,
        ext: Optional[str],
    ) -> None:
        self.guid: str = guid
        self._content: Optional[bytes] = content
        self._name: Optional[str] = name
        self._ext: Optional[str] = ext

    @property
    def content(self) -> bytes:
        if self._content is None:
            self._content = bytes()
        return self._content

    @property
    def name(self) -> str:
        if self._name is None:
            self._name = self.guid
        return self._name

    @property
    def ext(self) -> str:
        if self._ext is None:
            self._ext = ".bin"
        return self._ext


class Extractor:
    FILE_TYPES = {
        0x01: ("raw", "raw", "RAW"),
        0x02: ("freeform", "freeform", "FREEFORM"),
        0x03: ("security core", "sec", "SEC"),
        0x04: ("pei core", "pei.core", "PEI_CORE"),
        0x05: ("dxe core", "dxe.core", "DXE_CORE"),
        0x06: ("pei module", "peim", "PEIM"),
        0x07: ("driver", "dxe", "DRIVER"),
        0x08: ("combined pei module/driver", "peim.dxe", "COMBO_PEIM_DRIVER"),
        0x09: ("application", "app", "APPLICATION"),
        0x0A: ("system management", "smm", "SMM"),
        0x0C: ("combined smm/driver", "smm.dxe", "COMBO_SMM_DRIVER"),
        0x0D: ("smm core", "smm.core", "SMM_CORE"),
    }
    UI = {0x15: ("User interface name", "ui", "UI")}

    def __init__(self, firmware_data: bytes, file_guid: str):
        self._firmware_data: bytes = firmware_data
        self._file_guid: str = file_guid
        self._parser: Optional[uefi_firmware.AutoParser] = None
        self._extracted: bool = False
        self._ext: Optional[str] = None
        self._name: Optional[str] = None
        self._binary: Optional[UefiBinary] = None
        self._content: Optional[bytes] = None

    def _get_name(self, data: bytes) -> None:
        try:
            self._name = data.decode("utf-16le")
        except UnicodeDecodeError:
            pass

    def _search_binary(self, object: Any) -> None:
        for component in object.iterate_objects():
            guid = component.get("guid", None)
            attrs = component.get("attrs", None)
            if guid is not None and attrs is not None and guid == self._file_guid:
                if attrs.get("type", None) in Extractor.UI:
                    self._get_name(component["_self"].content[:-2])
                if attrs.get("type", None) in Extractor.FILE_TYPES:
                    self._content = component["_self"].content
            self._search_binary(component["_self"])

    def _extract(self) -> bool:
        potencial_volumes = uefi_firmware.search_firmware_volumes(self._firmware_data)
        for offset in potencial_volumes:
            self._parser = uefi_firmware.AutoParser(self._firmware_data[offset - 40 :])
            if self._parser.type() == "unknown":
                print(f"Current offset: {offset:#x}")
                continue
            break

        if self._parser.type() == "unknown":
            return False
        firmware = self._parser.parse()
        self._search_binary(firmware)
        return True

    @property
    def binary(self) -> bytes:
        if self._extracted:
            return self._binary
        self._extract()
        self._extracted = True
        if self._content is not None:
            self._binary = UefiBinary(
                content=self._content,
                name=self._name,
                guid=self._file_guid,
                ext=self._ext,
            )
        return self._binary


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
    """Scan single UEFI module."""

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


@click.command()
@click.argument("image_path")
@click.option("-r", "--rule", help="The path to the rule.", multiple=True)
def scan_firmware(image_path: str, rule: List[str]) -> bool:
    """Scan UEFI firmware image."""

    rules = rule

    error_prefix = click.style("ERROR", fg="red", bold=True)
    if not os.path.isfile(image_path):
        print(f"{error_prefix} check image path")
        return False
    if not all(rule and os.path.isfile(rule) for rule in rules):
        print(f"{error_prefix} check rule(s) path")
        return False

    # on linux platforms you can pass blob via shm://
    # uefi_analyzer = UefiAnalyzer(blob=data)

    uefi_rules: List[UefiRule] = list()

    for r in rules:
        with open(r, "r") as f:
            rule_content = f.read()
            uefi_rule = UefiRule(rule_content=rule_content)
            uefi_rules.append(uefi_rule)

    # Group rules by guids
    rules_guids: Dict[str, List[UefiRule]] = dict()
    for rule in uefi_rules:
        if rule.volume_guids is None:
            print(f"[I] Specify volume_guids in {rule.name} or use scan command")
            continue
        for guid in rule.volume_guids:
            if not guid in rules_guids:
                rules_guids[guid] = [rule]
            else:
                rules_guids[guid].append(rule)

    if not rules_guids.keys():
        print(
            f"{error_prefix} None of the rules specify volume_guids (use scan command)"
        )
        return False

    with open(image_path, "rb") as f:
        firmware_data = f.read()

    prefix = click.style("Scanner result", fg="green")
    no_threat = click.style("No threat detected", fg="green")
    threat = click.style(
        "FwHunt rule has been triggered and threat detected!", fg="red"
    )

    for volume_guid in rules_guids:
        extractor = Extractor(firmware_data, volume_guid)
        if extractor.binary is None:
            for rule in rules_guids[volume_guid]:
                print(
                    f"[I] Skipping the rule {rule.name} (module not present in firmware image)"
                )
            continue

        if not extractor.binary.content:
            continue

        with tempfile.NamedTemporaryFile(
            mode="wb",
            prefix=f"{extractor.binary.name}_",
            suffix=f".{extractor.binary.ext}",
            dir=None,
            delete=True,
        ) as f:
            f.write(extractor.binary.content)
            uefi_analyzer = UefiAnalyzer(image_path=f.name)
            scanner = UefiScanner(uefi_analyzer, rules_guids[volume_guid])

            for result in scanner.results:
                msg = threat if result.res else no_threat
                print(
                    f"{prefix} {result.rule.name} (variant: {result.variant_label}) {msg} ({extractor.binary.name})"
                )

        uefi_analyzer.close()

        return True


cli.add_command(analyze_image)
cli.add_command(scan)
cli.add_command(scan_firmware)

if __name__ == "__main__":
    cli()
