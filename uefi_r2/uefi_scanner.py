# SPDX-License-Identifier: GPL-3.0+

"""
Tools for analyzing UEFI firmware using radare2
"""

import json
import os
from typing import Any, Dict, List, Optional

import yaml

from uefi_r2.uefi_analyzer import (
    NvramVariable,
    UefiAnalyzer,
    UefiProtocol,
    UefiProtocolGuid,
    UefiService,
)


class UefiRule:
    """a rule for scanning EFI image"""

    def __init__(self, rule: str):
        self._rule: str = rule
        self._rule_name: str = str()
        self._uefi_rule: Dict[str, Any] = dict()
        self._nvram_vars: Optional[List[NvramVariable]] = None
        self._protocols: Optional[List[UefiProtocol]] = None
        self._protocol_guids: Optional[List[List[str]]] = None
        self._esil_rules: Optional[List[str]] = None
        if os.path.isfile(self._rule):
            try:
                with open(self._rule, "r") as f:
                    self._uefi_rule = yaml.safe_load(f)
            except yaml.scanner.ScannerError as e:
                print(f"Error: {repr(e)}")
        if self._uefi_rule:
            self._rule_name = list(self._uefi_rule.keys())[0]
        if self._rule_name:
            self._uefi_rule = self._uefi_rule[self._rule_name]

    def __str__(self):
        return json.dumps(self._uefi_rule, indent=2)

    def _get_nvram_vars(self) -> List[NvramVariable]:

        nvram_vars = list()
        if not "nvram" in self._uefi_rule:
            return nvram_vars
        for nvrams in self._uefi_rule["nvram"]:
            for num in nvrams:
                element_name: str = str()
                element_guid: str = str()
                element_service: str = str()
                nvram_item = nvrams[num]
                for obj in nvram_item:
                    if "name" in obj:
                        element_name = obj["name"]
                    if "guid" in obj:
                        element_guid = obj["guid"]
                    if "service" in obj:
                        element_service = obj["service"][0]["name"]
                service = UefiService(name=element_service, address=None)
                nvram_vars.append(
                    NvramVariable(name=element_name, guid=element_guid, service=service)
                )
        return nvram_vars

    @property
    def nvram_vars(self) -> List[NvramVariable]:
        """Get NVRAM variables from rule"""

        if self._nvram_vars is None:
            self._nvram_vars = self._get_nvram_vars()
        return self._nvram_vars

    def _get_protocols(self) -> List[UefiProtocol]:

        protocols = list()
        if not "protocols" in self._uefi_rule:
            return protocols
        for protocols_list in self._uefi_rule["protocols"]:
            for num in protocols_list:
                element_name: str = str()
                element_value: str = str()
                element_service: str = str()
                protocol_item = protocols_list[num]
                for obj in protocol_item:
                    if "name" in obj:
                        element_name = obj["name"]
                    if "value" in obj:
                        element_value = obj["value"]
                    if "service" in obj:
                        element_service = obj["service"][0]["name"]
                protocols.append(
                    UefiProtocol(
                        name=element_name,
                        value=element_value,
                        service=element_service,
                        address=None,
                        guid_address=None,
                    )
                )
        return protocols

    @property
    def protocols(self) -> List[UefiProtocol]:
        """Get protocols from rule"""

        if self._protocols is None:
            self._protocols = self._get_protocols()
        return self._protocols

    def _get_protocol_guids(self) -> List[UefiProtocolGuid]:

        protocol_guids = list()
        if not "guids" in self._uefi_rule:
            return protocol_guids
        for guids_list in self._uefi_rule["guids"]:
            for num in guids_list:
                element_name: str = str()
                element_value: str = str()
                guid_item = guids_list[num]
                for obj in guid_item:
                    if "name" in obj:
                        element_name = obj["name"]
                    if "value" in obj:
                        element_value = obj["value"]
                protocol_guids.append(
                    UefiProtocolGuid(
                        name=element_name,
                        value=element_value,
                        address=None,
                    )
                )
        return protocol_guids

    @property
    def protocol_guids(self) -> List[UefiProtocolGuid]:
        """Get GUIDs from rule"""

        if self._protocol_guids is None:
            self._protocol_guids = self._get_protocol_guids()
        return self._protocol_guids

    def _get_esil_rules(self) -> List[List[str]]:

        esil_rules = list()
        if not "esil" in self._uefi_rule:
            return esil_rules
        for esil_list in self._uefi_rule["esil"]:
            for num in esil_list:
                esil_rules.append(esil_list[num])
        return esil_rules

    @property
    def esil_rules(self) -> List[List[str]]:
        """Get esil rules"""

        if self._esil_rules is None:
            self._esil_rules = self._get_esil_rules()
        return self._esil_rules


class UefiScanner:
    """helper object for scanning an EFI image with a given rule"""

    def __init__(self, uefi_analyzer: UefiAnalyzer, uefi_rule: UefiRule):
        self._uefi_analyzer: UefiAnalyzer = uefi_analyzer
        self._uefi_rule: UefiRule = uefi_rule
        self._result: bool = None

    def _compare(self, x: list, y: list) -> bool:

        if len(x) != len(y):
            return False
        for i in range(len(x)):
            if x[i] == "X":
                continue
            if x[i] != y[i]:
                return False
        return True

    def _check_rule(self, esil_rule: List[List[str]]) -> bool:
        print(f"Current rule: {esil_rule}")
        for func in self._uefi_analyzer.functions:
            func_addr = func["offset"]
            func_insns = self._uefi_analyzer._r2.cmdj("pdfj @{:#x}".format(func_addr))
            ops = func_insns["ops"]
            for i in range(len(ops) - len(esil_rule) + 1):
                counter_item = 0
                for j in range(len(esil_rule)):
                    x, y = esil_rule[j].split(","), ops[i + j]["esil"].split(",")
                    if not self._compare(x, y):
                        continue
                    counter_item += 1
                if counter_item == len(esil_rule):
                    return True
        return False

    def _esil_scanner(self):

        if self._uefi_rule.esil_rules is None:
            return True
        for esil_rule in self._uefi_rule.esil_rules:
            if not self._check_rule(esil_rule):
                return False
        return True

    def _get_result(self) -> bool:

        # compare nvram
        for nvram_rule in self._uefi_rule.nvram_vars:
            nvram_matched = False
            for nvram_analyzer in self._uefi_analyzer.nvram_vars:
                if (
                    nvram_rule.name == nvram_analyzer.name
                    and nvram_rule.guid == nvram_analyzer.guid
                    and nvram_rule.service.name == nvram_analyzer.service.name
                ):
                    nvram_matched = True
                    break
            if not nvram_matched:
                return False
        # compare protocols
        for protocol_rule in self._uefi_rule.protocols:
            protocol_matched = False
            for protocol_analyzer in self._uefi_analyzer.protocols:
                if (
                    protocol_rule.name == protocol_analyzer.name
                    and protocol_rule.value == protocol_analyzer.value
                ):
                    protocol_matched = True
                    break
            if not protocol_matched:
                return False
        # compare guids
        for guid_rule in self._uefi_rule.protocol_guids:
            guid_matched = False
            for guid_analyzer in self._uefi_analyzer.protocol_guids:
                if (
                    guid_rule.name == guid_analyzer.name
                    and guid_rule.value == guid_analyzer.value
                ):
                    guid_matched = True
                    break
            if not guid_matched:
                return False
        return self._esil_scanner()

    @property
    def result(self) -> bool:
        """Get scanning result"""

        if self._result is None:
            self._result = self._get_result()
        return self._result
