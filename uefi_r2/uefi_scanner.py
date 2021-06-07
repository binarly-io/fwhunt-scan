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
        self._protocol_guids: Optional[List[UefiProtocolGuid]] = None
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

    @property
    def name(self) -> Optional[str]:
        """Get rule name from the metadata block"""
        try:
            return self._uefi_rule["meta"]["name"]
        except KeyError:
            return None

    @property
    def namespace(self) -> Optional[str]:
        """Get rule namespace from the metadata block"""
        try:
            return self._uefi_rule["meta"]["namespace"]
        except KeyError:
            return None

    @property
    def description(self) -> Optional[str]:
        """Get rule description URL from the metadata block"""
        try:
            return self._uefi_rule["meta"]["description"]
        except KeyError:
            return None

    def _get_nvram_vars(self) -> List[NvramVariable]:

        nvram_vars: List[NvramVariable] = list()
        if "nvram" not in self._uefi_rule:
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
                service = UefiService(name=element_service, address=0x0)
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

        protocols: List[UefiProtocol] = list()
        if "protocols" not in self._uefi_rule:
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
                        address=0x0,
                        guid_address=0x0,
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

        protocol_guids: List[UefiProtocolGuid] = list()
        if "guids" not in self._uefi_rule:
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
                        address=0x0,
                    )
                )
        return protocol_guids

    @property
    def protocol_guids(self) -> List[UefiProtocolGuid]:
        """Get GUIDs from rule"""

        if self._protocol_guids is None:
            self._protocol_guids = self._get_protocol_guids()
        return self._protocol_guids


class UefiScanner:
    """helper object for scanning an EFI image with a given rule"""

    def __init__(self, uefi_analyzer: UefiAnalyzer, uefi_rule: UefiRule):
        self._uefi_analyzer: UefiAnalyzer = uefi_analyzer
        self._uefi_rule: UefiRule = uefi_rule
        self._result: Optional[bool] = None

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
        return True

    @property
    def result(self) -> bool:
        """Get scanning result"""

        if self._result is None:
            self._result = self._get_result()
        return self._result
