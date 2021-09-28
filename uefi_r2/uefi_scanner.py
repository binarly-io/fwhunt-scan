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
    """A rule for scanning EFI image"""

    def __init__(self, rule: str):
        self._rule: str = rule
        self._rule_name: str = str()
        self._uefi_rule: Dict[str, Any] = dict()
        self._nvram_vars: Optional[List[NvramVariable]] = None
        self._protocols: Optional[List[UefiProtocol]] = None
        self._ppi_list: Optional[List[UefiProtocol]] = None
        self._protocol_guids: Optional[List[UefiProtocolGuid]] = None
        self._esil_rules: Optional[List[List[str]]] = None
        self._strings: Optional[List[str]] = None
        self._wide_strings: Optional[List[str]] = None
        self._hex_strings: Optional[List[str]] = None
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
        """Get optional rule description from the metadata block"""

        try:
            return self._uefi_rule["meta"]["description"]
        except KeyError:
            return None

    @property
    def url(self) -> Optional[str]:
        """Get optional rule URL from the metadata block"""

        try:
            return self._uefi_rule["meta"]["url"]
        except KeyError:
            return None

    def _get_strings(self) -> List[str]:
        strings: List[str] = list()
        if "strings" not in self._uefi_rule:
            return strings
        for string_id in self._uefi_rule["strings"]:
            string = self._uefi_rule["strings"][string_id]
            strings.append(string)
        return strings

    @property
    def strings(self) -> List[str]:
        """Get strings from rule"""

        if self._strings is None:
            self._strings = self._get_strings()
        return self._strings

    def _get_wide_strings(self) -> List[str]:
        wide_strings: List[str] = list()
        if "wide_strings" not in self._uefi_rule:
            return wide_strings
        for wide_string_id in self._uefi_rule["wide_strings"]:
            string = self._uefi_rule["wide_strings"][wide_string_id]
            wide_strings.append(string)
        return wide_strings

    @property
    def wide_strings(self) -> List[str]:
        """Get wide strings from rule"""

        if self._wide_strings is None:
            self._wide_strings = self._get_wide_strings()
        return self._wide_strings

    def _get_hex_strings(self) -> List[str]:
        hex_strings: List[str] = list()
        if "hex_strings" not in self._uefi_rule:
            return hex_strings
        for hex_string_id in self._uefi_rule["hex_strings"]:
            string = self._uefi_rule["hex_strings"][hex_string_id]
            hex_strings.append(string)
        return hex_strings

    @property
    def hex_strings(self) -> List[str]:
        """Get hex strings from rule"""

        if self._hex_strings is None:
            self._hex_strings = self._get_hex_strings()
        return self._hex_strings

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

    def _get_ppi_list(self) -> List[UefiProtocol]:
        ppi_list: List[UefiProtocol] = list()
        if "ppi" not in self._uefi_rule:
            return ppi_list
        for ppi in self._uefi_rule["ppi"]:
            for num in ppi:
                element_name: str = str()
                element_value: str = str()
                element_service: str = str()
                protocol_item = ppi[num]
                for obj in protocol_item:
                    if "name" in obj:
                        element_name = obj["name"]
                    if "value" in obj:
                        element_value = obj["value"]
                    if "service" in obj:
                        element_service = obj["service"][0]["name"]
                ppi_list.append(
                    UefiProtocol(
                        name=element_name,
                        value=element_value,
                        service=element_service,
                        address=0x0,
                        guid_address=0x0,
                    )
                )
        return ppi_list

    @property
    def ppi_list(self) -> List[UefiProtocol]:
        """Get PPI list from rule"""

        if self._ppi_list is None:
            self._ppi_list = self._get_ppi_list()
        return self._ppi_list

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

    def _get_esil_rules(self) -> List[List[str]]:
        esil_rules: List[List[str]] = list()
        if "esil" not in self._uefi_rule:
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
        self._result: Optional[bool] = None

    def _compare(self, x: list, y: list) -> bool:

        if len(x) != len(y):
            return False
        for i in range(len(x)):
            if x[i] == "X":
                continue
            if x[i] != y[i]:
                return False
        return True

    def _check_rule(self, esil_rule: List[str]) -> bool:
        """Esil scanner helper"""

        ops = self._uefi_analyzer.insns
        for i in range(len(ops) - len(esil_rule) + 1):
            counter_item = 0
            for j in range(len(esil_rule)):
                if "esil" not in ops[i + j]:
                    continue
                x, y = esil_rule[j].split(","), ops[i + j]["esil"].split(",")
                if not self._compare(x, y):
                    continue
                counter_item += 1
            if counter_item == len(esil_rule):
                return True
        return False

    def _esil_scanner(self) -> bool:
        """Match ESIL patterns"""

        if self._uefi_rule.esil_rules is None:
            return True
        for esil_rule in self._uefi_rule.esil_rules:
            if not self._check_rule(esil_rule):
                return False
        return True

    def _strings_scanner(self) -> bool:
        """Match strings"""

        if self._uefi_rule.strings is None:
            return True
        for string in self._uefi_rule.strings:
            res = self._uefi_analyzer._rz.cmdj("/j {}".format(string))
            if not res:
                return False
        return True

    def _wide_strings_scanner(self) -> bool:
        """Match wide strings"""

        if self._uefi_rule.wide_strings is None:
            return True
        for wide_string in self._uefi_rule.wide_strings:
            res = self._uefi_analyzer._rz.cmdj("/wj {}".format(wide_string))
            if not res:
                return False
        return True

    def _hex_strings_scanner(self) -> bool:
        """Match hex strings"""

        if self._uefi_rule.hex_strings is None:
            return True
        for hex_string in self._uefi_rule.hex_strings:
            res = self._uefi_analyzer._rz.cmdj("/xj {}".format(hex_string))
            if not res:
                return False
        return True

    def _nvram_scanner(self) -> bool:
        """Compare NVRAM"""

        if self._uefi_rule.nvram_vars is None:
            return True
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
        return True

    def _compare_protocols(self) -> bool:
        """Compare protocols"""

        if self._uefi_rule.protocols is None:
            return True
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
        return True

    def _compare_guids(self) -> bool:
        """Compare GUIDs"""

        if self._uefi_rule.protocol_guids is None:
            return True
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

    def _compare_ppi(self) -> bool:
        """Compare PPI"""

        if self._uefi_rule.ppi_list is None:
            return True
        for ppi_rule in self._uefi_rule.ppi_list:
            ppi_matched = False
            for ppi_analyzer in self._uefi_analyzer.ppi_list:
                if (
                    ppi_rule.name == ppi_analyzer.name
                    and ppi_rule.value == ppi_analyzer.value
                ):
                    ppi_matched = True
                    break
            if not ppi_matched:
                return False
        return True

    def _get_result(self) -> bool:

        # compare NVRAM
        result = self._nvram_scanner()
        if not result:
            return result

        # compare protocols
        result &= self._compare_protocols()
        if not result:
            return result

        # compare GUIDs
        result &= self._compare_guids()
        if not result:
            return result

        # compare PPI
        result &= self._compare_ppi()
        if not result:
            return result

        # match ESIL patterns
        result &= self._esil_scanner()
        if not result:
            return result

        # match strings
        result &= self._strings_scanner()
        if not result:
            return result

        # match wide strings
        result &= self._wide_strings_scanner()
        if not result:
            return result

        # match hex strings
        result &= self._hex_strings_scanner()
        if not result:
            return result

        return result

    @property
    def result(self) -> bool:
        """Get scanning result"""

        if self._result is None:
            self._result = self._get_result()
        return self._result
