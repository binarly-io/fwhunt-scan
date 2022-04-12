# SPDX-License-Identifier: GPL-3.0+

"""
Tools for analyzing UEFI firmware using radare2
"""

import binascii
from collections import defaultdict
import json
import os
from typing import Any, DefaultDict, Dict, Iterable, List, Optional, Set, Tuple, Union

import yaml

from uefi_r2.uefi_analyzer import (
    NvramVariable,
    UefiAnalyzer,
    UefiProtocol,
    UefiProtocolGuid,
    UefiService,
)


class CodePattern:
    """Code pattern"""

    def __init__(self, pattern: str, places: Optional[List[Any]]) -> None:
        self.pattern: str = pattern
        self.places: Optional[List[Any]] = places

        # if True, scan in all SW SMI handlers
        self.sw_smi_handlers: bool = False

        # if True, scan in all child SW SMI handlers
        self.child_sw_smi_handlers: bool = False

        # list of child SW SMI handlers GUIDs
        self.child_sw_smi_handlers_guids: List[str] = list()

        if self.places is not None:

            for place in self.places:
                if type(place) == str and place == "sw_smi_handlers":
                    self.sw_smi_handlers = True

                elif type(place) == str and place == "child_sw_smi_handlers":
                    self.child_sw_smi_handlers = True

                elif type(place) == dict:
                    if "child_sw_smi_handler" not in place:
                        continue
                    for guid in place["child_sw_smi_handler"]:
                        self.child_sw_smi_handlers_guids.append(guid)

    @property
    def __dict__(self):
        return dict(
            {
                "pattern": self.pattern,
                "sw_smi_handlers": self.sw_smi_handlers,
                "child_sw_smi_handlers": self.child_sw_smi_handlers,
                "child_sw_smi_handlers_guids": self.child_sw_smi_handlers_guids,
            }
        )


class UefiRule:
    """A rule for scanning EFI image"""

    def __init__(
        self, rule_path: Optional[str] = None, rule_content: Optional[str] = None
    ):
        self._rule: Optional[str] = rule_path
        self._rule_name: str = str()
        self._uefi_rule: Dict[str, Any] = dict()
        self._nvram_vars: Optional[List[NvramVariable]] = None  # TODO
        self._protocols: Optional[List[UefiProtocol]] = None  # TODO
        self._ppi_list: Optional[List[UefiProtocol]] = None  # TODO
        self._protocol_guids: Optional[List[UefiProtocolGuid]] = None  # TODO
        self._esil_rules: Optional[List[List[str]]] = None  # TODO
        self._strings: Optional[Dict[str, List[str]]] = None
        self._wide_strings: Optional[Dict[str, List[Dict[str, str]]]] = None
        self._hex_strings: Optional[Dict[str, List[str]]] = None
        self._code: Optional[List[Any]] = None  # TODO
        if self._rule is not None:
            if os.path.isfile(self._rule):
                try:
                    with open(self._rule, "r") as f:
                        self._uefi_rule = yaml.safe_load(f)
                except yaml.scanner.ScannerError as e:
                    print(f"Error: {repr(e)}")
        elif rule_content is not None:
            try:
                self._uefi_rule = yaml.safe_load(rule_content)
            except yaml.scanner.ScannerError as e:
                print(f"Error: {repr(e)}")
        if self._uefi_rule:
            self._rule_name = list(self._uefi_rule.keys())[0]
        if self._rule_name:
            self._uefi_rule = self._uefi_rule[self._rule_name]

    def __str__(self):
        return json.dumps(self._uefi_rule, indent=2)

    @property
    def author(self) -> Optional[str]:
        """Get author from the metadata block"""

        try:
            return self._uefi_rule["meta"]["author"]
        except KeyError:
            return None

    @property
    def name(self) -> Optional[str]:
        """Get rule name from the metadata block"""

        try:
            return self._uefi_rule["meta"]["name"]
        except KeyError:
            return None

    @property
    def version(self) -> Optional[str]:
        """Get rule version from the metadata block"""

        try:
            return self._uefi_rule["meta"]["version"]
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
    def license(self) -> Optional[str]:
        """Get rule license from the metadata block"""

        try:
            return self._uefi_rule["meta"]["license"]
        except KeyError:
            return None

    @property
    def cve_number(self) -> Optional[str]:
        """Get CVE number from the metadata block"""

        try:
            return self._uefi_rule["meta"]["CVE number"]
        except KeyError:
            return None

    @property
    def volume_guids(self) -> Optional[List[str]]:
        """Get any volume GUIDs from the metadata block"""

        try:
            return self._uefi_rule["meta"]["volume guids"]
        except KeyError:
            return None

    @property
    def vendor_id(self) -> Optional[str]:
        """Get vendor id from the metadata block"""

        try:
            return self._uefi_rule["meta"]["vendor id"]
        except KeyError:
            return None

    @property
    def cvss_score(self) -> Optional[str]:
        """Get CVSS score from the metadata block"""

        try:
            return self._uefi_rule["meta"]["CVSS score"]
        except KeyError:
            return None

    @property
    def advisory(self) -> Optional[str]:
        """Get advisory link from the metadata block"""

        try:
            return self._uefi_rule["meta"]["advisory"]
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

    def _get_code(self) -> List[Any]:
        code: List[Any] = list()
        if "code" not in self._uefi_rule:
            return code
        for index in self._uefi_rule["code"]:
            c = self._uefi_rule["code"][index]
            code.append(
                CodePattern(
                    pattern=c.get("pattern", None),
                    places=c.get("place", None),
                )
            )
        return code

    @property
    def code(self) -> List[Any]:
        """Get code from rule"""

        if self._code is None:
            self._code = self._get_code()
        return self._code

    def _get_strings(self) -> Dict[str, List[str]]:
        return self._uefi_rule.get("strings", dict())

    @property
    def strings(self) -> Dict[str, List[str]]:
        """Get strings from rule"""

        if self._strings is None:
            self._strings = self._get_strings()
        return self._strings

    def _get_wide_strings(self) -> Dict[str, List[Dict[str, str]]]:
        return self._uefi_rule.get("wide_strings", dict())

    @property
    def wide_strings(self) -> Dict[str, List[Dict[str, str]]]:
        """Get wide strings from rule"""

        if self._wide_strings is None:
            self._wide_strings = self._get_wide_strings()
        return self._wide_strings

    def _get_hex_strings(self) -> Dict[str, List[str]]:
        return self._uefi_rule.get("hex_strings", dict())

    @property
    def hex_strings(self) -> Dict[str, List[str]]:
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


class UefiScannerError(Exception):
    """Generic scanner error exception."""

    def __init__(self, value: str) -> None:
        self.value = value

    def __str__(self):
        return repr(self.value)


class UefiScanner:
    """helper object for scanning an EFI image with multiple rules"""

    def __init__(self, uefi_analyzer: UefiAnalyzer, uefi_rules: List[UefiRule]):
        self._uefi_analyzer: UefiAnalyzer = uefi_analyzer
        self._uefi_rules: List[UefiRule] = uefi_rules
        self._results: Optional[Set[int]] = None

        # decision indexes
        self._nvram_index: DefaultDict[NvramVariable, Set[int]] = defaultdict(set)
        self._protocol_index: DefaultDict[UefiProtocol, Set[int]] = defaultdict(set)
        self._ppi_index: DefaultDict[UefiProtocol, Set[int]] = defaultdict(set)
        self._protocol_guid_index: DefaultDict[
            UefiProtocolGuid, Set[int]
        ] = defaultdict(set)

        # likley not to be shared; indices correspond to self._uefi_rules
        self._string_index: List[Any] = list()
        self._hex_string_index: List[Any] = list()
        self._wide_string_index: List[Any] = list()

        self._esil_index: List[List[Any]] = list()
        self._code_index: List[List[Any]] = list()

        # temp values
        self._funcs_bounds: List[Tuple[int, int]] = list()
        self._rec_addrs: List[int] = list()

        self._index_rules()

    @staticmethod
    def _index_iterable_to_dict(
        target: DefaultDict[Any, Set[int]], source: Optional[Iterable[Any]], index: int
    ) -> None:
        if source is not None:
            for elem in source:
                target[elem].add(index)

    def _index_rule(self, rule: UefiRule, index: int) -> None:
        """Adds a rule to the index"""

        self._index_iterable_to_dict(self._nvram_index, rule.nvram_vars, index)
        self._index_iterable_to_dict(self._protocol_index, rule.protocols, index)
        self._index_iterable_to_dict(self._ppi_index, rule.ppi_list, index)
        self._index_iterable_to_dict(
            self._protocol_guid_index, rule.protocol_guids, index
        )

        self._string_index.append(rule.strings)
        self._wide_string_index.append(rule.wide_strings)
        self._hex_string_index.append(rule.hex_strings)
        self._esil_index.append(rule.esil_rules)
        self._code_index.append(rule.code)

    def _index_rules(self) -> None:
        """Creates index for all rules"""
        for i, rule in enumerate(self._uefi_rules):
            self._index_rule(rule, i)

    @staticmethod
    def _update_index_match(
        previous: Set[int], expected: Union[int, Set[int]], matched: bool
    ) -> Set[int]:
        if type(expected) is int:
            return previous if matched else (previous - {expected})
        elif type(expected) is set:
            return previous if matched else (previous - expected)
        else:
            raise TypeError("expected must be Union[int, Set[int]]")

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

    def _esil_scanner(self, current: Set[int]) -> Set[int]:
        """Match ESIL patterns"""

        matches = current

        for i, esil_rules in enumerate(self._esil_index):
            if i not in matches:
                continue

            esil_match = True
            for esil_rule in esil_rules:
                if not self._check_rule(esil_rule):
                    esil_match = False
                    break

            matches = self._update_index_match(matches, i, esil_match)

            if len(matches) == 0:
                break

        return matches

    def _and_strings(self, strings: List[str]) -> bool:
        res = True
        for string in strings:
            res &= not not self._uefi_analyzer._rz.cmdj("/j {}".format(string))
            if not res:
                break
        return res

    def _or_strings(self, strings: List[str]) -> bool:
        res = True
        for string in strings:
            res |= not not self._uefi_analyzer._rz.cmdj("/j {}".format(string))
            if res:
                break
        return res

    def _and_hex_strings(self, strings: List[str]) -> bool:
        res = True
        for string in strings:
            res &= not not self._uefi_analyzer._rz.cmdj("/xj {}".format(string))
            if not res:
                break
        return res

    def _or_hex_strings(self, strings: List[str]) -> bool:
        res = True
        for string in strings:
            res |= not not self._uefi_analyzer._rz.cmdj("/xj {}".format(string))
            if res:
                break
        return res

    def _and_wide_strings(self, strings: List[dict]) -> bool:
        res = True
        for item in strings:
            if "utf16le" in item:
                res &= not not self._uefi_analyzer._rz.cmdj(
                    "/wj {}".format(item["utf16le"])
                )
            elif "utf16be" in item:
                string = item["utf16be"]
                res &= not not self._uefi_analyzer._rz.cmdj(
                    "/xj {}".format(
                        binascii.hexlify(string.encode("utf-16be")).decode()
                    )
                )
            else:
                raise UefiScannerError("Wrong wide string format")

            if not res:
                break

        return res

    def _or_wide_strings(self, strings: List[dict]) -> bool:
        res = True
        for item in strings:
            if "utf16le" in item:
                res |= not not self._uefi_analyzer._rz.cmdj(
                    "/wj {}".format(item["utf16le"])
                )
            elif "utf16be" in item:
                string = item["utf16be"]
                res |= not not self._uefi_analyzer._rz.cmdj(
                    "/xj {}".format(
                        binascii.hexlify(string.encode("utf-16be")).decode()
                    )
                )
            else:
                raise UefiScannerError("Wrong wide string format")

            if res:
                break

        return res

    def _strings_scanner(self, current: Set[int]) -> Set[int]:
        """Match strings"""

        matches = current

        for i, rule_strings in enumerate(self._string_index):
            if i not in matches:
                continue

            final_res = True
            for op in rule_strings:

                # check kind of matches
                if op not in ["and", "or", "not-any", "not-all"]:
                    raise UefiScannerError(
                        f"Invalid kind of matches: {op} (possible kinds of matches: and, or, not-any, not-all)"
                    )

                res = True
                if op == "and":  # AND
                    res = self._and_strings(rule_strings[op])

                if op == "or":  # OR
                    res = self._or_strings(rule_strings[op])

                if op == "not-any":  # NOT OR
                    res = not self._or_strings(rule_strings[op])

                if op == "not-all":  # NOT AND
                    res = not self._and_strings(rule_strings[op])

                print(f"[I] Final: {res}, {op}: {rule_strings[op]}")

                final_res &= res  # AND between all sets of strings
                if not final_res:
                    break

            matches = self._update_index_match(matches, i, final_res)

        return matches

    def _wide_strings_scanner(self, current: Set[int]) -> Set[int]:
        """Match wide strings"""

        matches = current

        for i, rule_wide_strings in enumerate(self._wide_string_index):
            if i not in matches:
                continue

            final_res = True
            for op in rule_wide_strings:

                # check kind of matches
                if op not in ["and", "or", "not-any", "not-all"]:
                    raise UefiScannerError(
                        f"Invalid kind of matches: {op} (possible kinds of matches: and, or, not-any, not-all)"
                    )

                print(rule_wide_strings[op])
                res = True
                if op == "and":  # AND
                    res = self._and_wide_strings(rule_wide_strings[op])

                if op == "or":  # OR
                    res = self._or_wide_strings(rule_wide_strings[op])

                if op == "not-any":  # NOT OR
                    res = not self._or_wide_strings(rule_wide_strings[op])

                if op == "not-all":  # NOT AND
                    res = not self._and_wide_strings(rule_wide_strings[op])

                print(f"[I] Final: {res}, {op}: {rule_wide_strings[op]}")

                final_res &= res  # AND between all sets of strings
                if not final_res:
                    break

            matches = self._update_index_match(matches, i, final_res)

        return matches

    def _hex_strings_scanner(self, current: Set[int]) -> Set[int]:
        """Match hex strings"""

        matches = current

        for i, rule_hex_strings in enumerate(self._hex_string_index):
            if i not in matches:
                continue

            final_res = True
            for op in rule_hex_strings:

                # check kind of matches
                if op not in ["and", "or", "not-any", "not-all"]:
                    raise UefiScannerError(
                        f"Invalid kind of matches: {op} (possible kinds of matches: and, or, not-any, not-all)"
                    )

                res = True
                if op == "and":  # AND
                    res = self._and_hex_strings(rule_hex_strings[op])

                if op == "or":  # OR
                    res = self._or_hex_strings(rule_hex_strings[op])

                if op == "not-any":  # NOT OR
                    res = not self._or_hex_strings(rule_hex_strings[op])

                if op == "not-all":  # NOT AND
                    res = not self._and_hex_strings(rule_hex_strings[op])

                print(f"[I] Final: {res}, {op}: {rule_hex_strings[op]}")

                final_res &= res  # AND between all sets of strings
                if not final_res:
                    break

            matches = self._update_index_match(matches, i, final_res)

        return matches

    def _nvram_scanner(self, current: Set[int]) -> Set[int]:
        """Compare NVRAM"""

        matches = current

        for nvram_rule, expected in self._nvram_index.items():
            if matches.isdisjoint(expected):
                continue

            nvram_matched = False

            for nvram_analyzer in self._uefi_analyzer.nvram_vars:
                if (
                    nvram_rule.name == nvram_analyzer.name
                    and nvram_rule.guid == nvram_analyzer.guid
                    and nvram_rule.service.name == nvram_analyzer.service.name
                ):
                    nvram_matched = True
                    break

            matches = self._update_index_match(matches, expected, nvram_matched)

            if len(matches) == 0:
                break

        return matches

    def _compare_protocols(self, current: Set[int]) -> Set[int]:
        """Compare protocols"""

        matches = current

        for protocol_rule, expected in self._protocol_index.items():
            if matches.isdisjoint(expected):
                continue

            protocol_matched = False

            for protocol_analyzer in self._uefi_analyzer.protocols:
                if (
                    protocol_rule.name == protocol_analyzer.name
                    and protocol_rule.value == protocol_analyzer.value
                ):
                    protocol_matched = True
                    break

            matches = self._update_index_match(matches, expected, protocol_matched)

            if len(matches) == 0:
                break

        return matches

    def _compare_guids(self, current: Set[int]) -> Set[int]:
        """Compare GUIDs"""

        matches = current

        for guid_rule, expected in self._protocol_guid_index.items():
            if matches.isdisjoint(expected):
                continue

            guid_matched = False

            for guid_analyzer in self._uefi_analyzer.protocol_guids:
                # name or value should match (both are unique)
                if (
                    guid_rule.name == guid_analyzer.name
                    or guid_rule.value == guid_analyzer.value
                ):
                    guid_matched = True
                    break

            matches = self._update_index_match(matches, expected, guid_matched)

            if len(matches) == 0:
                break

        return matches

    def _compare_ppi(self, matches: Set[int]) -> Set[int]:
        """Compare PPI"""

        for ppi_rule, expected in self._ppi_index.items():
            if matches.isdisjoint(expected):
                continue

            ppi_matched = False
            for ppi_analyzer in self._uefi_analyzer.ppi_list:
                if (
                    ppi_rule.name == ppi_analyzer.name
                    and ppi_rule.value == ppi_analyzer.value
                ):
                    ppi_matched = True
                    break

            matches = self._update_index_match(matches, expected, ppi_matched)

            if len(matches) == 0:
                break

        return matches

    def _get_bounds(self, insns: List[Dict[str, Any]]) -> Tuple:
        """Get function end address"""

        funcs = list(self._uefi_analyzer._rz.cmdj("aflqj"))
        funcs.sort()

        start = insns[0].get("offset", None)
        end_insn = insns[-1].get("offset", None)

        if start is None or end_insn is None:
            return tuple((None, None))

        if start == funcs[-1]:
            return tuple((start, end_insn))

        try:
            start_index = funcs.index(start)
        except ValueError:
            return tuple((start, end_insn))

        end_func = funcs[start_index + 1]
        if end_insn < end_func:
            return tuple((start, end_insn))

        return tuple((start, end_func))

    @staticmethod
    def _tree_debug(start: int, end: int, depth: int) -> None:
        if not depth:
            print(
                f"\nFunction tree in the handler at {start:#x} (from {start:#x} to {end:#x})"
            )
        else:
            prefix = depth * "--"
            print(f"{prefix}{start:#x} (from {start:#x} to {end:#x})")

    def _get_bounds_rec(self, start_addr: int, depth: int, debug: bool) -> bool:
        """Recursively traverse the function and find the boundaries of all child functions"""

        self._uefi_analyzer._rz.cmd(f"s {start_addr:#x}")
        self._uefi_analyzer._rz.cmd(f"af")

        insns = self._uefi_analyzer._rz.cmd("pdrj")
        # prevent error messages to sys.stderr from rizin:
        # https://github.com/rizinorg/rz-pipe/blob/0f7ac66e6d679ebb03be26bf61a33f9ccf199f27/python/rzpipe/open_base.py#L261
        try:
            insns = json.loads(insns)
        except (ValueError, KeyError, TypeError) as _:
            return False

        # append function bounds
        start, end = self._get_bounds(insns)

        if start is not None and end is not None and start_addr == start:
            self._funcs_bounds.append((start, end))

        if debug:
            self._tree_debug(start_addr, end, depth)
            depth += 1

        # scan child functions
        for insn in insns:
            if insn.get("type", None) != "call":
                continue
            if "esil" not in insn:
                continue
            esil = insn["esil"].split(",")
            if esil[-3:] != ["=[]", "rip", "="]:
                continue
            try:
                address = int(esil[0])
                if address not in self._rec_addrs:
                    self._rec_addrs.append(address)
                    self._get_bounds_rec(address, depth, debug)
            except ValueError as _:
                continue

        return True

    def _hex_strings_scanner_bounds(self, pattern: str, start: int, end: int) -> bool:
        """Match hex strings"""

        res = self._uefi_analyzer._rz.cmdj(f"/xj {pattern}")
        if not res:
            return False

        for sres in res:
            offset = sres.get("offset", None)
            if offset is None:
                continue

            if offset >= start and offset <= end:
                return True

        return False

    def _clear_cache(self) -> None:
        self._funcs_bounds = list()
        self._rec_addrs = list()

    def _code_scan_rec(self, address: int, pattern: str) -> bool:

        self._clear_cache()

        self._get_bounds_rec(address, depth=0, debug=False)
        if not len(self._funcs_bounds):
            return False

        for start, end in self._funcs_bounds:
            if self._hex_strings_scanner_bounds(pattern, start, end):
                # Debug
                # print(f"Matched: {start:#x} - {end:#x}")
                return True

        return False

    def _code_scanner(self, current: Set[int]) -> Set[int]:
        """Compare code patterns"""

        matches = current

        for i, cs in enumerate(self._code_index):
            if i not in matches:
                continue

            res = True
            for c in cs:
                if c.sw_smi_handlers:
                    sw_smi_handler_res = False
                    for sw_smi_handler in self._uefi_analyzer.swsmi_handlers:
                        sw_smi_handler_res = self._code_scan_rec(
                            sw_smi_handler.address, c.pattern
                        )
                        if sw_smi_handler_res:
                            break
                    res &= sw_smi_handler_res
                    if not res:
                        break

                if c.child_sw_smi_handlers:
                    child_sw_smi_handler_res = False
                    for (
                        child_sw_smi_handler
                    ) in self._uefi_analyzer.child_swsmi_handlers:
                        child_sw_smi_handler_res = self._code_scan_rec(
                            child_sw_smi_handler.address, c.pattern
                        )
                        if child_sw_smi_handler_res:
                            break
                    res &= child_sw_smi_handler_res
                    if not res:
                        break

                if len(c.child_sw_smi_handlers_guids):
                    child_sw_smi_handler_res = False
                    for (
                        child_sw_smi_handler
                    ) in self._uefi_analyzer.child_swsmi_handlers:
                        if (
                            child_sw_smi_handler.handler_guid
                            not in c.child_sw_smi_handlers_guids
                        ):
                            continue
                        child_sw_smi_handler_res = self._code_scan_rec(
                            child_sw_smi_handler.address, c.pattern
                        )
                        res &= child_sw_smi_handler_res
                        if not res:
                            break
                    if not res:
                        break

            matches = self._update_index_match(matches, i, res)

        return matches

    def _get_results(self) -> Set[int]:
        matches = set(range(len(self._uefi_rules)))

        # compare NVRAM
        # matches = self._nvram_scanner(matches)
        # if len(matches) == 0:
        #     return matches

        # compare protocols
        # matches = self._compare_protocols(matches)
        # if len(matches) == 0:
        #     return matches

        # compare GUIDs
        # matches = self._compare_guids(matches)
        # if len(matches) == 0:
        #     return matches

        # compare PPI
        # matches = self._compare_ppi(matches)
        # if len(matches) == 0:
        #     return matches

        # match ESIL patterns
        # matches = self._esil_scanner(matches)
        # if len(matches) == 0:
        #     return matches

        # match code patterns
        # matches = self._code_scanner(matches)
        # if len(matches) == 0:
        #     return matches

        # match strings
        matches = self._strings_scanner(matches)
        if len(matches) == 0:
            return matches

        # match wide strings
        matches = self._wide_strings_scanner(matches)
        if len(matches) == 0:
            return matches

        # match hex strings
        matches = self._hex_strings_scanner(matches)
        if len(matches) == 0:
            return matches

        return matches

    @property
    def results(self) -> Set[int]:
        """Get scanning results as a list of matched rules"""

        if self._results is None:
            self._results = self._get_results()

        return self._results
