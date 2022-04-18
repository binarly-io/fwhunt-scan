# SPDX-License-Identifier: GPL-3.0+

"""
Tools for analyzing UEFI firmware using radare2
"""

import binascii
import json
import os
from typing import Any, DefaultDict, Dict, Iterable, List, Optional, Set, Tuple, Union

import yaml

from uefi_r2.uefi_analyzer import (
    NvramVariable,
    UefiAnalyzer,
    UefiGuid,
    UefiProtocol,
    UefiService,
)


class CodePattern:
    """Code pattern"""

    def __init__(self, pattern: str, place: Optional[str]) -> None:
        self.pattern: str = pattern
        self.place: Optional[str] = place

        # if True, scan in all SW SMI handlers
        self.sw_smi_handlers: bool = place == "sw_smi_handlers"

        # if True, scan in all child SW SMI handlers
        self.child_sw_smi_handlers: bool = place == "child_sw_smi_handlers"

    @property
    def __dict__(self):
        return dict(
            {
                "pattern": self.pattern,
                "sw_smi_handlers": self.sw_smi_handlers,
                "child_sw_smi_handlers": self.child_sw_smi_handlers,
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
        self._nvram_vars: Optional[Dict[str, List[NvramVariable]]] = None
        self._protocols: Optional[Dict[str, List[UefiProtocol]]] = None
        self._ppi_list: Optional[Dict[str, List[UefiProtocol]]] = None
        self._guids: Optional[Dict[str, List[UefiGuid]]] = None
        self._strings: Optional[Dict[str, List[str]]] = None
        self._wide_strings: Optional[Dict[str, List[Dict[str, str]]]] = None
        self._hex_strings: Optional[Dict[str, List[str]]] = None
        self._code: Optional[Dict[str, List[Dict[str, str]]]] = None
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

    def _get_code(self) -> Dict[str, List[Dict[str, str]]]:
        code: Dict[str, List[Dict[str, str]]] = dict()
        if "code" not in self._uefi_rule:
            return code
        for op in self._uefi_rule["code"]:
            code[op] = list()
            for c in self._uefi_rule["code"][op]:
                cp = CodePattern(
                    pattern=c.get("pattern", None),
                    place=c.get("place", None),
                )
                code[op].append(cp)
        return code

    @property
    def code(self) -> Dict[str, List[Dict[str, str]]]:
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

    def _get_nvram_vars(self) -> Dict[str, List[NvramVariable]]:
        nvram_vars: Dict[str, List[NvramVariable]] = dict()
        if "nvram" not in self._uefi_rule:
            return nvram_vars
        for op in self._uefi_rule["nvram"]:
            nvram_vars[op] = list()
            for element in self._uefi_rule["nvram"][op]:
                nvram_vars[op].append(
                    NvramVariable(
                        name=element["name"],
                        guid=element["guid"],
                        service=UefiService(
                            name=element["service"]["name"], address=0x0
                        ),
                    )
                )
        return nvram_vars

    @property
    def nvram_vars(self) -> Dict[str, List[NvramVariable]]:
        """Get NVRAM variables from rule"""

        if self._nvram_vars is None:
            self._nvram_vars = self._get_nvram_vars()
        return self._nvram_vars

    def _get_protocols(self) -> Dict[str, List[UefiProtocol]]:
        protocols: Dict[str, List[UefiProtocol]] = dict()
        if "protocols" not in self._uefi_rule:
            return protocols
        for op in self._uefi_rule["protocols"]:
            protocols[op] = list()
            for element in self._uefi_rule["protocols"][op]:
                protocols[op].append(
                    UefiProtocol(
                        name=element["name"],
                        value=element["value"],
                        service=element["service"]["name"],
                        address=0x0,
                        guid_address=0x0,
                    )
                )
        return protocols

    @property
    def protocols(self) -> Dict[str, List[UefiProtocol]]:
        """Get protocols from rule"""

        if self._protocols is None:
            self._protocols = self._get_protocols()
        return self._protocols

    def _get_ppi_list(self) -> Dict[str, List[UefiProtocol]]:
        ppi_list: Dict[str, List[UefiProtocol]] = dict()
        if "ppi" not in self._uefi_rule:
            return ppi_list
        for op in self._uefi_rule["ppi"]:
            ppi_list[op] = list()
            for element in self._uefi_rule["ppi"][op]:
                ppi_list[op].append(
                    UefiProtocol(
                        name=element["name"],
                        value=element["value"],
                        service=element["service"]["name"],
                        address=0x0,
                        guid_address=0x0,
                    )
                )
        return ppi_list

    @property
    def ppi_list(self) -> Dict[str, List[UefiProtocol]]:
        """Get PPI list from rule"""

        if self._ppi_list is None:
            self._ppi_list = self._get_ppi_list()
        return self._ppi_list

    def _get_guids(self) -> Dict[str, List[UefiGuid]]:
        guids: Dict[str, List[UefiGuid]] = dict()
        if "guids" not in self._uefi_rule:
            return guids
        for op in self._uefi_rule["guids"]:
            guids[op] = list()
            for element in self._uefi_rule["guids"][op]:
                guids[op].append(
                    UefiGuid(
                        name=element["name"],
                        value=element["value"],
                    )
                )
        return guids

    @property
    def guids(self) -> Dict[str, List[UefiGuid]]:
        """Get GUIDs from rule"""

        if self._guids is None:
            self._guids = self._get_guids()
        return self._guids


class UefiScannerError(Exception):
    """Generic scanner error exception."""

    def __init__(self, value: str) -> None:
        self.value = value

    def __str__(self):
        return repr(self.value)


class UefiScanner:
    """helper object for scanning an EFI image with multiple rules"""

    PROTOCOL: int = 0
    PPI: int = 1

    def __init__(self, uefi_analyzer: UefiAnalyzer, uefi_rules: List[UefiRule]):
        self._uefi_analyzer: UefiAnalyzer = uefi_analyzer
        self._uefi_rules: List[UefiRule] = uefi_rules
        self._results: Optional[Set[int]] = None

        # likley not to be shared; indices correspond to self._uefi_rules
        self._nvram_index: List[Any] = list()
        self._protocol_index: List[Any] = list()
        self._ppi_index: List[Any] = list()
        self._guid_index: List[Any] = list()
        self._string_index: List[Any] = list()
        self._hex_string_index: List[Any] = list()
        self._wide_string_index: List[Any] = list()

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

        self._nvram_index.append(rule.nvram_vars)
        self._protocol_index.append(rule.protocols)
        self._ppi_index.append(rule.ppi_list)
        self._guid_index.append(rule.guids)
        self._string_index.append(rule.strings)
        self._wide_string_index.append(rule.wide_strings)
        self._hex_string_index.append(rule.hex_strings)
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

    def _and_strings(self, strings: List[str]) -> bool:
        res = True
        for string in strings:
            res &= not not self._uefi_analyzer._rz.cmdj("/j {}".format(string))
            if not res:
                break
        return res

    def _or_strings(self, strings: List[str]) -> bool:
        res = False
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
        res = False
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
        res = False
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

                res = True
                if op == "and":  # AND
                    res = self._and_wide_strings(rule_wide_strings[op])

                if op == "or":  # OR
                    res = self._or_wide_strings(rule_wide_strings[op])

                if op == "not-any":  # NOT OR
                    res = not self._or_wide_strings(rule_wide_strings[op])

                if op == "not-all":  # NOT AND
                    res = not self._and_wide_strings(rule_wide_strings[op])

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

                final_res &= res  # AND between all sets of strings
                if not final_res:
                    break

            matches = self._update_index_match(matches, i, final_res)

        return matches

    def _search_nvram(self, nvram_rule: NvramVariable) -> bool:
        for nvram_analyzer in self._uefi_analyzer.nvram_vars:
            if (
                nvram_rule.name == nvram_analyzer.name
                and nvram_rule.guid == nvram_analyzer.guid
                and nvram_rule.service.name == nvram_analyzer.service.name
            ):
                return True
        return False

    def _and_nvram(self, nvram_vars: List[NvramVariable]) -> bool:
        res = True
        for nvram_var in nvram_vars:
            res &= self._search_nvram(nvram_var)
            if not res:
                break
        return res

    def _or_nvram(self, nvram_vars: List[NvramVariable]) -> bool:
        res = False
        for nvram_var in nvram_vars:
            res |= self._search_nvram(nvram_var)
            if res:
                break
        return res

    def _compare_nvram_vars(self, current: Set[int]) -> Set[int]:
        """Compare NVRAM variables"""

        matches = current

        for i, rule_nvram in enumerate(self._nvram_index):
            if i not in matches:
                continue

            final_res = True
            for op in rule_nvram:

                # check kind of matches
                if op not in ["and", "or", "not-any", "not-all"]:
                    raise UefiScannerError(
                        f"Invalid kind of matches: {op} (possible kinds of matches: and, or, not-any, not-all)"
                    )

                res = True
                if op == "and":  # AND
                    res = self._and_nvram(rule_nvram[op])

                if op == "or":  # OR
                    res = self._or_nvram(rule_nvram[op])

                if op == "not-any":  # NOT OR
                    res = not self._or_nvram(rule_nvram[op])

                if op == "not-all":  # NOT AND
                    res = not self._and_nvram(rule_nvram[op])

                final_res &= res  # AND between all sets of NVRAM variables
                if not final_res:
                    break

            matches = self._update_index_match(matches, i, final_res)

        return matches

    def _search_protocol(self, protocol_rule: UefiProtocol, mode: int) -> bool:
        items: List[UefiProtocol] = self._uefi_analyzer.protocols
        if mode == UefiScanner.PPI:
            items = self._uefi_analyzer.ppi_list
        for protocol_analyzer in items:
            if (
                protocol_rule.name == protocol_analyzer.name
                and protocol_rule.value == protocol_analyzer.value
                and protocol_rule.service == protocol_analyzer.service
            ):
                return True
        return False

    def _and_protocols(self, protocols: List[UefiProtocol], mode: int) -> bool:
        res = True
        for protocol in protocols:
            res &= self._search_protocol(protocol, mode)
            if not res:
                break
        return res

    def _or_protocols(self, protocols: List[UefiProtocol], mode: int) -> bool:
        res = False
        for protocol in protocols:
            res |= self._search_protocol(protocol, mode)
            if res:
                break
        return res

    def _compare_protocols(self, current: Set[int], mode: int) -> Set[int]:
        """Compare protocols"""

        matches = current

        for i, rule_protocol in enumerate(self._protocol_index):
            if i not in matches:
                continue

            final_res = True
            for op in rule_protocol:

                # check kind of matches
                if op not in ["and", "or", "not-any", "not-all"]:
                    raise UefiScannerError(
                        f"Invalid kind of matches: {op} (possible kinds of matches: and, or, not-any, not-all)"
                    )

                res = True
                if op == "and":  # AND
                    res = self._and_protocols(rule_protocol[op], mode)

                if op == "or":  # OR
                    res = self._or_protocols(rule_protocol[op], mode)

                if op == "not-any":  # NOT OR
                    res = not self._or_protocols(rule_protocol[op], mode)

                if op == "not-all":  # NOT AND
                    res = not self._and_protocols(rule_protocol[op], mode)

                final_res &= res  # AND between all sets of protocols
                if not final_res:
                    break

            matches = self._update_index_match(matches, i, final_res)

        return matches

    def _search_guid(self, guid_rule: UefiGuid) -> bool:
        for protocol_analyzer in self._uefi_analyzer.protocols:
            if (
                guid_rule.name == protocol_analyzer.name
                and guid_rule.value == protocol_analyzer.value
            ):
                return True
        return False

    def _and_guids(self, guids: List[UefiGuid]):
        res = True
        for guid in guids:
            res &= self._search_guid(guid)
            if not res:
                break
        return res

    def _or_guids(self, guids: List[UefiGuid]):
        res = False
        for guid in guids:
            res |= self._search_guid(guid)
            if res:
                break
        return res

    def _compare_guids(self, current: Set[int]) -> Set[int]:
        """Compare GUIDs"""

        matches = current

        for i, rule_guid in enumerate(self._guid_index):
            if i not in matches:
                continue

            final_res = True
            for op in rule_guid:

                # check kind of matches
                if op not in ["and", "or", "not-any", "not-all"]:
                    raise UefiScannerError(
                        f"Invalid kind of matches: {op} (possible kinds of matches: and, or, not-any, not-all)"
                    )

                res = True
                if op == "and":  # AND
                    res = self._and_guids(rule_guid[op])

                if op == "or":  # OR
                    res = self._or_guids(rule_guid[op])

                if op == "not-any":  # NOT OR
                    res = not self._or_guids(rule_guid[op])

                if op == "not-all":  # NOT AND
                    res = not self._and_guids(rule_guid[op])

                final_res &= res  # AND between all sets of GUIDs
                if not final_res:
                    break

            matches = self._update_index_match(matches, i, final_res)

        return matches

    def _compare_ppi(self, matches: Set[int]) -> Set[int]:
        """Compare PPI"""

        for i, ppi_rule in enumerate(self._ppi_index):
            if i not in matches:
                continue

            ppi_matched = False
            for ppi_analyzer in self._uefi_analyzer.ppi_list:
                if (
                    ppi_rule.name == ppi_analyzer.name
                    and ppi_rule.value == ppi_analyzer.value
                ):
                    ppi_matched = True
                    break

            matches = self._update_index_match(matches, i, ppi_matched)

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

    def _and_code(self, cs: List[CodePattern]) -> bool:
        res = True
        for c in cs:
            handlers = None
            if c.sw_smi_handlers:
                handlers = self._uefi_analyzer.swsmi_handlers
            elif c.child_sw_smi_handlers:
                handlers = self._uefi_analyzer.child_swsmi_handlers
            else:
                raise UefiScannerError(f"The search place is incorrect")
            search_res = False
            for handler in handlers:
                search_res = self._code_scan_rec(handler.address, c.pattern)
                if search_res:
                    break

            res &= search_res
            if not res:
                break

        return res

    def _or_code(self, cs: List[CodePattern]) -> bool:
        res = False
        for c in cs:
            handlers = None
            if c.sw_smi_handlers:
                handlers = self._uefi_analyzer.swsmi_handlers
            elif c.child_sw_smi_handlers:
                handlers = self._uefi_analyzer.child_swsmi_handlers
            else:
                raise UefiScannerError(f"The search place is incorrect")
            search_res = False
            for handler in handlers:
                search_res = self._code_scan_rec(handler.address, c.pattern)
                if search_res:
                    break

            res |= search_res
            if res:
                break

        return res

    def _code_scanner(self, current: Set[int]) -> Set[int]:
        """Compare code patterns"""

        matches = current

        for i, rule_code in enumerate(self._code_index):
            if i not in matches:
                continue

            final_res = True
            for op in rule_code:

                # check kind of matches
                if op not in ["and", "or", "not-any", "not-all"]:
                    raise UefiScannerError(
                        f"Invalid kind of matches: {op} (possible kinds of matches: and, or, not-any, not-all)"
                    )

                res = True
                if op == "and":  # AND
                    res = self._and_code(rule_code[op])

                if op == "or":  # OR
                    res = self._or_code(rule_code[op])

                if op == "not-any":  # NOT OR
                    res = not self._or_code(rule_code[op])

                if op == "not-all":  # NOT AND
                    res = not self._and_code(rule_code[op])

                final_res &= res  # AND between all sets of NVRAM variables
                if not final_res:
                    break

            matches = self._update_index_match(matches, i, final_res)

        return matches

    def _get_results(self) -> Set[int]:
        matches = set(range(len(self._uefi_rules)))

        # compare NVRAM variables
        matches = self._compare_nvram_vars(matches)
        if len(matches) == 0:
            return matches

        # compare protocols
        matches = self._compare_protocols(matches, UefiScanner.PROTOCOL)
        if len(matches) == 0:
            return matches

        # compare GUIDs
        matches = self._compare_guids(matches)
        if len(matches) == 0:
            return matches

        # compare PPI
        matches = self._compare_protocols(matches, UefiScanner.PPI)
        if len(matches) == 0:
            return matches

        # match code patterns
        matches = self._code_scanner(matches)
        if len(matches) == 0:
            return matches

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
