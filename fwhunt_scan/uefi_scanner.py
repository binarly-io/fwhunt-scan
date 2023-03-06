# SPDX-License-Identifier: GPL-3.0+

"""
Tools for analyzing UEFI firmware using radare2
"""

import binascii
import json
import os
from typing import Any, Dict, List, Optional, Tuple

import yaml

from fwhunt_scan.uefi_analyzer import (
    NvramVariable,
    UefiAnalyzer,
    UefiGuid,
    UefiProtocol,
    UefiService,
)


class CodePattern:
    """Code pattern"""

    def __init__(self, pattern: str, place: Optional[str]) -> None:
        self.pattern: str = str(pattern)
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


class UefiRuleVariant:
    """A rule for scanning EFI image (content without meta and variants)"""

    def __init__(self, rule_content: Dict[str, Any]):
        self._uefi_rule: Dict[str, Any] = rule_content
        self._nvram_vars: Optional[Dict[str, List[NvramVariable]]] = None
        self._protocols: Optional[Dict[str, List[UefiProtocol]]] = None
        self._ppi_list: Optional[Dict[str, List[UefiProtocol]]] = None
        self._guids: Optional[Dict[str, List[UefiGuid]]] = None
        self._strings: Optional[Dict[str, List[str]]] = None
        self._wide_strings: Optional[Dict[str, List[Dict[str, str]]]] = None
        self._hex_strings: Optional[Dict[str, List[str]]] = None
        self._code: Optional[Dict[str, List[CodePattern]]] = None

    def _get_code(self) -> Dict[str, List[CodePattern]]:
        code: Dict[str, List[CodePattern]] = dict()
        if "code" not in self._uefi_rule:
            return code
        dict_items = dict()
        if type(self._uefi_rule["code"]) == list:
            # if kind of matches is not specified
            dict_items["and"] = self._uefi_rule["code"]
        elif type(self._uefi_rule["code"]) == dict:
            dict_items = self._uefi_rule["code"]
        else:
            return code
        for op in dict_items:
            code[op] = list()
            for c in dict_items[op]:
                cp = CodePattern(
                    pattern=c.get("pattern", None),
                    place=c.get("place", None),
                )
                code[op].append(cp)
        return code

    @property
    def code(self) -> Dict[str, List[CodePattern]]:
        """Get code from rule"""

        if self._code is None:
            self._code = self._get_code()
        return self._code

    def _get_strings(self) -> Dict[str, List[str]]:
        strings: Dict[str, List[str]] = dict()
        if "strings" not in self._uefi_rule:
            return strings
        if type(self._uefi_rule["strings"]) == list:
            # if kind of matches is not specified
            strings["and"] = self._uefi_rule["strings"]
        elif type(self._uefi_rule["strings"]) == dict:
            strings = self._uefi_rule["strings"]
        else:
            return strings
        return strings

    @property
    def strings(self) -> Dict[str, List[str]]:
        """Get strings from rule"""

        if self._strings is None:
            self._strings = self._get_strings()
        return self._strings

    def _get_wide_strings(self) -> Dict[str, List[Dict[str, str]]]:
        wide_strings: Dict[str, List[Dict[str, str]]] = dict()
        if "wide_strings" not in self._uefi_rule:
            return wide_strings
        if type(self._uefi_rule["wide_strings"]) == list:
            # if kind of matches is not specified
            wide_strings["and"] = self._uefi_rule["wide_strings"]
        elif type(self._uefi_rule["wide_strings"]) == dict:
            wide_strings = self._uefi_rule["wide_strings"]
        else:
            return wide_strings
        return wide_strings

    @property
    def wide_strings(self) -> Dict[str, List[Dict[str, str]]]:
        """Get wide strings from rule"""

        if self._wide_strings is None:
            self._wide_strings = self._get_wide_strings()
        return self._wide_strings

    def _get_hex_strings(self) -> Dict[str, List[str]]:
        hex_strings: Dict[str, List[str]] = dict()
        if "hex_strings" not in self._uefi_rule:
            return hex_strings
        if type(self._uefi_rule["hex_strings"]) == list:
            # if kind of matches is not specified
            hex_strings["and"] = self._uefi_rule["hex_strings"]
        elif type(self._uefi_rule["hex_strings"]) == dict:
            hex_strings = self._uefi_rule["hex_strings"]
        else:
            return hex_strings
        return hex_strings

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
        dict_items = dict()
        if type(self._uefi_rule["nvram"]) == list:
            # if kind of matches is not specified
            dict_items["and"] = self._uefi_rule["nvram"]
        elif type(self._uefi_rule["nvram"]) == dict:
            dict_items = self._uefi_rule["nvram"]
        else:
            return nvram_vars
        for op in dict_items:
            nvram_vars[op] = list()
            for element in dict_items[op]:
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
        dict_items = dict()
        if type(self._uefi_rule["protocols"]) == list:
            # if kind of matches is not specified
            dict_items["and"] = self._uefi_rule["protocols"]
        elif type(self._uefi_rule["protocols"]) == dict:
            dict_items = self._uefi_rule["protocols"]
        else:
            return protocols
        for op in dict_items:
            protocols[op] = list()
            for element in dict_items[op]:
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
        dict_items = dict()
        if type(self._uefi_rule["ppi"]) == list:
            # if kind of matches is not specified
            dict_items["and"] = self._uefi_rule["ppi"]
        elif type(self._uefi_rule["ppi"]) == dict:
            dict_items = self._uefi_rule["ppi"]
        else:
            return ppi_list
        for op in dict_items:
            ppi_list[op] = list()
            for element in dict_items[op]:
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
        dict_items = dict()
        if type(self._uefi_rule["guids"]) == list:
            # if kind of matches is not specified
            dict_items["and"] = self._uefi_rule["guids"]
        elif type(self._uefi_rule["guids"]) == dict:
            dict_items = self._uefi_rule["guids"]
        else:
            return guids
        for op in dict_items:
            guids[op] = list()
            for element in dict_items[op]:
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


class UefiRule:
    """A rule for scanning EFI image"""

    def __init__(
        self, rule_path: Optional[str] = None, rule_content: Optional[str] = None
    ):
        self._rule: Optional[str] = rule_path
        self._rule_name: str = str()
        self._uefi_rule: Dict[str, Any] = dict()
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
        self._variants: Optional[Dict[str, UefiRuleVariant]] = None

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

    @property
    def target(self) -> Optional[str]:
        """Get optional rule target from the metadata block"""

        try:
            return self._uefi_rule["meta"]["target"]
        except KeyError:
            return None

    def _get_variants(self) -> Dict[str, UefiRuleVariant]:
        """Get rules variants"""

        variants: Dict[str, UefiRuleVariant] = dict()
        if "variants" in self._uefi_rule:
            for variant in self._uefi_rule["variants"]:
                variants[variant] = UefiRuleVariant(
                    rule_content=self._uefi_rule["variants"][variant]
                )

        if "variants" not in self._uefi_rule:
            rule_content = {
                k: self._uefi_rule[k] for k in self._uefi_rule if k != "meta"
            }
            variants["default"] = UefiRuleVariant(rule_content=rule_content)

        return variants

    @property
    def variants(self) -> Dict[str, UefiRuleVariant]:
        """Get GUIDs from rule"""

        if self._variants is None:
            self._variants = self._get_variants()
        return self._variants


class UefiScannerError(Exception):
    """Generic scanner error exception."""

    def __init__(self, value: str) -> None:
        self.value = value

    def __str__(self):
        return repr(self.value)


class UefiScannerRes:
    """Scanner result for single rule"""

    def __init__(self, rule: UefiRule, variant_label: str, res: bool) -> None:
        self.rule = rule
        self.variant_label = variant_label
        self.res = res


class UefiScanner:
    """helper object for scanning an EFI image with multiple rules"""

    PROTOCOL: int = 0
    PPI: int = 1

    def __init__(self, uefi_analyzer: UefiAnalyzer, uefi_rules: List[UefiRule]):
        self._uefi_analyzer: UefiAnalyzer = uefi_analyzer
        self._uefi_rules: List[UefiRule] = uefi_rules
        self._valid_rules: bool = self._check_rules()
        if not self._valid_rules:
            raise UefiScannerError(
                "Invalid rule format. Visit https://github.com/binarly-io/FwHunt to find the latest version of the rules format."
            )
        self._results: Optional[List[UefiScannerRes]] = None

    def _check_rule(self, rule: UefiRule):
        variants: Optional[Dict[str, UefiRuleVariant]] = None
        try:
            variants = rule.variants
        except KeyError:
            return False

        if not isinstance(variants, dict):
            return False

        for label in variants:
            if not isinstance(label, str):
                return False
            if not isinstance(variants[label], UefiRuleVariant):
                return False

        return True

    def _check_rules(self):
        for rule in self._uefi_rules:
            if not self._check_rule(rule):
                return False
        return True

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

    def _strings_scanner(self, rule_strings: Dict[str, List[str]]) -> bool:
        """Match strings"""

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

        return final_res

    def _wide_strings_scanner(
        self, rule_wide_strings: Dict[str, List[Dict[str, str]]]
    ) -> bool:
        """Match wide strings"""

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

        return final_res

    def _hex_strings_scanner(self, rule_hex_strings: Dict[str, List[str]]) -> bool:
        """Match hex strings"""

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

        return final_res

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

    def _compare_nvram_vars(self, rule_nvram: Dict[str, List[NvramVariable]]) -> bool:
        """Compare NVRAM variables"""

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

        return final_res

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

    def _compare_protocols(
        self, rule_protocol: Dict[str, List[UefiProtocol]], mode: int
    ) -> bool:
        """Compare protocols"""

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

        return final_res

    def _search_guid(self, guid_rule: UefiGuid) -> bool:
        for guid in self._uefi_analyzer.protocol_guids:
            if guid_rule.name == guid.name or guid_rule.value == guid.value:
                # True if name or value is matches
                # so that UNKNOWN_GUIDs can be specified
                return True
        return False

    def _and_guids(self, guids: List[UefiGuid]) -> bool:
        res = True
        for guid in guids:
            res &= self._search_guid(guid)
            if not res:
                break
        return res

    def _or_guids(self, guids: List[UefiGuid]) -> bool:
        res = False
        for guid in guids:
            res |= self._search_guid(guid)
            if res:
                break
        return res

    def _compare_guids(self, rule_guid: Dict[str, List[UefiGuid]]) -> bool:
        """Compare GUIDs"""

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

        return final_res

    def _get_bounds(self, insns: List[Dict[str, Any]]) -> Tuple:
        """Get function end address"""

        funcs = list(
            filter(
                lambda addr: addr,
                [addr.get("offset", None) for addr in self._uefi_analyzer.functions],
            )
        )
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
        self._uefi_analyzer._rz.cmd("af")

        insns = self._uefi_analyzer._rz.cmd("pdrj")
        # prevent error messages to sys.stderr from rizin:
        # https://github.com/rizinorg/rz-pipe/blob/0f7ac66e6d679ebb03be26bf61a33f9ccf199f27/python/rzpipe/open_base.py#L261
        try:
            insns = json.loads(insns)
        except (ValueError, KeyError, TypeError):
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
            except ValueError:
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
        self._funcs_bounds: List[Any] = list()
        self._rec_addrs: List[Any] = list()

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
            handlers: Optional[List[Any]] = None
            if c.sw_smi_handlers:
                handlers = self._uefi_analyzer.swsmi_handlers
            elif c.child_sw_smi_handlers:
                handlers = self._uefi_analyzer.child_swsmi_handlers
            else:
                raise UefiScannerError("The search place is incorrect")
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
            handlers: Optional[List[Any]] = None
            if c.sw_smi_handlers:
                handlers = self._uefi_analyzer.swsmi_handlers
            elif c.child_sw_smi_handlers:
                handlers = self._uefi_analyzer.child_swsmi_handlers
            else:
                raise UefiScannerError("The search place is incorrect")
            search_res = False
            for handler in handlers:
                search_res = self._code_scan_rec(handler.address, c.pattern)
                if search_res:
                    break

            res |= search_res
            if res:
                break

        return res

    def _code_scanner(self, rule_code: Dict[str, List[CodePattern]]) -> bool:
        """Compare code patterns"""

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

        return final_res

    def _get_results_variants(
        self, rule_variant: UefiRuleVariant, target: Optional[str]
    ) -> bool:
        if target in ["firmware"]:
            # match hex strings
            return self._hex_strings_scanner(rule_variant.hex_strings)

        res = True

        # compare NVRAM variables
        res &= self._compare_nvram_vars(rule_variant.nvram_vars)
        if not res:
            return res

        # compare protocols
        res &= self._compare_protocols(rule_variant.protocols, UefiScanner.PROTOCOL)
        if not res:
            return res

        # compare GUIDs
        res &= self._compare_guids(rule_variant.guids)
        if not res:
            return res

        # compare PPI
        res &= self._compare_protocols(rule_variant.ppi_list, UefiScanner.PPI)
        if not res:
            return res

        # match code patterns
        res &= self._code_scanner(rule_variant.code)
        if not res:
            return res

        # match strings
        res &= self._strings_scanner(rule_variant.strings)
        if not res:
            return res

        # match wide strings
        res &= self._wide_strings_scanner(rule_variant.wide_strings)
        if not res:
            return res

        # match hex strings
        res &= self._hex_strings_scanner(rule_variant.hex_strings)
        if not res:
            return res

        return res

    def _get_results(self) -> List[UefiScannerRes]:
        results: List[UefiScannerRes] = list()

        for uefi_rule in self._uefi_rules:
            for variant in uefi_rule.variants:
                res = self._get_results_variants(
                    uefi_rule.variants[variant], uefi_rule.target
                )
                results.append(
                    UefiScannerRes(rule=uefi_rule, variant_label=variant, res=res)
                )

        return results

    @property
    def results(self) -> List[UefiScannerRes]:
        """Get scanning results as a list of matched rules"""

        if self._results is None:
            self._results = self._get_results()

        return self._results
