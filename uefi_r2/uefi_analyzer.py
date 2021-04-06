# uefi_r2: tools for analyzing UEFI firmware using radare2
#
# pylint: disable=too-many-nested-blocks,invalid-name,superfluous-parens
# pylint: disable=missing-class-docstring,missing-function-docstring,missing-module-docstring
# pylint: disable=too-few-public-methods,too-many-arguments,too-many-instance-attributes

import json
import uuid

from typing import List, Dict, Any, Optional

import click
import r2pipe
from uefi_r2.uefi_protocols import GUID_FROM_BYTES, r2_uefi_guid
from uefi_r2.uefi_tables import (
    BS_PROTOCOLS_INFO_X64,
    OFFSET_TO_SERVICE,
    EFI_BOOT_SERVICES_X64,
    EFI_RUNTIME_SERVICES_X64,
)


class r2_uefi_service:
    def __init__(self, name: str, address: int) -> None:
        self.name: str = name
        self.address: int = address


class r2_uefi_protocol(r2_uefi_guid):
    def __init__(
        self, name: str, address: int, value: str, guid_address: int, service: str
    ) -> None:
        self.address: int = address
        self.guid_address: int = guid_address
        self.service: str = service

        # superclass
        self.name = name
        self.value = value


class r2_uefi_protocol_guid(r2_uefi_guid):
    def __init__(self, name: str, address: int, value: str) -> None:
        self.address: int = address

        # superclass
        self.name = name
        self.value = value


class r2_uefi_analyzer:
    def __init__(self, image_path: Optional[str] = None, debug: bool = False):
        """UEFI analyzer initialization"""

        # init r2
        self.r2_image_path = image_path
        if image_path:
            self.r2 = r2pipe.open(image_path, flags=["-2"])
            # analyze image
            self.r2.cmd("aaa")
        # debug
        self.r2_debug = debug
        # name
        self.r2_name = click.style("uefi_r2", fg="green", bold=True)
        # list of boot services
        self.bs_list: List[r2_uefi_service] = []
        self.bs_prot: List[r2_uefi_service] = []
        # list of runtime services
        self.rt_list: List[r2_uefi_service] = []
        # list of protocols
        self.protocols: List[r2_uefi_protocol] = []
        self.p_guids: List[r2_uefi_protocol_guid] = []

        # private???
        self.r2_info: List[Any] = []
        self.r2_strings: List[Any] = []
        self.r2_sections: List[Any] = []
        self.r2_functions: List[Any] = []
        self.g_bs: int = 0
        self.g_rt: int = 0

    def r2_get_common_properties(self) -> None:
        """Get common image properties (parsed header, strings, sections, functions)"""

        # get common info
        self.r2_info = self.r2.cmdj("ij")
        # get strings
        self.r2_strings = self.r2.cmdj("izzzj")
        # get sections
        self.r2_sections = self.r2.cmdj("iSj")
        # get functions
        self.r2_functions = self.r2.cmdj("aflj")

    def r2_get_g_bs_x64(self) -> bool:
        """Find BootServices table global address"""

        for func in self.r2_functions:
            func_addr = func["offset"]
            func_insns = self.r2.cmdj("pdfj @{:#x}".format(func_addr))
            g_bs_reg = None
            for insn in func_insns["ops"]:
                if "esil" in insn:
                    esil = insn["esil"].split(",")
                    if (
                        (esil[0] == "0x60")
                        and (esil[2] == "+")
                        and (esil[3] == "[8]")
                        and (esil[-1] == "=")
                    ):
                        g_bs_reg = esil[-2]
                    if g_bs_reg:
                        if (esil[0] == g_bs_reg) and (esil[-1] == "=[8]"):
                            if "ptr" in insn:
                                self.g_bs = insn["ptr"]
                                return True
        return False

    def r2_get_g_rt_x64(self) -> bool:
        """Find RuntimeServices table global address"""

        for func in self.r2_functions:
            func_addr = func["offset"]
            func_insns = self.r2.cmdj("pdfj @{:#x}".format(func_addr))
            g_rt_reg = None
            for insn in func_insns["ops"]:
                if "esil" in insn:
                    esil = insn["esil"].split(",")
                    if (
                        (esil[0] == "0x58")
                        and (esil[2] == "+")
                        and (esil[3] == "[8]")
                        and (esil[-1] == "=")
                    ):
                        g_rt_reg = esil[-2]
                    if g_rt_reg:
                        if (esil[0] == g_rt_reg) and (esil[-1] == "=[8]"):
                            if "ptr" in insn:
                                self.g_rt = insn["ptr"]
                                return True
        return False

    def r2_get_boot_services_g_bs_x64(self) -> bool:
        """Find boot services using g_bs"""

        for func in self.r2_functions:
            func_addr = func["offset"]
            func_insns = self.r2.cmdj("pdfj @{:#x}".format(func_addr))
            insn_index = 0
            for insn in func_insns["ops"]:
                # find "mov rax, qword [g_bs]" instruction
                g_bs_found = False
                if "esil" in insn:
                    esil = insn["esil"].split(",")
                    if (
                        (insn["type"] == "mov")
                        and (esil[-1] == "=")
                        and (esil[-3] == "[8]")
                        and (esil[-4] == "+")
                    ):
                        if ("ptr" in insn) and (insn["ptr"] == self.g_bs):
                            g_bs_found = True
                    if not g_bs_found:
                        insn_index += 1
                        continue
                    # if current instriction is "mov rax, qword [g_bs]"
                    for g_bs_area_insn in func_insns["ops"][
                        insn_index : insn_index + 0x10
                    ]:
                        if "esil" in g_bs_area_insn.keys():
                            g_bs_area_esil = g_bs_area_insn["esil"].split(",")
                            if (
                                (g_bs_area_insn["type"] == "ucall")
                                and (g_bs_area_esil[1] == "rax")
                                and (g_bs_area_esil[2] == "+")
                                and (g_bs_area_esil[3] == "[8]")
                                and (g_bs_area_esil[-1] == "=")
                            ):
                                if "ptr" in g_bs_area_insn:
                                    service_offset = g_bs_area_insn["ptr"]
                                    if service_offset in EFI_BOOT_SERVICES_X64:
                                        self.bs_list.append(
                                            r2_uefi_service(
                                                address=g_bs_area_insn["offset"],
                                                name=EFI_BOOT_SERVICES_X64[
                                                    service_offset
                                                ],
                                            )
                                        )
                                        break
                    insn_index += 1
        return True

    def r2_get_boot_services_prot_x64(self) -> bool:
        """Find boot service that work with protocols"""

        for func in self.r2_functions:
            func_addr = func["offset"]
            func_insns = self.r2.cmdj("pdfj @{:#x}".format(func_addr))
            for insn in func_insns["ops"]:
                if "esil" in insn:
                    esil = insn["esil"].split(",")
                    if (
                        (insn["type"] == "ucall")
                        and (esil[1] == "rax")
                        and (esil[2] == "+")
                        and (esil[3] == "[8]")
                    ):
                        if "ptr" in insn:
                            service_offset = insn["ptr"]
                            if service_offset in OFFSET_TO_SERVICE:
                                name = OFFSET_TO_SERVICE[service_offset]
                                # found boot service that work with protocol
                                new = True
                                for bs in self.bs_list:
                                    if bs.address == insn["offset"]:
                                        new = False
                                        break
                                bs = r2_uefi_service(address=insn["offset"], name=name)
                                if new:
                                    self.bs_list.append(bs)
                                self.bs_prot.append(bs)
                                break
        return True

    def r2_get_runtime_services_x64(self) -> bool:
        """Find all runtime services"""

        if not self.g_rt:
            return False
        for func in self.r2_functions:
            func_addr = func["offset"]
            func_insns = self.r2.cmdj("pdfj @{:#x}".format(func_addr))
            insn_index = 0
            for insn in func_insns["ops"]:
                # find "mov rax, qword [g_rt]" instruction
                g_rt_found = False
                if "esil" in insn:
                    esil = insn["esil"].split(",")
                    if (
                        (insn["type"] == "mov")
                        and (esil[-1] == "=")
                        and (esil[-3] == "[8]")
                        and (esil[-4] == "+")
                    ):
                        if ("ptr" in insn) and (insn["ptr"] == self.g_rt):
                            g_rt_found = True
                    if not g_rt_found:
                        insn_index += 1
                        continue
                    # if current instriction is "mov rax, qword [g_rt]"
                    for g_rt_area_insn in func_insns["ops"][
                        insn_index : insn_index + 0x10
                    ]:
                        g_rt_area_esil = g_rt_area_insn["esil"].split(",")
                        if (
                            (g_rt_area_insn["type"] == "ucall")
                            and (g_rt_area_esil[1] == "rax")
                            and (g_rt_area_esil[2] == "+")
                            and (g_rt_area_esil[3] == "[8]")
                            and (g_rt_area_esil[-1] == "=")
                        ):
                            if "ptr" in g_rt_area_insn:
                                service_offset = g_rt_area_insn["ptr"]
                                if service_offset in EFI_RUNTIME_SERVICES_X64:
                                    self.rt_list.append(
                                        r2_uefi_service(
                                            address=g_rt_area_insn["offset"],
                                            name=EFI_RUNTIME_SERVICES_X64[
                                                service_offset
                                            ],
                                        )
                                    )
                                    break
                    insn_index += 1
        return True

    def r2_get_protocols_x64(self) -> bool:
        """Find proprietary protocols"""

        for bs in self.bs_prot:
            block_insns = self.r2.cmdj("pdbj @{:#x}".format(bs.address))
            for insn in block_insns:
                if "esil" in insn:
                    esil = insn["esil"].split(",")
                    if (
                        (insn["type"] == "lea")
                        and (esil[-1] == "=")
                        and (esil[-2] == BS_PROTOCOLS_INFO_X64[bs.name]["reg"])
                        and (esil[-3] == "+")
                    ):
                        if "ptr" in insn:
                            p_guid_addr = insn["ptr"]
                            self.r2.cmd("s {:#x}".format(p_guid_addr))
                            p_guid_b = bytes(self.r2.cmdj("xj 16"))

                            # look up in known list
                            guid = GUID_FROM_BYTES.get(p_guid_b)
                            if not guid:
                                guid = r2_uefi_guid(
                                    value=str(uuid.UUID(bytes_le=p_guid_b)),
                                    name="proprietary_protocol",
                                )

                            self.protocols.append(
                                r2_uefi_protocol(
                                    name=guid.name,
                                    value=guid.value,
                                    guid_address=p_guid_addr,
                                    address=insn["offset"],
                                    service=bs.name,
                                )
                            )
        return True

    def r2_get_p_guids(self) -> bool:
        """Find protocols guids"""

        target_sections = [".data"]
        for section in self.r2_sections:
            if section["name"] in target_sections:
                self.r2.cmd("s {:#x}".format(section["vaddr"]))
                section_data = bytes(self.r2.cmdj("xj {:#d}".format(section["vsize"])))

                # find guids in section data:
                for i in range(len(section_data) - 15):
                    chunk = section_data[i : i + 16]
                    guid = GUID_FROM_BYTES.get(chunk)
                    if not guid:
                        continue
                    if guid.value in ["00000000-0000-0000-0000000000000000"]:
                        continue
                    self.p_guids.append(
                        r2_uefi_protocol_guid(
                            address=section["vaddr"] + i,
                            name=guid.name,
                            value=guid.value,
                        )
                    )
        return True

    @classmethod
    def r2_get_summary(cls, image_path: str, debug: bool = False) -> Dict[str, str]:
        """Collect all the information in a JSON object"""

        self = cls(image_path, debug)
        summary = {}

        self.r2_get_common_properties()
        summary["info"] = str(self.r2_info)
        if self.r2_debug:
            print(
                "{} r2_info:\n{}".format(
                    self.r2_name, json.dumps(self.r2_info, indent=4)
                )
            )

        self.r2_get_g_bs_x64()
        self.r2_get_g_rt_x64()
        summary["g_bs"] = str(self.g_bs)
        if self.r2_debug:
            print("{} g_bs: 0x{:x}".format(self.r2_name, self.g_bs))
        summary["g_rt"] = str(self.g_rt)
        if self.r2_debug:
            print("{} g_rt: 0x{:x}".format(self.r2_name, self.g_rt))

        self.r2_get_boot_services_g_bs_x64()
        self.r2_get_boot_services_prot_x64()
        summary["bs_list"] = str(self.bs_list)
        if self.r2_debug:
            print(
                "{} boot services:\n{}".format(
                    self.r2_name, json.dumps(self.bs_list, indent=4, default=vars)
                )
            )

        self.r2_get_runtime_services_x64()
        summary["rt_list"] = str(self.rt_list)
        if self.r2_debug:
            print(
                "{} runtime services:\n{}".format(
                    self.r2_name, json.dumps(self.rt_list, indent=4, default=vars)
                )
            )

        self.r2_get_p_guids()
        summary["p_guids"] = str(self.p_guids)
        if self.r2_debug:
            print(
                "{} guids:\n{}".format(
                    self.r2_name, json.dumps(self.p_guids, indent=4, default=vars)
                )
            )

        self.r2_get_protocols_x64()
        summary["protocols"] = str(self.protocols)
        if self.r2_debug:
            print(
                "{} protocols:\n{}".format(
                    self.r2_name, json.dumps(self.protocols, indent=4, default=vars)
                )
            )

        self.close()

        return summary

    @classmethod
    def r2_get_protocols_info(
        cls, image_path: str, debug: bool = False
    ) -> Dict[str, str]:

        self = cls(image_path, debug)
        summary = {}

        self.r2_get_common_properties()
        summary["info"] = str(self.r2_info)

        self.r2_get_g_bs_x64()
        summary["g_bs"] = str(self.g_bs)
        if self.r2_debug:
            print("{} g_bs: 0x{:x}".format(self.r2_name, self.g_bs))

        self.r2_get_boot_services_prot_x64()
        summary["bs_list"] = str(self.bs_list)
        if self.r2_debug:
            print(
                "{} boot services:\n{}".format(
                    self.r2_name, json.dumps(self.bs_list, indent=4)
                )
            )

        self.r2_get_protocols_x64()
        summary["protocols"] = str(self.protocols)
        if self.r2_debug:
            print(
                "{} protocols:\n{}".format(
                    self.r2_name, json.dumps(self.protocols, indent=4)
                )
            )

        self.close()

        return summary

    def close(self) -> None:
        self.r2.quit()

    def __exit__(self, exception_type, exception_value, traceback):
        self.r2.quit()
