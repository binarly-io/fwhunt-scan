# SPDX-License-Identifier: GPL-3.0+
#
# pylint: disable=too-many-nested-blocks,invalid-name
# pylint: disable=too-few-public-methods,too-many-arguments,too-many-instance-attributes

"""
Tools for analyzing UEFI firmware using radare2
"""

import uuid

from typing import List, Dict, Any, Optional, Tuple

import r2pipe
from uefi_r2.uefi_protocols import GUID_FROM_BYTES, UefiGuid
from uefi_r2.uefi_tables import (
    BS_PROTOCOLS_INFO_X64,
    OFFSET_TO_SERVICE,
    EFI_BOOT_SERVICES_X64,
    EFI_RUNTIME_SERVICES_X64,
)


class UefiService:
    """a UEFI service"""

    def __init__(self, name: str, address: int) -> None:
        self.name: str = name
        self.address: int = address

    @property
    def __dict__(self):
        val = {}
        if self.name:
            val["name"] = self.name
        if self.address:
            val["address"] = self.address
        return val


class UefiProtocol(UefiGuid):
    """a UEFI protocol"""

    def __init__(
        self, name: str, address: int, value: str, guid_address: int, service: str
    ) -> None:
        super().__init__(name=name, value=value)
        self.address: int = address
        self.guid_address: int = guid_address
        self.service: str = service

    @property
    def __dict__(self):
        val = super().__dict__
        if self.address:
            val["address"] = self.address
        if self.guid_address:
            val["guid_address"] = self.guid_address
        if self.service:
            val["service"] = self.service
        return val


class UefiProtocolGuid(UefiGuid):
    """a UEFI protocol GUID"""

    def __init__(self, name: str, address: int, value: str) -> None:
        super().__init__(name=name, value=value)
        self.address: int = address

    @property
    def __dict__(self):
        val = super().__dict__
        if self.address:
            val["address"] = self.address
        return val


class NvramVariable:
    """a UEFI NVRAM variable"""

    def __init__(self, name: str, guid: str, service: UefiService) -> None:
        self.name: str = name
        self.guid: str = guid
        self.service: UefiService = service

    @property
    def __dict__(self):
        val = {}
        if self.name:
            val["name"] = self.name
        if self.guid:
            val["guid"] = self.guid
        if self.service:
            val["service"] = {
                "name": self.service.name,
                "address": self.service.address,
            }
        return val


class UefiAnalyzer:
    """helper object to analyze the EFI binary and provide properties"""

    def __init__(
        self, image_path: Optional[str] = None, radare2home: Optional[str] = None
    ):
        """UEFI analyzer initialization"""

        # init r2
        if image_path:
            self._r2 = r2pipe.open(image_path, flags=["-2"], radare2home=radare2home)
            # analyze image
            self._r2.cmd("aaa")

        # private cache
        self._bs_list_g_bs: Optional[List[UefiService]] = None
        self._bs_list_prot: Optional[List[UefiService]] = None
        self._bs_prot: Optional[List[UefiService]] = None
        self._rt_list: Optional[List[UefiService]] = None
        self._protocols: Optional[List[UefiProtocol]] = None
        self._protocol_guids: Optional[List[UefiProtocolGuid]] = None
        self._nvram_vars: Optional[List[NvramVariable]] = None
        self._info: Optional[List[Any]] = None
        self._strings: Optional[List[Any]] = None
        self._sections: Optional[List[Any]] = None
        self._functions: Optional[List[Any]] = None
        self._g_bs: Optional[int] = None
        self._g_rt: Optional[int] = None

    @property
    def info(self) -> List[Any]:
        """Get common image properties (parsed header)"""
        if self._info is None:
            self._info = self._r2.cmdj("ij")
        return self._info

    @property
    def strings(self) -> List[Any]:
        """Get common image properties (strings)"""
        if self._strings is None:
            self._strings = self._r2.cmdj("izzzj")
        return self._strings

    @property
    def sections(self) -> List[Any]:
        """Get common image properties (sections)"""
        if self._sections is None:
            self._sections = self._r2.cmdj("iSj")
        return self._sections

    @property
    def functions(self) -> List[Any]:
        """Get common image properties (functions)"""
        if self._functions is None:
            self._functions = self._r2.cmdj("aflj")
        return self._functions

    def _get_g_bs_x64(self) -> int:

        for func in self.functions:
            func_addr = func["offset"]
            func_insns = self._r2.cmdj("pdfj @{:#x}".format(func_addr))
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
                                return insn["ptr"]
        return 0

    @property
    def g_bs(self) -> int:
        """Find BootServices table global address"""
        if self._g_bs is None:
            self._g_bs = self._get_g_bs_x64()
        return self._g_bs

    def _get_g_rt_x64(self) -> int:

        for func in self.functions:
            func_addr = func["offset"]
            func_insns = self._r2.cmdj("pdfj @{:#x}".format(func_addr))
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
                                return insn["ptr"]
        return 0

    @property
    def g_rt(self) -> int:
        """Find RuntimeServices table global address"""
        if self._g_rt is None:
            self._g_rt = self._get_g_rt_x64()
        return self._g_rt

    def _get_boot_services_g_bs_x64(self) -> List[UefiService]:

        bs_list = []
        for func in self.functions:
            func_addr = func["offset"]
            func_insns = self._r2.cmdj("pdfj @{:#x}".format(func_addr))
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
                                        bs_list.append(
                                            UefiService(
                                                address=g_bs_area_insn["offset"],
                                                name=EFI_BOOT_SERVICES_X64[
                                                    service_offset
                                                ],
                                            )
                                        )
                                        break
                    insn_index += 1
        return bs_list

    def _get_boot_services_prot_x64(
        self,
    ) -> Tuple[List[UefiService], List[UefiService]]:

        bs_list: List[UefiService] = []
        bs_prot: List[UefiService] = []
        for func in self.functions:
            func_addr = func["offset"]
            func_insns = self._r2.cmdj("pdfj @{:#x}".format(func_addr))
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
                                for bs in bs_list:
                                    if bs.address == insn["offset"]:
                                        new = False
                                        break
                                bs = UefiService(address=insn["offset"], name=name)
                                if new:
                                    bs_list.append(bs)
                                bs_prot.append(bs)
                                break
        return bs_list, bs_prot

    @property
    def boot_services(self) -> List[UefiService]:
        """Find boot services using g_bs"""
        if self._bs_list_g_bs is None:
            self._bs_list_g_bs = self._get_boot_services_g_bs_x64()
        if self._bs_list_prot is None:
            self._bs_list_prot, self._bs_prot = self._get_boot_services_prot_x64()
        return self._bs_list_g_bs + self._bs_list_prot

    @property
    def boot_services_protocols(self) -> List[Any]:
        """Find boot service that work with protocols"""
        if self._bs_prot is None:
            self._bs_list_prot, self._bs_prot = self._get_boot_services_prot_x64()
        return self._bs_prot

    def _get_runtime_services_x64(self) -> List[UefiService]:

        rt_list: List[UefiService] = []
        if not self.g_rt:
            return rt_list
        for func in self.functions:
            func_addr = func["offset"]
            func_insns = self._r2.cmdj("pdfj @{:#x}".format(func_addr))
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
                                    rt_list.append(
                                        UefiService(
                                            address=g_rt_area_insn["offset"],
                                            name=EFI_RUNTIME_SERVICES_X64[
                                                service_offset
                                            ],
                                        )
                                    )
                                    break
                    insn_index += 1
        return rt_list

    @property
    def runtime_services(self) -> List[UefiService]:
        """Find all runtime services"""
        if self._rt_list is None:
            self._rt_list = self._get_runtime_services_x64()
        return self._rt_list

    def _get_protocols_x64(self) -> List[UefiProtocol]:

        protocols = []
        for bs in self.boot_services_protocols:
            block_insns = self._r2.cmdj("pdbj @{:#x}".format(bs.address))
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
                            self._r2.cmd("s {:#x}".format(p_guid_addr))
                            p_guid_b = bytes(self._r2.cmdj("xj 16"))

                            # look up in known list
                            guid = GUID_FROM_BYTES.get(p_guid_b)
                            if not guid:
                                guid = UefiGuid(
                                    value=str(uuid.UUID(bytes_le=p_guid_b)).upper(),
                                    name="proprietary_protocol",
                                )

                            protocols.append(
                                UefiProtocol(
                                    name=guid.name,
                                    value=guid.value,
                                    guid_address=p_guid_addr,
                                    address=insn["offset"],
                                    service=bs.name,
                                )
                            )
        return protocols

    @property
    def protocols(self) -> List[UefiProtocol]:
        """Find proprietary protocols"""
        if self._protocols is None:
            self._protocols = self._get_protocols_x64()
        return self._protocols

    def _get_protocol_guids(self) -> List[UefiProtocolGuid]:

        protocol_guids = []
        target_sections = [".data"]
        for section in self.sections:
            if section["name"] in target_sections:
                self._r2.cmd("s {:#x}".format(section["vaddr"]))
                section_data = bytes(self._r2.cmdj("xj {:#d}".format(section["vsize"])))

                # find guids in section data:
                for i in range(len(section_data) - 15):
                    chunk = section_data[i : i + 16]
                    guid = GUID_FROM_BYTES.get(chunk)
                    if not guid:
                        continue
                    if guid.value in ["00000000-0000-0000-0000000000000000"]:
                        continue
                    protocol_guids.append(
                        UefiProtocolGuid(
                            address=section["vaddr"] + i,
                            name=guid.name,
                            value=guid.value,
                        )
                    )
        return protocol_guids

    @property
    def protocol_guids(self) -> List[UefiProtocolGuid]:
        """Find protocols guids"""
        if self._protocol_guids is None:
            self._protocol_guids = self._get_protocol_guids()
        return self._protocol_guids

    def r2_get_nvram_vars_x64(self) -> List[NvramVariable]:

        nvram_vars = []
        for service in self.runtime_services:
            if service.name in ["GetVariable", "SetVariable"]:
                # disassemble 8 instructions backward
                block_insns = self._r2.cmdj("pdj -8 @{:#x}".format(service.address))
                name: str = str()
                p_guid_b: bytes = bytes()
                for index in range(len(block_insns) - 2, -1, -1):
                    if not "refs" in block_insns[index]:
                        continue
                    if len(block_insns[index]["refs"]) > 1:
                        continue
                    ref_addr = block_insns[index]["refs"][0]["addr"]
                    if not "esil" in block_insns[index]:
                        continue
                    esil = block_insns[index]["esil"].split(",")
                    if (
                        (esil[-1] == "=")
                        and (esil[-2] == "rcx")
                        and (esil[-3] == "+")
                        and (esil[-4] == "rip")
                    ):
                        name = self._r2.cmd("psw @{:#x}".format(ref_addr))[:-1]
                    if (
                        (esil[-1] == "=")
                        and (esil[-2] == "rdx")
                        and (esil[-3] == "+")
                        and (esil[-4] == "rip")
                    ):
                        p_guid_b = bytes(self._r2.cmdj("xj 16 @{:#x}".format(ref_addr)))
                    if not name:
                        name = "Unknown"
                    if p_guid_b:
                        guid = str(uuid.UUID(bytes_le=p_guid_b)).upper()
                        nvram_vars.append(
                            NvramVariable(name=name, guid=guid, service=service)
                        )
                        break
        return nvram_vars

    @property
    def nvram_vars(self) -> List[NvramVariable]:
        """Find NVRAM variables passed to GetVariable and SetVariable services"""
        if self._nvram_vars is None:
            self._nvram_vars = self.r2_get_nvram_vars_x64()
        return self._nvram_vars

    @classmethod
    def get_summary(cls, image_path: str) -> Dict[str, Any]:
        """Collect all the information in a JSON object"""

        self = cls(image_path)
        summary = {}
        for key in self.info:
            summary[key] = self.info[key]
        summary["g_bs"] = str(self.g_bs)
        summary["g_rt"] = str(self.g_rt)
        summary["bs_list"] = [x.__dict__ for x in self.boot_services]
        summary["rt_list"] = [x.__dict__ for x in self.runtime_services]
        summary["p_guids"] = [x.__dict__ for x in self.protocol_guids]
        summary["protocols"] = [x.__dict__ for x in self.protocols]
        summary["nvram_vars"] = [x.__dict__ for x in self.nvram_vars]
        self.close()
        return summary

    @classmethod
    def get_protocols_info(cls, image_path: str) -> Dict[str, Any]:
        """Collect all the information in a JSON object"""

        self = cls(image_path)
        summary = {}
        for key in self.info:
            summary[key] = self.info[key]
        summary["g_bs"] = str(self.g_bs)
        summary["bs_list"] = [x.__dict__ for x in self.boot_services]
        summary["protocols"] = [x.__dict__ for x in self.protocols]
        self.close()
        return summary

    def close(self) -> None:
        """Quits the r2 instance, releasing resources"""
        self._r2.quit()

    def __exit__(self, exception_type, exception_value, traceback):
        self._r2.quit()
