# SPDX-License-Identifier: GPL-3.0+
#
# pylint: disable=too-many-nested-blocks,invalid-name
# pylint: disable=too-few-public-methods,too-many-arguments,too-many-instance-attributes

"""
Tools for analyzing UEFI firmware using radare2/rizin
"""

import json
import sys
import uuid
from types import TracebackType
from typing import Any, Dict, List, Optional, Type

import rzpipe

import fwhunt_scan.uefi_smm as uefi_smm
from fwhunt_scan.uefi_protocols import GUID_FROM_BYTES, UefiGuid
from fwhunt_scan.uefi_tables import (
    BS_PROTOCOLS_INFO_64_BIT,
    EFI_BOOT_SERVICES_64_BIT,
    EFI_PEI_SERVICES_32_BIT,
    EFI_RUNTIME_SERVICES_64_BIT,
    OFFSET_TO_SERVICE,
)
from fwhunt_scan.uefi_te import TerseExecutableError, TerseExecutableParser
from fwhunt_scan.uefi_types import (
    ChildSwSmiHandler,
    NvramVariable,
    SwSmiHandler,
    UefiGuid,
    UefiProtocol,
    UefiProtocolGuid,
    UefiService,
)
from fwhunt_scan.uefi_utils import get_int

if sys.version_info.major == 3 and sys.version_info.minor >= 8:
    from multiprocessing import shared_memory
if sys.version_info.major == 3 and (
    sys.version_info.minor >= 6 and sys.version_info.minor < 8
):
    import shared_memory


class UefiAnalyzerError(Exception):
    """Generic TE format error exception."""

    def __init__(self, value: str) -> None:
        self.value = value

    def __str__(self):
        return repr(self.value)


class UefiAnalyzer:
    """Helper object to analyze the EFI binary and provide properties"""

    def __init__(
        self,
        image_path: Optional[str] = None,
        blob: Optional[bytes] = None,
        rizinhome: Optional[str] = None,
    ):
        """UEFI analyzer initialization"""

        self._rz: rzpipe.open = None
        self._shm: Optional[shared_memory.SharedMemory] = None
        self._te: Optional[TerseExecutableParser] = None

        # init rizin
        if image_path:
            self._rz = rzpipe.open(
                filename=image_path, flags=["-2"], rizin_home=rizinhome
            )
            # analyze image
            self._rz.cmd("aaaa")
            try:
                self._te = TerseExecutableParser(image_path=image_path)
            except TerseExecutableError:
                self._te = None

        if blob and sys.platform in ["linux"]:
            if blob[:2] not in [b"MZ", b"VZ"]:
                raise UefiAnalyzerError("Invalid data format")
            blob_size = len(blob)
            self._shm = shared_memory.SharedMemory(create=True, size=blob_size)
            self._shm.buf[:] = blob[:]
            self._rz = rzpipe.open(
                filename=f"shm://{self._shm.name}/{blob_size:#d}",
                flags=["-2"],
                rizin_home=rizinhome,
            )
            self._rz.cmd("aaaa")
            try:
                self._te = TerseExecutableParser(blob=blob)
            except TerseExecutableError:
                self._te = None

        if self._rz is None:
            raise UefiAnalyzerError(
                "Failed to initialize radare2/rizin analyzing engine"
            )

        # private cache
        self._bs_list_g_bs: Optional[List[UefiService]] = None
        self._bs_prot: Optional[List[UefiService]] = None
        self._rt_list: Optional[List[UefiService]] = None
        self._pei_services: Optional[List[UefiService]] = None
        self._ppi_list: Optional[List[UefiProtocol]] = None
        self._protocols: Optional[List[UefiProtocol]] = None
        self._protocol_guids: Optional[List[UefiProtocolGuid]] = None
        self._nvram_vars: Optional[List[NvramVariable]] = None
        self._info: Optional[Dict[Any, Any]] = None
        self._strings: Optional[List[Any]] = None
        self._sections: Optional[List[Any]] = None
        self._functions: Optional[List[Any]] = None
        self._insns: Optional[List[Any]] = None
        self._g_bs: Optional[List[int]] = None
        self._g_rt: Optional[List[int]] = None
        self._smst_list: Optional[List[int]] = None

        # SMI handlers addresses
        self._swsmi_handlers: Optional[List[SwSmiHandler]] = None
        self._child_swsmi_handlers: Optional[List[ChildSwSmiHandler]] = None

    def __enter__(self):
        return self

    def _section_paddr(self, section_name: str) -> int:
        for section in self.sections:
            if section["name"] == section_name:
                return section["paddr"]
        return 0

    def _correct_addr(self, addr: int) -> int:
        if not self._te:
            return addr
        offset = (
            self._te.image_base + self._te.base_of_code - self._section_paddr(".text")
        )
        return addr + offset

    def _wrong_addr(self, addr: int) -> int:
        if not self._te:
            return addr
        offset = (
            self._te.image_base + self._te.base_of_code - self._section_paddr(".text")
        )
        return addr - offset

    def _pei_service_args_num(self, reg: str, addr: int) -> int:
        """Get number of arguments for specified PEI service call"""

        args_num = 0
        self._rz.cmd("s {:#x}".format(addr))
        res = self._rz.cmdj("pdbj")
        if not res:
            return 0

        # find current call in block
        for index in range(len(res)):
            if res[index]["offset"] == addr:
                break

        # get number of arguments
        for i in range(index, -1, -1):
            esil = res[i]["esil"].split(",")
            if len(esil) < 4:  # fix IndexError
                continue
            if esil[-3] == "4" and esil[-2] == "esp" and esil[-1] == "-=":
                args_num += 1
            if (
                len(esil) == 4
                and esil[-1] == "="
                and esil[-2] == reg
                and esil[-3] == "[4]"
            ):
                return args_num
        return 0

    @property
    def info(self) -> Dict[Any, Any]:
        """Get common image properties (parsed header)"""

        if self._info is None:
            self._info = self._rz.cmdj("ij")
        return self._info

    @property
    def strings(self) -> List[Any]:
        """Get common image properties (strings)"""

        if self._strings is None:
            self._strings = self._rz.cmdj("izzzj") or []
        return self._strings

    @property
    def sections(self) -> List[Any]:
        """Get common image properties (sections)"""

        if self._sections is None:
            self._sections = self._rz.cmdj("iSj") or []
        return self._sections

    @property
    def functions(self) -> List[Any]:
        """Get common image properties (functions)"""

        if self._functions is None:
            self._functions = self._rz.cmdj("aflj") or []
        return self._functions

    def _get_insns(self) -> List[Any]:
        insns = list()
        target_sections = [".text"]
        for section in self.sections:
            if section["name"] in target_sections:
                self._rz.cmd("s {:#x}".format(section["vaddr"]))
                insns = self._rz.cmdj("pDj {:#x}".format(section["vsize"]))
        return insns

    @property
    def insns(self) -> List[Any]:
        """Get instructions"""

        if self._insns is None:
            self._insns = self._get_insns()
        return self._insns

    def _get_bs_64bit(self) -> List[int]:
        res: List[int] = list()

        for func in self.functions:
            func_addr = func["offset"]
            func_insns = self._rz.cmdj("pdfj @ {:#x}".format(func_addr))
            g_bs_reg = None
            for insn in func_insns["ops"]:
                if "esil" in insn:
                    esil = insn["esil"].split(",")
                    if (
                        get_int(esil[0]) == 0x60
                        and (esil[2] == "+")
                        and (esil[3] == "[8]")
                        and (esil[-1] == "=")
                    ):
                        g_bs_reg = esil[-2]
                    if not g_bs_reg:
                        continue
                    if (
                        (esil[0] == g_bs_reg)
                        and (esil[-1] == "=[8]")
                        and ("ptr" in insn)
                    ):
                        res.append(insn["ptr"])
                        break
        return res

    @property
    def g_bs(self) -> List[int]:
        """Find BootServices table global address"""

        if self._g_bs is None:
            self._g_bs = self._get_bs_64bit()
        return self._g_bs

    def _get_rt_64bit(self) -> List[int]:
        res: List[int] = list()

        for func in self.functions:
            func_addr = func["offset"]
            func_insns = self._rz.cmdj("pdfj @ {:#x}".format(func_addr))
            g_rt_reg = None
            for insn in func_insns["ops"]:
                if "esil" in insn:
                    esil = insn["esil"].split(",")
                    if (
                        get_int(esil[0]) == 0x58
                        and (esil[2] == "+")
                        and (esil[3] == "[8]")
                        and (esil[-1] == "=")
                    ):
                        g_rt_reg = esil[-2]
                    if not g_rt_reg:
                        continue
                    if (
                        (esil[0] == g_rt_reg)
                        and (esil[-1] == "=[8]")
                        and ("ptr" in insn)
                    ):
                        res.append(insn["ptr"])
                        break
        return res

    @property
    def g_rt(self) -> List[int]:
        """Find RuntimeServices table global address"""

        if self._g_rt is None:
            self._g_rt = self._get_rt_64bit()
        return self._g_rt

    def _get_boot_services_bs_64bit(self) -> List[UefiService]:
        bs_list: List[UefiService] = list()
        addrs: List[int] = list()

        if not len(self.g_bs):
            return bs_list

        for insn in self.insns:
            # find "mov rax, qword [g_bs]" instruction
            found = False
            if "esil" not in insn:
                continue
            esil = insn["esil"].split(",")
            if (
                (insn["type"] == "mov")
                and (esil[-1] == "=")
                and (esil[-3] == "[8]")
                and (esil[-4] == "+")
            ):
                if ("ptr" in insn) and (insn["ptr"] in self.g_bs):
                    found = True
            if not found:
                continue

            # if current instriction is "mov rax, qword [g_bs]"
            index = self.insns.index(insn)
            for g_bs_area_insn in self.insns[index : index + 0x10]:
                if "esil" not in g_bs_area_insn.keys():
                    continue
                g_bs_area_esil = g_bs_area_insn["esil"].split(",")
                if not (
                    (g_bs_area_insn["type"] == "ucall")
                    and (g_bs_area_esil[1] == "rax")
                    and (g_bs_area_esil[2] == "+")
                    and (g_bs_area_esil[3] == "[8]")
                    and (g_bs_area_esil[-1] == "=")
                ):
                    continue
                if "ptr" not in g_bs_area_insn:
                    continue
                service_offset = g_bs_area_insn["ptr"]
                if service_offset in EFI_BOOT_SERVICES_64_BIT:
                    if g_bs_area_insn["offset"] in addrs:
                        break
                    bs_list.append(
                        UefiService(
                            address=g_bs_area_insn["offset"],
                            name=EFI_BOOT_SERVICES_64_BIT[service_offset],
                        )
                    )
                    break

        return bs_list

    def _get_boot_services_prot_64bit(self) -> List[UefiService]:
        bs_prot: List[UefiService] = list()

        for insn in self.insns:
            if "esil" not in insn:
                continue
            esil = insn["esil"].split(",")
            if not (
                (insn["type"] == "ucall")
                and (esil[1] == "rax")
                and (esil[2] == "+")
                and (esil[3] == "[8]")
            ):
                continue
            if "ptr" not in insn:
                continue
            service_offset = insn["ptr"]
            if service_offset in OFFSET_TO_SERVICE:
                name = OFFSET_TO_SERVICE[service_offset]
                # found boot service that work with protocol
                bs_prot.append(UefiService(address=insn["offset"], name=name))

        return bs_prot

    @property
    def boot_services(self) -> List[UefiService]:
        """Find boot services using g_bs"""

        if self._bs_list_g_bs is None:
            self._bs_list_g_bs = self._get_boot_services_bs_64bit()
        if self._bs_prot is None:
            self._bs_prot = self._get_boot_services_prot_64bit()
        return self._bs_list_g_bs + self._bs_prot

    @property
    def boot_services_protocols(self) -> List[Any]:
        """Find boot service that work with protocols"""

        if self._bs_prot is None:
            self._bs_prot = self._get_boot_services_prot_64bit()
        return self._bs_prot

    def _get_runtime_services_64bit(self) -> List[UefiService]:
        rt_list: List[UefiService] = list()

        if not len(self.g_rt):
            return rt_list

        for insn in self.insns:
            # find "mov rax, qword [g_rt]" instruction
            found = False
            if "esil" not in insn:
                continue
            esil = insn["esil"].split(",")
            if (
                (insn["type"] == "mov")
                and (esil[-1] == "=")
                and (esil[-3] == "[8]")
                and (esil[-4] == "+")
            ):
                if ("ptr" in insn) and (insn["ptr"] in self.g_rt):
                    found = True
            if not found:
                continue

            index = self.insns.index(insn)
            for g_rt_area_insn in self.insns[index : index + 0x10]:
                g_rt_area_esil = g_rt_area_insn["esil"].split(",")
                if not (
                    (g_rt_area_insn["type"] == "ucall")
                    and (g_rt_area_esil[1] == "rax")
                    and (g_rt_area_esil[2] == "+")
                    and (g_rt_area_esil[3] == "[8]")
                    and (g_rt_area_esil[-1] == "=")
                ):
                    continue
                if "ptr" not in g_rt_area_insn:
                    continue
                service_offset = g_rt_area_insn["ptr"]
                if service_offset in EFI_RUNTIME_SERVICES_64_BIT:
                    rt_list.append(
                        UefiService(
                            address=g_rt_area_insn["offset"],
                            name=EFI_RUNTIME_SERVICES_64_BIT[service_offset],
                        )
                    )
                    break
        return rt_list

    @property
    def runtime_services(self) -> List[UefiService]:
        """Find all runtime services"""

        if self._rt_list is None:
            self._rt_list = self._get_runtime_services_64bit()
        return self._rt_list

    def _get_protocols_64bit(self) -> List[UefiProtocol]:
        protocols = list()
        for bs in self.boot_services_protocols:
            block_insns = self._rz.cmd("pdbj @ {:#x}".format(bs.address))
            try:
                block_insns = json.loads(block_insns)
            except (ValueError, KeyError, TypeError) as _:
                continue
            for insn in block_insns:
                if "esil" in insn:
                    esil = insn["esil"].split(",")
                    if not (
                        (insn["type"] == "lea")
                        and (esil[-1] == "=")
                        and (esil[-2] == BS_PROTOCOLS_INFO_64_BIT[bs.name]["reg"])
                        and (esil[-3] == "+")
                    ):
                        continue
                    if "ptr" not in insn:
                        continue
                    p_guid_addr = insn["ptr"]
                    self._rz.cmd("s {:#x}".format(p_guid_addr))
                    p_guid_b = bytes(self._rz.cmdj("xj 16"))

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
            self._protocols = self._get_protocols_64bit()
        return self._protocols

    def _get_protocol_guids(self) -> List[UefiProtocolGuid]:
        protocol_guids = list()
        target_sections = [".data"]
        for section in self.sections:
            if section["name"] in target_sections:
                self._rz.cmd("s {:#x}".format(section["vaddr"]))
                section_data = bytes(self._rz.cmdj("xj {:#d}".format(section["vsize"])))

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
        """Find protocols GUIDs"""

        if self._protocol_guids is None:
            self._protocol_guids = self._get_protocol_guids()
        return self._protocol_guids

    def r2_get_nvram_vars_64bit(self) -> List[NvramVariable]:
        nvram_vars = list()
        for service in self.runtime_services:
            if service.name in ["GetVariable", "SetVariable"]:
                # disassemble 16 instructions backward
                block_insns = self._rz.cmdj("pdj -16 @ {:#x}".format(service.address))
                name: str = str()
                p_guid_b: bytes = bytes()
                for index in range(len(block_insns) - 2, -1, -1):
                    if "xrefs_from" not in block_insns[index]:
                        continue
                    ref_addr = block_insns[index]["xrefs_from"][0]["addr"]
                    if "esil" not in block_insns[index]:
                        continue
                    esil = block_insns[index]["esil"].split(",")
                    if (
                        (esil[-1] == "=")
                        and (esil[-2] == "rcx")
                        and (esil[-3] == "+")
                        and (esil[-4] == "rip")
                    ):
                        name = self._rz.cmd("psw @ {:#x}".format(ref_addr))[:-1]
                    if (
                        (esil[-1] == "=")
                        and (esil[-2] == "rdx")
                        and (esil[-3] == "+")
                        and (esil[-4] == "rip")
                    ):
                        p_guid_b = bytes(
                            self._rz.cmdj("xj 16 @ {:#x}".format(ref_addr))
                        )
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
            self._nvram_vars = self.r2_get_nvram_vars_64bit()
        return self._nvram_vars

    def _get_pei_services(self) -> List[UefiService]:
        pei_list: List[UefiService] = list()
        for func in self.functions:
            func_addr = func["offset"]
            func_insns = self._rz.cmdj("pdfj @ {:#x}".format(func_addr))
            for insn in func_insns["ops"]:
                if "esil" not in insn:
                    continue
                esil = insn["esil"].split(",")
                if esil[-1] == "=" and esil[-2] == "eip":
                    offset = get_int(esil[0])
                    if offset is None:
                        continue
                    if offset not in EFI_PEI_SERVICES_32_BIT.keys():
                        continue
                    reg = esil[1]
                    service: Dict[str, Any] = EFI_PEI_SERVICES_32_BIT[offset]

                    # found potential pei service, compare number of arguments
                    arg_num: Any = self._pei_service_args_num(reg, insn["offset"])
                    if arg_num < service["arg_num"]:
                        continue

                    # wrong addresses in r2 in case of TE
                    pei_list.append(
                        UefiService(address=insn["offset"], name=service["name"])
                    )

        return pei_list

    @property
    def pei_services(self) -> List[UefiService]:
        """Find all PEI services"""

        if self._pei_services is None:
            self._pei_services = self._get_pei_services()
        return self._pei_services

    def _get_ppi_list(self) -> List[UefiProtocol]:
        ppi_list: List[UefiProtocol] = list()
        for pei_service in self.pei_services:
            if pei_service.name != "LocatePpi":
                continue
            block_insns = self._rz.cmdj("pdj -16 @ {:#x}".format(pei_service.address))
            for index in range(len(block_insns) - 1, -1, -1):
                esil = block_insns[index]["esil"].split(",")
                if not (esil[-1] == "-=" and esil[-2] == "esp" and esil[-3] == "4"):
                    continue
                if "ptr" not in block_insns[index]:
                    continue
                current_block = block_insns[index]
                p_guid_addr = current_block["ptr"]
                baddr = self.info["bin"]["baddr"]
                if p_guid_addr < baddr:
                    continue
                # wrong addresses in r2 in case of TE
                p_guid_addr = self._wrong_addr(p_guid_addr)
                self._rz.cmd("s {:#x}".format(p_guid_addr))
                p_guid_b = bytes(self._rz.cmdj("xj 16"))
                # look up in known list
                guid = GUID_FROM_BYTES.get(p_guid_b)
                if not guid:
                    guid = UefiGuid(
                        value=str(uuid.UUID(bytes_le=p_guid_b)).upper(),
                        name="proprietary_ppi",
                    )
                ppi = UefiProtocol(
                    name=guid.name,
                    value=guid.value,
                    guid_address=p_guid_addr,
                    address=block_insns[index]["offset"],
                    service=pei_service.name,
                )
                if ppi not in ppi_list:
                    ppi_list.append(ppi)

        return ppi_list

    @property
    def ppi_list(self) -> List[UefiProtocol]:
        """Find all PPIs"""

        if self._ppi_list is None:
            self._ppi_list = self._get_ppi_list()
        return self._ppi_list

    @property
    def swsmi_handlers(self) -> List[SwSmiHandler]:
        """Find software SMI handlers"""

        if self._swsmi_handlers is None:
            self._swsmi_handlers = uefi_smm.get_sw_smi_handlers(self._rz)
        return self._swsmi_handlers

    @property
    def child_swsmi_handlers(self) -> List[ChildSwSmiHandler]:
        """Find child software SMI handlers"""

        if self._child_swsmi_handlers is None:
            self._child_swsmi_handlers = uefi_smm.get_child_sw_smi_handlers(
                self._rz, self.smst_list
            )
        return self._child_swsmi_handlers

    @property
    def smst_list(self) -> List[int]:
        """Find list of SMST"""

        if self._smst_list is None:
            self._smst_list = uefi_smm.get_smst_list(self._rz)
        return self._smst_list

    def get_summary(self) -> Dict[str, Any]:
        """Collect all the information in a JSON object"""

        summary = dict()

        for key in self.info:
            summary[key] = self.info[key]

        if "bin" not in summary:
            return summary

        if not (
            self.info["bin"]["class"].startswith("PE")
            or self.info["bin"]["class"].startswith("TE")
        ):
            return summary

        if self.info["bin"]["arch"] == "x86" and self.info["bin"]["bits"] == 32:
            summary["pei_list"] = [x.__dict__ for x in self.pei_services]
            summary["ppi_list"] = [x.__dict__ for x in self.ppi_list]
            summary["nvram_vars"] = [x.__dict__ for x in self.nvram_vars]

        elif self.info["bin"]["arch"] == "x86" and self.info["bin"]["bits"] == 64:
            summary["g_bs"] = self.g_bs
            summary["g_rt"] = self.g_rt
            summary["g_smst"] = [x for x in self.smst_list]
            summary["bs_list"] = [x.__dict__ for x in self.boot_services]
            summary["rt_list"] = [x.__dict__ for x in self.runtime_services]
            summary["protocols"] = [x.__dict__ for x in self.protocols]
            summary["nvram_vars"] = [x.__dict__ for x in self.nvram_vars]
            if len(self.swsmi_handlers) > 0:
                summary["swsmi_handlers"] = [x.__dict__ for x in self.swsmi_handlers]
            if len(self.child_swsmi_handlers) > 0:
                summary["child_swsmi_handlers"] = [
                    x.__dict__ for x in self.child_swsmi_handlers
                ]

        summary["p_guids"] = [x.__dict__ for x in self.protocol_guids]

        return summary

    def get_protocols_info(self) -> Dict[str, Any]:
        """Collect all the information in a JSON object"""

        summary = dict()
        for key in self.info:
            summary[key] = self.info[key]
        summary["g_bs"] = self.g_bs
        summary["bs_list"] = [x.__dict__ for x in self.boot_services]
        summary["protocols"] = [x.__dict__ for x in self.protocols]
        return summary

    def close(self) -> None:
        """Quits the r2 instance, releasing resources"""

        self._rz.quit()
        if self._shm is not None:
            self._shm.close()
            self._shm.unlink()

    def __exit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc_value: Optional[BaseException],
        traceback: Optional[TracebackType],
    ) -> None:
        self.close()
