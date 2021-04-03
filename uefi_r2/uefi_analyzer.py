# uefi_r2: tools for analyzing UEFI firmware using radare2
#
# pylint: disable=too-many-nested-blocks,invalid-name,superfluous-parens
# pylint: disable=missing-class-docstring,missing-function-docstring,missing-module-docstring
# pylint: disable=too-few-public-methods,too-many-arguments,too-many-instance-attributes

import json
from typing import List, Dict, Any

import click
import r2pipe
from uefi_r2.uefi_protocols import PROTOCOLS_GUIDS, GUID_TO_NAME, get_guid_str
from uefi_r2.uefi_tables import (BS_PROTOCOLS_INFO_X64, OFFSET_TO_SERVICE,
                                 EFI_BOOT_SERVICES_X64,
                                 EFI_RUNTIME_SERVICES_X64)


class r2_uefi_service:
    def __init__(self, name: str, address: int) -> None:
        self.name: str = name
        self.address: int = address


class r2_uefi_protocol:
    def __init__(
        self, name: str, address: int, guid: List[int], guid_address: int, service: str
    ) -> None:
        self.name: str = name
        self.address: int = address
        self.guid: List[int] = guid
        self.guid_address: int = guid_address
        self.service: str = service


class r2_uefi_protocol_guid:
    def __init__(self, name: str, address: int, value: List[int]) -> None:
        self.name: str = name
        self.address: int = address
        self.value: List[int] = value


class r2_uefi_analyzer:
    def __init__(self, image_path: str, debug: bool = False):
        """UEFI analyzer initialization"""

        # init r2
        self.r2_image_path = image_path
        self.r2 = r2pipe.open(image_path, flags=['-2'])
        # analyze image
        self.r2.cmd('aaa')
        # debug
        self.r2_debug = debug
        # name
        self.r2_name = click.style('uefi_r2', fg='green', bold=True)
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
        self.r2_info = self.r2.cmdj('ij')
        # get strings
        self.r2_strings = self.r2.cmdj('izzzj')
        # get sections
        self.r2_sections = self.r2.cmdj('iSj')
        # get functions
        self.r2_functions = self.r2.cmdj('aflj')

    def r2_get_g_bs_x64(self) -> bool:
        """Find BootServices table global address"""

        for func in self.r2_functions:
            func_addr = func['offset']
            func_insns = self.r2.cmdj('pdfj @{:#x}'.format(func_addr))
            g_bs_reg = None
            for insn in func_insns['ops']:
                if("esil" in insn):
                    esil = insn['esil'].split(',')
                    if (esil[0] == '0x60') and (esil[2] == '+') and (
                            esil[3] == '[8]') and (esil[-1] == '='):
                        g_bs_reg = esil[-2]
                    if g_bs_reg:
                        if (esil[0] == g_bs_reg) and (esil[-1] == '=[8]'):
                            if 'ptr' in insn:
                                self.g_bs = insn['ptr']
                                return True
        return False

    def r2_get_g_rt_x64(self) -> bool:
        """Find RuntimeServices table global address"""

        for func in self.r2_functions:
            func_addr = func['offset']
            func_insns = self.r2.cmdj('pdfj @{:#x}'.format(func_addr))
            g_rt_reg = None
            for insn in func_insns['ops']:
                if("esil" in insn):
                    esil = insn['esil'].split(',')
                    if (esil[0] == '0x58') and (esil[2] == '+') and (
                            esil[3] == '[8]') and (esil[-1] == '='):
                        g_rt_reg = esil[-2]
                    if g_rt_reg:
                        if (esil[0] == g_rt_reg) and (esil[-1] == '=[8]'):
                            if 'ptr' in insn:
                                self.g_rt = insn['ptr']
                                return True
        return False

    def r2_get_boot_services_g_bs_x64(self) -> bool:
        """Find boot services using g_bs"""

        for func in self.r2_functions:
            func_addr = func['offset']
            func_insns = self.r2.cmdj('pdfj @{:#x}'.format(func_addr))
            insn_index = 0
            for insn in func_insns['ops']:
                # find "mov rax, qword [g_bs]" instruction
                g_bs_found = False
                if("esil" in insn):
                    esil = insn['esil'].split(',')
                    if (insn['type'] == 'mov') and (esil[-1] == '=') and (
                            esil[-3] == '[8]') and (esil[-4] == '+'):
                        if ('ptr' in insn) and (insn['ptr'] == self.g_bs):
                            g_bs_found = True
                    if not g_bs_found:
                        insn_index += 1
                        continue
                    # if current instriction is "mov rax, qword [g_bs]"
                    for g_bs_area_insn in func_insns['ops'][insn_index:insn_index +
                                                            0x10]:
                        if "esil" in g_bs_area_insn.keys():
                            g_bs_area_esil = g_bs_area_insn['esil'].split(',')
                            if (g_bs_area_insn['type'] == 'ucall') and (
                                    g_bs_area_esil[1] == 'rax') and (
                                        g_bs_area_esil[2] == '+') and (
                                            g_bs_area_esil[3] == '[8]') and (
                                                g_bs_area_esil[-1] == '='):
                                if 'ptr' in g_bs_area_insn:
                                    service_offset = g_bs_area_insn['ptr']
                                    if service_offset in EFI_BOOT_SERVICES_X64:
                                        self.bs_list.append(
                                            r2_uefi_service(
                                                address=g_bs_area_insn['offset'],
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
            func_addr = func['offset']
            func_insns = self.r2.cmdj('pdfj @{:#x}'.format(func_addr))
            for insn in func_insns['ops']:
                if("esil" in insn):
                    esil = insn['esil'].split(',')
                    if (insn['type'] == 'ucall') and (esil[1] == 'rax') and (
                            esil[2] == '+') and (esil[3] == '[8]'):
                        if 'ptr' in insn:
                            service_offset = insn['ptr']
                            if service_offset in OFFSET_TO_SERVICE:
                                name = OFFSET_TO_SERVICE[service_offset]
                                # found boot service that work with protocol
                                new = True
                                for bs in self.bs_list:
                                    if bs.address == insn['offset']:
                                        new = False
                                        break
                                bs = r2_uefi_service(address=insn['offset'], name=name)
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
            func_addr = func['offset']
            func_insns = self.r2.cmdj('pdfj @{:#x}'.format(func_addr))
            insn_index = 0
            for insn in func_insns['ops']:
                # find "mov rax, qword [g_rt]" instruction
                g_rt_found = False
                if("esil" in insn):
                    esil = insn['esil'].split(',')
                    if (insn['type'] == 'mov') and (esil[-1] == '=') and (
                            esil[-3] == '[8]') and (esil[-4] == '+'):
                        if ('ptr' in insn) and (insn['ptr'] == self.g_bs):
                            g_rt_found = True
                    if not g_rt_found:
                        insn_index += 1
                        continue
                    # if current instriction is "mov rax, qword [g_rt]"
                    for g_rt_area_insn in func_insns['ops'][insn_index:insn_index +
                                                            0x10]:
                        g_rt_area_esil = g_rt_area_insn['esil'].split(',')
                        if (g_rt_area_insn['type'] == 'ucall') and (
                                g_rt_area_esil[1] == 'rax') and (
                                    g_rt_area_esil[2] == '+') and (
                                        g_rt_area_esil[3] == '[8]') and (
                                            g_rt_area_esil[-1] == '='):
                            if 'ptr' in g_rt_area_insn:
                                service_offset = g_rt_area_insn['ptr']
                                if service_offset in EFI_RUNTIME_SERVICES_X64:
                                    self.rt_list.append(
                                        r2_uefi_service(
                                            address=g_rt_area_insn['offset'],
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
            block_insns = self.r2.cmdj('pdbj @{:#x}'.format(bs.address))
            for insn in block_insns:
                if("esil" in insn):
                    esil = insn['esil'].split(',')
                    if (insn['type'] == 'lea') and (esil[-1] == '=') and (
                            esil[-2] == BS_PROTOCOLS_INFO_X64[
                                bs.name]['reg']) and (esil[-3] == '+'):
                        if 'ptr' in insn:
                            p_guid_addr = insn['ptr']
                            self.r2.cmd('s {:#x}'.format(p_guid_addr))
                            p_guid_b = self.r2.cmdj('xj 16')
                            p_guid = self._bytes_to_guid(p_guid_b)
                            self.protocols.append(
                                r2_uefi_protocol(
                                    name=GUID_TO_NAME.get(
                                        get_guid_str(p_guid), 'proprietary_protocol'
                                    ),
                                    guid_address=p_guid_addr,
                                    address=insn["offset"],
                                    guid=p_guid,
                                    service=bs.name,
                                )
                            )
        return True

    def r2_get_p_guids(self) -> bool:
        """Find protocols guids"""

        target_sections = ['.data']
        for section in self.r2_sections:
            if section['name'] in target_sections:
                self.r2.cmd('s {:#x}'.format(section['vaddr']))
                section_data = self.r2.cmdj('xj {:#d}'.format(
                    section['vsize']))
                # find guids in section data:
                for i in range(len(section_data) - 15):
                    if (section_data[i:i + 8] == [0x00] *
                            8) or (section_data[i:i + 8] == [0xff] * 8):
                        continue
                    chunk = section_data[i:i + 16]
                    for protocol in PROTOCOLS_GUIDS:
                        guid = PROTOCOLS_GUIDS[protocol]
                        b_guid = self._guid_to_bytes(guid)
                        if b_guid == chunk:
                            self.p_guids.append(
                                r2_uefi_protocol_guid(
                                    address=section['vaddr'] + i,
                                    name=protocol,
                                    value=guid,
                                )
                            )
                            break
        return True

    @classmethod
    def r2_get_summary(cls, image_path: str, debug: bool = False) -> Dict[str, str]:
        """Collect all the information in a JSON object"""

        self = cls(image_path, debug)
        summary = {}

        self.r2_get_common_properties()
        summary['info'] = str(self.r2_info)
        if self.r2_debug:
            print('{} r2_info:\n{}'.format(
                self.r2_name, json.dumps(self.r2_info, indent=4)))

        self.r2_get_g_bs_x64()
        self.r2_get_g_rt_x64()
        summary['g_bs'] = str(self.g_bs)
        if self.r2_debug:
            print('{} g_bs: 0x{:x}'.format(self.r2_name, self.g_bs))
        summary['g_rt'] = str(self.g_rt)
        if self.r2_debug:
            print('{} g_rt: 0x{:x}'.format(self.r2_name, self.g_rt))

        self.r2_get_boot_services_g_bs_x64()
        self.r2_get_boot_services_prot_x64()
        summary['bs_list'] = str(self.bs_list)
        if self.r2_debug:
            print('{} boot services:\n{}'.format(
                self.r2_name, json.dumps(self.bs_list, indent=4, default=vars)))

        self.r2_get_runtime_services_x64()
        summary['rt_list'] = str(self.rt_list)
        if self.r2_debug:
            print('{} runtime services:\n{}'.format(
                self.r2_name, json.dumps(self.rt_list, indent=4, default=vars)))

        self.r2_get_p_guids()
        summary['p_guids'] = str(self.p_guids)
        if self.r2_debug:
            print('{} guids:\n{}'.format(self.r2_name,
                                         json.dumps(self.p_guids, indent=4, default=vars)))

        self.r2_get_protocols_x64()
        summary['protocols'] = str(self.protocols)
        if self.r2_debug:
            print('{} protocols:\n{}'.format(
                self.r2_name, json.dumps(self.protocols, indent=4, default=vars)))

        self.close()

        return summary

    @classmethod
    def r2_get_protocols_info(
        cls, image_path: str, debug: bool = False
    ) -> Dict[str, str]:

        self = cls(image_path, debug)
        summary = {}

        self.r2_get_common_properties()
        summary['info'] = str(self.r2_info)

        self.r2_get_g_bs_x64()
        summary['g_bs'] = str(self.g_bs)
        if self.r2_debug:
            print('{} g_bs: 0x{:x}'.format(self.r2_name, self.g_bs))

        self.r2_get_boot_services_prot_x64()
        summary['bs_list'] = str(self.bs_list)
        if self.r2_debug:
            print('{} boot services:\n{}'.format(
                self.r2_name, json.dumps(self.bs_list, indent=4)))

        self.r2_get_protocols_x64()
        summary['protocols'] = str(self.protocols)
        if self.r2_debug:
            print('{} protocols:\n{}'.format(
                self.r2_name, json.dumps(self.protocols, indent=4)))

        self.close()

        return summary

    def _guid_to_bytes(self, guid: List[int]) -> List[int]:
        """Convert guid structure to array of bytes"""

        return self._dword_to_bytes(guid[0]) + self._word_to_bytes(
            guid[1]) + self._word_to_bytes(guid[2]) + guid[3:]

    @staticmethod
    def _bytes_to_guid(guid_b: List[int]) -> List[int]:
        """Convert array of bytes to guid structure"""

        return [
            (guid_b[0] | guid_b[1] << 8 | guid_b[2] << 16 | guid_b[3] << 24),
            (guid_b[4] | guid_b[5] << 8), (guid_b[6] | guid_b[7] << 8)
        ] + guid_b[8:]

    @staticmethod
    def _dword_to_bytes(dword: int) -> List[int]:
        """Convert dword to array of bytes"""

        return [(dword & 0x000000ff), (dword & 0x0000ff00) >> 8,
                (dword & 0x00ff0000) >> 16, (dword & 0xff000000) >> 24]

    @staticmethod
    def _word_to_bytes(word: int) -> List[int]:
        """Convert word to array of bytes"""

        return [(word & 0x00ff), (word & 0xff00) >> 8]

    def close(self) -> None:
        self.r2.quit()

    def __exit__(self, exception_type, exception_value, traceback):
        self.r2.quit()
