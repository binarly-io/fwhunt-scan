# uefi_r2: tools for analyzing UEFI firmware using radare2

import binascii
import json
import os
import struct

import click
import r2pipe
from uefi_r2.uefi_protocols import PROTOCOLS_GUIDS
from uefi_r2.uefi_tables import (BS_PROTOCOLS, BS_PROTOCOLS_INFO_X64,
                                 EFI_BOOT_SERVICES_X64,
                                 EFI_RUNTIME_SERVICES_X64)


class r2_uefi_analyzer():
    def __init__(self, image_path, debug=False):
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
        self.bs_list = []
        self.bs_prot = []
        # list of runtime services
        self.rt_list = []
        # list of protocols
        self.protocols = []

    def r2_get_common_properties(self):
        """Get common image properties (parsed header, strings, sections, functions)"""

        # get common info
        self.r2_info = self.r2.cmdj('ij')
        # get strings
        self.r2_strings = self.r2.cmdj('izzzj')
        # get sections
        self.r2_sections = self.r2.cmdj('iSj')
        # get functions
        self.r2_functions = self.r2.cmdj('aflj')

    def r2_get_g_bs_x64(self):
        """Find BootServices table global address"""

        for func in self.r2_functions:
            func_addr = func['offset']
            func_insns = self.r2.cmdj('pdfj @{:#x}'.format(func_addr))
            self.g_bs = 0
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

    def r2_get_g_rt_x64(self):
        """Find RuntimeServices table global address"""

        for func in self.r2_functions:
            func_addr = func['offset']
            func_insns = self.r2.cmdj('pdfj @{:#x}'.format(func_addr))
            self.g_rt = 0
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

    def r2_get_boot_services_g_bs_x64(self):
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
                        g_bs_area_esil = g_bs_area_insn['esil'].split(',')
                        if (g_bs_area_insn['type'] == 'ucall') and (
                                g_bs_area_esil[1] == 'rax') and (
                                    g_bs_area_esil[2] == '+') and (
                                        g_bs_area_esil[3] == '[8]') and (
                                            g_bs_area_esil[-1] == '='):
                            if 'ptr' in g_bs_area_insn:
                                service_offset = g_bs_area_insn['ptr']
                                if service_offset in EFI_BOOT_SERVICES_X64:
                                    self.bs_list.append({
                                        'address':
                                        g_bs_area_insn['offset'],
                                        'service_name':
                                        EFI_BOOT_SERVICES_X64[service_offset]
                                    })
                                    break
                    insn_index += 1
        return True

    def r2_get_boot_services_prot_x64(self):
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
                            for service_name in BS_PROTOCOLS_INFO_X64:
                                if BS_PROTOCOLS_INFO_X64[service_name][
                                        'offset'] == service_offset:
                                    # found boot service that work with protocol
                                    new = True
                                    for bs in self.bs_list:
                                        if bs['address'] == insn['offset']:
                                            new = False
                                            break
                                    service = {
                                        'address': insn['offset'],
                                        'service_name': service_name
                                    }
                                    if new:
                                        self.bs_list.append(service)
                                    self.bs_prot.append(service)
                                    break
        return True

    def r2_get_runtime_services_x64(self):
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
                                    self.rt_list.append({
                                        'address':
                                        g_rt_area_insn['offset'],
                                        'service_name':
                                        EFI_RUNTIME_SERVICES_X64[service_offset]
                                    })
                                    break
                    insn_index += 1
        return True

    def r2_get_protocols_x64(self):
        """Find proprietary protocols"""

        for bs in self.bs_prot:
            block_insns = self.r2.cmdj('pdbj @{:#x}'.format(bs['address']))
            for insn in block_insns:
                if("esil" in insn):
                    esil = insn['esil'].split(',')
                    if (insn['type'] == 'lea') and (esil[-1] == '=') and (
                            esil[-2] == BS_PROTOCOLS_INFO_X64[
                                bs['service_name']]['reg']) and (esil[-3] == '+'):
                        if 'ptr' in insn:
                            p_guid_addr = insn['ptr']
                            self.r2.cmd('s {:#x}'.format(p_guid_addr))
                            p_guid_b = self.r2.cmdj('xj 16')
                            p_guid = self._bytes_to_guid(p_guid_b)
                            p_elem = {}
                            p_elem['address'] = p_guid_addr
                            p_elem['p_guid_value'] = p_guid
                            for protocol in PROTOCOLS_GUIDS:
                                guid = PROTOCOLS_GUIDS[protocol]
                                if p_guid == guid:
                                    p_elem['p_name'] = protocol
                                    break
                            if not 'p_name' in p_elem:
                                p_elem['p_name'] = 'proprietary_protocol'
                            self.protocols.append(p_elem)
        return True

    def r2_get_p_guids(self):
        """Find protocols guids"""

        self.p_guids = []
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
                            self.p_guids.append({
                                'address': section['vaddr'] + i,
                                'p_guid_name': protocol,
                                'p_guid_value': guid
                            })
                            break
        return True

    @classmethod
    def r2_get_summary(cls, image_path, debug):
        """Collect all the information in a JSON object"""

        cls = cls(image_path, debug)
        summary = {}

        cls.r2_get_common_properties()
        summary['info'] = cls.r2_info

        cls.r2_get_g_bs_x64()
        cls.r2_get_g_rt_x64()
        summary['g_bs'] = cls.g_bs
        if cls.r2_debug:
            print('{} g_bs: 0x{:x}'.format(cls.r2_name, cls.g_bs))
        summary['g_rt'] = cls.g_rt
        if cls.r2_debug:
            print('{} g_rt: 0x{:x}'.format(cls.r2_name, cls.g_rt))

        cls.r2_get_boot_services_g_bs_x64()
        cls.r2_get_boot_services_prot_x64()
        summary['bs_list'] = cls.bs_list
        if cls.r2_debug:
            print('{} boot services:\n{}'.format(
                cls.r2_name, json.dumps(cls.bs_list, indent=4)))

        cls.r2_get_runtime_services_x64()
        summary['rt_list'] = cls.rt_list
        if cls.r2_debug:
            print('{} runtime services:\n{}'.format(
                cls.r2_name, json.dumps(cls.rt_list, indent=4)))

        cls.r2_get_p_guids()
        summary['p_guids'] = cls.p_guids
        if cls.r2_debug:
            print('{} guids:\n{}'.format(cls.r2_name,
                                         json.dumps(cls.p_guids, indent=4)))

        cls.r2_get_protocols_x64()
        summary['protocols'] = cls.p_guids
        if cls.r2_debug:
            print('{} protocols:\n{}'.format(
                cls.r2_name, json.dumps(cls.protocols, indent=4)))

        return summary

    def _guid_to_bytes(self, guid):
        """Convert guid structure to array of bytes"""

        return self._dword_to_bytes(guid[0]) + self._word_to_bytes(
            guid[1]) + self._word_to_bytes(guid[2]) + guid[3:]

    def _bytes_to_guid(self, guid_b):
        """Convert array of bytes to guid structure"""

        return [
            (guid_b[0] | guid_b[1] << 8 | guid_b[2] << 16 | guid_b[3] << 24),
            (guid_b[4] | guid_b[5] << 8), (guid_b[6] | guid_b[7] << 8)
        ] + guid_b[8:]

    @staticmethod
    def _dword_to_bytes(dword):
        """Convert dword to array of bytes"""

        return [(dword & 0x000000ff), (dword & 0x0000ff00) >> 8,
                (dword & 0x00ff0000) >> 16, (dword & 0xff000000) >> 24]

    @staticmethod
    def _word_to_bytes(word):
        """Convert word to array of bytes"""

        return [(word & 0x00ff), (word & 0xff00) >> 8]
