import binascii
import json
from typing import Any, Dict, List, Optional

import rzpipe

from uefi_r2.uefi_protocols import UefiGuid
from uefi_r2.uefi_types import SwSmiHandler


def get_int(item: str) -> Optional[int]:
    res = None
    for base in [10, 16]:
        try:
            value = int(item, base)
            return value
        except ValueError:
            continue
    return res


def get_xrefs_to_guids(rz: rzpipe.open, guids: UefiGuid) -> List[int]:
    code_addrs = list()  # xrefs from code
    for guid in guids:
        guid_bytes = binascii.hexlify(guid.bytes).decode()
        json_addrs = rz.cmdj(f"/xj {guid_bytes}")
        for element in json_addrs:
            if "offset" not in element:
                continue
            offset = element["offset"]

            # xrefs = rz.cmd(f"axtj @{offset:x}")
            # this doesn't work in rizin, so needs to be split into two separate steps (seek + axtj)

            # seek to GUID location in .data segment
            rz.cmd(f"s {offset:#x}")

            # get xrefs
            xrefs = rz.cmdj(f"axtj")

            for xref in xrefs:
                if "from" not in xref:
                    continue

                # get code address
                addr = xref["from"]
                code_addrs.append(addr)

    return code_addrs


def get_current_insn_index(
    insns: List[Dict[str, Any]], code_addr: int
) -> Optional[int]:

    current_insn = None
    try:
        current_insn = list(
            filter(lambda insn: insn.get("offset", None) == code_addr, insns)
        )[0]
    except IndexError:
        return None
    index = insns.index(current_insn)
    if not index:
        return None
    return index


def get_interface_from_bb(insns: List[Dict[str, Any]], code_addr: int) -> Optional[int]:
    """Get the address of the interface
    (in the case of local variables, this will be the address on the stack)"""

    res = None

    index = get_current_insn_index(insns, code_addr)
    if index is None:
        return res

    # check all instructions from index to 0
    for i in range(index - 1, -1, -1):
        insn = insns[i]
        if "esil" not in insn:
            continue
        esil = insn["esil"].split(",")
        if not (esil[-1] == "=" and esil[-2] == "r8"):
            continue
        try:
            res = int(esil[0], 16)
            return res
        except ValueError:
            continue

    return res


def get_interface_global(insns: List[Dict[str, Any]], code_addr: int) -> Optional[int]:
    """Get the address of the interface
    (in the case of local variables, this will be the address on the stack)"""

    res = None

    index = get_current_insn_index(insns, code_addr)
    if index is None:
        return res

    # check all instructions from index to 0
    for i in range(index - 1, -1, -1):
        insn = insns[i]
        if "esil" not in insn:
            continue
        esil = insn["esil"].split(",")
        if not (esil[-1] == "=" and esil[-2] == "r8"):
            continue
        res = insn.get("ptr", None)
        if res is not None:
            return res

    return res


def get_handler(insns: List[Dict[str, Any]]) -> Optional[SwSmiHandler]:
    address = None
    sw_smi_input_value = None

    for insn in insns:
        if "esil" not in insn:
            continue
        esil = insn["esil"].split(",")

        if (
            esil[-1] == "="
            and esil[-2] == "rdx"
            # skip esil[-3]
            # (esil[-3] == "+" or esil[-3] == "-")
            and esil[-4] == "rip"
        ):
            # handler address
            address = insn.get("ptr", None)

        if (
            esil[-1] == "=[8]"
            # skip esil[-3]
            # (esil[-3] == "+" or esil[-3] == "-")
            and (esil[-3] == "rbp" or esil[-3] == "rsp")
        ):
            value = get_int(esil[0])
            if value is None or value > 255:
                continue
            # handler number
            sw_smi_input_value = value

        # found `EfiSmmSwDispatch2Protocol->Register()`
        if esil == ["rax", "[8]", "rip", "8", "rsp", "-=", "rsp", "=[]", "rip", "="]:
            if address is not None:
                return SwSmiHandler(
                    address=address, sw_smi_input_value=sw_smi_input_value
                )

    return None


def get_handlers(rz: rzpipe.open, code_addr: int, interface: int) -> List[SwSmiHandler]:
    res: List[SwSmiHandler] = list()

    func = rz.cmdj(f"pdfj @{code_addr:#x}")
    insns = func.get("ops", None)
    if insns is None:
        return res

    index = get_current_insn_index(insns, code_addr)
    if index is None:
        return res

    # check all instructions from index to end of function
    for i in range(index + 1, len(insns), 1):
        insn = insns[i]
        if "esil" not in insn:
            continue
        esil = insn["esil"].split(",")

        # find `mov rax, [rbp+EfiSmmSwDispatch2Protocol]` instruction
        if not (esil[-1] == "=" and esil[-2] == "rax"):
            continue

        value = get_int(esil[0])
        if value is None:
            continue

        if value == interface:
            offset = insn.get("offset", None)
            bb = rz.cmdj(f"pdbj @{offset:#x}")
            handler = get_handler(bb)
            if handler is not None:
                res.append(handler)

    return res


def get_smst_bb(insns: List[Dict[str, Any]], interface: int) -> Optional[int]:
    res = None

    for insn in insns:
        if "esil" not in insn:
            continue
        esil = insn["esil"].split(",")

        # check esil insn ({offset},rip,+,rdx,=)
        if esil[-1] == "=" and esil[-2] == "rdx":
            res = insn.get("ptr", None)
            if res is not None:
                return res

    return res


def get_smst_func(rz: rzpipe.open, code_addr: int, interface: int) -> List[int]:
    res: List[int] = list()

    func = rz.cmdj(f"pdfj @{code_addr:#x}")
    insns = func.get("ops", None)
    if insns is None:
        return res

    index = get_current_insn_index(insns, code_addr)
    if index is None:
        return res

    # check all instructions from index to end of function
    for i in range(index + 1, len(insns), 1):
        insn = insns[i]
        if "esil" not in insn:
            continue
        esil = insn["esil"].split(",")
        if esil[-1] == "=" and esil[-2] == "rax" and esil[-3] == "[8]":
            if insn.get("ptr", None) == interface:
                offset = insn.get("offset", None)
                if offset is None:
                    continue
                bb = rz.cmdj(f"pdbj @{offset:#x}")
                smst = get_smst_bb(bb, interface)
                if smst is not None:
                    res.append(smst)
    return res


def get_smst_list(rz: rzpipe.open) -> List[int]:
    """Find SMST addresses"""

    res: List[int] = list()

    guids = [
        UefiGuid(
            "F4CCBFB7-F6E0-47FD-9DD410A8F150C191", name="EFI_SMM_BASE2_PROTOCOL_GUID"
        )
    ]
    code_addrs = get_xrefs_to_guids(rz, guids)
    for code_addr in code_addrs:
        bb = rz.cmdj(f"pdbj @{code_addr:#x}")
        interface = get_interface_global(bb, code_addr)
        if interface is None:
            continue
        res += get_smst_func(rz, code_addr, interface)

    return res


def get_sw_smi_handlers(rz: rzpipe.open) -> List[SwSmiHandler]:
    """Find Software SMI Handlers"""

    res: List[SwSmiHandler] = list()

    guids = [
        UefiGuid(
            "18A3C6DC-5EEA-48C8-A1C1B53389F98999",
            name="EFI_SMM_SW_DISPATCH2_PROTOCOL_GUID",
        ),
        UefiGuid(
            "E541B773-DD11-420C-B026DF993653F8BF",
            name="EFI_SMM_SW_DISPATCH_PROTOCOL_GUID",
        ),
    ]
    code_addrs = get_xrefs_to_guids(rz, guids)
    for code_addr in code_addrs:
        # get basic block information
        bb = rz.cmdj(f"pdbj @{code_addr:#x}")
        interface = get_interface_from_bb(bb, code_addr)
        if interface is None:
            continue

        # need to check the use of this interface below code_addr
        res += get_handlers(rz, code_addr, interface)

    return res
