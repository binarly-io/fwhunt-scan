# SPDX-License-Identifier: GPL-3.0+

import json
import uuid
from typing import Any, Dict, List, Optional

import rzpipe

from fwhunt_scan.uefi_protocols import UefiGuid
from fwhunt_scan.uefi_types import ChildSwSmiHandler, SwSmiHandler
from fwhunt_scan.uefi_utils import (
    get_current_insn_index,
    get_int,
    get_xrefs_to_data,
    get_xrefs_to_guids,
)


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
        res = get_int(esil[0])
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
            len(esil) > 4
            and esil[-1] == "="
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
    res_addrs: List[int] = list()

    func = rz.cmdj(f"pdfj @ {code_addr:#x}")
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
            if offset is None:
                continue
            bb = rz.cmdj(f"pdbj @ {offset:#x}")
            handler = get_handler(bb)
            if handler is not None:
                if handler.address not in res_addrs:
                    res.append(handler)
                    # prevent duplicates
                    res_addrs.append(handler.address)

    return res


def get_smst_bb(insns: List[Dict[str, Any]]) -> Optional[int]:
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

    func = rz.cmdj(f"pdfj @ {code_addr:#x}")
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
            # check both for global variable and local variable
            if insn.get("ptr", None) == interface or get_int(esil[0]) == interface:
                offset = insn.get("offset", None)
                if offset is None:
                    continue
                bb = rz.cmdj(f"pdbj @ {offset:#x}")
                smst = get_smst_bb(bb)
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
        bb = rz.cmdj(f"pdbj @ {code_addr:#x}")
        interface = get_interface_global(bb, code_addr)
        if interface is None:
            continue
        res += get_smst_func(rz, code_addr, interface)

    return res


def find_handler_register_service(insns: List[Dict[str, Any]]) -> Optional[int]:
    for insn in insns[::-1]:
        if "esil" not in insn:
            continue
        esil = insn["esil"].split(",")

        if esil[-7:] != ["8", "rsp", "-=", "rsp", "=[]", "rip", "="]:
            continue

        offset = get_int(esil[0])
        if offset == 0xE0:  # SmiHandlerRegister
            return insns.index(insn)

    return None


def get_child_sw_smi_handler_bb(
    rz: rzpipe.open, insns: List[Dict[str, Any]]
) -> Optional[ChildSwSmiHandler]:
    handler_address = None
    handler_guid = None

    end_index = find_handler_register_service(insns)
    if end_index is None:
        return None

    for insn in insns[:end_index][::-1]:
        if "esil" not in insn:
            continue
        esil = insn["esil"].split(",")

        # try to get handler address (Handler parameter)
        if esil[-1] == "=" and esil[-2] == "rcx":
            handler_address = insn.get("ptr", None)

        # try to get handler guid value (HandlerType parameter)
        if esil[-1] == "=" and esil[-2] == "rdx":
            guid_addr = insn.get("ptr", None)
            if guid_addr is not None:
                rz.cmd(f"s {guid_addr:#x}")
                guid_b = bytes(rz.cmdj("xj 16"))
                handler_guid = str(uuid.UUID(bytes_le=guid_b)).upper()

        if handler_address is not None and handler_guid is not None:
            return ChildSwSmiHandler(address=handler_address, handler_guid=handler_guid)

    if handler_address is not None:  # handler_guid is Optional
        return ChildSwSmiHandler(address=handler_address, handler_guid=handler_guid)

    return None


def get_child_sw_smi_handlers(
    rz: rzpipe.open, smst_list: List[int]
) -> List[ChildSwSmiHandler]:

    res: List[ChildSwSmiHandler] = list()

    haddrs = list()  # addresses

    for smst in smst_list:
        code_addrs = get_xrefs_to_data(rz, smst)
        for addr in code_addrs:
            # analyze instructions and found gSmst->SmiHandlerRegister call
            result = rz.cmd(f"pdj 24 @ {addr:#x}")
            # prevent error messages to sys.stderr from rizin:
            # https://github.com/rizinorg/rz-pipe/blob/0f7ac66e6d679ebb03be26bf61a33f9ccf199f27/python/rzpipe/open_base.py#L261
            try:
                bb = json.loads(result)
            except (ValueError, KeyError, TypeError) as _:
                continue
            handler = get_child_sw_smi_handler_bb(rz, bb)
            if handler is not None:
                if handler.address not in haddrs:
                    res.append(handler)
                    haddrs.append(handler.address)

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
        bb = rz.cmdj(f"pdbj @ {code_addr:#x}")
        interface = get_interface_from_bb(bb, code_addr)
        if interface is None:
            continue

        # need to check the use of this interface below code_addr
        res += get_handlers(rz, code_addr, interface)

    return res
