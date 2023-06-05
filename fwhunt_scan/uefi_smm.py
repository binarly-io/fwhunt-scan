# SPDX-License-Identifier: GPL-3.0+

import json
import uuid
from typing import Any, Dict, List, Optional

import rzpipe

from fwhunt_scan.uefi_protocols import UefiGuid
from fwhunt_scan.uefi_types import ChildSwSmiHandler, SmiHandler, SmiKind
from fwhunt_scan.uefi_utils import (
    get_current_insn_index,
    get_int,
    get_xrefs_to_data,
    get_xrefs_to_guids,
)


SMI_KINDS = {
    SmiKind.SW_SMI: [
        UefiGuid(
            "18A3C6DC-5EEA-48C8-A1C1B53389F98999",
            name="EFI_SMM_SW_DISPATCH2_PROTOCOL_GUID",
        ),
        UefiGuid(
            "E541B773-DD11-420C-B026DF993653F8BF",
            name="EFI_SMM_SW_DISPATCH_PROTOCOL_GUID",
        ),
    ],
    SmiKind.USB_SMI: [
        UefiGuid(
            "EE9B8D90-C5A6-40A2-BDE252558D33CCA1",
            name="EFI_SMM_USB_DISPATCH2_PROTOCOL_GUID",
        ),
        UefiGuid(
            "A05B6FFD-87AF-4E42-95C96228B63CF3F3",
            name="EFI_SMM_USB_DISPATCH_PROTOCOL_GUID",
        ),
    ],
    SmiKind.SX_SMI: [
        UefiGuid(
            "456D2859-A84B-4E47-A2EE3276D886997D",
            name="EFI_SMM_SX_DISPATCH2_PROTOCOL_GUID",
        ),
        UefiGuid(
            "14FC52BE-01DC-426C-91AEA23C3E220AE8",
            name="EFI_SMM_SX_DISPATCH_PROTOCOL_GUID",
        ),
    ],
    SmiKind.IO_TRAP_SMI: [
        UefiGuid(
            "58DC368D-7BFA-4E77-ABBC0E29418DF930",
            name="EFI_SMM_IO_TRAP_DISPATCH2_PROTOCOL_GUID",
        ),
        UefiGuid(
            "DB7F536B-EDE4-4714-A5C8E346EBAA201D",
            name="EFI_SMM_IO_TRAP_DISPATCH_PROTOCOL_GUID",
        ),
    ],
    SmiKind.GPI_SMI: [
        UefiGuid(
            "25566B03-B577-4CBF-958CED663EA24380",
            name="EFI_SMM_GPI_DISPATCH2_PROTOCOL_GUID",
        ),
        UefiGuid(
            "E0744B81-9513-49CD-8CEAE9245E7039DA",
            name="EFI_SMM_GPI_DISPATCH_PROTOCOL_GUID",
        ),
    ],
    SmiKind.STANDBY_BUTTON_SMI: [
        UefiGuid(
            "7300C4A1-43F2-4017-A51BC81A7F40585B",
            name="EFI_SMM_STANDBY_BUTTON_DISPATCH2_PROTOCOL_GUID",
        ),
        UefiGuid(
            "78965B98-B0BF-449E-8B22D2914E498A98",
            name="EFI_SMM_STANDBY_BUTTON_DISPATCH_PROTOCOL_GUID",
        ),
    ],
    SmiKind.PERIODIC_TIMER_SMI: [
        UefiGuid(
            "4CEC368E-8E8E-4D71-8BE1958C45FC8A53",
            name="EFI_SMM_PERIODIC_TIMER_DISPATCH2_PROTOCOL_GUID",
        ),
        UefiGuid(
            "9CCA03FC-4C9E-4A19-9B06ED7B479BDE55",
            name="EFI_SMM_PERIODIC_TIMER_DISPATCH_PROTOCOL_GUID",
        ),
    ],
    SmiKind.POWER_BUTTON_SMI: [
        UefiGuid(
            "1B1183FA-1823-46A7-88729C578755409D",
            name="EFI_SMM_POWER_BUTTON_DISPATCH2_PROTOCOL_GUID",
        ),
        UefiGuid(
            "B709EFA0-47A6-4B41-B93112ECE7A8EE56",
            name="EFI_SMM_POWER_BUTTON_DISPATCH_PROTOCOL_GUID",
        ),
    ],
    SmiKind.ICHN_SMI: [
        UefiGuid(
            "C50B323E-9075-4F2A-AC8ED2596A1085CC",
            name="EFI_SMM_ICHN_DISPATCH_PROTOCOL_GUID",
        ),
        UefiGuid(
            "ADF3A128-416D-4060-8DDF-30A1D7AAB699",
            name="EFI_SMM_ICHN_DISPATCH2_PROTOCOL_GUID",
        ),
    ],
    SmiKind.TCO_SMI: [
        UefiGuid(
            "0E2D6BB1-C624-446D-9982693CD181A607",
            name="EFI_SMM_TCO_DISPATCH_PROTOCOL_GUID",
        ),
    ],
    SmiKind.STANDBY_BUTTON_SMI: [
        UefiGuid(
            "7300C4A1-43F2-4017-A51BC81A7F40585B",
            name="EFI_SMM_STANDBY_BUTTON_DISPATCH2_PROTOCOL_GUID",
        ),
        UefiGuid(
            "78965B98-B0BF-449E-8B22D2914E498A98",
            name="EFI_SMM_STANDBY_BUTTON_DISPATCH_PROTOCOL_GUID",
        ),
    ],
    SmiKind.PERIODIC_TIMER_SMI: [
        UefiGuid(
            "4CEC368E-8E8E-4D71-8BE1958C45FC8A53",
            name="EFI_SMM_PERIODIC_TIMER_DISPATCH2_PROTOCOL_GUID",
        ),
        UefiGuid(
            "9CCA03FC-4C9E-4A19-9B06ED7B479BDE55",
            name="EFI_SMM_PERIODIC_TIMER_DISPATCH_PROTOCOL_GUID",
        ),
    ],
    SmiKind.POWER_BUTTON_SMI: [
        UefiGuid(
            "1B1183FA-1823-46A7-88729C578755409D",
            name="EFI_SMM_POWER_BUTTON_DISPATCH2_PROTOCOL_GUID",
        ),
        UefiGuid(
            "B709EFA0-47A6-4B41-B93112ECE7A8EE56",
            name="EFI_SMM_POWER_BUTTON_DISPATCH_PROTOCOL_GUID",
        ),
    ],
    SmiKind.PCH_TCO_SMI: [
        UefiGuid(
            "9E71D609-6D24-47FD-B572-6140F8D9C2A4",
            name="PCH_TCO_SMI_DISPATCH_PROTOCOL_GUID",
        ),
    ],
    SmiKind.PCH_PCIE_SMI: [
        UefiGuid(
            "3e7d2b56-3f47-42aa-8f6b-22f519818dab",
            name="PCH_PCIE_SMI_DISPATCH_PROTOCOL_GUID",
        ),
    ],
    SmiKind.PCH_ACPI_SMI: [
        UefiGuid(
            "d52bb262-f022-49ec-86d2-7a293a7a054b",
            name="PCH_ACPI_SMI_DISPATCH_PROTOCOL_GUID",
        ),
    ],
    SmiKind.PCH_GPIO_UNLOCK_SMI: [
        UefiGuid(
            "83339ef7-9392-4716-8d3a-d1fc67cd55db",
            name="PCH_GPIO_UNLOCK_SMI_DISPATCH_PROTOCOL_GUID",
        ),
    ],
    SmiKind.PCH_SMI: [
        UefiGuid(
            "e6a81bbf-873d-47fd-b6be-61b3e5720993",
            name="PCH_SMI_DISPATCH_PROTOCOL_GUID",
        ),
    ],
    SmiKind.PCH_ESPI_SMI: [
        UefiGuid(
            "b3c14ff3-bae8-456c-8631-27fe0ceb340c",
            name="PCH_ESPI_SMI_DISPATCH_PROTOCOL_GUID",
        ),
    ],
    SmiKind.ACPI_EN_SMI: [
        UefiGuid(
            "bd88ec68-ebe4-4f7b-935a-4f666642e75f",
            name="EFI_ACPI_EN_DISPATCH_PROTOCOL_GUID",
        ),
    ],
    SmiKind.ACPI_DIS_SMI: [
        UefiGuid(
            "9c939ba6-1fcc-46f6-b4e1-102dbe186567",
            name="EFI_ACPI_DIS_DISPATCH_PROTOCOL_GUID",
        ),
    ],
}


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


def get_handler(insns: List[Dict[str, Any]], kind: SmiKind) -> Optional[SmiHandler]:
    address = None

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

        # found `EfiSmmXXXDispatch2Protocol->Register()`
        if (
            esil == ["rax", "[8]", "rip", "8", "rsp", "-=", "rsp", "=[]", "rip", "="]
            and address is not None
        ):
            return SmiHandler(address=address, kind=kind)

    return None


def get_handlers(
    rz: rzpipe.open, code_addr: int, interface: int, kind: SmiKind
) -> List[SmiHandler]:
    res: List[SmiHandler] = list()
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
            handler = get_handler(bb, kind)
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
                if len(guid_b) == 16:
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
            except (ValueError, KeyError, TypeError):
                continue
            handler = get_child_sw_smi_handler_bb(rz, bb)
            if handler is not None:
                if handler.address not in haddrs:
                    res.append(handler)
                    haddrs.append(handler.address)

    return res


def get_smi_handlers(rz: rzpipe.open) -> List[SmiHandler]:
    """Find Software SMI Handlers"""

    res: List[SmiHandler] = list()

    for kind in SMI_KINDS:
        code_addrs = get_xrefs_to_guids(rz, SMI_KINDS[kind])
        for code_addr in code_addrs:
            # get basic block information
            bb = rz.cmdj(f"pdbj @ {code_addr:#x}")
            interface = get_interface_from_bb(bb, code_addr)
            if interface is None:
                continue

            # need to check the use of this interface below code_addr
            res += get_handlers(rz, code_addr, interface, kind)

    return res
