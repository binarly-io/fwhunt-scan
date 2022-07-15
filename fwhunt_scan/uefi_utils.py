# SPDX-License-Identifier: GPL-3.0+

import binascii
from typing import Any, Dict, List, Optional

import rzpipe

from fwhunt_scan.uefi_protocols import UefiGuid


def get_int(item: str) -> Optional[int]:
    res = None
    for base in [10, 16]:
        try:
            value = int(item, base)
            return value
        except ValueError:
            continue
    return res


def get_xrefs_to_guids(rz: rzpipe.open, guids: List[UefiGuid]) -> List[int]:
    code_addrs = list()  # xrefs from code
    for guid in guids:
        guid_bytes = binascii.hexlify(guid.bytes).decode()
        json_addrs = rz.cmdj(f"/xj {guid_bytes}")
        for element in json_addrs:
            if "offset" not in element:
                continue
            offset = element["offset"]

            # xrefs = rz.cmd(f"axtj @ {offset:x}")
            # this doesn't work in rizin, so needs to be split into two separate steps (seek + axtj)

            # seek to GUID location in .data segment
            rz.cmd(f"s {offset:#x}")

            # get xrefs
            xrefs = rz.cmdj("axtj")

            for xref in xrefs:
                if "from" not in xref:
                    continue

                # get code address
                addr = xref["from"]
                code_addrs.append(addr)

    return code_addrs


def get_xrefs_to_data(rz: rzpipe.open, addr: int) -> List[int]:
    code_addrs = list()  # xrefs from code

    rz.cmd(f"s {addr:#x}")

    # get xrefs
    xrefs = rz.cmdj("axtj")

    for xref in xrefs:
        if "from" not in xref:
            continue

        # get code address
        addr = xref["from"]
        if addr not in code_addrs:
            code_addrs.append(addr)

    return code_addrs


def get_current_insn_index(
    insns: Optional[List[Dict[str, Any]]], code_addr: int
) -> Optional[int]:

    if insns is None:
        return None

    current_insn = None

    for insn in insns:
        if insn.get("offset", None) == code_addr:
            current_insn = insn
            break

    if current_insn is None:
        return None

    return insns.index(current_insn)
