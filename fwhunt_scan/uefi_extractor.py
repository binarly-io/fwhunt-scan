import contextlib
import os
from typing import Any, Dict, List, Optional

import uefi_firmware


class UefiBinary:
    def __init__(
        self,
        content: Optional[bytes],
        name: Optional[str],
        guid: str,
        ext: Optional[str],
    ) -> None:
        self.guid: str = guid.lower()
        self._content: Optional[bytes] = content
        self._name: Optional[str] = name
        self._ext: Optional[str] = ext

    @property
    def content(self) -> bytes:
        if self._content is None:
            self._content = bytes()
        return self._content

    @property
    def name(self) -> str:
        if self._name is None:
            self._name = self.guid
        return self._name

    @property
    def ext(self) -> str:
        if self._ext is None:
            self._ext = ".bin"
        return self._ext


class UefiExtractor:
    FILE_TYPES = {
        0x01: ("raw", "raw", "RAW"),
        0x02: ("freeform", "freeform", "FREEFORM"),
        0x03: ("security core", "sec", "SEC"),
        0x04: ("pei core", "pei.core", "PEI_CORE"),
        0x05: ("dxe core", "dxe.core", "DXE_CORE"),
        0x06: ("pei module", "peim", "PEIM"),
        0x07: ("driver", "dxe", "DRIVER"),
        0x08: ("combined pei module/driver", "peim.dxe", "COMBO_PEIM_DRIVER"),
        0x09: ("application", "app", "APPLICATION"),
        0x0A: ("system management", "smm", "SMM"),
        0x0C: ("combined smm/driver", "smm.dxe", "COMBO_SMM_DRIVER"),
        0x0D: ("smm core", "smm.core", "SMM_CORE"),
    }
    SECTION_TYPES = {
        0x10: ("PE32 image", "pe", "PE32"),
        0x12: ("Terse executable (TE)", "te", "TE"),
    }
    UI = {0x15: ("User interface name", "ui", "UI")}

    def __init__(self, firmware_data: bytes, file_guids: List[str]):
        offset = firmware_data.find(b"_FVH")
        if offset >= 0:
            firmware_data = firmware_data[offset - 40 :]
        self._firmware_data: bytes = firmware_data
        self._file_guids: List[str] = [g.lower() for g in file_guids]
        self._parsers: List[uefi_firmware.AutoParser] = list()
        self._info: Dict[str, Any] = dict()
        self.binaries: List[UefiBinary] = list()

    def _compressed_search(self, object: Any, root_guid: str) -> None:
        if object is None:
            return

        for component in object.iterate_objects():
            attrs = component.get("attrs", None)
            if attrs is not None:
                type = attrs.get("type", None)
                if type in UefiExtractor.UI:
                    self._info[root_guid]["name"] = component["label"]
                if type in UefiExtractor.SECTION_TYPES:
                    self._info[root_guid]["content"] = component["_self"].content
            self._compressed_search(component["_self"], root_guid)

    def _compressed_handle(self, object: Any, root_guid: str) -> None:
        if object is None:
            return

        for obj in object.iterate_objects():
            if (
                obj.get("attrs", None) is not None
                and obj["attrs"].get("attrs", None) == 0x01
            ):  # if compressed
                self._compressed_search(obj["_self"], root_guid)

    def _append_binaries(self, object: Any) -> None:
        if object is None:
            return

        for component in object.iterate_objects():
            guid = component.get("guid", None)
            attrs = component.get("attrs", None)
            if guid is not None and attrs is not None:
                if guid not in self._info:
                    self._info[guid] = {"name": None, "ext": None, "content": None}
                type = attrs.get("type", None)
                if type in UefiExtractor.UI:
                    self._info[guid]["name"] = component["label"]
                if type in UefiExtractor.FILE_TYPES:
                    if self._info[guid]["ext"] is None:
                        ext = UefiExtractor.FILE_TYPES[type][1]
                        self._info[guid]["ext"] = f".{ext}"
                    self._compressed_handle(component["_self"], guid)
                if type in UefiExtractor.SECTION_TYPES:
                    self._info[guid]["content"] = component["_self"].content
            self._append_binaries(component["_self"])

    def _extract(self) -> bool:
        potencial_volumes = uefi_firmware.search_firmware_volumes(self._firmware_data)
        for offset in potencial_volumes:
            parser = uefi_firmware.AutoParser(self._firmware_data[offset - 40 :])
            if parser is None or parser.type() == "unknown":
                continue
            self._parsers.append(parser)

        if not len(self._parsers):
            return False

        for parser in self._parsers:
            firmware = parser.parse()
            self._append_binaries(firmware)

        return True

    def extract_all(self, ignore_guid: bool = False) -> None:
        with open(os.devnull, "w") as devnull:
            with contextlib.redirect_stderr(devnull):
                self._extract()
                for guid in self._info:
                    if ignore_guid or (
                        self._info[guid]["content"] is not None
                        and (guid in self._file_guids)
                    ):
                        self.binaries.append(
                            UefiBinary(
                                content=self._info[guid]["content"],
                                name=self._info[guid]["name"],
                                guid=guid,
                                ext=self._info[guid]["ext"],
                            )
                        )
