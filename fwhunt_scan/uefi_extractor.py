from typing import Any, List, Optional

import uefi_firmware


class UefiBinary:
    def __init__(
        self,
        content: Optional[bytes],
        name: Optional[str],
        guid: str,
        ext: Optional[str],
    ) -> None:
        self.guid: str = guid
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

    def __init__(self, firmware_data: bytes, file_guid: str):
        offset = firmware_data.find(b"_FVH")
        if offset >= 0:
            firmware_data = firmware_data[offset - 40 :]
        self._firmware_data: bytes = firmware_data
        self._file_guid: str = file_guid.lower()
        self._parsers: List[uefi_firmware.AutoParser] = list()
        self._extracted: bool = False
        self._ext: Optional[str] = None
        self._name: Optional[str] = None
        self._binary: Optional[UefiBinary] = None
        self._content: Optional[bytes] = None

    def _compressed_search(self, object: Any) -> None:
        for component in object.iterate_objects():
            attrs = component.get("attrs", None)
            if attrs is not None:
                type = attrs.get("type", None)
                if type in UefiExtractor.UI:
                    self._name = component["label"]
                if type in UefiExtractor.SECTION_TYPES:
                    self._content = component["_self"].content
            self._compressed_search(component["_self"])

    def _compressed_handle(self, object: Any) -> None:
        for obj in object.iterate_objects():
            if (
                obj.get("attrs", None) is not None
                and obj["attrs"].get("attrs", None) == 0x01
            ):  # if compressed
                self._compressed_search(obj["_self"])

    def _search_binary(self, object: Any) -> None:
        for component in object.iterate_objects():
            guid = component.get("guid", None)
            attrs = component.get("attrs", None)
            if guid is not None and attrs is not None and guid == self._file_guid:
                type = attrs.get("type", None)
                if type in UefiExtractor.UI:
                    self._name = component["label"]
                if type in UefiExtractor.FILE_TYPES:
                    if self._ext is None:
                        ext = UefiExtractor.FILE_TYPES[type][1]
                        self._ext = f".{ext}"
                    self._compressed_handle(component["_self"])
                if type in UefiExtractor.SECTION_TYPES:
                    self._content = component["_self"].content
            self._search_binary(component["_self"])

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
            self._search_binary(firmware)
            if self._content is not None:
                break

        return True

    @property
    def binary(self) -> Optional[UefiBinary]:
        if self._extracted:
            return self._binary
        self._extract()
        self._extracted = True
        if self._content is not None:
            self._binary = UefiBinary(
                content=self._content,
                name=self._name,
                guid=self._file_guid,
                ext=self._ext,
            )
        return self._binary
