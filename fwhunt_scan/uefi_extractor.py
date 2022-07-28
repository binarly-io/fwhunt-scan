from typing import Any, Optional

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
    UI = {0x15: ("User interface name", "ui", "UI")}

    def __init__(self, firmware_data: bytes, file_guid: str):
        self._firmware_data: bytes = firmware_data
        self._file_guid: str = file_guid.lower()
        self._parser: uefi_firmware.AutoParser = None
        self._extracted: bool = False
        self._ext: Optional[str] = None
        self._name: Optional[str] = None
        self._binary: Optional[UefiBinary] = None
        self._content: Optional[bytes] = None

    def _get_name(self, data: bytes) -> None:
        try:
            self._name = data.decode("utf-16le")
        except UnicodeDecodeError:
            pass

    def _search_binary(self, object: Any) -> None:
        for component in object.iterate_objects():
            guid = component.get("guid", None)
            attrs = component.get("attrs", None)
            if guid is not None and attrs is not None and guid == self._file_guid:
                if attrs.get("type", None) in UefiExtractor.UI:
                    self._get_name(component["_self"].content[:-2])
                if attrs.get("type", None) in UefiExtractor.FILE_TYPES:
                    self._content = component["_self"].content
            self._search_binary(component["_self"])

    def _extract(self) -> bool:
        potencial_volumes = uefi_firmware.search_firmware_volumes(self._firmware_data)
        for offset in potencial_volumes:
            self._parser = uefi_firmware.AutoParser(self._firmware_data[offset - 40 :])
            if self._parser.type() == "unknown":
                continue
            break

        if self._parser.type() == "unknown":
            return False
        firmware = self._parser.parse()
        self._search_binary(firmware)
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
