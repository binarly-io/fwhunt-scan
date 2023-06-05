# SPDX-License-Identifier: GPL-3.0+

import uuid
from enum import Enum
from typing import Optional


class SmiKind(Enum):
    CHILD_SW_SMI = 0
    SW_SMI = 1
    USB_SMI = 2
    SX_SMI = 3
    IO_TRAP_SMI = 4
    GPI_SMI = 5
    TCO_SMI = 6
    STANDBY_BUTTON_SMI = 7
    PERIODIC_TIMER_SMI = 8
    POWER_BUTTON_SMI = 9
    ICHN_SMI = 10
    PCH_TCO_SMI = 11
    PCH_PCIE_SMI = 12
    PCH_ACPI_SMI = 13
    PCH_GPIO_UNLOCK_SMI = 14
    PCH_SMI = 15
    PCH_ESPI_SMI = 16
    ACPI_EN_SMI = 17
    ACPI_DIS_SMI = 18


class UefiService:
    """A UEFI service"""

    def __init__(self, name: str, address: int) -> None:
        self.name: str = name
        self.address: int = address

    @property
    def __dict__(self):
        val = dict()
        if self.name:
            val["name"] = self.name
        if self.address:
            val["address"] = self.address
        return val


class UefiGuid:
    """A UEFI GUID"""

    def __init__(self, value: str, name: str) -> None:
        self.value: str = value
        self.name: str = name
        self._bytes: bytes = b""

    @property
    def bytes(self) -> bytes:
        """Convert guid structure to array of bytes"""
        if not self._bytes:
            self._bytes = uuid.UUID(self.value).bytes_le
        return self._bytes

    @property
    def __dict__(self):
        return {"value": self.value, "name": self.name}

    def __str__(self):
        return "{} ({})".format(self.value, self.name)


class UefiProtocol(UefiGuid):
    """A UEFI protocol"""

    def __init__(
        self, name: str, address: int, value: str, guid_address: int, service: str
    ) -> None:
        super().__init__(name=name, value=value)
        self.address: int = address
        self.guid_address: int = guid_address
        self.service: str = service

    @property
    def __dict__(self):
        val = super().__dict__
        if self.address:
            val["address"] = self.address
        if self.guid_address:
            val["guid_address"] = self.guid_address
        if self.service:
            val["service"] = self.service
        return val


class UefiProtocolGuid(UefiGuid):
    """A UEFI protocol GUID"""

    def __init__(self, name: str, address: int, value: str) -> None:
        super().__init__(name=name, value=value)
        self.address: int = address

    @property
    def __dict__(self):
        val = super().__dict__
        if self.address:
            val["address"] = self.address
        return val


class NvramVariable:
    """A UEFI NVRAM variable"""

    def __init__(self, name: str, guid: str, service: UefiService) -> None:
        self.name: str = name
        self.guid: str = guid
        self.service: UefiService = service

    @property
    def __dict__(self):
        val = dict()
        if self.name:
            val["name"] = self.name
        if self.guid:
            val["guid"] = self.guid
        if self.service:
            val["service"] = {
                "name": self.service.name,
                "address": self.service.address,
            }
        return val


class SmiHandler:
    """SMI handler basic class"""

    def __init__(self, address: int, kind: SmiKind) -> None:
        self.address = address
        self.kind = kind
        self._place: Optional[str] = None

    def _get_place(self):
        return f"{self.kind.name.lower()}_handlers"

    @property
    def place(self):
        if self._place is None:
            self._place = self._get_place()
        return self._place

    @property
    def __dict__(self):
        val = dict()
        if self.address:
            val["address"] = self.address
        if self.kind:
            val["kind"] = self.kind.name
        return val


class ChildSwSmiHandler(SmiHandler):
    """Child software SMI handler"""

    def __init__(self, handler_guid: Optional[str], address: int) -> None:
        super().__init__(address=address, kind=SmiKind.CHILD_SW_SMI)
        self.handler_guid = handler_guid

    @property
    def __dict__(self):
        val = dict()
        if self.address:
            val["address"] = self.address
        if self.handler_guid:
            val["handler_guid"] = self.handler_guid
        if self.kind:
            val["kind"] = self.kind.name
        return val
