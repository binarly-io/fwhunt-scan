from typing import Optional
import uuid


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

    def __init__(self, address: int) -> None:
        self.address = address

    @property
    def __dict__(self):
        val = dict()
        if self.address:
            val["address"] = self.address
        return val


class SwSmiHandler(SmiHandler):
    """Software SMI handler"""

    def __init__(self, sw_smi_input_value: Optional[int], address: int) -> None:
        super().__init__(address=address)
        self.sw_smi_input_value = sw_smi_input_value

    @property
    def __dict__(self):
        val = dict()
        if self.address:
            val["address"] = self.address
        if self.sw_smi_input_value:
            val["sw_smi_input_value"] = self.sw_smi_input_value
        return val


class ChildSwSmiHandler(SmiHandler):
    """Child software SMI handler"""

    def __init__(self, handler_guid: Optional[str], address: int) -> None:
        super().__init__(address=address)
        self.handler_guid = handler_guid

    @property
    def __dict__(self):
        val = dict()
        if self.address:
            val["address"] = self.address
        if self.handler_guid:
            val["handler_guid"] = self.handler_guid
        return val
