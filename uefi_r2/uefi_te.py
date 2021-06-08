import os
import struct


class TerseExecutableError(Exception):
    """Generic TE format error exception."""

    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)


class TerseExecutableParser:
    """Terse Executable header parser"""

    def __init__(self, image_path: str):
        self._image_path = image_path

        # check file path
        if not os.path.join(self._image_path):
            raise TerseExecutableError("Wrong file path")

        self._data: bytes = bytes()
        with open(self._image_path, "rb") as f:
            self._data = f.read()

        self._signature: bytes = self._data[:2]
        if self._signature != b"VZ":
            raise TerseExecutableError("Wrong signature")

        self._machine: int = None
        self._number_of_sections: int = None
        self._subsystem: int = None
        self._stripped_size: int = None
        self._address_of_entry_point: int = None
        self._base_of_code: int = None
        self._image_base: int = None

    def _parse(self):
        format = "<2sHBBHIIQ"
        data = self._data[: struct.calcsize(format)]
        if len(data) != struct.calcsize(format):
            raise TerseExecutableError("Can't parse header, file is too small")
        (
            self._signature,
            self._machine,
            self._number_of_sections,
            self._subsystem,
            self._stripped_size,
            self._address_of_entry_point,
            self._base_of_code,
            self._image_base,
        ) = struct.unpack(format, data)

    @property
    def signature(self) -> int:
        """Get Signature"""
        return self._signature.decode()

    @property
    def machine(self) -> int:
        """Get Machine"""
        if self._machine is None:
            self._parse()
        return self._machine

    @property
    def number_of_sections(self) -> int:
        """Get NumberOfSections"""
        if self._number_of_sections is None:
            self._parse()
        return self._number_of_sections

    @property
    def subsystem(self) -> int:
        """Get Subsystem"""
        if self._subsystem is None:
            self._parse()
        return self._subsystem

    @property
    def stripped_size(self) -> int:
        """Get StrippedSize"""
        if self._stripped_size is None:
            self._parse()
        return self._stripped_size

    @property
    def address_of_entry_point(self) -> int:
        """Get AddressOfEntryPoint"""
        if self._address_of_entry_point is None:
            self._parse()
        return self._address_of_entry_point

    @property
    def base_of_code(self) -> int:
        """Get BaseOfCode"""
        if self._base_of_code is None:
            self._parse()
        return self._base_of_code

    @property
    def image_base(self) -> int:
        """Get ImageBase"""
        if self._image_base is None:
            self._parse()
        return self._image_base

    def __str__(self):
        return "\n".join(
            [
                f"Machine: {self.machine:#x}",
                f"NumberOfSections = {self.number_of_sections:#x}",
                f"Subsystem = {self.subsystem:#x}",
                f"StrippedSize = {self.stripped_size:#x}",
                f"AddressOfEntryPoint = {self.address_of_entry_point:#x}",
                f"BaseOfCode = {self.base_of_code:#x}",
                f"ImageBase = {self.image_base:#x}",
            ]
        )
