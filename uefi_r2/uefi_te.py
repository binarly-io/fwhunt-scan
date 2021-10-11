import os
import struct
from typing import Optional


class TerseExecutableError(Exception):
    """Generic TE format error exception."""

    def __init__(self, value: str) -> None:
        self.value = value

    def __str__(self):
        return repr(self.value)


class TerseExecutableParser:
    """Terse Executable header parser"""

    def __init__(
        self, image_path: Optional[str] = None, blob: Optional[bytes] = None
    ) -> None:

        self._data: bytes = bytes()

        if blob is not None:
            self._data = blob

        elif image_path is not None:

            # check file path
            if not os.path.join(image_path):
                raise TerseExecutableError("Wrong file path")

            self._data = bytes()
            with open(image_path, "rb") as f:
                self._data = f.read()

        self._signature: bytes = self._data[:2]
        if self._signature != b"VZ":
            raise TerseExecutableError("Wrong signature")

        self._parse()

    def _parse(self) -> None:
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
    def signature(self) -> str:
        """Get Signature"""

        return self._signature.decode()

    @property
    def machine(self) -> int:
        """Get Machine"""

        return self._machine

    @property
    def number_of_sections(self) -> int:
        """Get NumberOfSections"""

        return self._number_of_sections

    @property
    def subsystem(self) -> int:
        """Get Subsystem"""

        return self._subsystem

    @property
    def stripped_size(self) -> int:
        """Get StrippedSize"""

        return self._stripped_size

    @property
    def address_of_entry_point(self) -> int:
        """Get AddressOfEntryPoint"""

        return self._address_of_entry_point

    @property
    def base_of_code(self) -> int:
        """Get BaseOfCode"""

        return self._base_of_code

    @property
    def image_base(self) -> int:
        """Get ImageBase"""

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
