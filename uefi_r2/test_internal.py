#!/usr/bin/env python

import unittest

from uefi_r2.uefi_analyzer import r2_uefi_analyzer
from uefi_r2.uefi_protocols import get_guid_str, PROTOCOLS_GUIDS, GUID_TO_NAME


class TestInternal(unittest.TestCase):
    def test_convert(self):

        tmp = r2_uefi_analyzer()
        arr = tmp._dword_to_bytes(0xFFFFFFFF)
        self.assertEqual(len(arr), 4)
        self.assertEqual(arr[0], 255)
        self.assertEqual(arr[1], 255)
        self.assertEqual(arr[2], 255)
        self.assertEqual(arr[3], 255)

        arr = tmp._word_to_bytes(0xFFFF)
        self.assertEqual(len(arr), 2)
        self.assertEqual(arr[0], 255)
        self.assertEqual(arr[1], 255)

        self.assertEqual(
            get_guid_str(PROTOCOLS_GUIDS["gEfiSmmVariableProtocolGuid"]),
            "ED32D533-99E6-4209-9CC02D72CDD998A7",
        )
        self.assertEqual(
            GUID_TO_NAME["C2702B74-800C-4131-87468FB5B89CE4AC"],
            "EFI_SMM_ACCESS2_PROTOCOL_GUID",
        )


if __name__ == "__main__":
    unittest.main()
