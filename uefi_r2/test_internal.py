#!/usr/bin/env python

import unittest

from .uefi_protocols import PROTOCOLS_GUIDS, GUID_FROM_VALUE


class TestInternal(unittest.TestCase):
    def test_convert(self):

        self.assertEqual(
            PROTOCOLS_GUIDS[144].value,
            "5C6FA2C9-9768-45F6-8E645AECCADAB481",
        )
        self.assertEqual(
            PROTOCOLS_GUIDS[144].bytes,
            b"\xc9\xa2o\\h\x97\xf6E\x8edZ\xec\xca\xda\xb4\x81",
        )
        self.assertEqual(
            GUID_FROM_VALUE["C2702B74-800C-4131-87468FB5B89CE4AC"].name,
            "EFI_SMM_ACCESS2_PROTOCOL_GUID",
        )


if __name__ == "__main__":
    unittest.main()
