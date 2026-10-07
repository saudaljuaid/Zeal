import importlib.util
import pathlib
import random
import struct
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "tools" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


image = load("image")
cell = load("check_cell")


def executable():
    data = bytearray(128)
    data[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<HHIQQQ", data, 16, 2, 62, 1, cell.BASE, 64, 0)
    struct.pack_into("<HHH", data, 52, 64, 56, 1)
    struct.pack_into("<IIQQQQQQ", data, 64, 1, 5, 120, cell.BASE, cell.BASE, 8, 8, 1)
    return data


class ImageTests(unittest.TestCase):
    def test_payload_round_trip_and_zero_padding(self):
        boot = b"\0" * 510 + b"\x55\xaa"
        for size in (1, 511, 512, 513, image.MAX_KERNEL):
            payload = random.Random(size).randbytes(size)
            disk = image.make_image(boot, payload)
            self.assertEqual(len(disk), image.DISK_SIZE)
            self.assertEqual(disk[:512], boot)
            self.assertEqual(disk[512:512 + size], payload)
            self.assertFalse(any(disk[512 + size:]))

    def test_malformed_sectors_and_payload_rejected(self):
        valid = b"\0" * 510 + b"\x55\xaa"
        for boot in (b"", valid[:511], valid + b"\0", valid[::-1]):
            with self.assertRaises(ValueError):
                image.make_image(boot, b"payload")
        for payload in (b"", b"\0" * (image.MAX_KERNEL + 1)):
            with self.assertRaises(ValueError):
                image.make_image(valid, payload)


class SealedCellTests(unittest.TestCase):
    def test_immutable_elf_is_accepted(self):
        cell.check_cell(executable())

    def test_corrupt_identity_and_truncated_headers_rejected(self):
        for offset, form, value in ((0, "B", 0), (4, "B", 1), (5, "B", 2),
                                    (7, "B", 1), (8, "B", 1), (15, "B", 1),
                                    (16, "H", 3), (18, "H", 3), (20, "I", 0),
                                    (48, "I", 1), (52, "H", 63), (24, "Q", cell.BASE + 1),
                                    (32, "Q", 120), (32, "Q", 0), (54, "H", 55), (56, "H", 0), (56, "H", 9)):
            data = executable()
            struct.pack_into("<" + form, data, offset, value)
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                cell.check_cell(data)
        for length in range(120):
            with self.assertRaises(ValueError):
                cell.check_cell(executable()[:length])

    def test_mutable_missing_and_out_of_bounds_segments_rejected(self):
        changes = ((64, "I", 0), (68, "I", 7), (68, "I", 4), (68, "I", 1),
                   (68, "I", 13), (72, "Q", 127), (72, "Q", 64), (88, "Q", cell.BASE + 1), (80, "Q", cell.BASE - 1),
                   (80, "Q", cell.BASE + cell.LIMIT), (96, "Q", 0),
                   (104, "Q", 9), (104, "Q", cell.LIMIT + 1), (112, "Q", 3),
                   (112, "Q", 4096))
        for offset, form, value in changes:
            data = executable()
            struct.pack_into("<" + form, data, offset, value)
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                cell.check_cell(data)

    def test_multiple_immutable_segments_and_overlap_boundaries(self):
        data = bytearray(192)
        data[:64] = executable()[:64]
        struct.pack_into("<H", data, 56, 2)
        for number in range(2):
            struct.pack_into("<IIQQQQQQ", data, 64 + number * 56,
                             1, 5 if number == 0 else 4, 176 + number * 8,
                             cell.BASE + number * 8, cell.BASE + number * 8, 8, 8, 1)
        cell.check_cell(data)
        for offset, value in ((136, 176), (144, cell.BASE), (152, cell.BASE)):
            corrupted = data.copy()
            struct.pack_into("<Q", corrupted, offset, value)
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                cell.check_cell(corrupted)
        memory_overlap = data.copy()
        struct.pack_into("<QQ", memory_overlap, 144, cell.BASE, cell.BASE)
        with self.assertRaises(ValueError):
            cell.check_cell(memory_overlap)
        stack = data.copy()
        struct.pack_into("<IIQQQQQQ", stack, 120, 0x6474E551, 7, 0, 0, 0, 0, 0, 0)
        with self.assertRaises(ValueError):
            cell.check_cell(stack)
        struct.pack_into("<I", stack, 124, 6)
        cell.check_cell(stack)


if __name__ == "__main__":
    unittest.main()
