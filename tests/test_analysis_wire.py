"""Compiled Zig packets must agree with independently specified Python bytes."""
import json
import os
import pathlib
import shlex
import struct
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]

class AnalysisWireTests(unittest.TestCase):
    def test_compiled_packets_and_actual_finite_storage(self):
        with tempfile.TemporaryDirectory() as directory:
            executable = pathlib.Path(directory) / "analysis-layout"
            subprocess.run(shlex.split(os.environ.get("ZIG", "zig")) + ["build-exe", "cells/analysis_layout.zig", "-O", "ReleaseSafe", "-femit-bin=" + str(executable)],
                           cwd=ROOT, capture_output=True, text=True, timeout=60, check=True)
            observed = json.loads(subprocess.run([str(executable)], capture_output=True, text=True, timeout=10, check=True).stdout)
        transaction = 0x123456789abcdef
        issuer, token = 0x123456789002, 0x4242a2
        expected = [
            struct.pack("<QQQB7x", transaction, 0x1122334455667788, 0, 1),
            struct.pack("<QQQB7x", transaction + 1, token, 0xabcdef05, 7),
            struct.pack("<QQQHB5x", transaction + 2, token, issuer, 127, 1),
            struct.pack("<QQQQ", transaction + 3, token, issuer, 0xabcdef06),
            struct.pack("<QQHBB8s3xB", transaction + 4, token, 127, 1, 0, bytes([255]) + bytes(7), 2),
            struct.pack("<QBBBB4xQQ", transaction + 5, 1, 11, 1, 2, (0xabcd05 << 32) | (0x4242 << 9) | 0x180, 128 | (127 << 16)),
        ]
        self.assertEqual(observed["message_size"], 48)
        self.assertEqual([bytes.fromhex(packet) for packet in observed["packets"]], expected)
        data = bytes([0, 255, 10, 128, 0, 10])
        digest = 0xcbf29ce484222325
        for byte in data:
            digest = ((digest ^ byte) * 0x100000001b3) & ((1 << 64) - 1)
        self.assertEqual(observed["tuple"], [6, 2, digest])
        self.assertGreaterEqual(observed["record_size"], 128)
        self.assertGreaterEqual(observed["table_size"], 2 * observed["record_size"] + 8 * 16)
        self.assertGreaterEqual(observed["server_size"], observed["table_size"] + 8 * 8)
        evidence = ROOT / "build/research/analysis-layout.json"
        evidence.parent.mkdir(parents=True, exist_ok=True)
        evidence.write_text(json.dumps(observed, indent=2) + "\n")
