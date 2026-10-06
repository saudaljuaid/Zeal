import json
import os
import pathlib
import re
import shlex
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
EXPECTED = {
    "version": 2, "message_size": 48, "message_align": 8, "message_payload": 16,
    "boot_size": 24, "boot_generation": 8, "request_size": 24, "request_rights": 16,
    "info_size": 32, "info_parent": 24, "find": 7, "delegate": 8, "query": 9,
    "revoke": 10, "no_space": -7, "file_read_right": 4, "cap_ack_right": 32,
    "delegate_right": 0x80000000,
    "sleep": 11, "recv_wait": 12, "timeout": -8, "wait_max_ticks": 1000,
}
C_SOURCE = r'''#include <stddef.h>
#include <stdio.h>
#include <zeal/abi.h>
int main(void) {
  printf("{\"version\":%u,\"message_size\":%zu,\"message_align\":%zu,\"message_payload\":%zu,"
         "\"boot_size\":%zu,\"boot_generation\":%zu,\"request_size\":%zu,\"request_rights\":%zu,"
         "\"info_size\":%zu,\"info_parent\":%zu,\"find\":%d,\"delegate\":%d,\"query\":%d,\"revoke\":%d,"
         "\"no_space\":%d,\"file_read_right\":%u,\"cap_ack_right\":%u,\"delegate_right\":%u,"
         "\"sleep\":%d,\"recv_wait\":%d,\"timeout\":%d,\"wait_max_ticks\":%llu}\n",
         Z_ABI_VERSION, sizeof(struct z_message), _Alignof(struct z_message), offsetof(struct z_message, payload),
         sizeof(struct z_boot_info), offsetof(struct z_boot_info, generation), sizeof(struct z_cap_request),
         offsetof(struct z_cap_request, rights), sizeof(struct z_cap_info), offsetof(struct z_cap_info, parent),
         Z_CAP_FIND, Z_CAP_DELEGATE, Z_CAP_QUERY, Z_CAP_REVOKE, Z_NO_SPACE,
         Z_RIGHT(Z_FILE_READ), Z_RIGHT(Z_CAP_ACK), Z_RIGHT_DELEGATE,
         Z_SLEEP, Z_RECV_WAIT, Z_TIMEOUT, (unsigned long long)Z_WAIT_MAX_TICKS);
}
'''


class LanguageLayoutTests(unittest.TestCase):
    def test_rust_wait_abi_constants_match(self):
        source = (ROOT / "policy/lib.rs").read_text()
        for rust_name, key in (("Z_ABI_VERSION", "version"), ("Z_SLEEP", "sleep"),
                               ("Z_RECV_WAIT", "recv_wait"), ("Z_TIMEOUT", "timeout"),
                               ("Z_WAIT_MAX_TICKS", "wait_max_ticks")):
            match = re.search(rf"pub const {rust_name}: \w+ = (-?\d+);", source)
            self.assertIsNotNone(match, rust_name)
            self.assertEqual(int(match.group(1)), EXPECTED[key], rust_name)

    def run_json(self, command):
        result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=20, check=True)
        return json.loads(result.stdout)

    def test_zig_and_c_layouts_match(self):
        zig = shlex.split(os.environ.get("ZIG", "zig"))
        actual_zig = self.run_json(zig + ["run", "cells/layout.zig"])
        self.assertEqual(actual_zig, EXPECTED)
        with tempfile.TemporaryDirectory() as directory:
            source = pathlib.Path(directory) / "abi.c"
            binary = pathlib.Path(directory) / "abi"
            source.write_text(C_SOURCE)
            cc = shlex.split(os.environ.get("CC", "cc"))
            subprocess.run(cc + ["-std=c11", "-Wall", "-Wextra", "-Werror", "-Iinclude",
                                 str(source), "-o", str(binary)], cwd=ROOT, timeout=20, check=True)
            self.assertEqual(self.run_json([str(binary)]), EXPECTED)


if __name__ == "__main__":
    unittest.main()
