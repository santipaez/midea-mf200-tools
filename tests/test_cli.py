"""Tests for the command line surface (no device required)."""

import io
import json
import unittest
from contextlib import redirect_stdout

from mf200 import cli


def run_cli(*args):
    output = io.StringIO()
    with redirect_stdout(output):
        code = cli.main(list(args))
    return code, output.getvalue()


class PresetCommandTests(unittest.TestCase):
    def test_presets_lists_the_quick_preset(self):
        code, output = run_cli("presets")
        self.assertEqual(code, 0)
        self.assertIn("quick", output)


class FrameCommandTests(unittest.TestCase):
    def test_frame_quick_json_emits_the_expected_body(self):
        code, output = run_cli("frame", "quick", "--json")
        self.assertEqual(code, 0)
        data = json.loads(output)
        self.assertEqual(data["program"], 0x02)
        self.assertEqual(data["body"], "02ff01ff02" + "ff" * 17)

    def test_frame_honours_option_overrides(self):
        code, output = run_cli("frame", "quick", "--temperature", "40", "--json")
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(output)["bytes"][7], 0x04)

    def test_unknown_preset_is_an_error(self):
        code, _ = run_cli("frame", "does-not-exist", "--json")
        self.assertNotEqual(code, 0)


class RunCommandTests(unittest.TestCase):
    def test_dry_run_never_reports_sent(self):
        code, output = run_cli("run", "quick", "--dry-run", "--json")
        self.assertEqual(code, 0)
        data = json.loads(output)
        self.assertFalse(data["sent"])


if __name__ == "__main__":
    unittest.main()
