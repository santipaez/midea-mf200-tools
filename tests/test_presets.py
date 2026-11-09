"""Tests for the named wash presets."""

import unittest

from mf200.frames import IGNORE
from mf200.presets import PRESETS, build_preset_body, get_preset


class PresetCatalogTests(unittest.TestCase):
    def test_expected_presets_exist(self):
        for name in (
            "cotton",
            "quick",
            "mixed",
            "wool",
            "rinse_spin",
            "spin",
            "dry",
            "steam",
            "fresh_air",
        ):
            self.assertIn(name, PRESETS)

    def test_unknown_preset_raises(self):
        with self.assertRaises(KeyError):
            get_preset("hyperspeed")


class PresetBodyTests(unittest.TestCase):
    def test_quick_preset_uses_quick_wash(self):
        self.assertEqual(build_preset_body("quick")[4], 0x02)

    def test_cotton_preset_uses_cotton(self):
        self.assertEqual(build_preset_body("cotton")[4], 0x00)

    def test_steam_preset_enables_steam(self):
        self.assertEqual(build_preset_body("steam")[16], 0x10)

    def test_spin_preset_uses_single_dehydration(self):
        self.assertEqual(build_preset_body("spin")[4], 0x09)

    def test_fresh_air_preset_targets_the_blocked_program(self):
        raw = build_preset_body("fresh_air")
        self.assertEqual(raw[4], 0x3C)
        self.assertEqual(raw[19], 0x01)

    def test_presets_leave_unknown_options_alone(self):
        raw = build_preset_body("quick")
        for index in (1, 6, 7, 8, 13, 16, 19):
            self.assertEqual(raw[index], IGNORE, f"byte {index}")


if __name__ == "__main__":
    unittest.main()
