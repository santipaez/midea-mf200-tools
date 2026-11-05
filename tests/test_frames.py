"""Golden-vector tests for the 22-byte control body.

The expected bytes come from the frame layout documented in
docs/protocol-map.md and exercised by tools/07_test_raw_program.py.
Every option not set by the caller must stay at 0xFF so the firmware
keeps its own default.
"""

import unittest

from mf200.frames import (
    BODY_SIZE,
    IGNORE,
    ControlOptions,
    build_control_body,
    resolve_program,
)


def body(**overrides):
    options = ControlOptions(**overrides)
    return build_control_body(options)


class BodyShapeTests(unittest.TestCase):
    def test_body_is_22_bytes(self):
        self.assertEqual(len(body(program="cotton")), BODY_SIZE)

    def test_control_type_is_set_command(self):
        self.assertEqual(body(program="cotton")[0], 0x02)

    def test_minimal_cotton_start_sets_program_and_start_only(self):
        expected = bytes([0x02, 0xFF, 0x01, 0xFF, 0x00] + [0xFF] * 17)
        self.assertEqual(body(program="cotton"), expected)

    def test_unset_options_stay_ignored(self):
        raw = body(program="quick_wash")
        for index in range(BODY_SIZE):
            if index not in (0, 2, 4):
                self.assertEqual(raw[index], IGNORE, f"byte {index}")


class ProgramTests(unittest.TestCase):
    def test_program_accepts_a_name(self):
        self.assertEqual(body(program="mixed_wash")[4], 0x03)

    def test_program_accepts_a_raw_id(self):
        self.assertEqual(body(program=0x6D)[4], 0x6D)

    def test_unknown_program_name_raises(self):
        with self.assertRaises(ValueError):
            resolve_program("not_a_program")

    def test_program_above_one_byte_raises(self):
        with self.assertRaises(ValueError):
            body(program=0x100)

    def test_negative_program_raises(self):
        with self.assertRaises(ValueError):
            body(program=-1)


class OptionEncodingTests(unittest.TestCase):
    def test_temperature_40_encodes_to_0x04(self):
        self.assertEqual(body(program="cotton", temperature=40)[7], 0x04)

    def test_temperature_0_encodes_to_0x01(self):
        self.assertEqual(body(program="cotton", temperature=0)[7], 0x01)

    def test_unknown_temperature_raises(self):
        with self.assertRaises(ValueError):
            body(program="cotton", temperature=50)

    def test_spin_800_encodes_to_0x03(self):
        self.assertEqual(body(program="cotton", spin_rpm=800)[8], 0x03)

    def test_spin_zero_encodes_to_0x00(self):
        self.assertEqual(body(program="cotton", spin_rpm=0)[8], 0x00)

    def test_unknown_spin_raises(self):
        with self.assertRaises(ValueError):
            body(program="cotton", spin_rpm=1234)

    def test_water_level_mid_encodes_to_0x02(self):
        self.assertEqual(body(program="cotton", water_level="mid")[5], 0x02)

    def test_unknown_water_level_raises(self):
        with self.assertRaises(ValueError):
            body(program="cotton", water_level="lukewarm")

    def test_wash_minutes_go_to_byte_9(self):
        self.assertEqual(body(program="cotton", wash_minutes=15)[9], 15)

    def test_spin_minutes_go_to_byte_10(self):
        self.assertEqual(body(program="cotton", spin_minutes=5)[10], 5)

    def test_dryer_level_goes_to_byte_6(self):
        self.assertEqual(body(program="cotton", dryer_level=2)[6], 0x02)

    def test_dryer_level_above_three_raises(self):
        with self.assertRaises(ValueError):
            body(program="cotton", dryer_level=4)

    def test_minutes_above_one_byte_raises(self):
        with self.assertRaises(ValueError):
            body(program="cotton", wash_minutes=256)


class FlagTests(unittest.TestCase):
    def test_steam_sets_bit_in_byte_16(self):
        self.assertEqual(body(program="cotton", steam=True)[16], 0x10)

    def test_air_fresh_sets_bit_in_byte_19(self):
        self.assertEqual(body(program="cotton", air_fresh=True)[19], 0x01)

    def test_spray_sets_bit_in_byte_13(self):
        self.assertEqual(body(program="cotton", spray=True)[13], 0x04)

    def test_flags_are_ignored_when_disabled(self):
        raw = body(program="cotton")
        for index in (13, 16, 19):
            self.assertEqual(raw[index], IGNORE, f"byte {index}")


class PowerTests(unittest.TestCase):
    def test_power_on_sets_byte_1(self):
        self.assertEqual(body(program="cotton", power=True)[1], 0x01)

    def test_power_off_sets_byte_1(self):
        self.assertEqual(body(program="cotton", power=False)[1], 0x00)

    def test_power_left_alone_by_default(self):
        self.assertEqual(body(program="cotton")[1], IGNORE)

    def test_start_false_writes_pause(self):
        self.assertEqual(body(program="cotton", start=False)[2], 0x00)


if __name__ == "__main__":
    unittest.main()
