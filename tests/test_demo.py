"""Tests for the demo backend (fake device, no network)."""

import unittest

from mf200.demo import DemoApp, FakeDevice


class FakeDeviceTests(unittest.TestCase):
    def test_starts_off_and_idle(self):
        device = FakeDevice()
        self.assertFalse(device.power)
        self.assertEqual(device.status, "idle")
        self.assertEqual(device.time_remaining, 0)

    def test_apply_turns_the_machine_on_and_runs_the_program(self):
        device = FakeDevice()
        device.apply(bytes([0x02, 0xFF, 0x01, 0xFF, 0x02] + [0xFF] * 17))
        self.assertTrue(device.power)
        self.assertEqual(device.status, "start")
        self.assertEqual(device.program, "quick_wash")
        self.assertGreater(device.time_remaining, 0)

    def test_stop_returns_to_idle(self):
        device = FakeDevice()
        device.apply(bytes([0x02, 0xFF, 0x01, 0xFF, 0x00] + [0xFF] * 17))
        device.stop()
        self.assertFalse(device.power)
        self.assertEqual(device.status, "idle")
        self.assertEqual(device.time_remaining, 0)


class DemoAppTests(unittest.TestCase):
    def setUp(self):
        self.app = DemoApp()

    def test_status_is_flagged_as_demo(self):
        self.assertTrue(self.app.status()["demo"])

    def test_presets_include_quick_and_its_frame(self):
        presets = {item["name"]: item for item in self.app.presets()}
        self.assertIn("quick", presets)
        self.assertEqual(presets["quick"]["program"], 0x02)
        self.assertEqual(presets["quick"]["body"][8:10], "02")

    def test_run_starts_the_fake_machine(self):
        result = self.app.run({"preset": "quick"})
        self.assertTrue(result["sent"])
        self.assertEqual(result["program"], 0x02)
        self.assertEqual(result["status"]["status"], "start")

    def test_run_accepts_overrides(self):
        result = self.app.run({"preset": "quick", "temperature": 40})
        self.assertEqual(result["body"][14:16], "04")

    def test_unknown_preset_raises(self):
        with self.assertRaises(KeyError):
            self.app.run({"preset": "warp_speed"})

    def test_stop_powers_the_fake_machine_off(self):
        self.app.run({"preset": "quick"})
        status = self.app.stop()
        self.assertFalse(status["power"])
        self.assertEqual(status["status"], "idle")


if __name__ == "__main__":
    unittest.main()
