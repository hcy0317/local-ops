import json
from pathlib import Path
import unittest
from unittest import mock

import server
from localops.platform.fake import FakePlatform


ROOT = Path(__file__).resolve().parents[2]


class BaselineGoldenTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.baseline = json.loads(
            (ROOT / "docs/windows-port/BASELINE-CONTRACTS.json").read_text(
                encoding="utf-8"
            )
        )

    def test_config_defaults_preserve_phase_zero_fields_additively(self):
        baseline_default = self.baseline["config"]["default"]
        for key, value in baseline_default.items():
            if key != "schemaVersion":
                self.assertEqual(server.Config.DEFAULT[key], value)
        self.assertEqual(
            server.Config.DEFAULT["schemaVersion"], server.CURRENT_SCHEMA_VERSION
        )

        for key, value in self.baseline["config"]["appDefault"].items():
            self.assertEqual(server.Config.APP_DEFAULT[key], value)
        self.assertEqual(server.Config.APP_DEFAULT["commandSpec"], None)
        self.assertEqual(server.Config.APP_DEFAULT["runtimeIdentity"], None)
        self.assertEqual(server.Config.APP_DEFAULT["importStatus"],
                         "needs_review")
        self.assertIsNone(server.Config.APP_DEFAULT["dockerResource"])
        self.assertFalse(server.Config.APP_DEFAULT["elevated"])

    def test_state_keys_match_phase_zero_baseline(self):
        with mock.patch.object(server, "PLATFORM", FakePlatform()):
            state = server.build_state(dict(server.Config.DEFAULT), 9600, {})

        self.assertTrue(set(self.baseline["state"]["keys"]).issubset(state))
        self.assertIn("platformInfo", state)
        self.assertFalse(state["degraded"])


if __name__ == "__main__":
    unittest.main()
