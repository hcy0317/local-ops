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

    def test_config_defaults_match_phase_zero_baseline(self):
        self.assertEqual(server.Config.DEFAULT, self.baseline["config"]["default"])
        self.assertEqual(
            server.Config.APP_DEFAULT,
            self.baseline["config"]["appDefault"],
        )

    def test_state_keys_match_phase_zero_baseline(self):
        with mock.patch.object(server, "PLATFORM", FakePlatform()):
            state = server.build_state(dict(server.Config.DEFAULT), 9600, {})

        self.assertEqual(set(state), set(self.baseline["state"]["keys"]))
        self.assertFalse(state["degraded"])


if __name__ == "__main__":
    unittest.main()
