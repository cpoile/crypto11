"""Protect PINs when native provisioning fails before output scanning starts."""
import runpy
import subprocess
import sys
import tempfile
import traceback
import unittest
from pathlib import Path
from unittest.mock import patch


class ProvisionFailureTests(unittest.TestCase):
    def test_failed_and_timed_out_commands_do_not_disclose_pins(self):
        script = Path(__file__).with_name("prepare.py")
        marker = "synthetic-pin-sentinel"
        for failure in (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            with self.subTest(failure=failure.__name__), tempfile.TemporaryDirectory() as root:
                def fail(args, **kwargs):
                    if failure is subprocess.TimeoutExpired:
                        raise failure(args, 15)
                    raise failure(1, args)

                with patch.object(sys, "argv", [str(script), root]), \
                        patch("secrets.token_hex", return_value=marker), \
                        patch("subprocess.run", side_effect=fail):
                    try:
                        runpy.run_path(str(script), run_name="__main__")
                    except SystemExit as error:
                        self.assertEqual(error.code, "SoftHSM token provisioning failed")
                        self.assertNotIn(marker, traceback.format_exc())
                    else:
                        self.fail("failed provisioning must exit unsuccessfully")


if __name__ == "__main__":
    unittest.main()
