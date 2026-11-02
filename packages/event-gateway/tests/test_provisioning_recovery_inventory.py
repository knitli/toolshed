"""Retained policy may authorize disposition, while provisioning still needs fresh policy."""
import copy
import hashlib
import os
from pathlib import Path
import plistlib
import tempfile
import time
import unittest
from unittest.mock import patch

from test_softnet_provisioning_downloads import bind_inventory, download_admission
import qualify_softnet_macos_vm as controller
import softnet_recovery as recovery


class RecoveryInventoryTests(unittest.TestCase):
    def test_real_admission_parser_forwards_recovery_opt_in_without_changing_default(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            home = root / 'home'
            home.mkdir(mode=0o700)
            admission = download_admission()
            admission.update(ownerUid=os.getuid(), tartHome=str(home), measurement={
                'configSha256': 'a' * 64, 'configBytes': 1,
                'diskSha256': 'b' * 64, 'diskBytes': 1,
                'nvramSha256': 'c' * 64, 'nvramBytes': 1})
            bind_inventory(admission, time.time_ns() - controller.PROVISIONING_INVENTORY_MAX_AGE_NS - 1000000000)
            raw = plistlib.dumps(admission, fmt=plistlib.FMT_BINARY)
            record_dir = root / 'record'
            record_dir.mkdir()
            with (patch.object(recovery, '_directory', side_effect=lambda path: os.open(path, os.O_RDONLY)),
                  patch.object(recovery, '_read', return_value=raw),
                  patch.object(controller, '_protected', side_effect=lambda path, *_args, **_kwargs: Path(path))):
                with self.assertRaisesRegex(recovery.RecoveryError, '^provisioning_inventory_stale$'):
                    controller._admission_record(record_dir)
                value, _account, _group, digest = controller._admission_record(
                    record_dir, allow_expired_inventory=True)
            self.assertEqual(value, admission)
            self.assertEqual(digest, hashlib.sha256(raw).hexdigest())

    def test_expired_inventory_is_recovery_only_and_future_or_invalid_times_still_fail(self):
        admission = download_admission()
        bind_inventory(admission, time.time_ns() - controller.PROVISIONING_INVENTORY_MAX_AGE_NS - 1000000000)
        with self.assertRaisesRegex(recovery.RecoveryError, '^provisioning_inventory_stale$'):
            controller._validate_provisioning_admission(admission)
        self.assertEqual(controller._validate_provisioning_admission(admission, allow_expired_inventory=True),
                         admission['provisioningDnsMap'])
        for observed in (time.time_ns() + 1000000000, 0, -1, True):
            with self.subTest(observed=observed):
                bind_inventory(admission, observed)
                with self.assertRaisesRegex(recovery.RecoveryError, '^provisioning_inventory_stale$'):
                    controller._validate_provisioning_admission(admission, allow_expired_inventory=True)

    def test_recovery_mode_preserves_static_policy_and_exact_boolean_guard(self):
        original = download_admission()
        bind_inventory(original, time.time_ns() - controller.PROVISIONING_INVENTORY_MAX_AGE_NS - 1000000000)
        mutations = (
            ('provisioningCaSha256', '0' * 64, 'unreviewed_provisioning_ca'),
            ('provisioningInventorySha256', '0' * 64, 'provisioning_inventory_digest_mismatch'),
            ('provisioningDeniedIPv4', ['140.82.112.3'], 'invalid_provisioning_destination_inventory'),
        )
        for key, value, code in mutations:
            with self.subTest(field=key):
                admission = copy.deepcopy(original)
                admission[key] = value
                with self.assertRaisesRegex(recovery.RecoveryError, '^' + code + '$'):
                    controller._validate_provisioning_admission(admission, allow_expired_inventory=True)
        denied = copy.deepcopy(original)
        denied['provisioningDeniedIPv4'].append(denied['provisioningDnsMap']['github.com'][0])
        bind_inventory(denied, time.time_ns() - controller.PROVISIONING_INVENTORY_MAX_AGE_NS - 1000000000)
        with self.assertRaisesRegex(recovery.RecoveryError, '^provisioning_destination_excluded$'):
            controller._validate_provisioning_admission(denied, allow_expired_inventory=True)
        for flag in (None, 0, 1, 'yes'):
            with self.subTest(flag=flag), self.assertRaisesRegex(
                    recovery.RecoveryError, '^invalid_inventory_expiry_mode$'):
                controller._validate_provisioning_admission(original, allow_expired_inventory=flag)


if __name__ == '__main__':
    unittest.main()
