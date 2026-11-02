"""Offline provisioning admission/lifecycle tests; no VM, preferences or network."""

from contextlib import ExitStack
import copy
import hashlib
import json
import os
from pathlib import Path
import plistlib
import socket
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from urllib.parse import urlsplit

SCRIPTS = Path(__file__).resolve().parents[1] / 'scripts'
sys.path.insert(0, str(SCRIPTS))
import qualify_softnet_macos_vm as supervisor  # noqa: E402
import native_workspace_provisioning_guest as guest  # noqa: E402
import softnet_recovery as recovery  # noqa: E402
from test_softnet_macos_vm import ExercisePatches, TargetPreferences  # noqa: E402


def download_admission():
    """Bind real manifest bytes to synthetic public destinations without resolving them."""
    manifest = (guest.ROOT / guest.MANIFEST_PATH).read_bytes()
    admission = {
        'kind': 'softnet-provisioning-download-admission-v1', 'ownerUid': 501,
        'tartHome': '/unused/private/tart', 'vmName': 'softnet-canary-' + 'a' * 32,
        'macAddress': '02:00:00:00:00:01', 'measurement': {},
        'provisioningManifest': manifest, 'provisioningBundleSha256': 'b' * 64,
        'provisioningCaSha256': supervisor.PROVISIONING_CA_SHA256,
        'provisioningDnsMap': {'ghcr.io': ['140.82.112.34'], 'github.com': ['140.82.112.3'],
                               'static.rust-lang.org': ['151.101.2.137'],
                               'release-assets.githubusercontent.com': ['185.199.108.133']},
        'provisioningDeniedIPv4': ['104.16.1.1'], 'provisioningInventorySha256': 'c' * 64,
    }
    bind_inventory(admission)
    return admission


def bind_inventory(admission, observed=None):
    """Bind a synthetic trusted operator snapshot without querying an account."""
    raw = json.dumps({'kind': 'native-provisioning-destination-inventory-v1',
                      'accountId': '5def525918a785eeda6decf66cf6b99b',
                      'observedAtUnixNs': time.time_ns() if observed is None else observed,
                      'deniedIPv4': admission['provisioningDeniedIPv4'],
                      'accountReadbackSha256': 'd' * 64, 'originReadbackSha256': 'e' * 64},
                     sort_keys=True).encode()
    admission['provisioningInventory'] = raw
    admission['provisioningInventorySha256'] = hashlib.sha256(raw).hexdigest()


def download_report(admission):
    """Synthesize the exact 120-asset receipt; never fetch its contents."""
    manifest = json.loads(admission['provisioningManifest'])
    records = []
    for asset in manifest['assets']:
        url = urlsplit(asset['url'])
        records.append({'name': asset['name'], 'initialUrl': asset['url'],
                        'finalHost': url.hostname, 'finalPath': url.path,
                        'selectedIPv4': admission['provisioningDnsMap'][url.hostname][0],
                        'status': 200, 'redirectCount': 0, 'outcome': 'downloaded',
                        'bytes': asset['maxBytes'], 'sha256': asset['sha256']})
    receipt = {'kind': guest.downloader.KIND, 'status': 'downloaded-only',
               'qualified': False, 'prepared': False, 'manifestSha256': guest.MANIFEST_SHA256,
               'caBundleSha256': admission['provisioningCaSha256'],
               'dnsMap': admission['provisioningDnsMap'],
               'assets': records, 'totalBytes': sum(item['bytes'] for item in records)}
    return {'kind': guest.RESULT_KIND, 'qualified': False, 'prepared': False,
            'guestRoot': '/private/tmp/knitli-native-provisioning-abcdefgh',
            'bundleSha256': admission['provisioningBundleSha256'], 'downloadReceipt': receipt}


class DownloadExercise(ExercisePatches):
    """Use the existing supervisor fakes for the one fixed stdin command."""

    def bounded(self, argv, **kwargs):
        if '/opt/homebrew/bin/python3' in argv:
            self.events.append(('command', tuple(argv), kwargs.copy()))
            self.received = os.read(kwargs['input_fd'], 1024)
            if self.probe_error:
                raise self.probe_error
            if kwargs['cancel_check']():
                raise supervisor.canary.CanaryError('tart_command_cancelled')
            return self.probe_stdout, b''
        return super().bounded(argv, **kwargs)


class ProvisioningControllerTests(unittest.TestCase):
    """Verify policy, descriptor ownership and existing recovery ordering."""

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.admission = download_admission()
        self.account = SimpleNamespace(pw_uid=os.getuid(), pw_gid=os.getgid(), pw_name='owner')

    def descriptor(self):
        path = self.root / 'input.json'
        path.write_bytes(b'fixed-stdin-payload')
        descriptor = os.open(path, os.O_RDONLY)
        self.addCleanup(lambda: self.close_if_open(descriptor))
        return descriptor

    @staticmethod
    def close_if_open(descriptor):
        try:
            os.close(descriptor)
        except OSError:
            pass

    def qualify_fakes(self, stack, descriptor):
        stack.enter_context(patch.object(supervisor.os, 'geteuid', return_value=0))
        stack.enter_context(patch.object(supervisor.sys, 'platform', 'darwin'))
        stack.enter_context(patch.object(supervisor, '_admission', return_value=(
            self.admission, self.account, 'staff', 'd' * 64)))
        factory = stack.enter_context(patch.object(supervisor, 'State'))
        state = factory.return_value.__enter__.return_value
        state.begin.return_value = (self.root / 'run', 'e' * 32)
        dns = stack.enter_context(patch.object(supervisor, '_resolve_provisioning_dns'))
        opened = stack.enter_context(patch.object(supervisor, '_open_provisioning_bundle', return_value=descriptor))
        return state, dns, opened

    def test_policy_rejects_private_cloudflare_and_known_account_destinations(self):
        self.assertEqual(supervisor._validate_provisioning_admission(self.admission),
                         self.admission['provisioningDnsMap'])
        for address, error in (('127.0.0.1', 'invalid_provisioning_admission'),
                               ('100.96.0.1', 'invalid_provisioning_admission'),
                               ('104.16.1.2', 'provisioning_destination_excluded'),
                               ('140.82.112.35', 'provisioning_destination_excluded')):
            value = copy.deepcopy(self.admission)
            value['provisioningDnsMap']['github.com'] = [address]
            if address == '140.82.112.35':
                value['provisioningDeniedIPv4'].append(address)
                bind_inventory(value)
            with self.subTest(address=address), self.assertRaisesRegex(recovery.RecoveryError, error):
                supervisor._validate_provisioning_admission(value)

    def test_policy_rejects_unreviewed_ca_and_missing_destination_inventory(self):
        for key, value, error in (('provisioningCaSha256', 'f' * 64, 'unreviewed_provisioning_ca'),
                                  ('provisioningDeniedIPv4', [], 'invalid_provisioning_destination_inventory'),
                                  ('provisioningInventorySha256', '', 'invalid_provisioning_destination_inventory')):
            admission = {**self.admission, key: value}
            with self.subTest(key=key), self.assertRaisesRegex(recovery.RecoveryError, error):
                supervisor._validate_provisioning_admission(admission)

    def test_inventory_is_digest_bound_fresh_and_agrees_with_denied_addresses(self):
        for mutation, expected in (
                ('bytes', 'provisioning_inventory_digest_mismatch'),
                ('denied', 'invalid_provisioning_destination_inventory'),
                ('stale', 'provisioning_inventory_stale'),
                ('future', 'provisioning_inventory_stale')):
            value = copy.deepcopy(self.admission)
            if mutation == 'bytes':
                value['provisioningInventory'] += b' '
            elif mutation == 'denied':
                value['provisioningDeniedIPv4'].append('140.82.112.35')
            else:
                observed = (time.time_ns() - supervisor.PROVISIONING_INVENTORY_MAX_AGE_NS - 1
                            if mutation == 'stale' else time.time_ns() + 10**12)
                bind_inventory(value, observed=observed)
            with self.subTest(mutation=mutation), self.assertRaisesRegex(recovery.RecoveryError, expected):
                supervisor._validate_provisioning_admission(value)

    def test_protected_admission_requires_exact_mode_schema(self):
        home = self.root / 'tart'
        (home / 'vms' / self.admission['vmName']).mkdir(parents=True)
        home.chmod(0o700)
        admission_root = self.root / 'admission'
        admission_root.mkdir()
        admission = {**self.admission, 'tartHome': str(home), 'measurement': {
            key + suffix: value for key in ('config', 'disk', 'nvram')
            for suffix, value in (('Sha256', 'a' * 64), ('Bytes', 1))}}
        with ExitStack() as stack:
            stack.enter_context(patch.object(recovery, '_directory', side_effect=lambda root: os.open(root, os.O_RDONLY)))
            read = stack.enter_context(patch.object(recovery, '_read'))
            stack.enter_context(patch.object(supervisor.pwd, 'getpwuid', return_value=self.account))
            stack.enter_context(patch.object(supervisor.grp, 'getgrgid', return_value=SimpleNamespace(gr_name='staff')))
            stack.enter_context(patch.object(supervisor, '_protected', side_effect=lambda path, *args, **kwargs: Path(path)))
            read.return_value = plistlib.dumps(admission)
            self.assertEqual(supervisor._admission_record(admission_root)[0], admission)
            for value in ({**admission, 'probeIPv4': '140.82.112.3'},
                          {**admission, 'kind': 'softnet-startup-admission-v1'},
                          {key: item for key, item in admission.items() if key != 'provisioningManifest'}):
                read.return_value = plistlib.dumps(value)
                with self.subTest(keys=sorted(value)), self.assertRaisesRegex(recovery.RecoveryError, 'invalid_admission'):
                    supervisor._admission_record(admission_root)

    def test_dns_requires_complete_exact_snapshot(self):
        mapping = self.admission['provisioningDnsMap']

        def resolve(host, *args):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', (value, 443))
                    for value in mapping[host]]

        supervisor._resolve_provisioning_dns(mapping, resolver=resolve)
        for answers in ([], [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('151.101.66.137', 443))],
                        [(socket.AF_INET6, socket.SOCK_STREAM, 6, '', ('::1', 443))]):
            with self.subTest(answers=answers), self.assertRaisesRegex(
                    recovery.RecoveryError, 'provisioning_dns_(invalid|drift)'):
                supervisor._resolve_provisioning_dns(mapping, resolver=lambda *args: answers)

    def test_qualify_rejects_dns_drift_before_opening_bundle_or_reserving_run(self):
        with ExitStack() as stack:
            state, dns, opened = self.qualify_fakes(stack, self.descriptor())
            dns.side_effect = recovery.RecoveryError('provisioning_dns_drift')
            exercise = stack.enter_context(patch.object(supervisor, '_exercise'))
            with self.assertRaisesRegex(recovery.RecoveryError, 'provisioning_dns_drift'):
                supervisor.qualify(self.root, provisioning_downloads=True)
            opened.assert_not_called()
            state.begin.assert_not_called()
            exercise.assert_not_called()

    def test_qualify_rejects_mixed_modes_before_admission(self):
        with ExitStack() as stack:
            state, _, opened = self.qualify_fakes(stack, self.descriptor())
            with self.assertRaisesRegex(recovery.RecoveryError, 'mutually_exclusive_probe_modes'):
                supervisor.qualify(self.root, provisioning_downloads=True, public_probe=True)
            opened.assert_not_called()
            state.begin.assert_not_called()

    def test_qualify_passes_verified_fd_and_closes_once_after_exercise(self):
        for failure in (None, supervisor.canary.CanaryError('tart_command_timeout')):
            descriptor = self.descriptor()
            with self.subTest(failure=failure), ExitStack() as stack:
                state, _, _ = self.qualify_fakes(stack, descriptor)

                def exercise(*args, **kwargs):
                    self.assertEqual(os.read(kwargs['provisioning_bundle_fd'], 1024), b'fixed-stdin-payload')
                    if failure:
                        raise failure
                    return {'vmStopped': True, 'vmReaped': True, 'helperReaped': True}

                stack.enter_context(patch.object(supervisor, '_exercise', side_effect=exercise))
                if failure:
                    with self.assertRaisesRegex(supervisor.canary.CanaryError, 'tart_command_timeout'):
                        supervisor.qualify(self.root, provisioning_downloads=True)
                    state.complete.assert_not_called()
                else:
                    report = supervisor.qualify(self.root, provisioning_downloads=True)
                    self.assertFalse(report['qualified'])
                    state.complete.assert_called_once()
                    identity = state.begin.call_args.args[0]
                    self.assertEqual(identity['provisioningManifest'], self.admission['provisioningManifest'])
                with self.assertRaises(OSError):
                    os.fstat(descriptor)

    def test_bundle_fd_is_rewound_and_tampering_closes_it(self):
        bundle = guest.build_bundle(guest.ROOT, b'CA fixture', self.admission['provisioningDnsMap'])
        admission = {**self.admission, 'provisioningBundleSha256': bundle['bundleSha256'],
                     'provisioningCaSha256': bundle['caBundleSha256']}
        path = self.root / 'provisioning-bundle.json'
        path.write_bytes(bundle['payload'])
        with patch.object(supervisor.recovery, '_directory', side_effect=lambda root: os.open(root, os.O_RDONLY)), \
                patch.object(supervisor.recovery, '_file', side_effect=lambda fd, name, flags: os.open(name, flags, dir_fd=fd)):
            descriptor = supervisor._open_provisioning_bundle(self.root, admission)
            try:
                self.assertEqual(os.read(descriptor, guest.MAX_BUNDLE_BYTES), bundle['payload'])
            finally:
                os.close(descriptor)
            path.write_bytes(bundle['payload'] + b' ')
            with self.assertRaisesRegex(ValueError, 'payload_digest_mismatch'):
                supervisor._open_provisioning_bundle(self.root, admission)

    def test_exercise_uses_only_fixed_stdin_download_and_restores_after_stop(self):
        self.admission['provisioningDnsMap']['github.com'].append('140.82.112.4')
        raw = json.dumps(download_report(self.admission)).encode()
        descriptor = self.descriptor()
        with DownloadExercise(probe_stdout=raw) as fakes:
            stop = supervisor._exercise(self.root, self.admission, self.account, 'staff',
                                        TargetPreferences, provisioning_bundle_fd=descriptor)
        self.assertTrue(all(stop.values()))
        self.assertEqual(fakes.received, b'fixed-stdin-payload')
        argv = next(event[1] for event in fakes.events if event[0] == 'popen')
        allowed = sorted({values[0] for values in self.admission['provisioningDnsMap'].values()},
                         key=lambda value: int(supervisor.ipaddress.IPv4Address(value)))
        self.assertIn('--allow=' + ','.join('out ' + value + '/32' for value in allowed), argv)
        self.assertIn('--block=0.0.0.0/0', argv)
        self.assertNotIn('out 140.82.112.4/32', ','.join(argv))
        commands = [event for event in fakes.events if event[0] == 'command' and '/opt/homebrew/bin/python3' in event[1]]
        self.assertEqual(len(commands), 1)
        self.assertEqual(commands[0][1], tuple(guest.command_template(supervisor.TART, self.admission['vmName'])))
        self.assertEqual(commands[0][2]['input_fd'], descriptor)
        self.assertEqual(commands[0][2]['output_limit'], guest.MAX_OUTPUT_BYTES)
        names = [event[0] for event in fakes.events]
        self.assertLess(max(index for index, name in enumerate(names) if name == 'stop_owned'), names.index('restore'))
        self.assertTrue(any(event[:2] == ('record', 'provisioning-download.json') for event in fakes.events))

    def test_failed_download_never_publishes_a_report_and_still_stops_before_restore(self):
        malformed = download_report(self.admission)
        malformed['downloadReceipt']['assets'][0]['sha256'] = '0' * 64
        cases = ((json.dumps(malformed).encode(), None, recovery.RecoveryError, 'invalid_provisioning_report'),
                 (b'', supervisor.canary.CanaryError('tart_command_timeout'),
                  supervisor.canary.CanaryError, 'tart_command_timeout'))
        for raw, error, error_type, message in cases:
            with self.subTest(error=error), DownloadExercise(probe_stdout=raw, probe_error=error) as fakes:
                with self.assertRaisesRegex(error_type, message):
                    supervisor._exercise(self.root, self.admission, self.account, 'staff',
                                         TargetPreferences, provisioning_bundle_fd=self.descriptor())
            self.assertFalse(any(event[:2] == ('record', 'provisioning-download.json') for event in fakes.events))
            names = [event[0] for event in fakes.events]
            self.assertLess(max(index for index, name in enumerate(names) if name == 'stop_owned'), names.index('restore'))


if __name__ == '__main__':
    unittest.main()
