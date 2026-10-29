#!/usr/bin/env python3
"""Explicit root operator disposition of one restored run with historical VM reaping unknown.

Installing or invoking this requires separate owner approval. No VM/helper is
started, no preferences are written, and no historical stop proof is replaced.
"""

import argparse
from functools import partial
import json
import os
from pathlib import Path
import subprocess  # nosec B404 -- Only the fixed pinned Tart executable, under the admitted nonroot account.
import sys
import time

import qualify_softnet_macos_vm as controller
import softnet_run_state as state


def _observe(admission_directory, run, identity, *, preferences_factory=controller.Preferences):
    observed_at = time.time_ns()
    admission, account, _, digest = controller._admission_record(admission_directory)
    expected_identity = {
        'vmName': admission['vmName'], 'macAddress': admission['macAddress'],
        'admissionSha256': digest, 'tartBinarySha256': controller.canary.TART_BINARY_SHA256,
        'softnetBinarySha256': controller.SOFTNET_SHA256}
    if 'probeIPv4' in admission:
        expected_identity['probeIPv4'] = admission['probeIPv4']
    controller._require(identity == expected_identity, 'disposition_admission_mismatch')
    controller._binary(controller.TART, controller.canary.TART_BINARY_SHA256)
    controller._binary(controller.SOFTNET, controller.SOFTNET_SHA256)
    config_path = controller._protected(
        Path(admission['tartHome']) / 'vms' / admission['vmName'] / 'config.json', account.pw_uid)
    _, _, raw = controller.canary._hash_file(
        config_path, maximum=controller.canary.MAX_CONFIG_BYTES, collect=True)
    config = json.loads(raw)
    controller._require(isinstance(config, dict) and config.get('os') == 'darwin'
                        and config.get('arch') == 'arm64'
                        and config.get('macAddress') == identity['macAddress'], 'vm_identity_mismatch')
    env = {**controller.ENV, 'HOME': admission['tartHome'], 'TART_HOME': admission['tartHome'],
           'TART_NO_AUTO_PRUNE': '1'}
    owner_popen = partial(subprocess.Popen, user=account.pw_uid, group=account.pw_gid, extra_groups=[])
    raw, _ = controller.canary._run_bounded(
        [str(controller.TART), 'get', admission['vmName'], '--format', 'json'],
        timeout=10, env=env, popen=owner_popen)
    controller._require(controller.canary._vm_stopped(raw), 'vm_not_stopped')
    table, _ = controller.canary._run_bounded(
        ['/bin/ps', '-A', '-o', 'pid=', '-o', 'comm='], timeout=5, env=controller.ENV)
    controller._require(bool(table.strip()), 'invalid_process_table')
    for line in table.splitlines():
        fields = line.split(None, 1)
        controller._require(len(fields) == 2 and fields[0].isdigit() and int(fields[0]) > 0,
                            'invalid_process_table')
        controller._require(Path(os.fsdecode(fields[1])).name not in {'tart', 'softnet'},
                            'runtime_quiescence_unproven')
    fd = controller.recovery._directory(run)
    try:
        with preferences_factory() as preferences:
            original, _ = controller.recovery._snapshot(fd, preferences)
            controller._require(preferences.equal(preferences.read(), original), 'preference_drift')
    finally:
        os.close(fd)
    return {'observedAtUnixNs': observed_at, 'vmStopped': True,
            'processesQuiet': True, 'preferencesOriginal': True}


def dispose(admission_directory, run_id, approval_reference, *,
            preferences_factory=controller.Preferences):
    """Record the separately approved exception while holding the controller lock."""
    controller._require(os.geteuid() == 0 and sys.platform == 'darwin', 'root_macos_required')
    state.dispose_failed_restored(
        controller.STATE_ROOT, run_id, approval_reference,
        observe=partial(_observe, Path(admission_directory), preferences_factory=preferences_factory))
    return {'kind': 'softnet-failed-restored-disposition-v1', 'runId': run_id,
            'status': 'failed-restored-disposition-recorded', 'admissionGateReleased': True,
            'historicalVmReapingProven': False, 'qualified': False, 'vmDeleted': False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--admission-dir', type=Path, required=True)
    parser.add_argument('--run-id', required=True)
    parser.add_argument('--approval-reference', required=True)
    parser.add_argument('--accept-historical-vm-reaping-unknown', action='store_true', required=True)
    args = parser.parse_args(argv)
    try:
        print(json.dumps(dispose(args.admission_dir, args.run_id, args.approval_reference), sort_keys=True))
    except (OSError, ValueError, RuntimeError):
        print('softnet_disposition_failed; retain all run records', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
