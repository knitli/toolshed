#!/usr/bin/env python3
"""Fixed, opt-in Softnet/Tart startup canary; installing/running it needs host approval.

A root supervisor owns recovery and Softnet; every Tart command runs as the
admitted nonroot user. This never installs tools, compiles, promotes, or deletes VMs.
"""

import argparse
import base64
import ipaddress
from functools import partial
import hashlib
import json
import os
from pathlib import Path
import plistlib
import pwd
import grp
import re
import signal
import socket
import stat
import subprocess  # nosec B404 -- Fixed pinned executables; Tart drops to the admitted nonroot account.
import sys
import threading
import time

import qualify_offline_macos_vm as canary
import softnet_recovery as recovery
import native_workspace_provisioning_guest as provisioning
from softnet_preferences import Preferences
from softnet_run_state import (
    COMMAND_ERROR_CODE,
    COMMAND_ERROR_TYPE,
    COMMAND_FAILURE_KIND,
    COMMAND_FAILURE_PHASES,
    State,
)

TART = Path('/usr/local/libexec/knitli-event-qualification/tart-2.41.1/tart.app/Contents/MacOS/tart')
SOFTNET = Path('/usr/local/libexec/knitli-event-qualification/softnet-0.22.1/softnet')
STATE_ROOT = Path('/private/var/db/knitli-event-qualification/softnet-runs')
SOFTNET_SHA256 = '1584af036b6d6d11319b2a3766d1be212534c525e3805bc566180aec7a1b2a0e'
ENV = {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'LC_ALL': 'C', 'LANG': 'C'}
PROVISIONING_FIELDS = {'provisioningBundleSha256', 'provisioningCaSha256',
                       'provisioningDnsMap', 'provisioningManifest'}
PROVISIONING_POLICY_FIELDS = {'provisioningDeniedIPv4', 'provisioningInventorySha256',
                              'provisioningInventory'}
PROVISIONING_INVENTORY_MAX_AGE_NS = 20 * 60 * 1_000_000_000
PROVISIONING_CA_SHA256 = '9dae8d76e55cb08991f2b672d58999ea15560d910759c16b544f843bdffbb994'
PROVISIONING_TIMEOUT = 1830
GUEST_SHUTDOWN_TIMEOUT = 120
GUEST_SHUTDOWN_KIND = 'softnet-guest-shutdown-v1'
# Published Cloudflare front-door ranges, verified 2026-11-02: https://www.cloudflare.com/ips-v4
# This supplements the fresh account-owned destination inventory in the protected admission.
PROVISIONING_EXCLUDED_NETWORKS = tuple(ipaddress.IPv4Network(value) for value in (
    '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22',
    '141.101.64.0/18', '108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20',
    '197.234.240.0/22', '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
    '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22'))
MEASUREMENT = {'configSha256', 'configBytes', 'diskSha256', 'diskBytes',
               'nvramSha256', 'nvramBytes'}
PUBLIC_PROBE_HOST = 'event-native-probe-83fc4c309835.knitli.workers.dev'
PUBLIC_PROBE_PATH = '/probe'
PUBLIC_PROBE_BODY_SHA256 = '773cdcdb36ecbdb7c720d4d135911f7d35252d862b10094f788d96a965b80600'
PUBLIC_PROBE_SOURCE = Path(__file__).with_name('softnet_public_probe_guest.py')
PUBLIC_PROBE_SOURCE_SHA256 = 'cbb45784a219065fc435f340757ea9c4d7e09d61babcd626a77070f3aed7d1f7'
PUBLIC_PROBE_OUTPUT_LIMIT = 4096
PUBLIC_PROBE_TIMEOUT = 25
PUBLIC_PROBE_DURATION_LIMIT_NS = 15_000_000_000
PUBLIC_PROBE_TIMEOUT_LIMIT_NS = PUBLIC_PROBE_TIMEOUT * 1_000_000_000
MAX_PUBLIC_PROBE_DNS_ANSWERS = 32
GUEST_ROUTE_IDENTITY_HOST = 'event-native-probe-83fc4c309835.knitli.workers.dev'
GUEST_ROUTE_IDENTITY_PATH = '/probe'
GUEST_ROUTE_POSITIVE_HOST = 'knitli.app'
GUEST_ROUTE_POSITIVE_PATH = '/site.webmanifest'
GUEST_ROUTE_POSITIVE_CONTENT_TYPE = 'application/manifest+json'
GUEST_ROUTE_POSITIVE_BODY_BYTES = 456
GUEST_ROUTE_POSITIVE_BODY_SHA256 = '096b1a4b927c04b0417ab1f49372e110c96d4db153cf3d6048f9d25c8b11d493'
GUEST_ROUTE_SOURCE = PUBLIC_PROBE_SOURCE
GUEST_ROUTE_SOURCE_SHA256 = 'cbb45784a219065fc435f340757ea9c4d7e09d61babcd626a77070f3aed7d1f7'
GUEST_ROUTE_OUTPUT_LIMIT = 4096
GUEST_ROUTE_TIMEOUT = 25
GUEST_ROUTE_DURATION_LIMIT_NS = 12_000_000_000
# Timeout/oversize failure receipts include bounded guest cleanup/unwind after the 12s deadline.
# This is the fixed 25s supervised command backstop; successful and ordinary reports stay at 12s.
GUEST_ROUTE_TIMEOUT_LIMIT_NS = GUEST_ROUTE_TIMEOUT * 1_000_000_000
GUEST_ROUTE_LOADER = (
    "import base64,sys; source=base64.b64decode(sys.argv[1],validate=True); "
    "sys.argv=[sys.argv[0]]+['--guest-route-contract']+sys.argv[2:]; "
    "exec(compile(source,'<fixed-guest-route-contract>','exec'))"
)
PUBLIC_PROBE_LOADER = (
    "import base64,sys; source=base64.b64decode(sys.argv[1],validate=True); "
    "sys.argv=[sys.argv[0]]+sys.argv[2:]; "
    "exec(compile(source,'<fixed-public-probe>','exec'))"
)


def _require(condition, code):
    if not condition:
        raise recovery.RecoveryError(code)


def _protected(path, uid, *, directory=False):
    """Validate fixed inputs without accepting symlinked/writable ancestry."""
    path = Path(path)
    _require(path.is_absolute() and '..' not in path.parts, 'unsafe_input_path')
    current = Path('/')
    for index, part in enumerate(path.parts[1:]):
        current /= part
        info = current.lstat()
        leaf = index == len(path.parts) - 2
        sticky = info.st_uid == 0 and bool(info.st_mode & stat.S_ISVTX)
        _require(not stat.S_ISLNK(info.st_mode) and info.st_uid in (0, uid)
                 and (not info.st_mode & 0o022 or (sticky and not leaf)), 'unsafe_input_path')
        _require(stat.S_ISDIR(info.st_mode) if not leaf or directory else stat.S_ISREG(info.st_mode),
                 'unsafe_input_path')
        canary._check_tart_acl(current)
    _require(len(path.parts) > 1, 'unsafe_input_path')
    return path


def _binary(path, digest):
    _protected(path, 0)
    info = path.stat()
    _require(info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o555, 'unsafe_binary')
    measured, _ = canary._hash_file(path, maximum=128 * 1024**2, require_executable=True)
    _require(measured == digest, 'binary_digest_mismatch')


def _admission_record(root, *, allow_expired_inventory=False):
    """Validate the protected operator record and storage identity, before measurement."""
    _require(type(allow_expired_inventory) is bool, 'invalid_inventory_expiry_mode')
    fd = recovery._directory(root)
    try:
        raw = recovery._read(fd, 'admission.plist')
    finally:
        os.close(fd)
    value = plistlib.loads(raw)
    base_keys = {'kind', 'ownerUid', 'tartHome', 'vmName', 'macAddress', 'measurement'}
    probe_admission = isinstance(value, dict) and set(value) == base_keys | {'probeIPv4'}
    route_fields = {'identityProbeIPv4', 'positiveOriginIPv4', 'publicTrustRootsSha256'}
    route_admission = isinstance(value, dict) and set(value) == base_keys | route_fields
    download_admission = (isinstance(value, dict)
                          and set(value) == base_keys | PROVISIONING_FIELDS | PROVISIONING_POLICY_FIELDS)
    _require(isinstance(value, dict) and (set(value) == base_keys or probe_admission
                                        or route_admission or download_admission),
             'invalid_admission')
    expected_kind = ('softnet-provisioning-download-admission-v1' if download_admission else
                     'softnet-guest-route-admission-v1' if route_admission else
                     'softnet-public-probe-admission-v1' if probe_admission else
                     'softnet-startup-admission-v1')
    _require(value['kind'] == expected_kind
             and type(value['ownerUid']) is int and value['ownerUid'] > 0,
             'invalid_admission')
    if download_admission:
        _validate_provisioning_admission(value, allow_expired_inventory=allow_expired_inventory)
    if probe_admission or route_admission:
        ip_keys = ('probeIPv4',) if probe_admission else ('identityProbeIPv4', 'positiveOriginIPv4')
        for key in ip_keys:
            _require(isinstance(value[key], str), 'invalid_admission')
            try:
                probe_ip = ipaddress.ip_address(value[key])
            except (TypeError, ValueError):
                raise recovery.RecoveryError('invalid_admission') from None
            _require(isinstance(probe_ip, ipaddress.IPv4Address) and probe_ip.is_global,
                     'invalid_admission')
        if route_admission:
            _require(isinstance(value['publicTrustRootsSha256'], str)
                     and re.fullmatch(r'[0-9a-f]{64}', value['publicTrustRootsSha256']),
                     'invalid_admission')
    _require(isinstance(value['vmName'], str)
             and re.fullmatch(r'softnet-canary-[0-9a-f]{32}', value['vmName'])
             and isinstance(value['macAddress'], str)
             and re.fullmatch(r'(?:[0-9a-f]{2}:){5}[0-9a-f]{2}', value['macAddress'])
             and not int(value['macAddress'][:2], 16) & 1, 'invalid_admission')
    measurement = value['measurement']
    _require(isinstance(measurement, dict) and set(measurement) == MEASUREMENT,
             'invalid_admission')
    for name, item in measurement.items():
        _require((type(item) is int and 0 < item <= canary.MAX_DISK_BYTES) if name.endswith('Bytes')
                 else (isinstance(item, str) and re.fullmatch('[0-9a-f]{64}', item)), 'invalid_admission')
    _require(isinstance(value['tartHome'], str), 'invalid_admission')
    try:
        account = pwd.getpwuid(value['ownerUid'])
        group = grp.getgrgid(account.pw_gid)
    except KeyError as error:
        raise recovery.RecoveryError('unknown_owner_account') from error
    _require(account.pw_gid > 0, 'nonroot_group_required')
    home = _protected(value['tartHome'], account.pw_uid, directory=True)
    _require(home.stat().st_uid == account.pw_uid and stat.S_IMODE(home.stat().st_mode) == 0o700,
             'unsafe_tart_home')
    _require(root != home and root not in home.parents and home not in root.parents,
             'state_inside_vm_storage')
    vm = _protected(home / 'vms' / value['vmName'], account.pw_uid, directory=True)
    _require(not (vm / 'state').exists() and not (vm / 'state').is_symlink(), 'saved_vm_state')
    return value, account, group.gr_name, hashlib.sha256(raw).hexdigest()


def _provisioning_binding(admission):
    return {'manifest_bytes': admission['provisioningManifest'],
            'dns_map': admission['provisioningDnsMap'],
            'ca_sha256': admission['provisioningCaSha256'],
            'bundle_sha256': admission['provisioningBundleSha256']}


def _validate_provisioning_admission(admission, *, allow_expired_inventory=False):
    """Bind the fixed public acquisition client to the reviewed destination policy."""
    _require(type(allow_expired_inventory) is bool, 'invalid_inventory_expiry_mode')
    try:
        _, mapping = provisioning.validate_binding(**_provisioning_binding(admission))
    except (TypeError, ValueError, KeyError):
        raise recovery.RecoveryError('invalid_provisioning_admission') from None
    _require(admission['provisioningCaSha256'] == PROVISIONING_CA_SHA256,
             'unreviewed_provisioning_ca')
    denied = admission.get('provisioningDeniedIPv4')
    _require(type(denied) is list and 0 < len(denied) <= 256,
             'invalid_provisioning_destination_inventory')
    try:
        _require(all(type(value) is str and str(ipaddress.IPv4Address(value)) == value
                     for value in denied) and len(set(denied)) == len(denied),
                 'invalid_provisioning_destination_inventory')
    except (TypeError, ValueError):
        raise recovery.RecoveryError('invalid_provisioning_destination_inventory') from None
    inventory = admission.get('provisioningInventorySha256')
    _require(type(inventory) is str and re.fullmatch('[0-9a-f]{64}', inventory),
             'invalid_provisioning_destination_inventory')
    inventory_raw = admission.get('provisioningInventory')
    _require(type(inventory_raw) is bytes and 0 < len(inventory_raw) <= 64 * 1024
             and hashlib.sha256(inventory_raw).hexdigest() == inventory,
             'provisioning_inventory_digest_mismatch')
    try:
        snapshot = provisioning.downloader._json_no_duplicates(inventory_raw)
    except (ValueError, UnicodeError, RecursionError):
        raise recovery.RecoveryError('invalid_provisioning_destination_inventory') from None
    _require(type(snapshot) is dict and set(snapshot) == {
        'kind', 'accountId', 'observedAtUnixNs', 'deniedIPv4',
        'accountReadbackSha256', 'originReadbackSha256'}
        and snapshot['kind'] == 'native-provisioning-destination-inventory-v1'
        and snapshot['accountId'] == '5def525918a785eeda6decf66cf6b99b'
        and snapshot['deniedIPv4'] == denied
        and all(type(snapshot[key]) is str and re.fullmatch('[0-9a-f]{64}', snapshot[key])
                for key in ('accountReadbackSha256', 'originReadbackSha256')),
        'invalid_provisioning_destination_inventory')
    observed = snapshot['observedAtUnixNs']
    age = time.time_ns() - observed if type(observed) is int else -1
    # Disposition validates retained policy but performs no provisioning or network requests.
    _require(type(observed) is int and observed > 0 and age >= 0
             and (allow_expired_inventory or age <= PROVISIONING_INVENTORY_MAX_AGE_NS),
             'provisioning_inventory_stale')
    for addresses in mapping.values():
        for address in addresses:
            ip = ipaddress.IPv4Address(address)
            _require(address not in denied and not any(ip in net for net in PROVISIONING_EXCLUDED_NETWORKS),
                     'provisioning_destination_excluded')
    return mapping


def snapshot_provisioning_admission(admission, bundle, resolver=None):
    """Freeze one fresh, policy-checked IPv4 DNS snapshot into the admission and bundle."""
    resolver = socket.getaddrinfo if resolver is None else resolver
    mapping = _validate_provisioning_admission(admission)
    document = provisioning.validate_payload(bundle, **_provisioning_binding(admission))
    denied = set(admission['provisioningDeniedIPv4'])
    snapshot = {}
    for host in sorted(mapping):
        try:
            answers = resolver(host, 443, socket.AF_UNSPEC, socket.SOCK_STREAM)
        except OSError:
            raise recovery.RecoveryError('provisioning_dns_failed') from None
        _require(isinstance(answers, (list, tuple)) and 0 < len(answers) <= 32,
                 'provisioning_dns_invalid')
        addresses = set()
        for answer in answers:
            _require(isinstance(answer, tuple) and len(answer) == 5
                     and answer[0] in (socket.AF_INET, socket.AF_INET6)
                     and answer[1] == socket.SOCK_STREAM
                     and isinstance(answer[4], tuple) and len(answer[4]) >= 2
                     and type(answer[4][0]) is str, 'provisioning_dns_invalid')
            try:
                address = ipaddress.ip_address(answer[4][0])
            except ValueError:
                raise recovery.RecoveryError('provisioning_dns_invalid') from None
            if answer[0] == socket.AF_INET:
                _require(isinstance(address, ipaddress.IPv4Address), 'provisioning_dns_invalid')
                _require(address.is_global and str(address) not in denied
                         and not any(address in net for net in PROVISIONING_EXCLUDED_NETWORKS),
                         'provisioning_destination_excluded')
                addresses.add(address)
            else:
                _require(isinstance(address, ipaddress.IPv6Address), 'provisioning_dns_invalid')
        _require(0 < len(addresses) <= 8, 'provisioning_dns_invalid')
        snapshot[host] = [str(address) for address in sorted(addresses, key=int)]

    try:
        document = {**document, 'dnsMap': snapshot}
        frozen_bundle = provisioning._canonical(document)
        frozen_admission = {**admission, 'provisioningDnsMap': snapshot,
                            'provisioningBundleSha256': hashlib.sha256(frozen_bundle).hexdigest()}
        _validate_provisioning_admission(frozen_admission)
        provisioning.validate_payload(frozen_bundle, **_provisioning_binding(frozen_admission))
    except (TypeError, ValueError, KeyError, UnicodeError, RecursionError):
        raise recovery.RecoveryError('invalid_provisioning_bundle') from None
    return frozen_admission, frozen_bundle


def _open_provisioning_bundle(root, admission):
    """Retain one verified root-owned read-only descriptor through child cleanup."""
    directory_fd = recovery._directory(root)
    try:
        descriptor = recovery._file(directory_fd, 'provisioning-bundle.json', os.O_RDONLY)
    finally:
        os.close(directory_fd)
    try:
        _require(os.fstat(descriptor).st_size <= provisioning.MAX_BUNDLE_BYTES,
                 'provisioning_bundle_oversized')
        with os.fdopen(os.dup(descriptor), 'rb') as stream:
            payload = stream.read(provisioning.MAX_BUNDLE_BYTES + 1)
        provisioning.validate_payload(payload, **_provisioning_binding(admission))
        os.lseek(descriptor, 0, os.SEEK_SET)
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _admission(root):
    value, account, group, admission_digest = _admission_record(root)
    vm = Path(value['tartHome']) / 'vms' / value['vmName']
    measurement = value['measurement']
    config_raw = None
    for filename, prefix, maximum in (('config.json', 'config', canary.MAX_CONFIG_BYTES),
                                      ('disk.img', 'disk', canary.MAX_DISK_BYTES),
                                      ('nvram.bin', 'nvram', canary.MAX_CONFIG_BYTES * 1024)):
        path = _protected(vm / filename, account.pw_uid)
        measured = canary._hash_file(path, maximum=maximum, collect=prefix == 'config')
        digest, size = measured[:2]
        if prefix == 'config':
            config_raw = measured[2]
        _require((digest, size) == (measurement[prefix + 'Sha256'], measurement[prefix + 'Bytes']),
                 'vm_measurement_mismatch')
    config = json.loads(config_raw)
    _require(isinstance(config, dict) and config.get('os') == 'darwin' and config.get('arch') == 'arm64'
             and config.get('macAddress') == value['macAddress'], 'vm_identity_mismatch')
    _binary(TART, canary.TART_BINARY_SHA256)
    _binary(SOFTNET, SOFTNET_SHA256)
    return value, account, group, admission_digest


def _resolve_public_probe_ip(resolver=None, host=PUBLIC_PROBE_HOST):
    """Select one deterministic globally routable IPv4 answer for a fixed origin."""
    resolver = socket.getaddrinfo if resolver is None else resolver
    try:
        answers = resolver(host, 443, socket.AF_INET, socket.SOCK_STREAM)
    except OSError:
        raise recovery.RecoveryError('public_probe_dns_failed') from None
    _require(isinstance(answers, (list, tuple)) and 0 < len(answers) <= MAX_PUBLIC_PROBE_DNS_ANSWERS,
             'public_probe_dns_answer_count')
    addresses = set()
    for answer in answers:
        _require(isinstance(answer, tuple) and len(answer) == 5
                 and answer[0] == socket.AF_INET and answer[1] == socket.SOCK_STREAM
                 and isinstance(answer[4], tuple) and len(answer[4]) >= 2,
                 'public_probe_dns_answer_invalid')
        _require(isinstance(answer[4][0], str), 'public_probe_dns_answer_invalid')
        try:
            address = ipaddress.ip_address(answer[4][0])
        except (TypeError, ValueError):
            raise recovery.RecoveryError('public_probe_dns_answer_invalid') from None
        _require(isinstance(address, ipaddress.IPv4Address) and address.is_global,
                 'public_probe_dns_answer_not_global')
        addresses.add(address)
    _require(addresses, 'public_probe_dns_empty')
    return str(sorted(addresses, key=int)[0])


def _validate_public_probe_report(raw, destination):
    """Validate the guest's receipt; the response body is never retained."""
    _require(isinstance(raw, bytes) and 0 < len(raw) <= PUBLIC_PROBE_OUTPUT_LIMIT
             and raw.endswith(b'\n'), 'public_probe_report_size')
    try:
        report = json.loads(raw)
    except (ValueError, UnicodeError):
        raise recovery.RecoveryError('public_probe_report_invalid') from None
    duration_limit_ns = (PUBLIC_PROBE_TIMEOUT_LIMIT_NS
                         if isinstance(report, dict) and report.get('error') == 'total_timeout'
                         else PUBLIC_PROBE_DURATION_LIMIT_NS)
    expected = {'kind', 'method', 'host', 'path', 'destinationIPv4', 'port',
                'startedAtUnixNs', 'finishedAtUnixNs', 'tlsVerified',
                'gatewayContextVerified', 'expectedHostPosturePassed', 'status',
                'bodyBytes', 'bodySha256', 'verified', 'error'}
    _require(isinstance(report, dict) and set(report) == expected
             and report['kind'] == 'native-guest-public-probe-v1'
             and report['method'] == 'GET' and report['host'] == PUBLIC_PROBE_HOST
             and report['path'] == PUBLIC_PROBE_PATH and report['destinationIPv4'] == destination
             and type(report['port']) is int and report['port'] == 443
             and type(report['startedAtUnixNs']) is int and report['startedAtUnixNs'] > 0
             and type(report['finishedAtUnixNs']) is int
             and report['finishedAtUnixNs'] >= report['startedAtUnixNs']
             and report['finishedAtUnixNs'] - report['startedAtUnixNs'] <= duration_limit_ns
             and type(report['tlsVerified']) is bool
             and type(report['gatewayContextVerified']) is bool
             and type(report['expectedHostPosturePassed']) is bool
             and type(report['status']) is int and 0 <= report['status'] <= 599
             and type(report['bodyBytes']) is int and 0 <= report['bodyBytes'] <= 17
             and isinstance(report['bodySha256'], str)
             and re.fullmatch(r'[0-9a-f]{64}', report['bodySha256'])
             and type(report['verified']) is bool
             and isinstance(report['error'], str)
             and report['error'] in {'', 'total_timeout', 'transport_error',
                                     'gateway_context_invalid'}
             and (report['gatewayContextVerified'] or report['error'] != ''),
             'public_probe_report_invalid')
    expected_success = (report['tlsVerified'] and report['gatewayContextVerified']
                        and report['status'] == 200
                        and report['bodyBytes'] == 16
                        and report['bodySha256'] == PUBLIC_PROBE_BODY_SHA256
                        and report['error'] == '')
    _require(report['verified'] is expected_success, 'public_probe_report_inconsistent')
    return report


def _validate_guest_route_report(raw, identity_ip, positive_ip, trust_roots_sha256):
    """Validate only the fixed two-leg receipt and its admitted guest trust inventory."""
    _require(isinstance(raw, bytes) and 0 < len(raw) <= GUEST_ROUTE_OUTPUT_LIMIT
             and raw.endswith(b'\n'), 'guest_route_report_size')
    try:
        report = json.loads(raw)
    except (ValueError, UnicodeError):
        raise recovery.RecoveryError('guest_route_report_invalid') from None
    expected = {
        'kind', 'identityHost', 'identityPath', 'identityDestinationIPv4', 'identityStatus',
        'identityTlsVerified', 'identityBodyBytes', 'identityBodySha256', 'identityNoStore',
        'identityNoGatewayMarkers', 'identityError', 'positiveHost', 'positivePath',
        'positiveDestinationIPv4', 'positiveStatus', 'positiveTlsVerified',
        'positiveContentType', 'positiveBodyBytes', 'positiveBodySha256', 'positiveError',
        'publicTrustRootsSha256', 'gatewayCaAbsent', 'startedAtUnixNs', 'finishedAtUnixNs',
        'verified', 'error'}
    timeout = (isinstance(report, dict) and isinstance(report.get('error'), str)
               and report['error'] in {'timeout', 'report_too_large'})
    elapsed_limit = GUEST_ROUTE_TIMEOUT_LIMIT_NS if timeout else GUEST_ROUTE_DURATION_LIMIT_NS
    _require(isinstance(report, dict) and set(report) == expected
             and report['kind'] == 'native-guest-route-contract-v1'
             and report['identityHost'] == GUEST_ROUTE_IDENTITY_HOST
             and report['identityPath'] == GUEST_ROUTE_IDENTITY_PATH
             and report['identityDestinationIPv4'] == identity_ip
             and report['positiveHost'] == GUEST_ROUTE_POSITIVE_HOST
             and report['positivePath'] == GUEST_ROUTE_POSITIVE_PATH
             and report['positiveDestinationIPv4'] == positive_ip
             and isinstance(report['publicTrustRootsSha256'], str)
             and type(report['startedAtUnixNs']) is int and report['startedAtUnixNs'] > 0
             and type(report['finishedAtUnixNs']) is int
             and report['finishedAtUnixNs'] >= report['startedAtUnixNs']
             and report['finishedAtUnixNs'] - report['startedAtUnixNs'] <= elapsed_limit
             and type(report['identityStatus']) is int and 0 <= report['identityStatus'] <= 599
             and type(report['identityTlsVerified']) is bool
             and type(report['identityBodyBytes']) is int and 0 <= report['identityBodyBytes'] <= 8192
             and isinstance(report['identityBodySha256'], str)
             and re.fullmatch(r'[0-9a-f]{64}', report['identityBodySha256'])
             and type(report['identityNoStore']) is bool
             and type(report['identityNoGatewayMarkers']) is bool
             and isinstance(report['identityError'], str)
             and report['identityError'] in {'', 'timeout', 'transport_error', 'tls_error',
                                              'trust_override', 'trust_roots_invalid',
                                              'trust_roots_mismatch', 'body_too_large',
                                              'report_too_large'}
             and type(report['positiveStatus']) is int and 0 <= report['positiveStatus'] <= 599
             and type(report['positiveTlsVerified']) is bool
             and isinstance(report['positiveContentType'], str)
             and report['positiveContentType'] in {'', GUEST_ROUTE_POSITIVE_CONTENT_TYPE}
             and type(report['positiveBodyBytes']) is int and 0 <= report['positiveBodyBytes'] <= 8192
             and isinstance(report['positiveBodySha256'], str)
             and re.fullmatch(r'[0-9a-f]{64}', report['positiveBodySha256'])
             and isinstance(report['positiveError'], str)
             and report['positiveError'] in {'', 'timeout', 'transport_error', 'tls_error',
                                              'trust_override', 'trust_roots_invalid',
                                              'trust_roots_mismatch', 'body_too_large',
                                              'report_too_large'}
             and type(report['gatewayCaAbsent']) is bool
             and type(report['verified']) is bool
             and isinstance(report['error'], str)
             and report['error'] in {'', 'timeout', 'transport_error', 'tls_error',
                                     'trust_override', 'trust_roots_invalid', 'trust_roots_mismatch',
                                     'body_too_large', 'predicate_failed', 'report_too_large'},
             'guest_route_report_invalid')
    preflight_errors = {'trust_override', 'trust_roots_invalid', 'trust_roots_mismatch'}
    if report['error'] in preflight_errors:
        empty_hash = hashlib.sha256(b'').hexdigest()
        _require(report['identityError'] == report['error']
                 and report['positiveError'] == report['error']
                 and report['publicTrustRootsSha256'] == ''
                 and report['gatewayCaAbsent'] is False
                 and report['identityStatus'] == 0 and report['positiveStatus'] == 0
                 and report['identityTlsVerified'] is False
                 and report['positiveTlsVerified'] is False
                 and report['identityBodyBytes'] == 0 and report['positiveBodyBytes'] == 0
                 and report['identityBodySha256'] == empty_hash
                 and report['positiveBodySha256'] == empty_hash
                 and report['identityNoStore'] is False
                 and report['identityNoGatewayMarkers'] is False
                 and report['positiveContentType'] == ''
                 and report['verified'] is False, 'guest_route_report_inconsistent')
        return report
    if report['error'] == 'report_too_large':
        empty_hash = hashlib.sha256(b'').hexdigest()
        _require(report['identityError'] == report['error']
                 and report['positiveError'] == report['error']
                 and report['publicTrustRootsSha256'] == trust_roots_sha256
                 and report['gatewayCaAbsent'] is True
                 and report['identityStatus'] == 0 and report['positiveStatus'] == 0
                 and report['identityTlsVerified'] is False
                 and report['positiveTlsVerified'] is False
                 and report['identityBodyBytes'] == 0 and report['positiveBodyBytes'] == 0
                 and report['identityBodySha256'] == empty_hash
                 and report['positiveBodySha256'] == empty_hash
                 and report['identityNoStore'] is False
                 and report['identityNoGatewayMarkers'] is False
                 and report['positiveContentType'] == ''
                 and report['verified'] is False, 'guest_route_report_inconsistent')
        return report
    _require(report['publicTrustRootsSha256'] == trust_roots_sha256
             and report['gatewayCaAbsent'] is True, 'guest_route_report_invalid')
    identity_ok = (report['identityTlsVerified'] and report['identityStatus'] == 404
                   and report['identityBodyBytes'] == 0
                   and report['identityBodySha256'] == hashlib.sha256(b'').hexdigest()
                   and report['identityNoStore'] and report['identityNoGatewayMarkers']
                   and report['identityError'] == '')
    positive_ok = (report['positiveTlsVerified'] and report['positiveStatus'] == 200
                   and report['positiveContentType'] == GUEST_ROUTE_POSITIVE_CONTENT_TYPE
                   and report['positiveBodyBytes'] == GUEST_ROUTE_POSITIVE_BODY_BYTES
                   and report['positiveBodySha256'] == GUEST_ROUTE_POSITIVE_BODY_SHA256
                   and report['positiveError'] == '')
    expected_error = '' if identity_ok and positive_ok else (
        report['positiveError'] or report['identityError'] or 'predicate_failed')
    _require(report['verified'] is (identity_ok and positive_ok)
             and report['error'] == expected_error, 'guest_route_report_inconsistent')
    return report


def _child_exited(process):
    _require(process.returncode is None, 'owned_child_already_reaped')
    return os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is not None


def _child_exit_status(process):
    """Read an owned child's status without reaping its PID or releasing its process group."""
    _require(process.returncode is None, 'owned_child_already_reaped')
    info = os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
    if info is None:
        return None
    _require(info.si_pid == process.pid and info.si_code == os.CLD_EXITED,
             'owned_child_abnormal_exit')
    return info.si_status


def _await_guest_shutdown(vm, vm_name, command):
    """Require the acknowledged guest shutdown to end Tart naturally and cleanly."""
    command([str(TART), 'exec', vm_name, '/bin/sh', '-c',
             'exec /usr/bin/sudo -n /sbin/shutdown -h +10sec </dev/null >/dev/null 2>&1'], timeout=15,
            output_limit=canary.MAX_SHORT_OUTPUT)
    deadline = time.monotonic() + GUEST_SHUTDOWN_TIMEOUT
    exit_code = _child_exit_status(vm)
    while exit_code is None:
        _require(time.monotonic() < deadline, 'guest_shutdown_timeout')
        time.sleep(0.2)
        exit_code = _child_exit_status(vm)
    _require(_group_quiet(vm.pid), 'guest_shutdown_process_group_not_quiet')
    _require(type(exit_code) is int and exit_code == 0, 'guest_shutdown_abnormal_exit')
    raw, _ = command([str(TART), 'get', vm_name, '--format', 'json'], timeout=10)
    _require(canary._vm_stopped(raw), 'guest_shutdown_state_unconfirmed')
    return {'kind': GUEST_SHUTDOWN_KIND, 'version': 1,
            'requestAccepted': True, 'vmRunExitCode': exit_code, 'vmStopped': True}


def _group_quiet(pid):
    """Keep the child PID reserved while independently observing every group member."""
    raw, _ = canary._run_bounded(['/bin/ps', '-A', '-o', 'pid=', '-o', 'pgid=', '-o', 'stat='],
                                 timeout=5, env=ENV, output_limit=canary.MAX_PROCESS_TABLE_BYTES)
    leader = False
    quiet = True
    for line in raw.splitlines():
        fields = line.split()
        _require(len(fields) == 3 and fields[0].isdigit() and fields[1].isdigit(),
                 'invalid_process_table')
        member, group = int(fields[0]), int(fields[1])
        if group == pid:
            _require(re.fullmatch(rb'[A-Za-z+<NsEXLTWsl-]+', fields[2]),
                     'invalid_process_table')
            leader |= member == pid
            quiet &= fields[2].startswith(b'Z')
    _require(leader, 'owned_group_identity_lost')
    return quiet


def _stop_owned(process, log_thread=None):
    """No poll/wait before the group is quiet: the unreaped leader reserves its PGID."""
    _require(process.returncode is None, 'owned_child_already_reaped')
    try:
        pgid = os.getpgid(process.pid)
        sid = os.getsid(process.pid)
    except ProcessLookupError:
        # Darwin cannot query a zombie's IDs, so prove its exit and reserved PGID without reaping it.
        _require(_child_exited(process), 'owned_group_identity_lost')
        _group_quiet(process.pid)
    else:
        _require(pgid == process.pid and sid == process.pid, 'owned_group_identity_lost')
        _child_exited(process)
    try:
        os.killpg(process.pid, signal.SIGINT)
    except (ProcessLookupError, PermissionError):
        pass
    canary._wait_owned_vm_exit(process, 2)
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass  # The process-table proof below must still succeed, including on Darwin zombies.
    deadline = time.monotonic() + 5
    while not _group_quiet(process.pid):
        _require(time.monotonic() < deadline, 'owned_group_still_live')
        time.sleep(0.05)
    _require(_child_exited(process), 'owned_child_not_exited')
    if log_thread is not None:
        log_thread.join(timeout=2)
        _require(not log_thread.is_alive(), 'log_drainer_unjoined')
    process.wait(timeout=5)


def _record(directory, name, value):
    fd = recovery._directory(directory)
    try:
        payload = ((json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()
                   if name == 'provisioning-download.json' else
                   plistlib.dumps(value, fmt=plistlib.FMT_BINARY))
        recovery._publish(fd, name, payload)
    finally:
        os.close(fd)


def _record_command_failure(run, phase, error, *, command_error=None):
    _require(phase in COMMAND_FAILURE_PHASES, 'invalid_command_failure_phase')
    output = (canary._command_failure_output(error)
              or canary._command_failure_output(command_error) or {
        'stdoutTail': b'', 'stderrTail': b'', 'stdoutObservedBytes': 0,
        'stderrObservedBytes': 0, 'exitCode': None})
    error_type = type(error).__name__
    error_code = str(error)
    return _record(run, 'command-failure.plist', {
        'kind': COMMAND_FAILURE_KIND, 'phase': phase,
        'errorType': error_type if COMMAND_ERROR_TYPE.fullmatch(error_type)
        else 'Exception',
        'errorCode': error_code if COMMAND_ERROR_CODE.fullmatch(error_code)
        else 'unclassified_failure', **output})


def _start_logs(process, directory, failures):
    directory.mkdir(mode=0o700)
    result = {}

    def drain():
        try:
            canary._drain_tart_logs(process, failures, result, directory)
        except BaseException:
            failures.append('log_drainer_failed')

    thread = threading.Thread(target=drain, daemon=True)
    thread.start()
    return thread


def _reap_children(vm, helper, threads, stop, failures, *, record_error=None,
                   vm_naturally_exited=False):
    for key, process in (('vmReaped', vm), ('helperReaped', helper)):
        if process is not None:
            if key == 'vmReaped' and vm_naturally_exited:
                continue
            try:
                _stop_owned(process, log_thread=threads.get(process))
                stop[key] = True
            except BaseException as exc:
                failures.append(key + '_unproven')
                if record_error is not None:
                    record_error(exc)
    for thread in threads.values():
        thread.join(timeout=2)
        if thread.is_alive():
            failures.append('log_drainer_unjoined')
    if vm is not None and vm_naturally_exited:
        vm_thread = threads.get(vm)
        if vm_thread is not None and vm_thread.is_alive():
            failures.append('vm_log_drainer_unjoined')
            reap_error = recovery.RecoveryError('vm_log_drainer_unjoined')
        else:
            reap_error = None
            try:
                _require(_group_quiet(vm.pid), 'guest_shutdown_process_group_not_quiet')
                _require(_child_exited(vm), 'owned_child_not_exited')
                exit_code = vm.wait(timeout=5)
                _require(type(exit_code) is int and exit_code == 0,
                         'guest_shutdown_abnormal_exit')
                stop['vmReaped'] = True
            except BaseException as exc:
                reap_error = exc
        if reap_error is not None:
            failures.append('vm_natural_reap_unproven')
            if record_error is not None:
                record_error(reap_error)
            if vm.returncode is None:
                try:
                    # This is safety cleanup only: the earlier failure remains fatal,
                    # and the host Tart stop command stays disabled on the natural path.
                    _stop_owned(vm, log_thread=vm_thread)
                    stop['vmReaped'] = True
                except BaseException as cleanup_error:
                    failures.append('vm_natural_cleanup_unproven')
                    if record_error is not None:
                        record_error(cleanup_error)


def _exercise(run, admission, account, group, preferences_factory, *, public_probe_ip=None,
              guest_route_ips=None, provisioning_bundle_fd=None):
    provisioning_downloads = provisioning_bundle_fd is not None
    env = {**ENV, 'HOME': admission['tartHome'], 'TART_HOME': admission['tartHome'],
           'TART_NO_AUTO_PRUNE': '1'}
    owner_popen = partial(subprocess.Popen, user=account.pw_uid, group=account.pw_gid, extra_groups=[])
    bounded_command = partial(canary._run_bounded, env=env, popen=owner_popen)
    command_cleanup_errors = []
    command_processes = []

    def record_command_error(exc):
        """Keep cleanup diagnostics and unreaped Tart handles through reporting."""
        errors, processes = canary._command_cleanup_metadata(exc)
        for item in errors:
            if item not in command_cleanup_errors:
                command_cleanup_errors.append(item)
        for process in processes:
            if all(process is not existing for existing in command_processes):
                command_processes.append(process)

    def command(argv, **kwargs):
        try:
            return bounded_command(argv, **kwargs)
        except BaseException as exc:
            record_command_error(exc)
            raise
    vm_name = admission['vmName']
    try:
        raw, _ = command([str(TART), 'get', vm_name, '--format', 'json'], timeout=10)
        _require(canary._vm_stopped(raw), 'vm_not_stopped_before_capture')
        recovery.capture(run, preferences_factory=preferences_factory)
    except BaseException as exc:
        if provisioning_downloads:
            try:
                _record_command_failure(run, 'prelaunch', exc)
            except BaseException as write_error:
                raise recovery.RecoveryError('command_failure_record_failed') from write_error
        raise
    vm = helper = None
    vm_attempted = False
    first = second = None
    threads = {}
    failures = []
    error = None
    phase = 'vm-start'
    readiness_error = None
    diagnostic_write_error = None
    guest_shutdown_confirmed = False
    stop = {'vmReaped': True, 'helperReaped': True, 'vmStopped': False}
    previous = canary._install_termination_handlers()
    try:
        first, second = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
        for endpoint in (first, second):
            endpoint.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1024 * 1024)
            endpoint.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
        _record(run, 'launch.plist', {'vmName': vm_name, 'macAddress': admission['macAddress']})
        stop['helperReaped'] = False
        helper_argv = [str(SOFTNET), '--vm-fd', '0', '--vm-mac-address', admission['macAddress']]
        allowed_ips = ([public_probe_ip] if public_probe_ip is not None else
                       sorted(set(guest_route_ips or ()), key=lambda value: int(ipaddress.IPv4Address(value))))
        if provisioning_bundle_fd is not None:
            # The fixed downloader selects only the first admitted answer per host.
            allowed_ips = sorted({values[0] for values in admission['provisioningDnsMap'].values()},
                                 key=lambda value: int(ipaddress.IPv4Address(value)))
        if allowed_ips:
            destinations = ','.join('out ' + destination + '/32' for destination in allowed_ips)
            helper_argv.append('--allow=' + destinations)
        helper_argv.extend(['--block=0.0.0.0/0', '--user', account.pw_name, '--group', group])
        helper = subprocess.Popen(
            helper_argv,
            stdin=first, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=ENV,
            close_fds=True, start_new_session=True)  # nosec B603 -- Fixed root-owned digest-pinned helper and fixed flags.
        threads[helper] = _start_logs(helper, run / 'helper-logs', failures)
        first.close()
        first = None
        vm_attempted = True
        stop['vmReaped'] = stop['vmStopped'] = False
        vm = owner_popen(
            [str(TART), 'run', vm_name, f'--net-fd={second.fileno()}', '--no-clipboard',
             '--no-audio', '--no-usb-accessories', '--no-graphics'],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=env, close_fds=True, pass_fds=(second.fileno(),), start_new_session=True)
        threads[vm] = _start_logs(vm, run / 'vm-logs', failures)
        second.close()
        second = None
        phase = 'vm-readiness'
        deadline = time.monotonic() + canary.VM_READY_TIMEOUT
        while True:
            _require(not failures and not _child_exited(helper) and not _child_exited(vm),
                     'owned_child_exited_or_log_failure')
            try:
                command([str(TART), 'exec', vm_name, '/usr/bin/true'],
                        timeout=canary.VM_READY_PROBE_TIMEOUT)
                break
            except canary.CanaryError as exc:
                readiness_error = exc
                cleanup_errors, unreaped_processes = canary._command_cleanup_metadata(exc)
                if cleanup_errors or unreaped_processes:
                    # The failure is retryable only when the runner proved that
                    # its own command process group was cleaned up.
                    raise
                if str(exc) not in {'tart_command_failed', 'tart_command_timeout'}:
                    raise
                _require(time.monotonic() < deadline, 'vm_readiness_timeout')
                time.sleep(canary.VM_READY_RETRY_INTERVAL)
        phase = 'preference-readback'
        with preferences_factory() as preferences:
            _require(preferences.equal(preferences.read(), preferences.encode_target()),
                     'softnet_target_not_observed')
        _require(not failures and not _child_exited(helper) and not _child_exited(vm),
                 'owned_child_exited_or_log_failure')
        if provisioning_bundle_fd is not None:
            phase = 'provisioning-command'
            stdout, _ = command(
                provisioning.command_template(TART, vm_name), input_fd=provisioning_bundle_fd,
                timeout=PROVISIONING_TIMEOUT, output_limit=provisioning.MAX_OUTPUT_BYTES,
                cancel_check=lambda: bool(failures or _child_exited(helper) or _child_exited(vm)))
            phase = 'provisioning-receipt'
            try:
                report = provisioning.validate_result(stdout, **_provisioning_binding(admission))
            except (TypeError, ValueError):
                raise recovery.RecoveryError('invalid_provisioning_report') from None
            _record(run, 'provisioning-download.json', report)
            phase = 'guest-shutdown'
            shutdown_receipt = _await_guest_shutdown(vm, vm_name, command)
            guest_shutdown_confirmed = True
            _record(run, 'guest-shutdown.plist', shutdown_receipt)
        elif public_probe_ip is not None:
            source = _protected(PUBLIC_PROBE_SOURCE, 0)
            source_bytes = source.read_bytes()
            _require(len(source_bytes) <= 64 * 1024
                     and hashlib.sha256(source_bytes).hexdigest() == PUBLIC_PROBE_SOURCE_SHA256,
                     'public_probe_source_digest_mismatch')
            stdout, _ = command(
                [str(TART), 'exec', vm_name, '/usr/bin/python3', '-I', '-c',
                 PUBLIC_PROBE_LOADER, base64.b64encode(source_bytes).decode('ascii'), public_probe_ip],
                timeout=PUBLIC_PROBE_TIMEOUT, output_limit=PUBLIC_PROBE_OUTPUT_LIMIT)
            report = _validate_public_probe_report(stdout, public_probe_ip)
            _record(run, 'probe.plist', report)
            _require(report['verified'], 'public_probe_result_failed')
        elif guest_route_ips is not None:
            identity_ip, positive_ip = guest_route_ips
            source = _protected(GUEST_ROUTE_SOURCE, 0)
            source_bytes = source.read_bytes()
            _require(len(source_bytes) <= 64 * 1024
                     and hashlib.sha256(source_bytes).hexdigest() == GUEST_ROUTE_SOURCE_SHA256,
                     'guest_route_source_digest_mismatch')
            stdout, _ = command(
                [str(TART), 'exec', vm_name, '/usr/bin/python3', '-I', '-c',
                 GUEST_ROUTE_LOADER, base64.b64encode(source_bytes).decode('ascii'),
                 identity_ip, positive_ip, admission['publicTrustRootsSha256']],
                timeout=GUEST_ROUTE_TIMEOUT, output_limit=GUEST_ROUTE_OUTPUT_LIMIT)
            report = _validate_guest_route_report(
                stdout, identity_ip, positive_ip, admission['publicTrustRootsSha256'])
            _record(run, 'route-probe.plist', report)
            _require(report['verified'], 'guest_route_result_failed')
    except BaseException as exc:
        error = exc
        if provisioning_downloads:
            try:
                _record_command_failure(
                    run, phase, exc,
                    command_error=readiness_error if phase == 'vm-readiness' else None)
            except BaseException as write_error:
                diagnostic_write_error = write_error
    finally:
        canary._ignore_termination_handlers(previous)
        try:
            for endpoint in (first, second):
                if endpoint is not None:
                    endpoint.close()
            if vm_attempted:
                if not guest_shutdown_confirmed:
                    try:
                        command([str(TART), 'stop', vm_name], timeout=15)
                    except BaseException:
                        failures.append('vm_stop_command_failed')
            _reap_children(vm, helper, threads, stop, failures,
                           record_error=record_command_error,
                           vm_naturally_exited=guest_shutdown_confirmed)
            try:
                raw, _ = command([str(TART), 'get', vm_name, '--format', 'json'], timeout=10)
                stop['vmStopped'] = canary._vm_stopped(raw)
            except BaseException:
                stop['vmStopped'] = False
            _record(run, 'stop.plist', stop)
            try:
                _require(all(stop.values()) and not failures, 'cleanup_unproven')
            except BaseException as cleanup_error:
                canary._attach_command_cleanup(
                    cleanup_error, command_cleanup_errors, command_processes)
                raise
            if command_cleanup_errors or command_processes:
                # An uncertain Tart command may still mutate host preferences.
                # Leave the snapshot reservation and run incomplete for operator
                # recovery; process handles stay attached to the raised error.
                if error is None:
                    error = recovery.RecoveryError('cleanup_unproven')
                canary._attach_command_cleanup(
                    error, command_cleanup_errors, command_processes)
            else:
                recovery.restore(run, preferences_factory=preferences_factory)
        finally:
            canary._restore_termination_handlers(previous)
    if error is not None:
        if diagnostic_write_error is not None:
            raise recovery.RecoveryError('command_failure_record_failed') from diagnostic_write_error
        raise error
    return stop


def qualify(admission_directory, *, public_probe=False, guest_route_contract=False,
            provisioning_downloads=False, preferences_factory=Preferences):
    """Run the fixed startup canary or one fixed public-probe observation."""
    _require(os.geteuid() == 0 and sys.platform == 'darwin', 'root_macos_required')
    _require(sys.version_info >= (3, 13) and callable(getattr(os, 'waitid', None))
             and all(hasattr(os, name) for name in (
                 'P_PID', 'WEXITED', 'WNOHANG', 'WNOWAIT', 'CLD_EXITED')),
             'python_3_13_nonreaping_wait_required')
    root = Path(admission_directory)
    # Admission is root-only; no executable paths, guest commands, or helper flags are accepted.
    bundle_fd = None
    try:
        with State(STATE_ROOT) as state:
            admission, account, group, digest = _admission(root)
            probe_ip = None
            route_ips = None
            if sum(bool(mode) for mode in (public_probe, guest_route_contract, provisioning_downloads)) > 1:
                raise recovery.RecoveryError('mutually_exclusive_probe_modes')
            if provisioning_downloads:
                _require(admission['kind'] == 'softnet-provisioning-download-admission-v1',
                         'provisioning_download_admission_required')
                _validate_provisioning_admission(admission)
                bundle_fd = _open_provisioning_bundle(root, admission)
            elif guest_route_contract:
                _require(admission['kind'] == 'softnet-guest-route-admission-v1',
                         'guest_route_admission_required')
                identity_ip = _resolve_public_probe_ip(host=GUEST_ROUTE_IDENTITY_HOST)
                positive_ip = _resolve_public_probe_ip(host=GUEST_ROUTE_POSITIVE_HOST)
                _require(admission['identityProbeIPv4'] == identity_ip
                         and admission['positiveOriginIPv4'] == positive_ip,
                         'guest_route_admission_mismatch')
                route_ips = (identity_ip, positive_ip)
            elif public_probe:
                _require(admission['kind'] == 'softnet-public-probe-admission-v1',
                         'public_probe_admission_required')
                probe_ip = _resolve_public_probe_ip()
                _require(admission['probeIPv4'] == probe_ip, 'public_probe_admission_mismatch')
            else:
                _require(admission['kind'] == 'softnet-startup-admission-v1',
                         'public_probe_mode_required')
            identity = {'vmName': admission['vmName'], 'macAddress': admission['macAddress'],
                        'tartBinarySha256': canary.TART_BINARY_SHA256,
                        'softnetBinarySha256': SOFTNET_SHA256, 'admissionSha256': digest}
            if probe_ip is not None:
                identity['probeIPv4'] = probe_ip
            if route_ips is not None:
                identity.update({'identityProbeIPv4': route_ips[0], 'positiveOriginIPv4': route_ips[1],
                                 'publicTrustRootsSha256': admission['publicTrustRootsSha256']})
            exercise_options = {'public_probe_ip': probe_ip, 'guest_route_ips': route_ips}
            if provisioning_downloads:
                identity.update({key: admission[key] for key in PROVISIONING_FIELDS})
                exercise_options['provisioning_bundle_fd'] = bundle_fd
            run, run_id = state.begin(identity)
            stop = _exercise(run, admission, account, group, preferences_factory, **exercise_options)
            state.complete(run, stop)
            return {'kind': ('softnet-provisioning-download-canary-v1' if provisioning_downloads else
                             'softnet-guest-route-canary-v1' if route_ips else
                             'softnet-public-probe-canary-v1' if probe_ip else 'softnet-startup-canary-v1'),
                    'runId': run_id, 'status': 'passed', 'qualified': False,
                    'preferencesRestored': True, 'vmDeleted': False}
    finally:
        if bundle_fd is not None:
            os.close(bundle_fd)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--admission-dir', type=Path, required=True)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--public-probe', action='store_true')
    mode.add_argument('--guest-route-contract', action='store_true')
    mode.add_argument('--provisioning-downloads', action='store_true')
    args = parser.parse_args(argv)
    try:
        print(json.dumps(qualify(args.admission_dir, public_probe=args.public_probe,
                                 guest_route_contract=args.guest_route_contract,
                                 provisioning_downloads=args.provisioning_downloads), sort_keys=True))
    except (OSError, ValueError, RuntimeError):
        print('softnet_canary_failed; retain admission and run journal', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
