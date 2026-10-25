#!/usr/bin/env python3
"""Prepare a fresh paired client from authenticated protected-main release inputs."""

import argparse
import base64
import configparser
import csv
from email.parser import BytesParser
import hashlib
import importlib.util
import io
import json
import os
import platform
import re
import shlex
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tomllib
import urllib.error
import venv
import zipfile


ROOT = Path(__file__).resolve().parents[1]
PREFIX = "packages/event-gateway/"
HELPER = "docs/native-bridge/qualification-installed.py"
SELF = "scripts/install_paired_client.py"
SPEC = importlib.util.spec_from_file_location("paired_provenance", ROOT / "scripts/verify_native_ci_provenance.py")
V = importlib.util.module_from_spec(SPEC)
sys.dont_write_bytecode = True
SPEC.loader.exec_module(V)
WHEEL_LIMIT = 16 * 1024 * 1024


def require(condition, message):
    if not condition:
        raise ValueError(message)


def read_file(path, limit):
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_size <= limit, "unsafe_or_oversized_input")
        data = stream.read(limit + 1)
        require(len(data) <= limit, "oversized_input")
        return data


def destination_path(value):
    path = Path(value)
    require(path.is_absolute() and '..' not in path.parts, "destination_must_be_absolute")
    require(not os.path.lexists(path), "destination_already_exists")
    for parent in path.parents:
        info = parent.lstat()
        sticky = info.st_uid == 0 and info.st_mode & stat.S_ISVTX
        require(stat.S_ISDIR(info.st_mode) and info.st_uid in (0, os.getuid())
                and (not info.st_mode & 0o022 or sticky), "unsafe_destination_parent")
    return path


def create_destination(path):
    """Create exclusively beneath validated handles, never through a swapped symlink."""
    parent = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    created = False
    try:
        for component in path.parts[1:-1]:
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            os.close(parent)
            parent = child
            info = os.fstat(parent)
            sticky = info.st_uid == 0 and info.st_mode & stat.S_ISVTX
            require(info.st_uid in (0, os.getuid()) and (not info.st_mode & 0o022 or sticky),
                    "unsafe_destination_parent")
        os.mkdir(path.name, mode=0o700, dir_fd=parent)
        created = True
        return parent, os.stat(path.name, dir_fd=parent, follow_symlinks=False)
    except BaseException as error:
        if created:
            try:
                os.rmdir(path.name, dir_fd=parent)
            except FileNotFoundError:
                pass
            except OSError:
                error.add_note('Empty destination rollback failed; active installation was not touched')
        os.close(parent)
        raise


def wheel_payload(data, expected, project):
    """Check every installable member before pip can process the wheel."""
    distribution = project['name'].replace('-', '_') + '-' + project['version'] + '.dist-info/'
    metadata_paths = {distribution + name for name in ('METADATA', 'WHEEL', 'RECORD', 'entry_points.txt')}
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        entries = archive.infolist()
        names = [item.filename for item in entries]
        require(len(entries) <= 4096 and len(names) == len(set(names)), "duplicate_wheel_member")
        require(sum(item.file_size for item in entries) <= WHEEL_LIMIT, "oversized_wheel_payload")
        require(all(not item.is_dir() and not item.flag_bits & 1
                    and stat.S_IFMT(item.external_attr >> 16) in (0, stat.S_IFREG)
                    and item.filename in set(expected) | metadata_paths for item in entries), "unexpected_wheel_member")
        require(set(names) == set(expected) | metadata_paths, "wheel_files_differ")
        files = {name: archive.read(name) for name in names}
    require(all(files[name] == value for name, value in expected.items()), "wheel_source_mismatch")
    metadata = BytesParser().parsebytes(files[distribution + 'METADATA'])
    require(metadata.get_all('Name') == [project['name']] and metadata.get_all('Version') == [project['version']]
            and metadata.get_all('Requires-Python') == [project['requires-python']], "wheel_metadata_mismatch")

    # Hatch canonicalizes specifier order; compare the same comma-separated bounds.
    def requirement(value):
        match = re.fullmatch(r'([A-Za-z0-9_-]+)([<>=!~].*)', value.replace(' ', ''))
        require(match is not None, 'unsupported_dependency_metadata')
        name, bounds = match.groups()
        return name.lower().replace('_', '-'), tuple(sorted(bounds.split(',')))
    require(sorted(map(requirement, metadata.get_all('Requires-Dist', [])))
            == sorted(map(requirement, project['dependencies']))
            and not metadata.get_all('Provides-Extra'), "wheel_dependencies_mismatch")
    wheel = BytesParser().parsebytes(files[distribution + 'WHEEL'])
    require(wheel.get('Root-Is-Purelib') == 'true' and wheel.get_all('Tag') == ['py3-none-any'], "unsupported_wheel")
    entry = configparser.ConfigParser()
    entry.read_string(files[distribution + 'entry_points.txt'].decode())
    require(entry.sections() == ['console_scripts'] and dict(entry['console_scripts']) == project['scripts']
            and not entry.defaults(), "wheel_entrypoints_mismatch")
    rows = list(csv.reader(io.StringIO(files[distribution + 'RECORD'].decode())))
    require(all(len(row) == 3 for row in rows) and len(rows) == len(files)
            and {row[0] for row in rows} == set(files), "invalid_wheel_record")
    for name, digest, size in rows:
        if name == distribution + 'RECORD':
            require(digest == size == '', "invalid_wheel_record")
        else:
            encoded = base64.urlsafe_b64encode(hashlib.sha256(files[name]).digest()).rstrip(b'=').decode()
            require(digest == 'sha256=' + encoded and size == str(len(files[name])), "invalid_wheel_record")


def locked_requirements(data, project):
    """Export only the current CPython runtime closure, with approved wheel hashes."""
    lock = tomllib.loads(data.decode())
    packages = {row['name']: row for row in lock['package']}
    require(len(packages) == len(lock['package']) and lock['version'] == 1, "ambiguous_lock")
    root = packages[project['name']]
    require(root['version'] == project['version'] and {row['name'] for row in root['dependencies']}
            == {re.split(r'[<>=!~]', value, maxsplit=1)[0] for value in project['dependencies']},
            "lock_project_mismatch")
    pending = list(root['dependencies'])
    selected = {}
    while pending:
        dependency = pending.pop()
        require(set(dependency) <= {'name', 'marker'} and dependency.get('marker') in (
            None, "implementation_name != 'PyPy'", "platform_python_implementation != 'PyPy'",
        ), "unsupported_lock_marker")
        name = dependency['name']
        if name in selected:
            continue
        row = packages[name]
        require(row['source'] == {'registry': 'https://pypi.org/simple'}
                and re.fullmatch(r'[a-z0-9][a-z0-9-]*', name)
                and re.fullmatch(r'[0-9]+(?:\.[0-9]+)*', row['version']), "unsupported_locked_package")
        hashes = sorted({wheel['hash'] for wheel in row['wheels']})
        require(hashes and all(value.startswith('sha256:') and V.sha(value[7:]) for value in hashes),
                "missing_locked_wheel_hash")
        selected[name] = name + '==' + row['version'] + ''.join(' --hash=' + value for value in hashes)
        pending.extend(row.get('dependencies', []))
    return '\n'.join(selected[name] for name in sorted(selected)) + '\n'


def preflight(api, wheel, artifact, destination, *, enrollment_only=False):
    """Authenticate the protected-main wheel; paired installs also require native release proof."""
    destination = destination_path(destination)
    require(artifact is not None or enrollment_only, "native_artifact_required")
    require(artifact is None or not enrollment_only, "native_artifact_not_allowed_for_enrollment_only")
    require(api.request('')['id'] == V.REPOSITORY_ID, "wrong_repository")
    branch = api.request('branches/main')
    require(branch.get('protected') is True, "main_not_protected")
    main = branch['commit']['sha']
    require(V.sha(main, 40), "invalid_main_revision")
    trusted_helpers = {}
    for path in (SELF, 'scripts/verify_native_ci_provenance.py', V.REGISTRY.removeprefix(PREFIX), HELPER):
        trusted_helpers[path] = api.blob(PREFIX + path, main)
        require(read_file(ROOT / path, V.LIMIT) == trusted_helpers[path], "local_policy_differs_from_main")
    tree = api.request(f'git/trees/{main}?recursive=1')
    require(tree.get('truncated') is False, "truncated_main_tree")
    expected = {}
    for entry in tree['tree']:
        path = entry['path']
        source = PREFIX + 'src/event_gateway/'
        contract = PREFIX + 'contracts/event-v1/'
        if path.startswith(source) or path.startswith(contract):
            if entry['type'] == 'tree':
                continue
            require(entry['type'] == 'blob' and entry['mode'] in ('100644', '100755'), "unsafe_source_entry")
            name = ('event_gateway/' + path[len(source):] if path.startswith(source)
                    else 'event_gateway/contracts/event-v1/' + path[len(contract):])
            expected[name] = api.blob(path, main)
    require('event_gateway/launcher.py' in expected and 'event_gateway/__init__.py' in expected, "missing_package")
    project = tomllib.loads(api.blob(PREFIX + 'pyproject.toml', main).decode())['project']
    wheel = Path(wheel)
    require(wheel.name == project['name'].replace('-', '_') + '-' + project['version'] + '-py3-none-any.whl',
            "unexpected_wheel_filename")
    requirements = locked_requirements(api.blob(PREFIX + 'uv.lock', main), project)
    wheel_bytes = read_file(wheel, WHEEL_LIMIT)
    wheel_payload(wheel_bytes, expected, project)
    selected = None
    if not enrollment_only:
        selected = V.selection(json.loads(api.blob(V.PROVENANCE, main)))
        pins = V.pins(expected['event_gateway/launcher.py'])
        require(pins['QUALIFIED_SHA256'] == selected['binarySha256']
                and pins['QUALIFIED_CODE_MODE_HOST_SHA256'] == selected['codeModeHostSha256'], "consumer_native_pair_mismatch")
        V.verify_metadata(selected, api.request('actions/workflows/event-native-build.yml'),
                          api.request(f"actions/runs/{selected['runId']}/attempts/{selected['runAttempt']}"),
                          api.request(f"actions/artifacts/{selected['artifactId']}"))
        V.require_ancestry(api, selected['headSha'], main)
        try:
            inputs, manifest = V.resolve_build_inputs(api, main, main, selected)
        except (ValueError, urllib.error.HTTPError) as error:
            if isinstance(error, urllib.error.HTTPError) and error.code != 404:
                raise
            raise ValueError(
                'consumer_native_pair_mismatch: promoted native recipe unavailable or unverified; '
                'keep previous working client until paired release is promoted'
            ) from error
        artifact = Path(artifact)
        require(stat.S_ISREG(artifact.lstat().st_mode), "unsafe_native_archive")
        V.verify_archive(artifact, selected, inputs, manifest)
    require(api.request('branches/main')['commit']['sha'] == main, "main_changed_during_preflight")
    return {'main': main, 'destination': destination, 'wheel_name': wheel.name, 'wheel': wheel_bytes,
            'expected': expected, 'selected': selected, 'inputs': None if enrollment_only else inputs,
            'manifest': None if enrollment_only else manifest,
            'artifact': None if enrollment_only else artifact, 'requirements': requirements,
            'helper': trusted_helpers[HELPER], 'enrollment_only': enrollment_only}


def install_wheel(destination, wheel, requirements, wheel_sha256):
    venv.EnvBuilder(with_pip=True).create(destination)
    # Fixed environment prevents pip config, proxy, credentials or index overrides.
    environment = {'PATH': '/usr/bin:/bin', 'HOME': str(destination), 'PIP_CONFIG_FILE': os.devnull,
                   'TMPDIR': str(destination)}
    command = [str(destination / 'bin/python'), '-I', '-m', 'pip', '--isolated', 'install',
               '--only-binary=:all:', '--index-url', 'https://pypi.org/simple', '--no-cache-dir',
               '--disable-pip-version-check', '--require-hashes', '--no-deps']
    subprocess.run([*command, '-r', str(requirements)], check=True, env=environment)
    own_requirement = destination / '.paired-wheel.txt'
    own_requirement.write_text(wheel.as_uri() + ' --hash=sha256:' + wheel_sha256 + '\n')
    subprocess.run([*command, '-r', str(own_requirement)], check=True, env=environment)
    subprocess.run([str(destination / 'bin/python'), '-I', '-m', 'pip', '--isolated', 'check'],
                   check=True, env=environment)


POSTCHECK = '''import importlib.util, sys
from pathlib import Path
helper, source, binary, digest = sys.argv[1:]
spec = importlib.util.spec_from_file_location("paired_installed", helper)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
module.verified_python()
module.verify_installed(source)
from event_gateway import launcher
launcher.qualified_binary(binary, digest)
module.verified_executable(Path(sys.prefix) / "bin/knitli-event-gateway")
'''


def verify_destination(destination, source, helper, selected):
    subprocess.run([str(destination / 'bin/python'), '-I', '-c', POSTCHECK, str(helper),
                    str(source / 'src/event_gateway'), str(destination / 'native/codex'),
                    selected['binarySha256']], check=True,
                   env={'PATH': '/usr/bin:/bin', 'HOME': str(destination)})


def enrollment_entrypoint(destination):
    command = 'from event_gateway.cli import enrollment_main; raise SystemExit(enrollment_main())'
    return ('#!/bin/sh\nexec ' + shlex.quote(str(destination / 'bin/python')) + ' -I -c '
            + shlex.quote(command) + ' "$@"\n').encode()


def restrict_enrollment_entrypoint(destination):
    entrypoint = destination / 'bin/knitli-event-gateway'
    info = entrypoint.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid in (0, os.getuid()), 'unsafe_installed_entrypoint')
    fd = os.open(entrypoint, os.O_WRONLY | os.O_NOFOLLOW | os.O_TRUNC)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(enrollment_entrypoint(destination))
    entrypoint.chmod(0o700)
    return entrypoint


ENROLLMENT_POSTCHECK = '''import importlib.util, sys
from pathlib import Path
helper, source = sys.argv[1:]
spec = importlib.util.spec_from_file_location("paired_installed", helper)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
module.verified_python()
module.verify_installed(source)
module.verified_executable(Path(sys.prefix) / "bin/knitli-event-gateway")
'''


def verify_enrollment_destination(destination, source, helper):
    subprocess.run([str(destination / 'bin/python'), '-I', '-c', ENROLLMENT_POSTCHECK,
                    str(helper), str(source / 'src/event_gateway')], check=True,
                   env={'PATH': '/usr/bin:/bin', 'HOME': str(destination)})
    entrypoint = destination / 'bin/knitli-event-gateway'
    info = entrypoint.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid in (0, os.getuid()) and info.st_mode & 0o111
            and entrypoint.read_bytes() == enrollment_entrypoint(destination),
            'enrollment_entrypoint_mismatch')


def install(plan):
    """Populate only a fresh private destination; hand off only after verification."""
    destination = destination_path(plan['destination'])
    if not plan['enrollment_only']:
        V.verify_archive(plan['artifact'], plan['selected'], plan['inputs'], plan['manifest'])
    parent, identity = create_destination(destination)
    try:
        current = destination.lstat()
        require((current.st_dev, current.st_ino) == (identity.st_dev, identity.st_ino),
                "destination_parent_changed")
        source = destination / '.paired-source'
        for name, data in plan['expected'].items():
            relative = name.removeprefix('event_gateway/')
            target = source / (relative if relative.startswith('contracts/') else 'src/event_gateway/' + relative)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        helper = source / 'qualification-installed.py'
        helper.write_bytes(plan['helper'])
        wheel = destination / plan['wheel_name']
        wheel.write_bytes(plan['wheel'])
        requirements = destination / '.paired-requirements.txt'
        requirements.write_text(plan['requirements'])
        install_wheel(destination, wheel, requirements, V.digest(plan['wheel']))
        if plan['enrollment_only']:
            restrict_enrollment_entrypoint(destination)
            verify_enrollment_destination(destination, source, helper)
            return {'sourceRevision': plan['main'], 'wheelSha256': V.digest(plan['wheel']),
                    'environment': str(destination), 'command': str(destination / 'bin/knitli-event-gateway'),
                    'profile': 'enrollment-only'}
        native = destination / 'native'
        native.mkdir(mode=0o700)
        with zipfile.ZipFile(plan['artifact']) as archive:
            for name, digest in (('codex', plan['selected']['binarySha256']),
                                 ('codex-code-mode-host', plan['selected']['codeModeHostSha256'])):
                with archive.open(name) as incoming, (native / name).open('xb') as output:
                    remaining = V.MEMBERS[name]
                    while chunk := incoming.read(min(1024 * 1024, remaining + 1)):
                        remaining -= len(chunk)
                        require(remaining >= 0, 'oversized_native_member')
                        output.write(chunk)
                with (native / name).open('rb') as stream:
                    require(hashlib.file_digest(stream, 'sha256').hexdigest() == digest, 'copied_native_hash_mismatch')
                (native / name).chmod(0o700)
        V.verify_archive(plan['artifact'], plan['selected'], plan['inputs'], plan['manifest'])
        verify_destination(destination, source, helper, plan['selected'])
        return {'sourceRevision': plan['main'], 'wheelSha256': V.digest(plan['wheel']),
                'binarySha256': plan['selected']['binarySha256'],
                'codeModeHostSha256': plan['selected']['codeModeHostSha256'],
                'environment': str(destination), 'binary': str(native / 'codex')}
    except BaseException as error:
        try:
            current = os.stat(destination.name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            current = None
        if current and (current.st_dev, current.st_ino) == (identity.st_dev, identity.st_ino):
            try:
                shutil.rmtree(destination.name, dir_fd=parent)
            except OSError:
                error.add_note('Owned destination cleanup failed; active installation was not touched')
        raise
    finally:
        os.close(parent)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--wheel', required=True)
    parser.add_argument('--native-artifact')
    parser.add_argument('--enrollment-only', action='store_true',
                        help='Install only enrollment/status/help commands; native launch remains unavailable')
    parser.add_argument('--destination', required=True)
    args = parser.parse_args()
    require(sys.flags.isolated and sys.version_info >= (3, 13) and sys.platform == "darwin"
            and platform.machine() == "arm64" and sys.implementation.name == "cpython",
            "requires_isolated_macos_arm64_cpython_3_13")
    token = os.environ.get('GITHUB_TOKEN')
    require(bool(token), "github_token_required")
    require(args.enrollment_only or args.native_artifact is not None, 'native_artifact_required')
    require(not (args.enrollment_only and args.native_artifact is not None),
            'native_artifact_not_allowed_for_enrollment_only')
    result = install(preflight(V.GitHub(token), args.wheel, args.native_artifact, args.destination,
                               enrollment_only=args.enrollment_only))
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
