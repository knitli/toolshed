#!/usr/bin/env python3
"""Export immutable Event Runtime git blobs or verify their checked-in hashes.

Refresh: --pin <40-lowercase-hex-commit> [--repository <git-url-or-path>]
Check offline: --check; CI upstream verification: --check --fetch.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
DEST = ROOT / 'contracts/event-v1'
REPOSITORY = 'https://github.com/knitli/knitli-site.git'
SOURCES = ['src/protocol.schema.json', 'src/protocol.ts', 'src/policy.ts', '__tests__/fixtures/protocol-v1.json']


def digest(data):
    return hashlib.sha256(data).hexdigest()


def fetch_blobs(repository, pin):
    with tempfile.TemporaryDirectory(prefix='event-contract-') as directory:
        def git(*args):
            return subprocess.check_output(['git', '-C', directory, *args], stderr=subprocess.PIPE)
        git('init', '--bare', '--quiet')
        git('fetch', '--quiet', '--depth=1', '--no-tags', repository, pin)
        if git('rev-parse', 'FETCH_HEAD').decode().strip() != pin:
            raise ValueError('commit_mismatch')
        return {source: git('show', f'{pin}:apps/os/packages/event-runtime/{source}') for source in SOURCES}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pin')
    parser.add_argument('--repository', default=REPOSITORY)
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--fetch', action='store_true')
    args = parser.parse_args()
    try:
        if args.check:
            if args.pin:
                parser.error('--check uses the manifest pin; omit --pin')
            manifest = json.loads((DEST / 'manifest.json').read_text())
            pin = manifest['commit']
        else:
            pin = args.pin
        if not isinstance(pin, str) or not re.fullmatch('[0-9a-f]{40}', pin):
            parser.error('an explicit 40-character lowercase hexadecimal commit is required')
        if args.check:
            expected_paths = {'apps/os/packages/event-runtime/' + p for p in SOURCES}
            if manifest['protocolVersion'] != 1 or manifest['repository'] != REPOSITORY or {entry['originalPath'] for entry in manifest['files']} != expected_paths or len(manifest['files']) != len(SOURCES):
                raise ValueError('invalid_manifest')
            upstream = fetch_blobs(args.repository, pin) if args.fetch else None
            for entry in manifest['files']:
                name = entry['originalPath'].rsplit('/', 1)[-1]
                if entry['file'] != name:
                    raise ValueError('invalid_manifest')
                blob = (DEST / name).read_bytes()
                if digest(blob) != entry['sha256']:
                    raise ValueError('contract_hash_mismatch')
                source = entry['originalPath'].removeprefix('apps/os/packages/event-runtime/')
                if upstream is not None and blob != upstream[source]:
                    raise ValueError('upstream_blob_mismatch')
            print('contract verified: ' + pin)
        else:
            blobs = fetch_blobs(args.repository, pin)
            DEST.mkdir(parents=True, exist_ok=True)
            entries = []
            for source, blob in blobs.items():
                name = source.rsplit('/', 1)[-1]
                (DEST / name).write_bytes(blob)
                entries.append({'file': name, 'originalPath': 'apps/os/packages/event-runtime/' + source, 'sha256': digest(blob)})
            (DEST / 'manifest.json').write_text(json.dumps({'repository': REPOSITORY, 'commit': pin, 'protocolVersion': 1, 'files': entries}, indent=2) + '\n')
            print('contract exported: ' + pin)
    except (ValueError, KeyError, TypeError, OSError, subprocess.CalledProcessError):
        parser.exit(1, 'contract verification or export failed\n')


if __name__ == '__main__':
    main()
