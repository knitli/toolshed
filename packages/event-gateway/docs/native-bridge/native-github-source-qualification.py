"""Qualification-only synthetic GitHub transport; never installs production hooks."""
import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import shlex
import sys

INSTALLED_SHA = '22002b7e599c266b512546c67ff383a643846624adb2b188520250d19fcd061c'
SUBJECT = {'installationId': 1, 'repositoryId': 2, 'prNumber': 3}
REQUEST = {'subject': SUBJECT, 'fromVersion': 2, 'toVersion': 3}
ORIGIN = 'https://events.example.com'
PRINCIPAL = 'qualification@example.com'
ENDPOINT = '/v1/github/source/read'


def require(value, message):
    if not value:
        raise AssertionError(message)


def page(nonce):
    return {'status': 'ok', 'subject': SUBJECT, 'requestedRange': {'fromVersion': 2, 'toVersion': 3},
            'coverageStartVersion': 1,
            'anchor': {'sourceVersion': 3, 'epoch': 1, 'observationEpoch': 1, 'observedAt': 0},
            'items': [{'phase': 'anchor', 'sourceVersion': 3, 'epoch': 1,
                       'recordType': 'request', 'recordKey': 'review-request',
                       'value': {'kind': 'review_request', 'identity': nonce, 'from': None, 'to': 'present'}}],
            'nextCursor': None, 'complete': True}


def prepare(source, nonce, package_source, installed_helper):
    source.write_text(json.dumps(page(nonce)) + '\n')
    runner = source.with_suffix('.py')
    runner.write_bytes(Path(__file__).read_bytes())
    runner.chmod(0o600)
    helper = source.with_suffix('.installed.py')
    data = Path(installed_helper).read_bytes()
    require(hashlib.sha256(data).hexdigest() == INSTALLED_SHA, 'installed helper digest mismatch')
    helper.write_bytes(data)
    helper.chmod(0o600)
    args = [sys.executable, '-I', '-B', str(runner), str(source), str(package_source), str(helper)]
    program = 'text(await tools.exec_command(' + json.dumps({
        'cmd': shlex.join(args), 'shell': '/bin/bash', 'login': False, 'max_output_tokens': 2000, 'yield_time_ms': 1000}) + '));'
    return program


def verify_output(requests, nonce, source, verify):
    require(nonce not in json.dumps(requests[0]), "source nonce leaked before execution")
    output = verify(requests, json.dumps(page(nonce)))
    witness = json.loads(source.with_suffix('.witness.json').read_text())
    require(witness == {'request': REQUEST, 'signatureVerified': True, 'syntheticTransportCalls': 1,
                        'realCloudCalls': 0, 'cliExitCode': 0}, 'invalid synthetic transport witness')
    return output


def run_cli(source):
    # These ports exist only in this disposable qualification process.
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from event_gateway import cli
    from event_gateway.cloud import CloudClient, Credentials, canonical_node_proof
    private_key = Ed25519PrivateKey.generate()
    calls = []

    async def credentials():
        return Credentials('synthetic-access', 'synthetic-agent')

    async def send(**wire):
        require(not calls, 'duplicate source request')
        require(wire['url'] == ORIGIN + ENDPOINT and wire['method'] == 'POST', 'wrong source endpoint')
        require(json.loads(wire['body']) == REQUEST, 'wrong source subject or range')
        require(wire['timeout'] == 5 and wire['max_response_bytes'] == 8192
                and wire['follow_redirects'] is False, 'unsafe transport options')
        headers = wire['headers']
        require(headers['cf-access-token'] == 'synthetic-access'
                and headers['authorization'] == 'Bearer synthetic-agent', 'wrong synthetic credentials')
        proof = json.loads(headers['x-event-node-proof'])
        signature = base64.urlsafe_b64decode(proof['signature'] + '==')
        private_key.public_key().verify(signature, canonical_node_proof(
            PRINCIPAL, ORIGIN, ENDPOINT, wire['body'], proof))
        calls.append(REQUEST)
        return 200, {'content-type': 'application/json'}, source.read_bytes()

    client = CloudClient(origin=ORIGIN, principal=PRINCIPAL, agent='codex',
                         node_id='12345678-1234-4123-8123-123456789012', node_generation=1,
                         private_key=private_key, credentials=credentials, send=send)
    original = cli.load_cloud_client
    cli.load_cloud_client = lambda *_: client
    try:
        code = cli.main(['--state-dir', str(source.parent / 'source-state'), 'github-source-read',
                         '--cloud-config', str(source.parent / 'unused-synthetic-config'),
                         '--installation-id', '1', '--repository-id', '2', '--pr-number', '3',
                         '--from-version', '2', '--to-version', '3'])
    finally:
        cli.load_cloud_client = original
    require(calls == [REQUEST] and code == 0, 'installed CLI source read failed')
    source.with_suffix('.witness.json').write_text(json.dumps({
        'request': REQUEST, 'signatureVerified': True, 'syntheticTransportCalls': len(calls),
        'realCloudCalls': 0, 'cliExitCode': code}))
    return code


def main():
    source, package_source, helper_path = map(Path, sys.argv[1:])
    require(hashlib.sha256(helper_path.read_bytes()).hexdigest() == INSTALLED_SHA,
            'installed helper digest mismatch')
    spec = importlib.util.spec_from_file_location('qualification_installed', helper_path)
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    helper.verify_installed(package_source)
    helper.verified_python()
    return run_cli(source)


if __name__ == '__main__':
    sys.exit(main())
