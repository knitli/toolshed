#!/usr/bin/env python3
"""Disposable genuine native + production local + workerd, with explicit authority fixtures."""
import asyncio
import argparse
import base64
import copy
import hashlib
import http.client
import importlib.util
import json
from pathlib import Path
import select
import subprocess  # nosec B404 - Controlled fixture launches the explicit Node executable.
import sys
import tempfile
import time
from uuid import UUID, uuid4

parser = argparse.ArgumentParser(description=__doc__)
for name in ('package', 'qualifier', 'binary', 'binary-sha', 'node', 'cloud-source', 'esbuild', 'miniflare', 'output'):
    parser.add_argument('--' + name, required=True)
args = parser.parse_args()
PACKAGE, QUALIFIER, BINARY = (Path(x).resolve(strict=True) for x in (args.package, args.qualifier, args.binary))
BINARY_SHA, NODE = args.binary_sha, str(Path(args.node).resolve(strict=True))
BROKER = Path(__file__).with_name('coupled-workerd-broker.mjs')
OUTPUT = Path(args.output).resolve()
sys.path.insert(0, str(PACKAGE / 'src'))
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from event_gateway.cloud import CloudClient, Credentials
from event_gateway.gateway import Gateway
from event_gateway.native import NativeBridgeAdapter, validate_receipt
from event_gateway.store import Store, IDENTITY


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def b64(value):
    return base64.urlsafe_b64encode(value).rstrip(b'=').decode()


async def exercise(bridge, model, native_process, witness, address):
    node_key, transport_key = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    node_id, runtime_id = str(uuid4()), str(uuid4())
    wires, auth_calls, drop_reply = [], 0, True

    def post(path, body, headers=None, cap=1048576):
        connection = http.client.HTTPConnection('127.0.0.1', address['port'], timeout=5)
        try:
            fixture_headers = {'cf-access-token': 'fixture-access', 'authorization': 'Bearer fixture-agent'}
            connection.request('POST', path, body=body, headers={**(fixture_headers if headers is None else headers),
                               'x-fixture-secret': address['secret'], 'content-type': 'application/json'})
            response = connection.getresponse()
            raw = response.read(cap + 1)
            require(len(raw) <= cap, 'response bound')
            return response.status, {'content-type': response.getheader('content-type')}, raw
        finally:
            connection.close()

    def fixture(path, data=None):
        status, _, raw = post(path, json.dumps(data or {}).encode())
        require(status == 200, 'fixture failure: ' + path + ' ' + str(status))
        return json.loads(raw)

    challenge = fixture('/fixture/challenge', {'nodeId': node_id, 'publicKey': {
        'kty': 'OKP', 'crv': 'Ed25519', 'x': b64(node_key.public_key().public_bytes_raw())},
        'meshIp': '100.96.0.1', 'meshPort': 8789, 'agents': ['pilot']})
    fixture('/v1/nodes/complete', {'challengeId': challenge['challengeId'],
            'signature': b64(node_key.sign(challenge['signingPayload'].encode()))})
    delivery = fixture('/fixture/setup', {'nodeId': node_id, 'runtimeId': runtime_id,
        'transportPrivateKey': b64(transport_key.private_bytes(serialization.Encoding.DER,
             serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))})
    e, signed = delivery['envelope'], delivery['signedDelivery']
    ident = e['deliveryId']

    async def credentials():
        nonlocal auth_calls
        auth_calls += 1
        return Credentials('fixture-access', 'fixture-agent')

    async def send(**wire):
        nonlocal drop_reply
        require(wire['method'] == 'POST' and wire['url'].startswith('https://events.example.com/'), 'closed transport')
        require((wire['timeout'], wire['max_response_bytes'], wire['follow_redirects']) == (5, 8192, False), 'limits')
        path = wire['url'].removeprefix('https://events.example.com')
        response = await asyncio.to_thread(post, path, wire['body'], wire['headers'], 8192)
        proof = json.loads(wire['headers']['x-event-node-proof'])
        wires.append({'path': path, 'body': wire['body'].decode(), 'proof': proof, 'responseStatus': response[0]})
        body = json.loads(wire['body'])
        if path == '/v1/ack' and body['status'] == 'observed' and response[0] == 200 and drop_reply:
            drop_reply = False
            require(json.loads(response[2])['status'] == 'observed', 'real commit before reply loss')
            raise TimeoutError('real workerd committed observation; response deliberately lost')
        return response

    def gateway(store):
        cloud = CloudClient(origin='https://events.example.com', principal=e['principal'], agent=e['agent'],
            node_id=node_id, node_generation=e['nodeGeneration'], private_key=node_key,
            credentials=credentials, send=send)
        return Gateway(store, cloud, lambda mapping: NativeBridgeAdapter(mapping, bridge),
            audience=node_id, keys={'fixture-transport': transport_key.public_key()})

    with tempfile.TemporaryDirectory(prefix='native-workerd-local-') as temporary:
        state = Path(temporary).resolve() / 'private'
        store = Store(state)
        try:
            mapping = {key: e[key] for key in IDENTITY}
            mapping.update(nativeThreadId=witness['threadId'], leaseExpiresAt=time.time()+60)
            store.put_attachment(mapping)
            app = gateway(store)
            require(app.accept(signed['body'].encode(), signature=signed['headers']['x-event-signature'],
                audience=signed['headers']['x-event-audience'], key_id=signed['headers']['x-event-key-id'])['deliveryId'] == ident,
                'actual workerd signed delivery')
            require((await app.dispatch(ident))['status'] == 'submitted', 'real claim and registration')
            before = fixture('/fixture/read')
            require(len(before['slots']) == 1 and before['cloud']['attempts'][0]['state'] == 'submitted', 'retained slot')
            require(before['cloud']['manual_sources'][0]['observed_source_state_version'] is None, 'no early watermark')
            deadline = time.monotonic()+12
            while drop_reply:
                require(time.monotonic() < deadline and native_process.poll() is None, 'observation deadline')
                result = await app.reconcile(ident)
                if drop_reply:
                    await asyncio.sleep(.05)
            require(result['reason'] == 'native_observed_ack_pending', 'lost reply remains pending')
            original = copy.deepcopy(store.current_attempt(ident))
            request = original['native_request']
            observed = validate_receipt(request, original['input_recorded_receipt'], allow_input_recorded=True)
            require(UUID(observed['itemId']).version == 7 and observed['itemId'] != observed['turnId'], 'actual Core item')
            fixture('/fixture/alarm')
            settled = fixture('/fixture/read')
            require(not settled['slots'] and not settled['cloud']['slot_intents'], 'real slot drained')
            for table in ('attempts', 'deliveries', 'native_claims'):
                require(settled['cloud'][table][0]['state'] == 'observed', 'actual observed ' + table)
            require(json.loads(settled['cloud']['attempts'][0]['native_observed_ack_json']) == original['native_observed_ack'], 'immutable cloud ACK')
            require(settled['cloud']['manual_sources'][0]['observed_source_state_version'] == e['sourceStateVersion'], 'current watermark')
            require(settled['budget']['used'] == 1, 'one fixture authority charge')
            expiry_deadline = time.monotonic()+10
            while time.time_ns()//1_000_000 <= request['permitExpiresAt']:
                require(time.monotonic() < expiry_deadline, 'permit expiry phase')
                await asyncio.sleep(.05)
            nonce = bridge.nonce
            store.close()
            store = Store(state)
            app = gateway(store)
            require((await app.reconcile(ident))['status'] == 'observed', 'exact lost-reply recovery')
            require(bridge.nonce == nonce and bridge.attempts == {request['attemptId']: request}, 'no native repeat')
            require(wires[-2]['body'] == wires[-1]['body'] and wires[-2]['proof']['nonce'] != wires[-1]['proof']['nonce'], 'same ACK fresh proof')
            require(auth_calls == len(wires) and len(wires) == 4, 'credentials refreshed; one claim/two ACK phases/retry')
            require(fixture('/fixture/read') == settled, 'replay leaves real cloud state unchanged')
            require(store.status()['pending'] == 0, 'local capacity complete')
            require(model.request_counts['primary'] == 1 and model.request_counts['title'] <= 1
                and model.request_counts['unknown'] == 0, 'one mock-model primary')
            return {'result': 'PASS', 'qualification': 'fixture-qualified-native-local-workerd',
                'binarySha256': BINARY_SHA, 'nativeProcessRestarted': False, 'localStoreRestarted': True,
                'realModelCalls': 0, 'modelRequests': model.request_counts,
                'nativeRequest': request, 'fullInputRecordedReceipt': original['input_recorded_receipt'],
                'before': before, 'settled': settled, 'wire': wires, 'productionAdmissionProven': False,
                'mocks': ['qualified runtime/admin setup', 'Access edge/ Messaging credentials and budget',
                          'manual source publication', 'queue metrics', 'loopback instead of Mesh']}
        finally:
            store.close()


def main():
    require(hashlib.sha256(BINARY.read_bytes()).hexdigest() == BINARY_SHA, 'frozen native binary')
    spec = importlib.util.spec_from_file_location('coupled_qualifier', QUALIFIER)
    launcher = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(launcher)
    with open(str(OUTPUT) + '.broker.log', 'w') as log:
        # Trusted resolved CLI Node path, fixed broker, argument array, synthetic environment.
        broker = subprocess.Popen([NODE, str(BROKER)], stdout=subprocess.PIPE, stderr=log, text=True,  # nosec B603
            env={'PATH': '/usr/bin:/bin', 'HOME': tempfile.gettempdir(),
                 'FIXTURE_CLOUD_SOURCE': str(Path(args.cloud_source).resolve(strict=True)),
                 'FIXTURE_ESBUILD': str(Path(args.esbuild).resolve(strict=True)),
                 'FIXTURE_MINIFLARE': str(Path(args.miniflare).resolve(strict=True))}, cwd=tempfile.gettempdir())
        try:
            require(select.select([broker.stdout], [], [], 30)[0], 'broker startup deadline')
            address = json.loads(broker.stdout.readline())

            def callback(bridge, model, process, witness):
                try:
                    return asyncio.run(exercise(bridge, model, process, witness, address))
                finally:
                    model.release_primary.set()
            launcher.qualify_input_recorded = callback
            proof = launcher.qualify(BINARY, input_recorded=True)
            paths = [Path(__file__), BROKER, BROKER.with_name('coupled-workerd-worker.ts'), QUALIFIER,
                     *sorted((PACKAGE/'src/event_gateway').glob('*.py'))]
            proof['sourceSha256'] = {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}
            target = OUTPUT
            target.write_text(json.dumps(proof, indent=2)+'\n')
            print(json.dumps({'result': 'PASS', 'proof': str(target), 'productionAdmissionProven': False}))
        finally:
            broker.terminate()
            try:
                broker.wait(timeout=10)
            except subprocess.TimeoutExpired:
                broker.kill()
                broker.wait(timeout=5)


if __name__ == '__main__':
    main()
