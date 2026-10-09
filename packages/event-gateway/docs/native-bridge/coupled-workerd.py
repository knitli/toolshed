#!/usr/bin/env python3
"""Disposable genuine native + production local + workerd, with explicit authority fixtures."""
import asyncio
import argparse
import base64
import copy
from contextlib import ExitStack
import hashlib
import http.client
import importlib.util
import importlib.metadata
import json
from pathlib import Path
import select
import subprocess  # nosec B404 - Controlled fixture launches the explicit Node executable.
import sys
import tempfile
import time
from uuid import UUID, uuid4

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('package', 'qualifier', 'binary', 'binary-sha', 'node', 'cloud-source', 'esbuild', 'miniflare', 'output'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--installed', action='store_true', help='Use the installed wheel, without adding source imports')
    parser.add_argument('--restart-native', action='store_true', help='Recover an expired v3 receipt after native process restart')
    parser.add_argument('--terminal-no-start', action='store_true', help='Qualify actual terminal refusal and durable cloud settlement')
    parser.add_argument('--forget-terminal', action='store_true', help='Restart native before terminal recovery; unknown must stay fenced')
    args = parser.parse_args()
    if args.restart_native and args.terminal_no_start:
        parser.error('--restart-native and --terminal-no-start are mutually exclusive')
    if args.forget_terminal and not args.terminal_no_start:
        parser.error('--forget-terminal requires --terminal-no-start')
    PACKAGE, QUALIFIER, BINARY = (Path(x).resolve(strict=True) for x in (args.package, args.qualifier, args.binary))
    BINARY_SHA, NODE = args.binary_sha, str(Path(args.node).resolve(strict=True))
    BROKER = Path(__file__).with_name('coupled-workerd-broker.mjs')
    OUTPUT = Path(args.output).resolve()
    if not args.installed:
        sys.path.insert(0, str(PACKAGE / 'src'))
    # Package selection above deliberately precedes the imports used by this fixture.
    from cryptography.hazmat.primitives import serialization  # noqa: E402
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
    import event_gateway  # noqa: E402
    from event_gateway.cloud import CloudClient, Credentials  # noqa: E402
    from event_gateway.gateway import Gateway  # noqa: E402
    from event_gateway.native import NativeBridgeAdapter, validate_receipt  # noqa: E402
    from event_gateway.store import Store, IDENTITY  # noqa: E402


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def b64(value):
    return base64.urlsafe_b64encode(value).rstrip(b'=').decode()


async def wait_for_permit_expiry(request, native_process):
    deadline = time.monotonic() + 10
    while time.time_ns() // 1_000_000 <= request['permitExpiresAt']:
        require(time.monotonic() < deadline and native_process.poll() is None,
            'native delay fixture exceeded deadline or native process stopped')
        await asyncio.sleep(.02)


def verify_native_restart(old_process, native_process, witness, new_witness, launcher):
    checks = {'oldTuiStopped': old_process.poll() is not None,
        'oldBackendStopped': not launcher.alive(witness['backendPid']),
        'tuiPidRotated': native_process.pid != old_process.pid,
        **{key + 'Rotated': new_witness[key] != witness[key] for key in (
            'clientId', 'serverInstanceId', 'backendPid', 'threadId')}}
    require(all(checks.values()), 'old native processes stopped and all restart identities rotated')
    return checks


async def restart_native(bridge, model, native_process, witness, launcher, resources, request):
    wire_request = {key: value for key, value in request.items() if key != 'receiptVersion'}
    require(request['receiptVersion'] == 3, 'explicit durable reader identity')
    deadline = time.monotonic() + 12
    while True:
        recorded = bridge.receipt(wire_request)
        require(recorded['status'] in ('started', 'inputRecorded'), 'native observation state')
        if recorded['status'] == 'inputRecorded' and model.request_counts['primary'] == 1:
            break
        require(time.monotonic() < deadline and native_process.poll() is None, 'native input deadline')
        await asyncio.sleep(.05)
    model.release_primary.set()
    deadline = time.monotonic() + 12
    while time.time_ns() // 1_000_000 <= request['permitExpiresAt'] or not bridge.challenge()['eligible']:
        require(time.monotonic() < deadline and native_process.poll() is None, 'expiry and idle wait')
        await asyncio.sleep(.05)
    old_process = native_process
    native_args = list(old_process.args)
    root = Path(native_args[native_args.index('-C') + 1])
    launcher.stop_process(old_process, witness['backendPid'])
    bridge.close()
    bridge, native_process, new_witness = resources.enter_context(
        launcher.native_client(native_args, root, receipt_version=3))
    verify_native_restart(old_process, native_process, witness, new_witness, launcher)
    return bridge, native_process, new_witness, recorded


def require_observed_settlement(settled, original, envelope):
    require(not settled['slots'] and not settled['cloud']['slot_intents'], 'real slot drained')
    for table in ('attempts', 'deliveries', 'native_claims'):
        require(settled['cloud'][table][0]['state'] == 'observed', 'actual observed ' + table)
    require(json.loads(settled['cloud']['attempts'][0]['native_observed_ack_json']) == original['native_observed_ack'], 'immutable cloud ACK')
    require(settled['cloud']['manual_sources'][0]['observed_source_state_version'] == envelope['sourceStateVersion'], 'current watermark')
    require(settled['budget']['used'] == 1, 'one fixture authority charge')


async def await_observed_ack(app, ident, native_process, reply_pending):
    deadline = time.monotonic()+12
    while reply_pending():
        require(time.monotonic() < deadline and native_process.poll() is None, 'observation deadline')
        result = await app.reconcile(ident)
        if reply_pending():
            await asyncio.sleep(.05)
    return result


async def exercise(bridge, model, native_process, witness, address, launcher):
    node_key, transport_key = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    node_id, runtime_id = str(uuid4()), str(uuid4())
    wires, auth_calls, drop_reply = [], 0, True
    terminal_receipts = []

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
        if args.terminal_no_start and path == '/v1/dispatch/settle-no-start' and response[0] == 200 and drop_reply:
            drop_reply = False
            require(json.loads(response[2])['status'] == 'not_started', 'real no-start commit before reply loss')
            raise TimeoutError('real workerd committed no-start; response deliberately lost')
        if path == '/v1/ack' and body['status'] == 'observed' and response[0] == 200 and drop_reply:
            drop_reply = False
            require(json.loads(response[2])['status'] == 'observed', 'real commit before reply loss')
            raise TimeoutError('real workerd committed observation; response deliberately lost')
        return response

    class DelayedNativeAdapter(NativeBridgeAdapter):
        async def submit(self, request):
            if not terminal_receipts:
                require(store.current_attempt(ident)['state'] == 'submitting', 'request durable before native delay')
                require(store.current_attempt(ident)['native_request'] == request, 'exact durable native identity')
                # Fixture delay after durable submission intent; the actual native backend refuses expiry.
                await wait_for_permit_expiry(request, native_process)
                fresh = await asyncio.to_thread(bridge.challenge)
                require(all(fresh[k] == request[k] for k in (
                    'clientId', 'generation', 'serverInstanceId', 'serverGeneration', 'threadId')),
                    'unchanged selected native identity')
                receipt = await super().submit(request)
                require(receipt['outcome']['status'] == 'terminalNotStarted', 'actual terminal no-start required')
                require(receipt['outcome']['reason'] == 'permitExpired', 'native expired admitted permit')
                terminal_receipts.append(receipt)
                raise TimeoutError('fixture loses actual native terminal reply before local persistence')
            return await super().submit(request)

    def gateway(store):
        cloud = CloudClient(origin='https://events.example.com', principal=e['principal'], agent=e['agent'],
            node_id=node_id, node_generation=e['nodeGeneration'], private_key=node_key,
            credentials=credentials, send=send)
        adapter = DelayedNativeAdapter if args.terminal_no_start else NativeBridgeAdapter
        return Gateway(store, cloud, lambda mapping: adapter(mapping, bridge),
            audience=node_id, keys={'fixture-transport': transport_key.public_key()})

    with tempfile.TemporaryDirectory(prefix='native-workerd-local-') as temporary, ExitStack() as resources:
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
            if args.terminal_no_start:
                require((await app.dispatch(ident))['status'] == 'ambiguous', 'lost native reply fences attempt')
                original = copy.deepcopy(store.current_attempt(ident))
                require(original['receipt'] is None, 'terminal reply not persisted before recovery')
                before = fixture('/fixture/read')
                require(before['budget']['used'] == 1 and len(before['slots']) == 1, 'admission charged and slot retained')
                if args.forget_terminal:
                    native_args = list(native_process.args)
                    root = Path(native_args[native_args.index('-C') + 1])
                    old_process = native_process
                    launcher.stop_process(native_process, witness['backendPid'])
                    bridge.close()
                    bridge, native_process, new_witness = resources.enter_context(
                        launcher.native_client(native_args, root, receipt_version=3))
                    restart_checks = verify_native_restart(old_process, native_process, witness, new_witness, launcher)
                    store.close()
                    store = Store(state)
                    app = gateway(store)
                    native_exchanges = []
                    exchange = bridge.exchange

                    def record_exchange(body, seconds):
                        sent = {'nonce': bridge.nonce + 1, **copy.deepcopy(body)}
                        response = exchange(body, seconds)
                        native_exchanges.append({'sent': sent, 'received': copy.deepcopy(response)})
                        return response

                    bridge.exchange = record_exchange
                    wire_request = {key: value for key, value in original['native_request'].items() if key != 'receiptVersion'}
                    for index in range(3):
                        nonce = bridge.nonce
                        require((await app.reconcile(ident))['status'] == 'ambiguous', 'missing terminal remains unknown')
                        require(len(native_exchanges) == index + 1 and not bridge.closed, 'unknown requires successful native communication')
                        recorded = native_exchanges[-1]
                        require(recorded['sent'] == {'nonce': nonce + 1, 'receipt': wire_request}, 'exact read-only recovery frame')
                        require(recorded['received']['nonce'] == nonce + 1 and bridge.nonce == nonce + 1, 'actual matching response nonce')
                        require(validate_receipt(original['native_request'], recorded['received']['receipt'], allow_input_recorded=True)
                            == {'status': 'unknown'}, 'actual native unknown receipt with exact original identity')
                        require((await app.dispatch(ident))['status'] == 'ambiguous', 'unknown never dispatches replacement')
                    after = store.current_attempt(ident)
                    require(after['attempt_id'] == original['attempt_id'] and after['receipt'] is None, 'unknown keeps exact original fence')
                    require(len(wires) == 1 and len(bridge.attempts) == 1, 'unknown issues no new cloud claim or native start')
                    require(fixture('/fixture/read') == before, 'unknown leaves coordinator unchanged')
                    require(all(count == 0 for count in model.request_counts.values()), 'unknown causes no model traffic')
                    return {'result': 'PASS', 'qualification': 'fixture-qualified-terminal-lost-on-native-restart',
                        'binarySha256': BINARY_SHA, 'productionAdmissionProven': False,
                        'nativeProcessRestarted': all(restart_checks.values()), 'restartChecks': restart_checks,
                        'unknownNeverRetriesProven': True,
                        'nativeExchanges': native_exchanges, 'nativeBridgeOpen': not bridge.closed,
                        'original': original, 'actualTerminalBeforeLoss': terminal_receipts[0], 'after': after,
                        'before': before, 'wire': wires, 'modelRequests': model.request_counts,
                        'realModelCalls': 0, 'nativeTerminalReceiptDurableAcrossNativeRestart': False}
                nonce = bridge.nonce
                store.close()
                store = Store(state)
                app = gateway(store)
                require((await app.reconcile(ident))['status'] == 'settlement_pending', 'lost settlement reply durable')
                pending = copy.deepcopy(store.current_attempt(ident))
                require(pending['receipt']['outcome'] == {**terminal_receipts[0]['outcome'], 'replayed': True}, 'actual exact read-only terminal recovery')
                require(bridge.nonce == nonce + 1, 'recovery issues one receipt lookup')
                fixture('/fixture/alarm')
                settled = fixture('/fixture/read')
                require(settled['budget']['used'] == 1, 'original budget remains charged')
                require(len(settled['slots']) == 1, 'pending delivery retains its actual slot')
                require(settled['cloud']['attempts'][0]['state'] == 'not_started', 'exact old attempt retired')
                require(settled['cloud']['native_claims'][0]['permit_id'] == original['admission']['permitId']
                    and settled['cloud']['native_claims'][0]['state'] == 'not_started', 'exact old permit retired')
                store.close()
                store = Store(state)
                app = gateway(store)
                nonce = bridge.nonce
                require((await app.reconcile(ident))['status'] == 'queued', 'exact settlement replay creates fresh waiting attempt')
                require(bridge.nonce == nonce, 'settlement recovery performs no native operation')
                require(wires[-2]['body'] == wires[-1]['body'] and wires[-2]['proof']['nonce'] != wires[-1]['proof']['nonce'], 'same settlement fresh proof')
                require(fixture('/fixture/read') == settled, 'settlement replay leaves coordinator unchanged')
                require((await app.dispatch(ident))['status'] == 'submitted', 'one legitimate fresh native attempt')
                replacement = copy.deepcopy(store.current_attempt(ident))
                require(replacement['attempt_id'] != original['attempt_id']
                    and replacement['admission']['permitId'] != original['admission']['permitId'], 'fresh attempt and permit')
                await app.dispatch(ident)
                require(len([w for w in wires if w['path'] == '/v1/dispatch/claim']) == 2, 'exactly original and one fresh claim')
                require(len(bridge.attempts) == 2, 'only original refused start and one fresh start')
                deadline = time.monotonic() + 12
                while model.request_counts['primary'] != 1:
                    require(time.monotonic() < deadline and native_process.poll() is None, 'fresh native model deadline')
                    await asyncio.sleep(.02)
                require(model.request_counts['unknown'] == 0, 'no unknown mock request')
                after = fixture('/fixture/read')
                require(after['budget']['used'] == 2, 'original charge retained plus one fresh charge')
                require(after['cloud']['no_start_settlements'] == settled['cloud']['no_start_settlements']
                    and len(after['cloud']['no_start_settlements']) == 1
                    and json.loads(after['cloud']['no_start_settlements'][0]['result_json'])['evidence'] == pending['evidence'],
                    'exact immutable terminal evidence survives fresh attempt')
                old_attempts = [row for row in after['cloud']['attempts'] if row['attempt_id'] == original['attempt_id']]
                require(len(old_attempts) == 1 and old_attempts[0]['state'] == 'not_started'
                    and old_attempts[0]['permit_id'] == original['admission']['permitId'], 'old attempt and permit remain retired')
                fresh_attempts = [row for row in after['cloud']['attempts'] if row['attempt_id'] == replacement['attempt_id']]
                require(len(after['cloud']['attempts']) == 2 and len(fresh_attempts) == 1
                    and fresh_attempts[0]['state'] == 'submitted', 'only fresh attempt is submitted')
                require(len(after['cloud']['native_claims']) == 1
                    and after['cloud']['native_claims'][0]['attempt_id'] == replacement['attempt_id']
                    and after['cloud']['native_claims'][0]['permit_id'] == replacement['admission']['permitId']
                    and after['cloud']['native_claims'][0]['state'] == 'submitted', 'current claim belongs to fresh permit')
                require(after['slots'] == settled['slots'] and len(after['slots']) == 1
                    and after['cloud']['deliveries'][0]['state'] == 'submitted'
                    and after['cloud']['manual_sources'][0]['observed_source_state_version'] is None,
                    'submitted delivery retains capacity without observation')
                return {'result': 'PASS', 'qualification': 'fixture-qualified-terminal-no-start-local-workerd',
                    'binarySha256': BINARY_SHA, 'productionAdmissionProven': False,
                    'nativeTerminalReceiptDurableAcrossNativeRestart': False, 'nativeProcessRestarted': False,
                    'oldStartNoStartSettlementProven': True, 'original': original, 'terminalReceipt': terminal_receipts[0],
                    'pending': pending, 'before': before, 'settled': settled, 'replacement': replacement, 'after': after,
                    'wire': wires, 'modelRequests': model.request_counts, 'realModelCalls': 0,
                    'mocks': ['post-persistence submission delay', 'lost native and cloud replies', 'qualified runtime/admin setup',
                        'Access/Messaging identity and budget', 'manual source publication', 'queue metrics', 'loopback instead of Mesh']}
            require((await app.dispatch(ident))['status'] == 'submitted', 'real claim and registration')
            before = fixture('/fixture/read')
            require(len(before['slots']) == 1 and before['cloud']['attempts'][0]['state'] == 'submitted', 'retained slot')
            require(before['cloud']['manual_sources'][0]['observed_source_state_version'] is None, 'no early watermark')
            restart = None
            if args.restart_native:
                # Observe Core independently; the gateway must recover this receipt only
                # from the new native process, never from a pre-restart local receipt.
                prior = store.current_attempt(ident)
                request = prior['native_request']
                old_process = native_process
                bridge, native_process, new_witness, recorded = await restart_native(
                    bridge, model, native_process, witness, launcher, resources, request)
                store.close()
                store = Store(state)
                app = gateway(store)
                restored = store.current_attempt(ident)
                require(restored['native_request'] == request and not restored.get('input_recorded_receipt'),
                        'only submitted identity persisted before restart')
                require(await NativeBridgeAdapter(mapping, bridge).check() == 'unavailable', 'old attachment unavailable')
                restart = {'oldPid': old_process.pid, 'newPid': native_process.pid,
                           'oldWitness': witness, 'newWitness': new_witness,
                           'expiredBeforeRecovery': True, 'oldAttachmentUnavailable': True,
                           'gatewayReceiptAbsentBeforeRecovery': True, 'independentlyRecorded': recorded}
            result = await await_observed_ack(app, ident, native_process, lambda: drop_reply)
            require(result['reason'] == 'native_observed_ack_pending', 'lost reply remains pending')
            original = copy.deepcopy(store.current_attempt(ident))
            request = original['native_request']
            observed = validate_receipt(request, original['input_recorded_receipt'], allow_input_recorded=True)
            if restart is not None:
                require(observed == restart['independentlyRecorded'], 'exact Core receipt recovered after native restart')
            require(UUID(observed['itemId']).version == 7 and observed['itemId'] != observed['turnId'], 'actual Core item')
            fixture('/fixture/alarm')
            settled = fixture('/fixture/read')
            require_observed_settlement(settled, original, e)
            expiry_deadline = time.monotonic()+10
            while time.time_ns()//1_000_000 <= request['permitExpiresAt']:
                require(time.monotonic() < expiry_deadline, 'permit expiry phase')
                await asyncio.sleep(.05)
            nonce = bridge.nonce
            store.close()
            store = Store(state)
            app = gateway(store)
            require((await app.reconcile(ident))['status'] == 'observed', 'exact lost-reply recovery')
            wire_request = {key: value for key, value in request.items() if key != 'receiptVersion'}
            require(bridge.nonce == nonce and bridge.attempts == {request['attemptId']: wire_request}, 'no native repeat')
            require(wires[-2]['body'] == wires[-1]['body'] and wires[-2]['proof']['nonce'] != wires[-1]['proof']['nonce'], 'same ACK fresh proof')
            require(auth_calls == len(wires) and len(wires) == 4, 'credentials refreshed; one claim/two ACK phases/retry')
            require(fixture('/fixture/read') == settled, 'replay leaves real cloud state unchanged')
            require(store.status()['pending'] == 0, 'local capacity complete')
            require(model.request_counts['primary'] == 1 and model.request_counts['title'] <= 1
                and model.request_counts['unknown'] == 0, 'one mock-model primary')
            return {'result': 'PASS', 'qualification': 'fixture-qualified-native-local-workerd',
                'binarySha256': BINARY_SHA, 'nativeProcessRestarted': restart is not None, 'localStoreRestarted': True,
                'restart': restart, 'installedPackage': args.installed,
                'oldStartNoStartSettlementProven': False,
                'realModelCalls': 0, 'modelRequests': model.request_counts,
                'nativeRequest': request, 'fullInputRecordedReceipt': original['input_recorded_receipt'],
                'before': before, 'settled': settled, 'wire': wires, 'productionAdmissionProven': False,
                'mocks': ['qualified runtime/admin setup', 'Access edge/ Messaging credentials and budget',
                          'manual source publication', 'queue metrics', 'loopback instead of Mesh']}
        finally:
            store.close()


def main():
    if args.installed:
        distribution = importlib.metadata.distribution('knitli-event-gateway')
        require('event_gateway/native_reader.py' in {str(file) for file in distribution.files or ()},
                'reader must belong to an installed wheel, not an editable source checkout')
        require(Path(event_gateway.__file__).resolve() ==
                Path(distribution.locate_file('event_gateway/__init__.py')).resolve(),
                'package import must match installed distribution')
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
                    return asyncio.run(exercise(bridge, model, process, witness, address, launcher))
                finally:
                    model.release_primary.set()
            launcher.qualify_input_recorded = callback
            proof = launcher.qualify(BINARY, input_recorded=True, receipt_version=3 if args.restart_native or args.terminal_no_start else 2)
            paths = [Path(__file__), BROKER, BROKER.with_name('coupled-workerd-worker.ts'),
                     BROKER.with_name('coupled-workerd-source-hashes.mjs'), QUALIFIER,
                     *sorted(Path(event_gateway.__file__).parent.glob('*.py'))]
            proof['cloudBundle'] = address['bundle']
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
