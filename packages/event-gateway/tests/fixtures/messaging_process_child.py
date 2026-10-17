"""Owned disposable gateway process with post-commit crash barriers."""
import asyncio
import json
import os
from pathlib import Path
import sys
import threading
import unittest

from test_messaging_workerd import LoopbackTransport, MessagingWorkerdTests


def record(path):
    """Keep attempted side effects observable after SIGKILL, even if an exception is caught."""
    with Path(path).open('ab', buffering=0) as stream:
        stream.write(b'called\n')
        os.fsync(stream.fileno())


def snapshot(gateway, delivery_id):
    store = gateway.store
    return {'attempt': store.current_attempt(delivery_id), 'delivery': store.delivery(delivery_id),
            'attemptCount': store.db.execute('SELECT COUNT(*) FROM attempts').fetchone()[0],
            'pending': store.list_pending(), 'reconcilable': store.list_reconcilable(),
            'nativeCalls': gateway.fixture_native_calls}


async def run(config, phase):
    case = unittest.TestCase()
    transport = LoopbackTransport(config['address'])
    send = transport.send
    delivery_id = config['seed']['envelope']['deliveryId']

    def barrier():
        print(json.dumps({'phase': phase, 'pid': os.getpid(), 'claims': transport.claims,
                          'snapshot': snapshot(gateway, delivery_id)}), flush=True)
        # The parent kills this process; block outside SQLite transactions and asyncio cancellation.
        threading.Event().wait(60)
        raise TimeoutError('parent did not kill gateway at crash barrier')

    async def observed_send(**wire):
        record(config['httpLog'])
        response = await send(**wire)
        if phase == 'response':
            case.assertEqual(response[0], 200)
            case.assertEqual(json.loads(response[2])['status'], 'admitted')
            barrier()
        return response

    transport.send = observed_send
    try:
        gateway = MessagingWorkerdTests.gateway(case, Path(config['ledger']), config['address'], transport, config['seed'])

        def native_forbidden(*_):
            record(config['nativeLog'])
            gateway.fixture_native_calls.append(True)
            raise AssertionError('native adapter must never be constructed')

        gateway.adapter_factory = native_forbidden
        if phase == 'intent':
            begin = gateway.store._begin_messaging_claim_history

            def begin_then_stop(delivery_id):
                result = begin(delivery_id)
                barrier()
                return result

            gateway.store._begin_messaging_claim_history = begin_then_stop
        elif phase == 'admission':
            record_admission = gateway.store._record_messaging_admission_history

            def record_then_stop(delivery_id, admission, *, node_id):
                result = record_admission(delivery_id, admission, node_id=node_id)
                barrier()
                return result

            gateway.store._record_messaging_admission_history = record_then_stop
        elif phase not in ('response', 'restart'):
            raise ValueError('unknown crash phase')
        before = snapshot(gateway, delivery_id)
        result = await gateway._claim_messaging_history(delivery_id)
        if phase != 'restart':
            raise AssertionError('gateway missed requested crash barrier')
        repeated = await gateway._claim_messaging_history(delivery_id)
        MessagingWorkerdTests.assert_inert(case, gateway, config['seed'])
        print(json.dumps({'phase': phase, 'pid': os.getpid(), 'claims': transport.claims,
                          'before': before, 'after': snapshot(gateway, delivery_id),
                          'result': result, 'repeated': repeated}), flush=True)
    finally:
        case.doCleanups()


if __name__ == '__main__':
    asyncio.run(run(json.loads(Path(sys.argv[1]).read_text()), sys.argv[2]))
