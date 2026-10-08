"""Run canonical candidate semantic verdicts with the installed gateway validator.

This explicit corpus input is a qualification tool, never a snapshot updater.
"""
import argparse
import json
from pathlib import Path

from event_gateway.protocol import (
    ProtocolError, parse_envelope, parse_acknowledgment, derive_delivery_id,
    matches_delivery_id, acknowledgment_matches_delivery,
    acknowledgment_advances_current_watermark,
)


def check(path):
    vectors = json.loads(Path(path).read_text())
    if vectors['schemaVersion'] != 1:
        raise ValueError('unsupported semantic corpus version')
    parsers = {'envelope': parse_envelope, 'acknowledgment': parse_acknowledgment}
    for vector in vectors['rawCases']:
        verdict = None
        try:
            parsers[vector['kind']](vector['raw'].encode('utf-8'), vector['nowMs'])
        except ProtocolError as error:
            verdict = error.code
        if verdict != vector['expectedError']:
            raise AssertionError((vector['case'], verdict))
    for vector in vectors['digestCases']:
        envelope = vector['envelope']
        if (derive_delivery_id(envelope) != vector['expectedDigest']
                or matches_delivery_id(envelope) is not vector['matches']):
            raise AssertionError(vector['case'])
    for vector in vectors['bindingCases']:
        envelope, ack = vector['envelope'], vector['acknowledgment']
        if (acknowledgment_matches_delivery(envelope, ack) is not vector['matches']
                or acknowledgment_advances_current_watermark(
                    envelope, ack, vector['currentSourceStateVersion']) is not vector['advances']):
            raise AssertionError(vector['case'])
    count = sum(len(vectors[key]) for key in ('rawCases', 'digestCases', 'bindingCases'))
    print(f'PASS: {count} canonical semantic verdicts')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('corpus', type=Path)
    check(parser.parse_args().corpus)
