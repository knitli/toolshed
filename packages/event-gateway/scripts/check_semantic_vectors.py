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
    assert vectors['schemaVersion'] == 1
    parsers = {'envelope': parse_envelope, 'acknowledgment': parse_acknowledgment}
    for vector in vectors['rawCases']:
        verdict = None
        try:
            parsers[vector['kind']](vector['raw'].encode('utf-8'), vector['nowMs'])
        except ProtocolError as error:
            verdict = error.code
        assert verdict == vector['expectedError'], (vector['case'], verdict)
    for vector in vectors['digestCases']:
        envelope = vector['envelope']
        assert derive_delivery_id(envelope) == vector['expectedDigest'], vector['case']
        assert matches_delivery_id(envelope) is vector['matches'], vector['case']
    for vector in vectors['bindingCases']:
        envelope, ack = vector['envelope'], vector['acknowledgment']
        assert acknowledgment_matches_delivery(envelope, ack) is vector['matches'], vector['case']
        assert acknowledgment_advances_current_watermark(
            envelope, ack, vector['currentSourceStateVersion']) is vector['advances'], vector['case']
    count = sum(len(vectors[key]) for key in ('rawCases', 'digestCases', 'bindingCases'))
    print(f'PASS: {count} canonical semantic verdicts')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('corpus', type=Path)
    check(parser.parse_args().corpus)
