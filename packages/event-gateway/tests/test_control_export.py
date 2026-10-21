"""The control exporter authenticates every source before evaluating schemas."""
import hashlib
import json
from pathlib import Path
import re
import shutil

# Test-only subprocesses invoke fixed git/node source-pin probes.
import subprocess  # nosec B404
import tempfile
import unittest


PACKAGE = Path(__file__).resolve().parents[1]
EXPORTER = PACKAGE / 'contracts/event-control-v1/export.mjs'
NEW_SOURCES = (
    'github/host-storage-version.ts',
    'messaging/protocol-v2.ts',
    'messaging/preparation.ts',
    'messaging/delivery-authority.ts',
    'messaging/materialization.ts',
    'messaging/consumer-authority.ts',
    'github/conversion-manifest-store.ts',
    'github/conversion-planning.ts',
    'github/initial-conversion.ts',
    'github/initial-watch-host-store.ts',
    'github/initial-watch-preparation.ts',
    'github/material-cache.ts',
    'github/material-delete.ts',
    'github/material-read-contract.ts',
    'github/actor-policy.ts',
    'github/material-read.ts',
    'github/reconciliation-internal.ts',
    'github/reconciliation-store.ts',
    'github/reconciliation-planner.ts',
    'github/initial-plan-material-read.ts',
    'github/source-reference-contract.ts',
    'github/source-reference-store.ts',
    'quarantine-inventory.ts',
    'quarantine-inventory-contract.ts',
    'quarantine-inventory-validation.ts',
    'assigned-stock-contract.ts',
    'github/event-read-contract.ts',
    '../../authority/src/text.ts',
    '../../gatekeeper-messaging/src/mailbox.ts',
    '../../gatekeeper-messaging/src/event-bridge.ts',
    '../../gatekeeper-messaging/src/message-preparation.ts',
    '../../gatekeeper-messaging/src/event-authority-contract.ts',
    '../../gatekeeper-messaging/src/event-authority.ts',
    '../../gatekeeper-messaging/src/source-preparation.ts',
    '../../gatekeeper-messaging/src/event-wake-budget.ts',
    '../../gatekeeper-messaging/src/message-consumer-admission.ts',
    '../../gatekeeper-messaging/src/message-route-control.ts',
    '../../gatekeeper-messaging/src/message-route-control-contract.ts',
    '../../gatekeeper-messaging/src/message-route-owner-proof.ts',
    '../../gatekeeper-messaging/src/message-attempt-settlement.ts',
    '../../gatekeeper-messaging/src/activation.ts',
    '../../gatekeeper-messaging/src/orders.ts',
    '../../gatekeeper-messaging/src/registry.ts',
    '../../gatekeeper-messaging/src/tasks.ts',
    '../../gatekeeper-messaging/src/model.ts',
    '../../gatekeeper-messaging/src/receipts.ts',
    '../../gatekeeper-messaging/src/credentials.ts',
    '../../gatekeeper-messaging/src/presence.ts',
    '../../gatekeeper-messaging/src/access-audiences.ts',
    '../../gatekeeper-messaging/src/order-acts.ts',
    '../../gatekeeper-messaging/src/grant-acts.ts',
    '../../gatekeeper-messaging/src/acts.ts',
    '../../gatekeeper-messaging/src/presence-host.ts',
    '../../gatekeeper-messaging/src/core-acts.ts',
    '../../gatekeeper-messaging/src/scopes.ts',
    '../../gatekeeper-messaging/src/authority-contract.ts',
    '../../gatekeeper-messaging/src/enforcement.ts',
    '../../gatekeeper-messaging/src/auth.ts',
    '../../../scripts/deploy.ts',
    '../../authority/src/act.ts',
    '../../authority/src/canonical.ts',
    '../../authority/src/scope.ts',
    '../../authority/src/task.ts',
    '../../authority/src/contract-kit.ts',
    '../../authority/src/snapshot.ts',
    '../../authority/src/credential-chain.ts',
    '../../authority/src/human-proof.ts',
    '../../authority/src/floor.ts',
    '../../authority/src/webauthn.ts',
    '../../authority/src/contracts.ts',
    '../../authority/src/render.ts',
)


class ControlExportTests(unittest.TestCase):
    def test_new_sources_are_checked_before_evaluation(self):
        source = EXPORTER.read_text()
        names = re.findall(r"'([^']+)'", source.split('const names = [', 1)[1].split('];', 1)[0])
        self.assertEqual(len(names), 108)
        self.assertEqual(len(set(names)), 108)
        for name in NEW_SOURCES:
            self.assertIn(name, names)
        git = shutil.which("git")
        node = shutil.which("node")
        self.assertIsNotNone(git, "git is required for the source pin test")
        self.assertIsNotNone(node, "node is required for the source pin test")
        # Resolved executables, fixed arguments, no shell; inspect this checkout only.
        git_dir = subprocess.check_output(  # nosec B603
            [git, '-C', str(PACKAGE), 'rev-parse', '--absolute-git-dir'], text=True).strip()
        revision = subprocess.check_output(  # nosec B603
            [git, '-C', str(PACKAGE), 'rev-parse', 'HEAD'], text=True).strip()
        with tempfile.TemporaryDirectory(prefix='control-export-test-') as directory:
            root = Path(directory).resolve()
            (root / '.git').write_text(f'gitdir: {git_dir}\n')
            os_root = root / 'apps/os'
            base = os_root / 'packages/event-runtime/src'
            output = root / 'candidate'
            output.mkdir()
            shutil.copyfile(EXPORTER, output / 'export.mjs')
            zod = root / 'zod'
            zod.mkdir()
            (zod / 'package.json').write_text('{"version":"test"}')
            (zod / 'index.mjs').write_text("throw Error('SCHEMA_EVALUATED');\n")
            sources = {}
            for name in names:
                path = (base / name).resolve()
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("throw Error('SCHEMA_EVALUATED');\n")
                sources[path.relative_to(root).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
            manifest = {'revision': revision, 'zodVersion': 'test', 'sources': sources}
            pin = output / 'manifest.json'
            pin.write_text(json.dumps(manifest))

            def run():
                # Resolved executable, fixed arguments, no shell; owned disposable fixture.
                return subprocess.run(  # nosec B603
                    [node, str(output / 'export.mjs'), str(os_root),
                     str(zod / 'index.mjs'), '--check'],
                    text=True, capture_output=True, check=False, timeout=10)

            # Matching pins reach evaluation, so the negative checks cannot pass vacuously.
            result = run()
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('SCHEMA_EVALUATED', result.stderr)
            for name in NEW_SOURCES:
                path = base / name
                original = path.read_bytes()
                key = path.resolve().relative_to(root).as_posix()
                for mutation in ('changed', 'missing-file', 'missing-pin'):
                    with self.subTest(source=name, mutation=mutation):
                        if mutation == 'changed':
                            path.write_bytes(original + b'\n')
                        elif mutation == 'missing-file':
                            path.unlink()
                        else:
                            pin.write_text(json.dumps({**manifest, 'sources': {
                                k: v for k, v in sources.items() if k != key}}))
                        result = run()
                        self.assertNotEqual(result.returncode, 0)
                        self.assertNotIn('SCHEMA_EVALUATED', result.stderr)
                        self.assertIn('ENOENT' if mutation == 'missing-file'
                                      else 'source pin mismatch before evaluation', result.stderr)
                        path.write_bytes(original)
                        pin.write_text(json.dumps(manifest))


if __name__ == '__main__':
    unittest.main()
