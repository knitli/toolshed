"""Read-only native transport canary; never connects to the user's daemon."""
import argparse
import asyncio
import json
import os
from pathlib import Path
import subprocess
import tempfile

from event_gateway.codex import CodexRpc


async def probe(binary):
    binary = Path(binary)
    if not binary.is_absolute() or not binary.is_file():
        raise ValueError('--binary must identify an absolute executable path')
    temporary_root = '/private/tmp' if Path('/private/tmp').is_dir() else '/tmp'
    with tempfile.TemporaryDirectory(prefix='event-native-', dir=temporary_root) as directory:
        alias = Path(directory) / 'native.sock'
        # No auth tokens or user configuration inherited by the isolated server.
        environment = {'PATH': os.defpath, 'CODEX_HOME': directory}
        process = subprocess.Popen([str(binary), 'app-server', '--listen', f'unix://{alias}'],
                                   env=environment, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        canonical = identity = None
        try:
            async with asyncio.timeout(10):
                while not alias.exists():
                    if process.poll() is not None:
                        raise RuntimeError('isolated native server exited')
                    await asyncio.sleep(0.05)
            # Codex publishes a short canonical Unix socket via our unique alias.
            canonical = alias.resolve(strict=True)
            info = canonical.lstat()
            identity = info.st_dev, info.st_ino
            rpc = CodexRpc(str(canonical))
            diagnostics = await rpc.call('server/diagnostics', {})
            loaded = await rpc.call('thread/loaded/list', {})
            if diagnostics['process']['id'] != process.pid or loaded['data'] != []:
                raise RuntimeError('isolated native identity or empty-thread check failed')
            return {'version': rpc.user_agent.split('/', 1)[1].split(' ', 1)[0],
                    'userAgentProduct': rpc.user_agent.split(' ', 1)[0],
                    'pidMatches': True, 'loadedThreads': 0, 'modelTurns': 0}
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
            # Never remove the shared socket directory or a replaced socket.
            if canonical is not None and canonical.exists():
                info = canonical.lstat()
                if (info.st_dev, info.st_ino) == identity:
                    canonical.unlink()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', required=True, help='absolute path to the exact Codex executable')
    args = parser.parse_args()
    print(json.dumps(asyncio.run(probe(args.binary)), sort_keys=True))


if __name__ == '__main__':
    main()
