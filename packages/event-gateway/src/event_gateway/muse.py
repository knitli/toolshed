"""Owner-reported Muse monitor contract; never starts a monitor or grants authority."""

from copy import deepcopy
import re
import shlex
from urllib.parse import urlsplit


class MuseMonitorError(ValueError):
    """A safe validation code, without command, URL, or token contents."""

    def __init__(self):
        """Expose a safe monitor validation code."""
        self.code = 'invalid_muse_monitor'
        super().__init__(self.code)


_FIELDS = frozenset(('description', 'command', 'ws', 'ws_subprotocols', 'persistent',
                     'timeout_ms', 'wake_delay_ms', 'show_lines'))
_TOKEN = re.compile(r"[!#$%&'*+\-.^_`|~0-9A-Za-z]+\Z")


def _milliseconds(value, *, zero=False):
    return (isinstance(value, int) and not isinstance(value, bool)
            and (1000 <= value <= 1800000 or zero and value == 0))


def _valid_websocket_uri(uri):
    # urlsplit removes some raw controls instead of rejecting them.
    if any(char.isspace() or ord(char) < 32 or ord(char) == 127
           or char in '<>\"{}|\\^`' for char in uri):
        return False
    try:
        parsed = urlsplit(uri)
        authority = parsed.netloc
        valid = (parsed.scheme in ('ws', 'wss') and bool(parsed.hostname)
                 and '#' not in uri and '@' not in authority
                 and re.search(r'%(?![0-9A-Fa-f]{2})', authority) is None)
        if authority.startswith('['):
            suffix = authority[authority.index(']') + 1:]
            valid = valid and (suffix in ('', ':') or suffix.startswith(':') and suffix[1:].isdigit())
        # Reading port also rejects malformed/out-of-range URL ports.
        _ = parsed.port
    except ValueError:
        valid = False
    return valid


def normalize_monitor(value):
    """Validate the reported input contract and materialize applicable defaults."""
    # A persistent monitor has no timeout key. A command is shell source, not argv;
    # use command_monitor when constructing it from trusted executable/arguments.
    # Neither this value nor a native tool return is a delivery receipt.
    if (not isinstance(value, dict) or set(value) - _FIELDS
            or not isinstance(value.get('description'), str)
            or ('command' in value) == ('ws' in value)):
        raise MuseMonitorError()
    source = 'command' if 'command' in value else 'ws'
    if not isinstance(value[source], str) or '\x00' in value[source]:
        raise MuseMonitorError()
    if source == 'ws' and not _valid_websocket_uri(value['ws']):
        raise MuseMonitorError()
    if 'ws_subprotocols' in value:
        protocols = value['ws_subprotocols']
        if (source != 'ws' or not isinstance(protocols, list)
                or any(not isinstance(item, str) or not _TOKEN.fullmatch(item)
                       for item in protocols)
                or len(set(protocols)) != len(protocols)):
            raise MuseMonitorError()
    for key in ('persistent', 'show_lines'):
        if key in value and not isinstance(value[key], bool):
            raise MuseMonitorError()
    persistent = value.get('persistent', False)
    if 'timeout_ms' in value and (persistent or not _milliseconds(value['timeout_ms'])):
        raise MuseMonitorError()
    if 'wake_delay_ms' in value and not _milliseconds(value['wake_delay_ms'], zero=True):
        raise MuseMonitorError()
    result = deepcopy(value)
    result.setdefault('persistent', False)
    result.setdefault('wake_delay_ms', 120000)
    result.setdefault('show_lines', False)
    if not persistent:
        result.setdefault('timeout_ms', 300000)
    return result


def command_monitor(description, argv, **options):
    """Build monitor input without executing anything or discovering a session."""
    # The caller supplies trusted argv. Quoting prevents shell interpolation of each
    # argument; it cannot establish executable provenance, session ownership or read
    # authority. A real authorized polling command remains a separate prerequisite.
    if (not isinstance(argv, (list, tuple)) or not argv
            or any(not isinstance(arg, str) or '\x00' in arg for arg in argv)
            or not argv[0] or '/' not in argv[0]
            or set(options) - (_FIELDS - {'description', 'command', 'ws', 'ws_subprotocols'})):
        raise MuseMonitorError()
    # A slash bypasses shell builtin lookup without resolving against our process PATH.
    # Command position must be quoted even for shlex-safe assignments/reserved words.
    executable = "'" + argv[0].replace("'", "'\"'\"'") + "'"
    command = ' '.join((executable, *(shlex.quote(arg) for arg in argv[1:])))
    return normalize_monitor({'description': description, 'command': command, **options})
